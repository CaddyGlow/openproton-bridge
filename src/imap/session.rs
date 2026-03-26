use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info, warn};

use super::command::{
    parse_command, Command, FetchItem, ImapFlag, SearchKey, SequenceSet, StatusDataItem,
    StoreAction,
};
use super::gluon_connector::GluonImapConnector;
use super::mailbox;
use super::mailbox_catalog::GluonMailboxCatalog;
use super::mailbox_mutation::GluonMailboxMutation;
use super::mailbox_view::GluonMailboxView;
use super::response::ResponseWriter;
use super::rfc822;
use super::types::{ImapUid, ProtonMessageId, ScopedMailboxId};
use super::Result;

/// RFC 2177 recommends servers terminate IDLE after 30 minutes.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, PartialEq)]
enum State {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

/// Tracks which UIDs have been claimed as \Recent per mailbox.
/// First session to SELECT a mailbox after new messages arrive claims \Recent.
#[derive(Debug, Default)]
pub struct RecentTracker {
    claimed: Mutex<HashMap<String, HashSet<u32>>>,
}

impl RecentTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Claim recent UIDs for a mailbox. Returns which UIDs were newly claimed.
    pub fn claim(&self, mailbox: &str, uids: &[ImapUid]) -> HashSet<ImapUid> {
        let mut claimed = self.claimed.lock().unwrap_or_else(|e| e.into_inner());
        let set = claimed.entry(mailbox.to_string()).or_default();
        let mut recent = HashSet::new();
        for &uid in uids {
            if set.insert(uid.value()) {
                recent.insert(uid);
            }
        }
        recent
    }

    /// Count unclaimed UIDs for STATUS RECENT.
    pub fn count_unclaimed(&self, mailbox: &str, uids: &[ImapUid]) -> u32 {
        let claimed = self.claimed.lock().unwrap_or_else(|e| e.into_inner());
        let set = claimed.get(mailbox);
        uids.iter()
            .filter(|uid| set.map(|s| !s.contains(&uid.value())).unwrap_or(true))
            .count() as u32
    }

    /// Remove UIDs (e.g., after expunge).
    pub fn remove(&self, mailbox: &str, uids: &[ImapUid]) {
        let mut claimed = self.claimed.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(set) = claimed.get_mut(mailbox) {
            for uid in uids {
                set.remove(&uid.value());
            }
        }
    }
}

pub struct SessionConfig {
    pub connector: Arc<dyn gluon_rs_mail::ImapConnector>,
    pub gluon_connector: Arc<dyn GluonImapConnector>,
    pub mailbox_catalog: Arc<dyn GluonMailboxCatalog>,
    pub mailbox_mutation: Arc<dyn GluonMailboxMutation>,
    pub mailbox_view: Arc<dyn GluonMailboxView>,
    pub recent_tracker: Arc<RecentTracker>,
}

static NEXT_IMAP_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Sentinel returned to the caller to signal STARTTLS upgrade is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAction {
    Continue,
    StartTls,
    Close,
}

pub struct ImapSession<R, W: AsyncWriteExt + Unpin> {
    reader: BufReader<R>,
    writer: ResponseWriter<W>,
    state: State,
    config: Arc<SessionConfig>,
    selected_mailbox: Option<String>,
    selected_mailbox_mod_seq: Option<u64>,
    selected_mailbox_uids: Vec<ImapUid>,
    selected_mailbox_flags: HashMap<ImapUid, Vec<String>>,
    selected_mailbox_internal_id: Option<u64>,
    storage_user_id: Option<String>,
    selected_read_only: bool,
    authenticated_account_id: Option<String>,
    user_labels: Vec<mailbox::ResolvedMailbox>,
    starttls_available: bool,
    connection_id: u64,
    recent_uids: HashSet<ImapUid>,
    store_session: Option<gluon_rs_mail::StoreSession>,
}

impl<R, W> ImapSession<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    pub fn new(reader: R, writer: W, config: Arc<SessionConfig>) -> Self {
        Self::with_starttls(reader, writer, config, true)
    }

    pub fn with_starttls(
        reader: R,
        writer: W,
        config: Arc<SessionConfig>,
        starttls_available: bool,
    ) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer: ResponseWriter::new(writer),
            state: State::NotAuthenticated,
            config,
            selected_mailbox: None,
            selected_mailbox_mod_seq: None,
            selected_mailbox_uids: Vec::new(),
            selected_mailbox_flags: HashMap::new(),
            selected_mailbox_internal_id: None,
            storage_user_id: None,
            selected_read_only: false,
            authenticated_account_id: None,
            user_labels: Vec::new(),
            starttls_available,
            connection_id: NEXT_IMAP_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
            recent_uids: HashSet::new(),
            store_session: None,
        }
    }

    pub async fn greet(&mut self) -> Result<()> {
        self.writer
            .untagged("OK IMAP4rev1 openproton-bridge ready")
            .await
    }

    pub async fn run(&mut self) -> Result<SessionAction> {
        self.run_inner(true).await
    }

    pub async fn run_after_starttls(&mut self) -> Result<SessionAction> {
        self.run_inner(false).await
    }

    async fn run_inner(&mut self, send_greeting: bool) -> Result<SessionAction> {
        if send_greeting {
            self.greet().await?;
        }

        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).await?;
            if n == 0 {
                debug!(connection_id = self.connection_id, "client disconnected");
                return Ok(SessionAction::Close);
            }

            let line = line.trim_end().to_string();
            if line.is_empty() {
                continue;
            }

            debug!(
                pkg = "imap/session",
                session = self.connection_id,
                line = %line,
                msg = %line,
                "{line}"
            );

            match self.handle_line(&line).await? {
                SessionAction::Continue => {}
                SessionAction::StartTls => return Ok(SessionAction::StartTls),
                SessionAction::Close => return Ok(SessionAction::Close),
            }
        }
    }

    pub async fn handle_line(&mut self, line: &str) -> Result<SessionAction> {
        let cmd = match parse_command(line) {
            Ok(c) => c,
            Err(e) => {
                // Try to extract tag for BAD response
                let tag = line.split_whitespace().next().unwrap_or("*").to_string();
                self.writer
                    .tagged_bad(&tag, &format!("parse error: {}", e))
                    .await?;
                return Ok(SessionAction::Continue);
            }
        };

        match cmd {
            Command::Capability { ref tag } => self.cmd_capability(tag).await?,
            Command::Login {
                ref tag,
                ref username,
                ref password,
            } => self.cmd_login(tag, username, password).await?,
            Command::Logout { ref tag } => {
                self.cmd_logout(tag).await?;
                return Ok(SessionAction::Close);
            }
            Command::Noop { ref tag } => self.cmd_noop(tag).await?,
            Command::Idle { ref tag } => self.cmd_idle(tag).await?,
            Command::StartTls { ref tag } => {
                self.cmd_starttls(tag).await?;
                return Ok(SessionAction::StartTls);
            }
            Command::List {
                ref tag,
                ref reference,
                ref pattern,
            } => self.cmd_list(tag, reference, pattern).await?,
            Command::Lsub {
                ref tag,
                ref reference,
                ref pattern,
            } => self.cmd_lsub(tag, reference, pattern).await?,
            Command::Select {
                ref tag,
                ref mailbox,
            } => self.cmd_select(tag, mailbox).await?,
            Command::Create {
                ref tag,
                ref mailbox,
            } => self.cmd_create(tag, mailbox).await?,
            Command::Delete {
                ref tag,
                ref mailbox,
            } => self.cmd_delete(tag, mailbox).await?,
            Command::Subscribe {
                ref tag,
                ref mailbox,
            } => self.cmd_subscribe(tag, mailbox).await?,
            Command::Unsubscribe {
                ref tag,
                ref mailbox,
            } => self.cmd_unsubscribe(tag, mailbox).await?,
            Command::Status {
                ref tag,
                ref mailbox,
                ref items,
            } => self.cmd_status(tag, mailbox, items).await?,
            Command::Check { ref tag } => self.cmd_check(tag).await?,
            Command::Close { ref tag } => self.cmd_close(tag).await?,
            Command::Fetch {
                ref tag,
                ref sequence,
                ref items,
                uid,
            } => self.cmd_fetch(tag, sequence, items, uid).await?,
            Command::Store {
                ref tag,
                ref sequence,
                ref action,
                ref flags,
                uid,
            } => self.cmd_store(tag, sequence, action, flags, uid).await?,
            Command::Search {
                ref tag,
                ref criteria,
                uid,
            } => self.cmd_search(tag, criteria, uid).await?,
            Command::Expunge { ref tag } => self.cmd_expunge(tag).await?,
            Command::Copy {
                ref tag,
                ref sequence,
                ref mailbox,
                uid,
            } => self.cmd_copy(tag, sequence, mailbox, uid).await?,
            Command::Move {
                ref tag,
                ref sequence,
                ref mailbox,
                uid,
            } => self.cmd_move(tag, sequence, mailbox, uid).await?,
            Command::Examine {
                ref tag,
                ref mailbox,
            } => self.cmd_examine(tag, mailbox).await?,
            Command::UidExpunge {
                ref tag,
                ref sequence,
            } => self.cmd_uid_expunge(tag, sequence).await?,
            Command::Unselect { ref tag } => self.cmd_unselect(tag).await?,
            Command::Append {
                ref tag,
                ref mailbox,
                ref flags,
                ref date,
                literal_size,
            } => {
                self.cmd_append(tag, mailbox, flags, date, literal_size)
                    .await?
            }
        }

        Ok(SessionAction::Continue)
    }

    async fn cmd_capability(&mut self, tag: &str) -> Result<()> {
        let caps = if self.state == State::NotAuthenticated {
            if self.starttls_available {
                "CAPABILITY IMAP4rev1 STARTTLS IDLE UIDPLUS MOVE UNSELECT"
            } else {
                "CAPABILITY IMAP4rev1 IDLE UIDPLUS MOVE UNSELECT"
            }
        } else {
            "CAPABILITY IMAP4rev1 IDLE UIDPLUS MOVE UNSELECT"
        };
        self.writer.untagged(caps).await?;
        self.writer
            .tagged_ok(tag, None, "CAPABILITY completed")
            .await
    }

    async fn cmd_login(&mut self, tag: &str, username: &str, password: &str) -> Result<()> {
        if self.state != State::NotAuthenticated {
            return self.writer.tagged_bad(tag, "already authenticated").await;
        }

        let auth_result = match self.config.connector.authorize(username, password).await {
            Ok(r) => r,
            Err(gluon_rs_mail::ImapError::AuthFailed) => {
                return self
                    .writer
                    .tagged_no(tag, "[AUTHENTICATIONFAILED] invalid credentials")
                    .await;
            }
            Err(e) => {
                warn!(error = %e, "connector authorize failed");
                return self
                    .writer
                    .tagged_no(tag, &format!("login failed: {e}"))
                    .await;
            }
        };

        // Convert MailboxInfo back to ResolvedMailbox for the session's user_labels
        self.user_labels = auth_result
            .mailboxes
            .into_iter()
            .map(|mb| mailbox::ResolvedMailbox {
                name: mb.name,
                label_id: mb.id,
                special_use: mb.special_use,
                selectable: mb.selectable,
            })
            .collect();

        self.authenticated_account_id = Some(auth_result.account_id.clone());
        self.storage_user_id = Some(
            self.config
                .gluon_connector
                .resolve_storage_user_id(Some(&auth_result.account_id))
                .to_string(),
        );
        self.state = State::Authenticated;

        match self
            .config
            .gluon_connector
            .acquire_store_session(Some(&auth_result.account_id))
            .await
        {
            Ok(session) => self.store_session = Some(session),
            Err(e) => {
                warn!(error = %e, "failed to acquire pinned store session, falling back to pool");
            }
        }

        info!(
            service = "imap",
            msg = "IMAP login successful",
            connection_id = self.connection_id,
            email = %auth_result.primary_email,
            "IMAP login successful"
        );
        self.writer.tagged_ok(tag, None, "LOGIN completed").await
    }

    async fn cmd_logout(&mut self, tag: &str) -> Result<()> {
        self.writer.untagged("BYE server logging out").await?;
        self.state = State::Logout;
        self.authenticated_account_id = None;
        self.storage_user_id = None;
        self.selected_mailbox = None;
        self.selected_mailbox_mod_seq = None;
        self.selected_mailbox_internal_id = None;
        self.selected_mailbox_uids.clear();
        self.selected_mailbox_flags.clear();
        self.store_session = None;
        self.writer.tagged_ok(tag, None, "LOGOUT completed").await
    }

    async fn cmd_noop(&mut self, tag: &str) -> Result<()> {
        self.emit_selected_mailbox_exists_update().await?;
        self.writer.tagged_ok(tag, None, "NOOP completed").await
    }

    async fn cmd_idle(&mut self, tag: &str) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        let scoped_mailbox = self
            .selected_mailbox
            .as_ref()
            .map(|mailbox| self.scoped_mailbox_name(mailbox))
            .ok_or_else(|| super::ImapError::Protocol("no mailbox selected".to_string()))?;
        let mut update_rx = self.config.gluon_connector.subscribe_updates();
        self.writer.continuation("idling").await?;
        self.emit_selected_mailbox_exists_update().await?;

        let idle_deadline = tokio::time::Instant::now() + IDLE_TIMEOUT;
        let idle_timeout = tokio::time::sleep_until(idle_deadline);
        tokio::pin!(idle_timeout);

        loop {
            let mut line = String::new();
            tokio::select! {
                _ = &mut idle_timeout => {
                    debug!("IDLE timeout after 30 minutes");
                    break;
                }
                update = update_rx.recv() => {
                    match update {
                        Ok(update) if update.affects_scoped_mailbox(&scoped_mailbox) => {
                            self.emit_selected_mailbox_exists_update().await?;
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            self.emit_selected_mailbox_exists_update().await?;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
                read = self.reader.read_line(&mut line) => {
                    let n = read?;
                    if n == 0 {
                        return Ok(());
                    }

                    let trimmed = line.trim_end_matches(['\r', '\n']).trim();
                    if trimmed.eq_ignore_ascii_case("DONE") {
                        break;
                    }

                    if !trimmed.is_empty() {
                        self.writer.untagged("BAD expected DONE").await?;
                    }
                }
            }
        }

        self.writer.tagged_ok(tag, None, "IDLE terminated").await
    }

    async fn cmd_starttls(&mut self, tag: &str) -> Result<()> {
        if self.state != State::NotAuthenticated {
            return self
                .writer
                .tagged_bad(tag, "STARTTLS only in not-authenticated state")
                .await;
        }
        if !self.starttls_available {
            return self.writer.tagged_bad(tag, "STARTTLS unavailable").await;
        }
        self.writer
            .tagged_ok(tag, None, "begin TLS negotiation")
            .await
    }

    fn scoped_mailbox_name(&self, mailbox: &str) -> ScopedMailboxId {
        ScopedMailboxId::from_parts(self.authenticated_account_id.as_deref(), mailbox)
    }

    async fn resolve_mailbox(&self, name: &str) -> Option<mailbox::ResolvedMailbox> {
        if let Some(mb) = self.config.mailbox_catalog.resolve_mailbox(
            self.authenticated_account_id.as_deref(),
            &self.user_labels,
            name,
        ) {
            return Some(mb);
        }
        // Fall back to checking the gluon store for dynamically created mailboxes
        let scoped = self.scoped_mailbox_name(name);
        if self.config.gluon_connector.mailbox_exists(&scoped).await {
            return Some(mailbox::ResolvedMailbox {
                name: name.to_string(),
                label_id: name.to_string(),
                special_use: None,
                selectable: true,
            });
        }
        None
    }

    fn all_mailboxes(&self) -> Vec<mailbox::ResolvedMailbox> {
        self.config
            .mailbox_catalog
            .all_mailboxes(self.authenticated_account_id.as_deref(), &self.user_labels)
    }

    fn resolve_target_uids(
        &self,
        all_uids: &[ImapUid],
        sequence: &SequenceSet,
        uid_mode: bool,
    ) -> Vec<ImapUid> {
        if all_uids.is_empty() {
            return Vec::new();
        }

        let max_uid = all_uids.last().map(|u| u.value()).unwrap_or(0);
        let max_seq = all_uids.len() as u32;

        if uid_mode {
            all_uids
                .iter()
                .filter(|uid| sequence.contains(uid.value(), max_uid))
                .copied()
                .collect()
        } else {
            all_uids
                .iter()
                .enumerate()
                .filter(|(i, _)| sequence.contains(*i as u32 + 1, max_seq))
                .map(|(_, &uid)| uid)
                .collect()
        }
    }

    async fn copy_message_local(
        &self,
        source_mailbox: &ScopedMailboxId,
        dest_mailbox: &ScopedMailboxId,
        source_uid: ImapUid,
    ) -> Result<Option<ImapUid>> {
        let mutation = self.config.mailbox_mutation.clone();
        let Some(proton_id) = mutation.get_proton_id(source_mailbox, source_uid).await? else {
            return Ok(None);
        };
        let Some(metadata) = mutation.get_metadata(source_mailbox, source_uid).await? else {
            return Ok(None);
        };

        let dest_uid = mutation
            .store_metadata(
                dest_mailbox,
                &ProtonMessageId::from(proton_id.as_str()),
                metadata,
            )
            .await?;

        let flags = mutation.get_flags(source_mailbox, source_uid).await?;
        mutation.set_flags(dest_mailbox, dest_uid, flags).await?;

        if let Some(rfc822) = mutation.get_rfc822(source_mailbox, source_uid).await? {
            mutation
                .store_rfc822(dest_mailbox, dest_uid, rfc822)
                .await?;
        }

        Ok(Some(dest_uid))
    }

    async fn refresh_selected_snapshot(&mut self) -> Result<()> {
        let Some(mailbox) = self.selected_mailbox.clone() else {
            return Ok(());
        };
        let data = if let (Some(ref mut ss), Some(mb_id)) =
            (&mut self.store_session, self.selected_mailbox_internal_id)
        {
            select_data_from_session(ss, mb_id).await?
        } else {
            let scoped = self.scoped_mailbox_name(&mailbox);
            self.config
                .mailbox_view
                .select_mailbox_data_fast(&scoped)
                .await?
        };
        self.selected_mailbox_uids = data.uids;
        self.selected_mailbox_flags = data.flags;
        self.selected_mailbox_mod_seq = Some(data.snapshot.mod_seq);
        Ok(())
    }

    async fn emit_selected_mailbox_exists_update(&mut self) -> Result<()> {
        if self.state != State::Selected {
            return Ok(());
        }
        let Some(mailbox) = self.selected_mailbox.clone() else {
            return Ok(());
        };

        let select_data = if let (Some(ref mut ss), Some(mb_id)) =
            (&mut self.store_session, self.selected_mailbox_internal_id)
        {
            select_data_from_session(ss, mb_id).await?
        } else {
            let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
            self.config
                .mailbox_view
                .select_mailbox_data_fast(&scoped_mailbox)
                .await?
        };

        let previous_mod_seq = self.selected_mailbox_mod_seq.unwrap_or(0);
        let previous_exists = self.selected_mailbox_uids.len() as u32;
        let current_uids = select_data.uids;
        let current_flags = select_data.flags;
        let snapshot = select_data.snapshot;

        let has_uid_change = current_uids != self.selected_mailbox_uids;
        let has_flag_change = current_uids
            .iter()
            .any(|uid| self.selected_mailbox_flags.get(uid) != current_flags.get(uid));

        if snapshot.mod_seq > previous_mod_seq
            || snapshot.exists != previous_exists
            || has_uid_change
            || has_flag_change
        {
            if self.selected_mailbox_mod_seq.is_some() {
                let current_uid_set: HashSet<ImapUid> = current_uids.iter().copied().collect();
                let mut removed_count = 0u32;
                for (idx, uid) in self.selected_mailbox_uids.iter().enumerate() {
                    if !current_uid_set.contains(uid) {
                        let seq = idx as u32 + 1 - removed_count;
                        self.writer.untagged(&format!("{seq} EXPUNGE")).await?;
                        removed_count = removed_count.saturating_add(1);
                    }
                }

                if snapshot.exists != previous_exists {
                    self.writer
                        .untagged(&format!("{} EXISTS", snapshot.exists))
                        .await?;
                }

                for (idx, uid) in current_uids.iter().enumerate() {
                    let Some(new_flags) = current_flags.get(uid) else {
                        continue;
                    };
                    let old_flags = self.selected_mailbox_flags.get(uid);
                    if old_flags.is_none() || old_flags != Some(new_flags) {
                        let flag_str = new_flags.join(" ");
                        self.writer
                            .untagged(&format!("{} FETCH (FLAGS ({}))", idx + 1, flag_str))
                            .await?;
                    }
                }
            } else {
                self.writer
                    .untagged(&format!("{} EXISTS", snapshot.exists))
                    .await?;
            }

            self.selected_mailbox_uids = current_uids;
            self.selected_mailbox_flags = current_flags;
            self.selected_mailbox_mod_seq = Some(snapshot.mod_seq);
        }
        Ok(())
    }

    fn matches_list_pattern(name: &str, pattern: &str) -> bool {
        // RFC 3501 6.3.8 wildcard matching:
        //   '*' matches zero or more characters (including hierarchy separator)
        //   '%' matches zero or more characters but not hierarchy separator '/'
        Self::glob_match(name.as_bytes(), pattern.as_bytes())
    }

    fn glob_match(name: &[u8], pattern: &[u8]) -> bool {
        let mut ni = 0;
        let mut pi = 0;
        let mut star_pi = usize::MAX;
        let mut star_ni = 0;

        while ni < name.len() {
            if pi < pattern.len()
                && (pattern[pi] == b'*' || (pattern[pi] == b'%' && name[ni] != b'/'))
            {
                if pattern[pi] == b'*' {
                    star_pi = pi;
                    star_ni = ni;
                    pi += 1;
                    continue;
                } else {
                    // '%' -- try to match zero chars first, backtrack if needed
                    star_pi = pi;
                    star_ni = ni;
                    pi += 1;
                    continue;
                }
            }

            if pi < pattern.len()
                && (pattern[pi].eq_ignore_ascii_case(&name[ni]) || pattern[pi] == b'?')
            {
                ni += 1;
                pi += 1;
                continue;
            }

            if star_pi != usize::MAX {
                pi = star_pi + 1;
                star_ni += 1;
                // For '%', cannot skip over '/'
                if pattern[star_pi] == b'%' && star_ni <= name.len() {
                    if star_ni > 0 && name[star_ni - 1] == b'/' {
                        return false;
                    }
                }
                ni = star_ni;
                continue;
            }

            return false;
        }

        while pi < pattern.len() && (pattern[pi] == b'*' || pattern[pi] == b'%') {
            pi += 1;
        }
        pi == pattern.len()
    }

    fn format_list_entry(kind: &str, mb: &mailbox::ResolvedMailbox) -> String {
        let mut attrs = Vec::new();
        if !mb.selectable {
            attrs.push("\\Noselect".to_string());
        }
        if let Some(su) = &mb.special_use {
            attrs.push(su.clone());
        }
        let attr_str = attrs.join(" ");
        format!("{kind} ({attr_str}) \"/\" \"{name}\"", name = mb.name)
    }

    async fn cmd_list(&mut self, tag: &str, reference: &str, pattern: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        if pattern.is_empty() {
            self.writer.untagged("LIST (\\Noselect) \"/\" \"\"").await?;
        } else {
            let full_pattern = if reference.is_empty() {
                pattern.to_string()
            } else {
                format!("{reference}{pattern}")
            };

            let all = self.all_mailboxes();
            // Collect parent paths that need \Noselect entries
            let mut parents: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for mb in &all {
                let mut path = String::new();
                for (i, seg) in mb.name.split('/').enumerate() {
                    if i > 0 {
                        path.push('/');
                    }
                    path.push_str(seg);
                    // Only add as parent if it's not a real mailbox
                    if path != mb.name && !all.iter().any(|m| m.name.eq_ignore_ascii_case(&path)) {
                        parents.insert(path.clone());
                    }
                }
            }

            // Emit real mailboxes
            for mb in &all {
                if Self::matches_list_pattern(&mb.name, &full_pattern) {
                    self.writer
                        .untagged(&Self::format_list_entry("LIST", mb))
                        .await?;
                }
            }

            // Emit parent-only \Noselect entries
            for parent in &parents {
                if Self::matches_list_pattern(parent, &full_pattern) {
                    self.writer
                        .untagged(&format!("LIST (\\Noselect) \"/\" \"{}\"", parent))
                        .await?;
                }
            }
        }

        self.writer.tagged_ok(tag, None, "LIST completed").await
    }

    async fn cmd_lsub(&mut self, tag: &str, reference: &str, pattern: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        if pattern.is_empty() {
            self.writer.untagged("LSUB (\\Noselect) \"/\" \"\"").await?;
        } else {
            let full_pattern = if reference.is_empty() {
                pattern.to_string()
            } else {
                format!("{reference}{pattern}")
            };
            for mb in self.all_mailboxes() {
                if Self::matches_list_pattern(&mb.name, &full_pattern) {
                    self.writer
                        .untagged(&Self::format_list_entry("LSUB", &mb))
                        .await?;
                }
            }
        }

        self.writer.tagged_ok(tag, None, "LSUB completed").await
    }

    async fn cmd_create(&mut self, tag: &str, mailbox_name: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        // If mailbox already exists, return OK for idempotent behavior.
        // imaptest expects CREATE to succeed even if the mailbox exists.
        if self.resolve_mailbox(mailbox_name).await.is_some() {
            return self.writer.tagged_ok(tag, None, "CREATE completed").await;
        }

        let scoped = self.scoped_mailbox_name(mailbox_name);
        if let Err(e) = self.config.gluon_connector.create_mailbox(&scoped).await {
            return self
                .writer
                .tagged_no(tag, &format!("CREATE failed: {e}"))
                .await;
        }

        // Add to session's user_labels so it can be resolved immediately
        self.user_labels.push(mailbox::ResolvedMailbox {
            name: mailbox_name.to_string(),
            label_id: mailbox_name.to_string(),
            special_use: None,
            selectable: true,
        });

        self.writer.tagged_ok(tag, None, "CREATE completed").await
    }

    async fn cmd_delete(&mut self, tag: &str, mailbox_name: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        // Cannot delete system mailboxes
        if mailbox::find_mailbox(mailbox_name).is_some() {
            return self
                .writer
                .tagged_no(tag, "[CANNOT] cannot delete system mailbox")
                .await;
        }

        // Cannot delete selected mailbox
        if self.selected_mailbox.as_deref() == Some(mailbox_name) {
            return self
                .writer
                .tagged_no(tag, "cannot delete selected mailbox")
                .await;
        }

        let scoped = self.scoped_mailbox_name(mailbox_name);
        if let Err(e) = self
            .config
            .gluon_connector
            .delete_mailbox(&scoped, false)
            .await
        {
            return self
                .writer
                .tagged_no(tag, &format!("DELETE failed: {e}"))
                .await;
        }

        // Remove from session's user_labels
        self.user_labels.retain(|l| l.name != mailbox_name);

        self.writer.tagged_ok(tag, None, "DELETE completed").await
    }

    async fn cmd_subscribe(&mut self, tag: &str, mailbox_name: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        // Check if mailbox exists - if so, silently succeed (all mailboxes are subscribed)
        if self.resolve_mailbox(mailbox_name).await.is_some() {
            return self
                .writer
                .tagged_ok(tag, None, "SUBSCRIBE completed")
                .await;
        }

        // Mailbox doesn't exist
        self.writer
            .tagged_no(tag, "[NONEXISTENT] mailbox does not exist")
            .await
    }

    async fn cmd_unsubscribe(&mut self, tag: &str, mailbox_name: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        // Check if mailbox exists - if so, silently succeed (we don't actually unsubscribe)
        if self.resolve_mailbox(mailbox_name).await.is_some() {
            return self
                .writer
                .tagged_ok(tag, None, "UNSUBSCRIBE completed")
                .await;
        }

        // Mailbox doesn't exist
        self.writer
            .tagged_no(tag, "[NONEXISTENT] mailbox does not exist")
            .await
    }

    async fn cmd_select(&mut self, tag: &str, mailbox_name: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        let mb = match self.resolve_mailbox(mailbox_name).await {
            Some(m) => m,
            None => {
                return self
                    .writer
                    .tagged_no(tag, &format!("mailbox not found: {}", mailbox_name))
                    .await;
            }
        };

        if !mb.selectable {
            return self
                .writer
                .tagged_no(tag, &format!("mailbox not selectable: {}", mailbox_name))
                .await;
        }

        let mutation = self.config.mailbox_mutation.clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mb.name);
        let cached_uids = self.config.mailbox_view.list_uids(&scoped_mailbox).await?;

        if cached_uids.is_empty() {
            let account_id = self
                .authenticated_account_id
                .as_deref()
                .unwrap_or("unknown");

            let mut page = 0i32;
            let mut loaded = 0usize;
            loop {
                let meta_page = match self
                    .config
                    .connector
                    .fetch_message_metadata_page(account_id, &mb.label_id, page, 150)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, page, "failed to fetch message metadata");
                        return self.writer.tagged_no(tag, "failed to fetch messages").await;
                    }
                };

                if meta_page.messages.is_empty() {
                    break;
                }

                for meta in &meta_page.messages {
                    mutation
                        .store_metadata(
                            &scoped_mailbox,
                            &ProtonMessageId::from(meta.id.as_str()),
                            meta.clone(),
                        )
                        .await?;
                }

                loaded = loaded.saturating_add(meta_page.messages.len());
                let total = usize::try_from(meta_page.total.max(0)).unwrap_or(usize::MAX);
                if loaded >= total {
                    break;
                }
                page += 1;
            }
        } else {
            info!(
                service = "imap",
                msg = "Messages are already synced, skipping",
                user_id = self.authenticated_account_id.as_deref().unwrap_or("unknown"),
                mailbox = %mb.name,
                count = cached_uids.len(),
                "Messages are already synced, skipping"
            );
        }

        let select_data = if let Some(ref mut ss) = self.store_session {
            if let Some(mb_internal_id) = resolve_mailbox_internal_id(ss, &mb.name).await {
                self.selected_mailbox_internal_id = Some(mb_internal_id);
                select_data_from_session(ss, mb_internal_id).await?
            } else {
                self.selected_mailbox_internal_id = None;
                self.config
                    .mailbox_view
                    .select_mailbox_data_fast(&scoped_mailbox)
                    .await?
            }
        } else {
            self.selected_mailbox_internal_id = None;
            self.config
                .mailbox_view
                .select_mailbox_data_fast(&scoped_mailbox)
                .await?
        };

        // Collect custom keywords from all messages in the mailbox
        let mut keywords: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for flags in select_data.flags.values() {
            for flag in flags {
                if !flag.starts_with('\\') {
                    keywords.insert(flag.clone());
                }
            }
        }

        let mut flags_list = "\\Seen \\Answered \\Flagged \\Deleted \\Draft".to_string();
        for kw in &keywords {
            flags_list.push(' ');
            flags_list.push_str(kw);
        }

        // Claim recent UIDs for this session
        self.recent_uids = self
            .config
            .recent_tracker
            .claim(&mb.name, &select_data.uids);
        let recent_count = self.recent_uids.len();

        self.writer
            .untagged(&format!("{} EXISTS", select_data.status.exists))
            .await?;
        self.writer
            .untagged(&format!("{recent_count} RECENT"))
            .await?;
        self.writer
            .untagged(&format!("FLAGS ({flags_list})"))
            .await?;
        self.writer
            .untagged(&format!(
                "OK [PERMANENTFLAGS ({flags_list} \\*)] Flags permitted"
            ))
            .await?;
        self.writer
            .untagged(&format!(
                "OK [UIDVALIDITY {}] UIDs valid",
                select_data.status.uid_validity
            ))
            .await?;
        self.writer
            .untagged(&format!(
                "OK [UIDNEXT {}] Predicted next UID",
                select_data.status.next_uid
            ))
            .await?;
        if let Some(first_unseen_seq) = select_data.first_unseen_seq {
            self.writer
                .untagged(&format!("OK [UNSEEN {}] First unseen", first_unseen_seq))
                .await?;
        }

        self.selected_mailbox = Some(mb.name.to_string());
        self.selected_mailbox_mod_seq = Some(select_data.snapshot.mod_seq);
        self.selected_mailbox_uids = select_data.uids.clone();
        self.selected_mailbox_flags = select_data.flags;
        self.selected_read_only = false;
        self.state = State::Selected;

        info!(
            service = "imap",
            msg = "mailbox selected",
            mailbox = %mb.name,
            messages = select_data.status.exists,
            "mailbox selected"
        );

        self.writer
            .tagged_ok(tag, Some("READ-WRITE"), "SELECT completed")
            .await
    }

    async fn cmd_status(
        &mut self,
        tag: &str,
        mailbox_name: &str,
        items: &[StatusDataItem],
    ) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        let mb = match self.resolve_mailbox(mailbox_name).await {
            Some(m) => m,
            None => {
                return self
                    .writer
                    .tagged_no(tag, &format!("mailbox not found: {}", mailbox_name))
                    .await;
            }
        };

        let scoped_mailbox = self.scoped_mailbox_name(&mb.name);
        let status = self
            .config
            .mailbox_view
            .mailbox_status(&scoped_mailbox)
            .await?;

        let mut attrs = Vec::new();
        for item in items {
            match item {
                StatusDataItem::Messages => attrs.push(format!("MESSAGES {}", status.exists)),
                StatusDataItem::Recent => {
                    let uids = self.config.mailbox_view.list_uids(&scoped_mailbox).await?;
                    let recent = self.config.recent_tracker.count_unclaimed(&mb.name, &uids);
                    attrs.push(format!("RECENT {recent}"));
                }
                StatusDataItem::UidNext => attrs.push(format!("UIDNEXT {}", status.next_uid)),
                StatusDataItem::UidValidity => {
                    attrs.push(format!("UIDVALIDITY {}", status.uid_validity))
                }
                StatusDataItem::Unseen => attrs.push(format!("UNSEEN {}", status.unseen)),
            }
        }

        self.writer
            .untagged(&format!(
                "STATUS {} ({})",
                format_mailbox_name(&mb.name),
                attrs.join(" ")
            ))
            .await?;
        self.writer.tagged_ok(tag, None, "STATUS completed").await
    }

    async fn cmd_close(&mut self, tag: &str) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }
        if !self.selected_read_only {
            // Silently expunge deleted messages for read-write selections.
            let _ = self.do_expunge(true, None).await?;
        }

        self.selected_mailbox = None;
        self.selected_mailbox_mod_seq = None;
        self.selected_mailbox_internal_id = None;
        self.selected_mailbox_uids.clear();
        self.selected_mailbox_flags.clear();
        self.selected_read_only = false;
        self.state = State::Authenticated;
        self.writer.tagged_ok(tag, None, "CLOSE completed").await
    }

    async fn cmd_unselect(&mut self, tag: &str) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }
        // Unlike CLOSE, do NOT expunge deleted messages
        self.selected_mailbox = None;
        self.selected_mailbox_mod_seq = None;
        self.selected_mailbox_internal_id = None;
        self.selected_mailbox_uids.clear();
        self.selected_mailbox_flags.clear();
        self.selected_read_only = false;
        self.state = State::Authenticated;
        self.writer.tagged_ok(tag, None, "UNSELECT completed").await
    }

    async fn cmd_check(&mut self, tag: &str) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }
        self.emit_selected_mailbox_exists_update().await?;
        self.writer.tagged_ok(tag, None, "CHECK completed").await
    }

    async fn cmd_examine(&mut self, tag: &str, mailbox_name: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        let mb = match self.resolve_mailbox(mailbox_name).await {
            Some(m) => m,
            None => {
                return self
                    .writer
                    .tagged_no(tag, &format!("mailbox not found: {}", mailbox_name))
                    .await;
            }
        };

        if !mb.selectable {
            return self
                .writer
                .tagged_no(tag, &format!("mailbox not selectable: {}", mailbox_name))
                .await;
        }

        let mutation = self.config.mailbox_mutation.clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mb.name);
        let cached_uids = self.config.mailbox_view.list_uids(&scoped_mailbox).await?;

        if cached_uids.is_empty() {
            let account_id = self
                .authenticated_account_id
                .as_deref()
                .unwrap_or("unknown");

            let mut page = 0i32;
            let mut loaded = 0usize;
            loop {
                let meta_page = match self
                    .config
                    .connector
                    .fetch_message_metadata_page(account_id, &mb.label_id, page, 150)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, page, "failed to fetch message metadata");
                        return self.writer.tagged_no(tag, "failed to fetch messages").await;
                    }
                };

                if meta_page.messages.is_empty() {
                    break;
                }

                for meta in &meta_page.messages {
                    mutation
                        .store_metadata(
                            &scoped_mailbox,
                            &ProtonMessageId::from(meta.id.as_str()),
                            meta.clone(),
                        )
                        .await?;
                }

                loaded = loaded.saturating_add(meta_page.messages.len());
                let total = usize::try_from(meta_page.total.max(0)).unwrap_or(usize::MAX);
                if loaded >= total {
                    break;
                }
                page += 1;
            }
        }

        let select_data = self
            .config
            .mailbox_view
            .select_mailbox_data_fast(&scoped_mailbox)
            .await?;

        self.writer
            .untagged(&format!("{} EXISTS", select_data.status.exists))
            .await?;
        self.writer.untagged("0 RECENT").await?;
        self.writer
            .untagged("FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)")
            .await?;
        self.writer
            .untagged(&format!(
                "OK [UIDVALIDITY {}]",
                select_data.status.uid_validity
            ))
            .await?;
        self.writer
            .untagged(&format!("OK [UIDNEXT {}]", select_data.status.next_uid))
            .await?;
        if let Some(first_unseen_seq) = select_data.first_unseen_seq {
            self.writer
                .untagged(&format!("OK [UNSEEN {}]", first_unseen_seq))
                .await?;
        }

        self.selected_mailbox = Some(mb.name.to_string());
        self.selected_mailbox_mod_seq = Some(select_data.snapshot.mod_seq);
        self.selected_mailbox_uids = select_data.uids.clone();
        self.selected_mailbox_flags = select_data.flags;
        self.selected_read_only = true;
        self.state = State::Selected;

        info!(
            service = "imap",
            msg = "mailbox examined (read-only)",
            mailbox = %mb.name,
            messages = select_data.status.exists,
            "mailbox examined (read-only)"
        );

        self.writer
            .tagged_ok(tag, Some("READ-ONLY"), "EXAMINE completed")
            .await
    }

    async fn cmd_fetch(
        &mut self,
        tag: &str,
        sequence: &SequenceSet,
        items: &[FetchItem],
        uid_mode: bool,
    ) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        self.refresh_selected_snapshot().await?;
        let mailbox = self.selected_mailbox.as_ref().unwrap().clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let mailbox_view = self.config.mailbox_view.clone();
        let all_uids = self.selected_mailbox_uids.clone();

        if all_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "FETCH completed").await;
        }

        let max_uid = all_uids.last().map(|u| u.value()).unwrap_or(0);
        let max_seq = all_uids.len() as u32;

        // Expand macro items and ensure UID is included for UID FETCH (RFC 3501 7.4.2)
        let mut expanded = expand_fetch_items(items);
        if uid_mode && !expanded.contains(&FetchItem::Uid) {
            expanded.insert(0, FetchItem::Uid);
        }
        let needs_body_sections = expanded
            .iter()
            .any(|i| matches!(i, FetchItem::BodySection { .. }));
        let needs_full_rfc822 = expanded.iter().any(|i| match i {
            FetchItem::BodySection { section, .. } => {
                !body_section_is_header_only(section.as_deref())
            }
            FetchItem::Rfc822Text => true,
            _ => false,
        });
        let needs_metadata = expanded.iter().any(|i| {
            matches!(
                i,
                FetchItem::Envelope
                    | FetchItem::Rfc822Size
                    | FetchItem::Rfc822Header
                    | FetchItem::Rfc822Text
                    | FetchItem::InternalDate
                    | FetchItem::BodyStructure
                    | FetchItem::Body
                    | FetchItem::BodySection { .. }
            )
        });

        // Resolve which messages to fetch from current mailbox snapshot.
        let target_messages: Vec<(ImapUid, u32)> = if uid_mode {
            all_uids
                .iter()
                .enumerate()
                .filter(|(_, uid)| sequence.contains(uid.value(), max_uid))
                .map(|(i, &uid)| (uid, i as u32 + 1))
                .collect()
        } else {
            all_uids
                .iter()
                .enumerate()
                .filter(|(i, _)| sequence.contains(*i as u32 + 1, max_seq))
                .map(|(i, &uid)| (uid, i as u32 + 1))
                .collect()
        };
        let seen_flag = "\\Seen".to_string();
        let user_id = self
            .authenticated_account_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let header_only_body_fetch = needs_body_sections && !needs_full_rfc822;
        let target_fetch_count = target_messages.len() as u32;
        let mut cache_hits = 0u32;
        let mut cache_misses = 0u32;

        // Take the pinned store session for the duration of the fetch loop to
        // avoid per-message pool.acquire() overhead.
        let mut pinned_session = self.store_session.take();
        let pinned_mb_id = self.selected_mailbox_internal_id;
        let pinned_account_paths = if pinned_session.is_some() {
            self.storage_user_id
                .as_deref()
                .and_then(|suid| self.config.gluon_connector.account_paths(suid).ok())
        } else {
            None
        };

        for (uid, seq) in target_messages {
            let meta = if needs_metadata {
                if let (Some(ref mut ss), Some(mb_id), Some(ref ap)) =
                    (&mut pinned_session, pinned_mb_id, &pinned_account_paths)
                {
                    match ss.message_by_uid(mb_id, uid.value(), ap) {
                        Ok(Some(message)) => {
                            let blob_data = if message.blob_exists {
                                self.storage_user_id.as_deref().and_then(|suid| {
                                    self.config
                                        .gluon_connector
                                        .read_message_blob(suid, &message.summary.internal_id)
                                        .ok()
                                })
                            } else {
                                None
                            };
                            let parsed = blob_data.as_deref().and_then(|data| {
                                super::gluon_mailbox_view::parse_metadata_from_rfc822(
                                    &scoped_mailbox,
                                    &message.summary,
                                    data,
                                )
                            });
                            Some(parsed.unwrap_or_else(|| {
                                super::gluon_mailbox_view::fallback_metadata(
                                    &scoped_mailbox,
                                    &message,
                                )
                            }))
                        }
                        Ok(None) => None,
                        Err(_) => mailbox_view.get_metadata(&scoped_mailbox, uid).await?,
                    }
                } else {
                    mailbox_view.get_metadata(&scoped_mailbox, uid).await?
                }
            } else {
                None
            };
            let mut flags = self
                .selected_mailbox_flags
                .get(&uid)
                .cloned()
                .unwrap_or_default();
            if self.recent_uids.contains(&uid) {
                flags.push("\\Recent".to_string());
            }
            let mut has_seen = flags.iter().any(|flag| flag == &seen_flag);

            if needs_body_sections {
                if let Some(ref meta) = meta {
                    debug!(
                        pkg = "gluon/state/mailbox",
                        UID = uid.value(),
                        mboxID = %scoped_mailbox,
                        messageID = %meta.id,
                        msg = "Fetch Body",
                        "Fetch Body"
                    );
                }
            }

            let mut parts: Vec<String> = Vec::with_capacity(expanded.len());
            let mut part_literals: HashMap<usize, Vec<u8>> = HashMap::new();

            let mut rfc822_data = None;
            let needs_rfc822_header_or_text = expanded
                .iter()
                .any(|i| matches!(i, FetchItem::Rfc822Header | FetchItem::Rfc822Text));
            let needs_rfc822_load = (needs_body_sections && !header_only_body_fetch)
                || needs_full_rfc822
                || needs_rfc822_header_or_text;
            if needs_rfc822_load {
                rfc822_data = mailbox_view.get_rfc822(&scoped_mailbox, uid).await?;
                if rfc822_data.is_some() {
                    cache_hits = cache_hits.saturating_add(1);
                } else {
                    cache_misses = cache_misses.saturating_add(1);
                }
                if rfc822_data.is_none() && needs_full_rfc822 {
                    // Fetch + decrypt on demand for full/body/text paths.
                    if let Some(ref meta) = meta {
                        rfc822_data = self
                            .fetch_and_cache_rfc822(&scoped_mailbox, uid, &meta.id)
                            .await?;
                    }
                }
            }

            for item in &expanded {
                match item {
                    FetchItem::Flags => {
                        let flag_str = flags.join(" ");
                        parts.push(format!("FLAGS ({})", flag_str));
                    }
                    FetchItem::Uid => {
                        parts.push(format!("UID {}", uid));
                    }
                    FetchItem::Envelope => {
                        if let Some(ref meta) = meta {
                            // Need the original header for envelope
                            let header = if let Some(ref data) = rfc822_data {
                                extract_header_section(data)
                            } else {
                                String::new()
                            };
                            let env = rfc822::build_envelope(meta, &header);
                            parts.push(format!("ENVELOPE {}", env));
                        }
                    }
                    FetchItem::Rfc822Size => {
                        if let Some(ref data) = rfc822_data {
                            parts.push(format!("RFC822.SIZE {}", data.len()));
                        } else if let Some(ref meta) = meta {
                            parts.push(format!("RFC822.SIZE {}", meta.size));
                        }
                    }
                    FetchItem::Rfc822Header => {
                        let header_data = if let Some(ref data) = rfc822_data {
                            extract_header_section(data).into_bytes()
                        } else if let Some(ref meta) = meta {
                            build_metadata_header_section(meta).into_bytes()
                        } else {
                            Vec::new()
                        };
                        let idx = parts.len();
                        parts.push(format!("RFC822.HEADER {{{}}}", header_data.len()));
                        part_literals.insert(idx, header_data);
                    }
                    FetchItem::Rfc822Text => {
                        let text_data = if let Some(ref data) = rfc822_data {
                            extract_text_section(data)
                        } else {
                            Vec::new()
                        };
                        let idx = parts.len();
                        parts.push(format!("RFC822.TEXT {{{}}}", text_data.len()));
                        part_literals.insert(idx, text_data);
                    }
                    FetchItem::InternalDate => {
                        if let Some(ref meta) = meta {
                            parts.push(format!(
                                "INTERNALDATE {}",
                                rfc822::format_internal_date(meta.time)
                            ));
                        }
                    }
                    FetchItem::BodyStructure => {
                        let structure = if let Some(ref data) = rfc822_data {
                            rfc822::build_bodystructure(data)
                        } else if let Some(ref m) = meta {
                            rfc822::simple_text_structure(m.size as usize)
                        } else {
                            rfc822::simple_text_structure(0)
                        };
                        parts.push(format!("BODYSTRUCTURE {}", structure));
                    }
                    FetchItem::Body => {
                        let body = if let Some(ref data) = rfc822_data {
                            rfc822::build_body(data)
                        } else if let Some(ref m) = meta {
                            rfc822::simple_text_body(m.size as usize)
                        } else {
                            rfc822::simple_text_body(0)
                        };
                        parts.push(format!("BODY {}", body));
                    }
                    FetchItem::BodySection {
                        section,
                        peek,
                        partial,
                    } => {
                        let section_tag = match (section, partial) {
                            (Some(s), Some((origin, _))) => {
                                format!("BODY[{}]<{}>", s, origin)
                            }
                            (Some(s), None) => format!("BODY[{}]", s),
                            (None, Some((origin, _))) => format!("BODY[]<{}>", origin),
                            (None, None) => "BODY[]".to_string(),
                        };

                        let body_data = if let Some(ref data) = rfc822_data {
                            match section {
                                Some(s) => {
                                    let upper = s.to_uppercase();
                                    if upper.starts_with("HEADER.FIELDS") {
                                        let fields = parse_header_field_names(s);
                                        let hdr = extract_header_section(data);
                                        filter_headers_by_fields(&hdr, &fields).into_bytes()
                                    } else if upper == "HEADER" {
                                        extract_header_section(data).into_bytes()
                                    } else if upper == "TEXT" {
                                        extract_text_section(data)
                                    } else if s
                                        .as_bytes()
                                        .first()
                                        .is_some_and(|b| b.is_ascii_digit())
                                    {
                                        rfc822::extract_mime_part(data, s).unwrap_or_default()
                                    } else {
                                        data.clone()
                                    }
                                }
                                None => data.clone(),
                            }
                        } else if let Some(ref meta) = meta {
                            match section {
                                Some(s) => {
                                    let upper = s.to_uppercase();
                                    if upper.starts_with("HEADER.FIELDS") {
                                        let fields = parse_header_field_names(s);
                                        let hdr = build_metadata_header_section(meta);
                                        filter_headers_by_fields(&hdr, &fields).into_bytes()
                                    } else if upper == "HEADER" {
                                        build_metadata_header_section(meta).into_bytes()
                                    } else {
                                        Vec::new()
                                    }
                                }
                                None => Vec::new(),
                            }
                        } else {
                            Vec::new()
                        };

                        // Apply partial range if specified
                        let body_data = if let Some((origin, count)) = partial {
                            let origin = *origin as usize;
                            let count = *count as usize;
                            if origin >= body_data.len() {
                                Vec::new()
                            } else {
                                let end = (origin + count).min(body_data.len());
                                body_data[origin..end].to_vec()
                            }
                        } else {
                            body_data
                        };

                        let idx = parts.len();
                        parts.push(format!("{} {{{}}}", section_tag, body_data.len()));
                        part_literals.insert(idx, body_data);

                        if !peek && !self.selected_read_only {
                            // Set \Seen flag
                            if !has_seen {
                                self.config
                                    .mailbox_mutation
                                    .add_flags(
                                        &scoped_mailbox,
                                        uid,
                                        std::slice::from_ref(&seen_flag),
                                    )
                                    .await?;
                                has_seen = true;
                                // Mark as read on API via connector
                                if let Some(ref meta) = meta {
                                    if let Some(ref account_id) = self.authenticated_account_id {
                                        if let Err(err) = self
                                            .config
                                            .connector
                                            .mark_messages_read(
                                                account_id,
                                                &[meta.id.as_str()],
                                                true,
                                            )
                                            .await
                                        {
                                            warn!(
                                                error = %err,
                                                mailbox = %mailbox,
                                                proton_id = %meta.id,
                                                "failed to sync read state upstream"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            if !parts.is_empty() {
                if part_literals.is_empty() {
                    let parts_str = parts.join(" ");
                    let line = format!("* {} FETCH ({})\r\n", seq, parts_str);
                    self.writer.raw(line.as_bytes()).await?;
                } else {
                    let mut out = Vec::new();
                    out.extend_from_slice(format!("* {} FETCH (", seq).as_bytes());
                    for (i, part) in parts.iter().enumerate() {
                        if i > 0 {
                            out.extend_from_slice(b" ");
                        }
                        out.extend_from_slice(part.as_bytes());
                        if let Some(literal) = part_literals.get(&i) {
                            out.extend_from_slice(b"\r\n");
                            out.extend_from_slice(literal);
                        }
                    }
                    out.extend_from_slice(b")\r\n");
                    self.writer.raw(&out).await?;
                }
            }
        }

        // Restore the pinned store session after the fetch loop.
        self.store_session = pinned_session;

        if needs_body_sections {
            if header_only_body_fetch {
                // Match bridge behavior: header index fetch should avoid RFC822 disk/blob reads.
                info!(
                    service = "imap",
                    msg = "rfc822_cache_miss",
                    user_id = %user_id,
                    mailbox = %mailbox,
                    count = target_fetch_count,
                    "rfc822_cache_miss"
                );
            } else {
                if cache_hits > 0 {
                    info!(
                        service = "imap",
                        msg = "rfc822_cache_hit",
                        user_id = %user_id,
                        mailbox = %mailbox,
                        count = cache_hits,
                        "rfc822_cache_hit"
                    );
                }
                if cache_misses > 0 {
                    info!(
                        service = "imap",
                        msg = "rfc822_cache_miss",
                        user_id = %user_id,
                        mailbox = %mailbox,
                        count = cache_misses,
                        "rfc822_cache_miss"
                    );
                }
            }
        }

        self.writer.flush().await?;
        self.writer.tagged_ok(tag, None, "FETCH completed").await
    }

    async fn fetch_and_cache_rfc822(
        &mut self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        proton_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        let account_id = match &self.authenticated_account_id {
            Some(id) => id.clone(),
            None => return Ok(None),
        };

        let data = match self
            .config
            .connector
            .get_message_literal(&account_id, proton_id)
            .await
        {
            Ok(Some(d)) => d,
            Ok(None) => return Ok(None),
            Err(e) => {
                warn!(proton_id = %proton_id, error = %e, "connector failed to fetch message");
                return Ok(None);
            }
        };

        self.config
            .mailbox_mutation
            .store_rfc822(mailbox, uid, data.clone())
            .await?;

        Ok(Some(data))
    }

    async fn cmd_store(
        &mut self,
        tag: &str,
        sequence: &SequenceSet,
        action: &StoreAction,
        flags: &[ImapFlag],
        uid_mode: bool,
    ) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        if self.selected_read_only {
            return self.writer.tagged_no(tag, "mailbox is read-only").await;
        }

        self.refresh_selected_snapshot().await?;
        let mailbox = self.selected_mailbox.as_ref().unwrap().clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let mutation = &self.config.mailbox_mutation;
        let all_uids = self.selected_mailbox_uids.clone();

        if all_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "STORE completed").await;
        }

        let target_uids = self.resolve_target_uids(&all_uids, sequence, uid_mode);

        let flag_strings: Vec<String> = flags.iter().map(|f| f.as_str().to_string()).collect();
        let silent = matches!(
            action,
            StoreAction::SetFlagsSilent
                | StoreAction::AddFlagsSilent
                | StoreAction::RemoveFlagsSilent
        );

        // Take pinned session for the store loop to avoid per-message pool.acquire().
        let mut pinned_session = self.store_session.take();
        let pinned_mb_id = self.selected_mailbox_internal_id;

        for &uid in &target_uids {
            // Fast path: use pinned session for flag reads/writes.
            let used_pinned = if let (Some(ref mut ss), Some(mb_id)) =
                (&mut pinned_session, pinned_mb_id)
            {
                if let Ok(Some(internal_id)) = ss.message_internal_id_by_uid(mb_id, uid.value()) {
                    let previous_flags =
                        ss.message_flags_by_internal_id(&internal_id).map_err(|e| {
                            super::ImapError::Protocol(format!("store session flags: {e}"))
                        })?;
                    let had_seen = previous_flags.iter().any(|flag| flag == "\\Seen");
                    let had_flagged = previous_flags.iter().any(|flag| flag == "\\Flagged");

                    match action {
                        StoreAction::SetFlags | StoreAction::SetFlagsSilent => {
                            ss.set_message_flags(&internal_id, &flag_strings)
                                .map_err(|e| {
                                    super::ImapError::Protocol(format!(
                                        "store session set_flags: {e}"
                                    ))
                                })?;
                        }
                        StoreAction::AddFlags | StoreAction::AddFlagsSilent => {
                            ss.add_message_flags(&internal_id, &flag_strings)
                                .map_err(|e| {
                                    super::ImapError::Protocol(format!(
                                        "store session add_flags: {e}"
                                    ))
                                })?;
                        }
                        StoreAction::RemoveFlags | StoreAction::RemoveFlagsSilent => {
                            ss.remove_message_flags(&internal_id, &flag_strings)
                                .map_err(|e| {
                                    super::ImapError::Protocol(format!(
                                        "store session remove_flags: {e}"
                                    ))
                                })?;
                        }
                    }

                    if let Some(ref account_id) = self.authenticated_account_id {
                        if let Ok(Some(proton_id)) = ss.message_remote_id_by_uid(mb_id, uid.value())
                        {
                            let current_flags =
                                ss.message_flags_by_internal_id(&internal_id).map_err(|e| {
                                    super::ImapError::Protocol(format!("store session flags: {e}"))
                                })?;
                            let has_seen = current_flags.iter().any(|flag| flag == "\\Seen");
                            let has_flagged = current_flags.iter().any(|flag| flag == "\\Flagged");

                            if had_seen != has_seen {
                                if let Err(err) = self
                                    .config
                                    .connector
                                    .mark_messages_read(account_id, &[proton_id.as_str()], has_seen)
                                    .await
                                {
                                    warn!(
                                        error = %err,
                                        mailbox = %mailbox,
                                        uid = uid.value(),
                                        proton_id = %proton_id,
                                        "failed to sync seen flag upstream"
                                    );
                                    self.store_session = pinned_session;
                                    return self
                                        .writer
                                        .tagged_no(tag, "STORE failed: upstream mutation failed")
                                        .await;
                                }
                            }

                            if had_flagged != has_flagged {
                                if let Err(err) = self
                                    .config
                                    .connector
                                    .mark_messages_starred(
                                        account_id,
                                        &[proton_id.as_str()],
                                        has_flagged,
                                    )
                                    .await
                                {
                                    warn!(
                                        error = %err,
                                        mailbox = %mailbox,
                                        uid = uid.value(),
                                        proton_id = %proton_id,
                                        "failed to sync flagged state upstream"
                                    );
                                    self.store_session = pinned_session;
                                    return self
                                        .writer
                                        .tagged_no(tag, "STORE failed: upstream mutation failed")
                                        .await;
                                }
                            }
                        }
                    }

                    if !silent {
                        let seq = all_uids
                            .iter()
                            .position(|&u| u == uid)
                            .map(|i| i as u32 + 1)
                            .unwrap_or(0);
                        let current_flags =
                            ss.message_flags_by_internal_id(&internal_id).map_err(|e| {
                                super::ImapError::Protocol(format!("store session flags: {e}"))
                            })?;
                        let flag_str = current_flags.join(" ");
                        let fetch_items = if uid_mode {
                            format!("UID {uid} FLAGS ({flag_str})")
                        } else {
                            format!("FLAGS ({flag_str})")
                        };
                        self.writer
                            .untagged(&format!("{seq} FETCH ({fetch_items})"))
                            .await?;
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            };

            // Fallback: use trait-based mutation path.
            if !used_pinned {
                let previous_flags = mutation.get_flags(&scoped_mailbox, uid).await?;
                let had_seen = previous_flags.iter().any(|flag| flag == "\\Seen");
                let had_flagged = previous_flags.iter().any(|flag| flag == "\\Flagged");

                match action {
                    StoreAction::SetFlags | StoreAction::SetFlagsSilent => {
                        mutation
                            .set_flags(&scoped_mailbox, uid, flag_strings.clone())
                            .await?;
                    }
                    StoreAction::AddFlags | StoreAction::AddFlagsSilent => {
                        mutation
                            .add_flags(&scoped_mailbox, uid, &flag_strings)
                            .await?;
                    }
                    StoreAction::RemoveFlags | StoreAction::RemoveFlagsSilent => {
                        mutation
                            .remove_flags(&scoped_mailbox, uid, &flag_strings)
                            .await?;
                    }
                }

                if let Some(ref account_id) = self.authenticated_account_id {
                    if let Some(proton_id) = mutation.get_proton_id(&scoped_mailbox, uid).await? {
                        let id_ref = proton_id.as_str();
                        let current_flags = mutation.get_flags(&scoped_mailbox, uid).await?;
                        let has_seen = current_flags.iter().any(|flag| flag == "\\Seen");
                        let has_flagged = current_flags.iter().any(|flag| flag == "\\Flagged");

                        if had_seen != has_seen {
                            if let Err(err) = self
                                .config
                                .connector
                                .mark_messages_read(account_id, &[id_ref], has_seen)
                                .await
                            {
                                warn!(
                                    error = %err,
                                    mailbox = %mailbox,
                                    uid = uid.value(),
                                    proton_id = %proton_id,
                                    "failed to sync seen flag upstream"
                                );
                                self.store_session = pinned_session;
                                return self
                                    .writer
                                    .tagged_no(tag, "STORE failed: upstream mutation failed")
                                    .await;
                            }
                        }

                        if had_flagged != has_flagged {
                            if let Err(err) = self
                                .config
                                .connector
                                .mark_messages_starred(account_id, &[id_ref], has_flagged)
                                .await
                            {
                                warn!(
                                    error = %err,
                                    mailbox = %mailbox,
                                    uid = uid.value(),
                                    proton_id = %proton_id,
                                    "failed to sync flagged state upstream"
                                );
                                self.store_session = pinned_session;
                                return self
                                    .writer
                                    .tagged_no(tag, "STORE failed: upstream mutation failed")
                                    .await;
                            }
                        }
                    }
                }

                if !silent {
                    let seq = mutation
                        .uid_to_seq(&scoped_mailbox, uid)
                        .await?
                        .unwrap_or(0);
                    let current_flags = mutation.get_flags(&scoped_mailbox, uid).await?;
                    let flag_str = current_flags.join(" ");
                    let fetch_items = if uid_mode {
                        format!("UID {uid} FLAGS ({flag_str})")
                    } else {
                        format!("FLAGS ({flag_str})")
                    };
                    self.writer
                        .untagged(&format!("{seq} FETCH ({fetch_items})"))
                        .await?;
                }
            }
        }

        self.store_session = pinned_session;
        self.writer.tagged_ok(tag, None, "STORE completed").await
    }

    async fn cmd_search(
        &mut self,
        tag: &str,
        criteria: &[SearchKey],
        uid_mode: bool,
    ) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        self.refresh_selected_snapshot().await?;
        let mailbox = self.selected_mailbox.as_ref().unwrap().clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let _mailbox_view = self.config.mailbox_view.clone();
        let all_uids = self.selected_mailbox_uids.clone();
        let needs_rfc822 = criteria.iter().any(search_key_needs_rfc822);

        let mut results = Vec::new();
        let max_uid = all_uids.last().copied().unwrap_or(ImapUid::from(0u32));

        for (i, &uid) in all_uids.iter().enumerate() {
            let seq = i as u32 + 1;
            let meta = self
                .config
                .mailbox_view
                .get_metadata(&scoped_mailbox, uid)
                .await?;
            let flags = self
                .config
                .mailbox_view
                .get_flags(&scoped_mailbox, uid)
                .await?;

            let mut rfc822_data = if needs_rfc822 {
                self.config
                    .mailbox_view
                    .get_rfc822(&scoped_mailbox, uid)
                    .await?
            } else {
                None
            };
            if needs_rfc822 && rfc822_data.is_none() {
                if let Some(meta) = meta.as_ref() {
                    rfc822_data = self
                        .fetch_and_cache_rfc822(&scoped_mailbox, uid, &meta.id)
                        .await?;
                }
            }

            let matches = criteria.iter().all(|c| {
                evaluate_search_key(c, uid, &meta, &flags, max_uid, rfc822_data.as_deref())
            });

            if matches {
                if uid_mode {
                    results.push(uid.to_string());
                } else {
                    results.push(seq.to_string());
                }
            }
        }

        if results.is_empty() {
            self.writer.untagged("SEARCH").await?;
        } else {
            self.writer
                .untagged(&format!("SEARCH {}", results.join(" ")))
                .await?;
        }

        self.writer.tagged_ok(tag, None, "SEARCH completed").await
    }

    async fn cmd_expunge(&mut self, tag: &str) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        if self.selected_read_only {
            return self.writer.tagged_no(tag, "mailbox is read-only").await;
        }

        if self.do_expunge(false, Some(tag)).await? {
            self.writer.tagged_ok(tag, None, "EXPUNGE completed").await
        } else {
            Ok(())
        }
    }

    async fn do_expunge(&mut self, silent: bool, tag: Option<&str>) -> Result<bool> {
        let mailbox = match &self.selected_mailbox {
            Some(m) => m.clone(),
            None => return Ok(true),
        };
        self.refresh_selected_snapshot().await?;
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let mutation = &self.config.mailbox_mutation;
        let all_uids = self.selected_mailbox_uids.clone();
        let cached_flags = &self.selected_mailbox_flags;

        // Identify deleted UIDs from cached flags (avoids per-message get_flags calls).
        let deleted_uids: Vec<ImapUid> = all_uids
            .iter()
            .filter(|uid| {
                cached_flags
                    .get(uid)
                    .map(|flags| flags.iter().any(|f| f == "\\Deleted"))
                    .unwrap_or(false)
            })
            .copied()
            .collect();

        if deleted_uids.is_empty() {
            return Ok(true);
        }

        let mut expunged_seqs = Vec::new();
        let mut offset = 0u32;
        let mut successfully_expunged_uids = Vec::new();

        for (i, &uid) in all_uids.iter().enumerate() {
            if !deleted_uids.contains(&uid) {
                continue;
            }
            let seq = i as u32 + 1 - offset;

            // Sync upstream: permanently delete if in Trash or Spam, otherwise move to Trash.
            if let Some(ref account_id) = self.authenticated_account_id {
                if let Some(proton_id) = mutation.get_proton_id(&scoped_mailbox, uid).await? {
                    let is_trash_or_spam = self
                        .resolve_mailbox(&mailbox)
                        .await
                        .map(|mb| {
                            mb.label_id == gluon_rs_mail::well_known::TRASH_LABEL
                                || mb.label_id == gluon_rs_mail::well_known::SPAM_LABEL
                        })
                        .unwrap_or(false);

                    let result = if is_trash_or_spam {
                        self.config
                            .connector
                            .delete_messages(account_id, &[proton_id.as_str()])
                            .await
                    } else {
                        self.config
                            .connector
                            .trash_messages(account_id, &[proton_id.as_str()])
                            .await
                    };

                    if let Err(err) = result {
                        warn!(
                            error = %err,
                            mailbox = %mailbox,
                            uid = uid.value(),
                            proton_id = %proton_id,
                            permanent = is_trash_or_spam,
                            "failed to sync expunge mutation upstream"
                        );
                        if let Some(tag) = tag {
                            self.writer
                                .tagged_no(tag, "EXPUNGE failed: upstream mutation failed")
                                .await?;
                            return Ok(false);
                        }
                    }
                }
            }

            successfully_expunged_uids.push(uid);
            expunged_seqs.push(seq);
            offset += 1;
        }

        // Batch remove all successfully expunged messages from local store.
        mutation
            .batch_remove_messages(&scoped_mailbox, &successfully_expunged_uids)
            .await?;

        if !silent {
            for seq in &expunged_seqs {
                self.writer.untagged(&format!("{} EXPUNGE", seq)).await?;
            }
        }

        Ok(true)
    }

    async fn cmd_uid_expunge(&mut self, tag: &str, sequence: &SequenceSet) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        if self.selected_read_only {
            return self.writer.tagged_no(tag, "mailbox is read-only").await;
        }

        let mailbox = match &self.selected_mailbox {
            Some(m) => m.clone(),
            None => return self.writer.tagged_no(tag, "no mailbox selected").await,
        };
        self.refresh_selected_snapshot().await?;
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let mutation = &self.config.mailbox_mutation;
        let all_uids = self.selected_mailbox_uids.clone();

        if all_uids.is_empty() {
            return self
                .writer
                .tagged_ok(tag, None, "UID EXPUNGE completed")
                .await;
        }

        let max_uid = *all_uids.last().unwrap();
        let cached_flags = &self.selected_mailbox_flags;
        let mut expunged_seqs = Vec::new();
        let mut successfully_expunged_uids = Vec::new();
        let mut offset = 0u32;

        for (i, &uid) in all_uids.iter().enumerate() {
            // Only expunge if UID is in the sequence set AND has \Deleted flag
            if !sequence.contains(uid.value(), max_uid.value()) {
                continue;
            }

            let is_deleted = cached_flags
                .get(&uid)
                .map(|flags| flags.iter().any(|f| f == "\\Deleted"))
                .unwrap_or(false);

            if is_deleted {
                let seq = i as u32 + 1 - offset;

                // Permanently delete if in Trash or Spam, otherwise move to Trash
                if let Some(ref account_id) = self.authenticated_account_id {
                    if let Some(proton_id) = mutation.get_proton_id(&scoped_mailbox, uid).await? {
                        let is_trash_or_spam = self
                            .resolve_mailbox(&mailbox)
                            .await
                            .map(|mb| {
                                mb.label_id == gluon_rs_mail::well_known::TRASH_LABEL
                                    || mb.label_id == gluon_rs_mail::well_known::SPAM_LABEL
                            })
                            .unwrap_or(false);

                        let result = if is_trash_or_spam {
                            self.config
                                .connector
                                .delete_messages(account_id, &[proton_id.as_str()])
                                .await
                        } else {
                            self.config
                                .connector
                                .trash_messages(account_id, &[proton_id.as_str()])
                                .await
                        };

                        if let Err(err) = result {
                            warn!(
                                error = %err,
                                mailbox = %mailbox,
                                uid = uid.value(),
                                proton_id = %proton_id,
                                permanent = is_trash_or_spam,
                                "failed to sync uid expunge mutation upstream"
                            );
                            return self
                                .writer
                                .tagged_no(tag, "UID EXPUNGE failed: upstream mutation failed")
                                .await;
                        }
                    }
                }

                successfully_expunged_uids.push(uid);
                expunged_seqs.push(seq);
                offset += 1;
            }
        }

        // Batch remove all successfully expunged messages from local store.
        mutation
            .batch_remove_messages(&scoped_mailbox, &successfully_expunged_uids)
            .await?;

        for seq in &expunged_seqs {
            self.writer.untagged(&format!("{} EXPUNGE", seq)).await?;
        }

        self.writer
            .tagged_ok(tag, None, "UID EXPUNGE completed")
            .await
    }

    async fn cmd_copy(
        &mut self,
        tag: &str,
        sequence: &SequenceSet,
        dest_name: &str,
        uid_mode: bool,
    ) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        let dest_mb = match self.resolve_mailbox(dest_name).await {
            Some(m) => m,
            None => {
                return self
                    .writer
                    .tagged_no(
                        tag,
                        &format!("[TRYCREATE] mailbox not found: {}", dest_name),
                    )
                    .await;
            }
        };

        self.refresh_selected_snapshot().await?;
        let mailbox = self.selected_mailbox.as_ref().unwrap().clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let scoped_dest_mailbox = self.scoped_mailbox_name(&dest_mb.name);
        if scoped_mailbox == scoped_dest_mailbox {
            return self.writer.tagged_ok(tag, None, "COPY completed").await;
        }

        let mutation = &self.config.mailbox_mutation;
        let all_uids = self.selected_mailbox_uids.clone();

        if all_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "COPY completed").await;
        }

        let target_uids = self.resolve_target_uids(&all_uids, sequence, uid_mode);

        let mut src_uids = Vec::new();
        let mut dst_uids = Vec::new();

        for &uid in &target_uids {
            if let Some(ref account_id) = self.authenticated_account_id {
                if let Some(proton_id) = mutation.get_proton_id(&scoped_mailbox, uid).await? {
                    if let Err(err) = self
                        .config
                        .connector
                        .label_messages(account_id, &[proton_id.as_str()], &dest_mb.label_id)
                        .await
                    {
                        warn!(
                            error = %err,
                            source_mailbox = %mailbox,
                            destination_mailbox = %dest_mb.name,
                            uid = uid.value(),
                            proton_id = %proton_id,
                            "failed to sync copy destination label upstream"
                        );
                        return self
                            .writer
                            .tagged_no(tag, "COPY failed: upstream mutation failed")
                            .await;
                    }
                }
            }

            if let Some(dest_uid) = self
                .copy_message_local(&scoped_mailbox, &scoped_dest_mailbox, uid)
                .await?
            {
                src_uids.push(uid);
                dst_uids.push(dest_uid);
            }
        }

        let dest_status = mutation.mailbox_status(&scoped_dest_mailbox).await?;
        let copyuid_code = format_copyuid(dest_status.uid_validity, &src_uids, &dst_uids);
        self.writer
            .tagged_ok(tag, Some(&copyuid_code), "COPY completed")
            .await
    }

    async fn cmd_move(
        &mut self,
        tag: &str,
        sequence: &SequenceSet,
        dest_name: &str,
        uid_mode: bool,
    ) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        if self.selected_read_only {
            return self.writer.tagged_no(tag, "mailbox is read-only").await;
        }

        let dest_mb = match self.resolve_mailbox(dest_name).await {
            Some(m) => m,
            None => {
                return self
                    .writer
                    .tagged_no(
                        tag,
                        &format!("[TRYCREATE] mailbox not found: {}", dest_name),
                    )
                    .await;
            }
        };

        let mailbox = self.selected_mailbox.as_ref().unwrap().clone();
        let source_mb = self
            .resolve_mailbox(&mailbox)
            .await
            .unwrap_or_else(|| dest_mb.clone());
        self.refresh_selected_snapshot().await?;
        let scoped_source_mailbox = self.scoped_mailbox_name(&mailbox);
        let scoped_dest_mailbox = self.scoped_mailbox_name(&dest_mb.name);
        if scoped_source_mailbox == scoped_dest_mailbox {
            return self.writer.tagged_ok(tag, None, "MOVE completed").await;
        }

        let mutation = &self.config.mailbox_mutation;
        let all_uids = self.selected_mailbox_uids.clone();
        if all_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "MOVE completed").await;
        }

        let target_uids = self.resolve_target_uids(&all_uids, sequence, uid_mode);
        if target_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "MOVE completed").await;
        }

        let target_uid_set: HashSet<ImapUid> = target_uids.iter().copied().collect();
        let mut src_uids = Vec::new();
        let mut dst_uids = Vec::new();
        let mut expunged_seqs = Vec::new();
        let mut offset = 0u32;

        for (i, &uid) in all_uids.iter().enumerate() {
            if !target_uid_set.contains(&uid) {
                continue;
            }

            let Some(proton_id) = mutation.get_proton_id(&scoped_source_mailbox, uid).await? else {
                continue;
            };

            let seq = i as u32 + 1 - offset;

            if let Some(ref account_id) = self.authenticated_account_id {
                if let Err(err) = self
                    .config
                    .connector
                    .label_messages(account_id, &[proton_id.as_str()], &dest_mb.label_id)
                    .await
                {
                    warn!(
                        error = %err,
                        source_mailbox = %mailbox,
                        destination_mailbox = %dest_mb.name,
                        uid = uid.value(),
                        proton_id = %proton_id,
                        "failed to sync move destination label upstream"
                    );
                    return self
                        .writer
                        .tagged_no(tag, "MOVE failed: upstream mutation failed")
                        .await;
                }

                if source_mb.label_id != dest_mb.label_id {
                    if let Err(err) = self
                        .config
                        .connector
                        .unlabel_messages(account_id, &[proton_id.as_str()], &source_mb.label_id)
                        .await
                    {
                        warn!(
                            error = %err,
                            source_mailbox = %mailbox,
                            destination_mailbox = %dest_mb.name,
                            uid = uid.value(),
                            proton_id = %proton_id,
                            "failed to sync move source label removal upstream"
                        );
                        return self
                            .writer
                            .tagged_no(tag, "MOVE failed: upstream mutation failed")
                            .await;
                    }
                }
            }

            if let Some(dest_uid) = self
                .copy_message_local(&scoped_source_mailbox, &scoped_dest_mailbox, uid)
                .await?
            {
                src_uids.push(uid);
                dst_uids.push(dest_uid);
                mutation.remove_message(&scoped_source_mailbox, uid).await?;
                expunged_seqs.push(seq);
                offset += 1;
            }
        }

        let dest_status = mutation.mailbox_status(&scoped_dest_mailbox).await?;
        let copyuid_code = format_copyuid(dest_status.uid_validity, &src_uids, &dst_uids);

        for seq in expunged_seqs {
            self.writer.untagged(&format!("{seq} EXPUNGE")).await?;
        }

        self.writer
            .tagged_ok(tag, Some(&copyuid_code), "MOVE completed")
            .await
    }

    async fn cmd_append(
        &mut self,
        tag: &str,
        mailbox_name: &str,
        flags: &[ImapFlag],
        append_date: &Option<String>,
        literal_size: u32,
    ) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        let mb = match self.resolve_mailbox(mailbox_name).await {
            Some(m) => m,
            None => {
                // Consume and discard the literal before responding
                self.writer.continuation("Ready").await?;
                let mut discard = vec![0u8; literal_size as usize];
                tokio::io::AsyncReadExt::read_exact(&mut self.reader, &mut discard).await?;
                let mut crlf = [0u8; 2];
                let _ = tokio::io::AsyncReadExt::read_exact(&mut self.reader, &mut crlf).await;
                return self
                    .writer
                    .tagged_no(
                        tag,
                        &format!("[TRYCREATE] mailbox not found: {}", mailbox_name),
                    )
                    .await;
            }
        };

        if !mb.selectable {
            self.writer.continuation("Ready").await?;
            let mut discard = vec![0u8; literal_size as usize];
            tokio::io::AsyncReadExt::read_exact(&mut self.reader, &mut discard).await?;
            let mut crlf = [0u8; 2];
            let _ = tokio::io::AsyncReadExt::read_exact(&mut self.reader, &mut crlf).await;
            return self.writer.tagged_no(tag, "mailbox not selectable").await;
        }

        // Send continuation and read the literal data
        self.writer.continuation("Ready").await?;
        let mut literal = vec![0u8; literal_size as usize];
        tokio::io::AsyncReadExt::read_exact(&mut self.reader, &mut literal).await?;
        // Consume trailing CRLF after literal
        let mut crlf = [0u8; 2];
        let _ = tokio::io::AsyncReadExt::read_exact(&mut self.reader, &mut crlf).await;

        // Build metadata from the RFC822 message
        let header_text = extract_header_section(&literal);

        let extract_hdr = |name: &str| -> Option<String> {
            let search = format!("{}:", name);
            let search_lower = search.to_lowercase();
            header_text
                .lines()
                .find(|l| l.to_lowercase().starts_with(&search_lower))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        };

        let subject = extract_hdr("Subject").unwrap_or_default();
        let from_str = extract_hdr("From").unwrap_or_default();
        let sender = parse_append_address(&from_str);
        let to_list = extract_hdr("To")
            .map(|v| parse_address_list_header(&v))
            .unwrap_or_default();
        let cc_list = extract_hdr("Cc")
            .map(|v| parse_address_list_header(&v))
            .unwrap_or_default();
        let bcc_list = extract_hdr("Bcc")
            .map(|v| parse_address_list_header(&v))
            .unwrap_or_default();
        let reply_tos = extract_hdr("Reply-To")
            .map(|v| parse_address_list_header(&v))
            .unwrap_or_default();
        let external_id = extract_hdr("Message-Id").or_else(|| extract_hdr("Message-ID"));

        // Use APPEND date argument if provided, else Date header, else now
        let time = append_date
            .as_deref()
            .and_then(parse_rfc2822_date)
            .or_else(|| extract_sent_date(&literal))
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64
            });

        let is_unread = !flags.iter().any(|f| matches!(f, ImapFlag::Seen));

        // Try to import upstream via connector.
        let import_flags = gluon_rs_mail::well_known::MESSAGE_FLAG_RECEIVED
            | gluon_rs_mail::well_known::MESSAGE_FLAG_IMPORTED;
        let proton_id = if let Some(ref account_id) = self.authenticated_account_id {
            match self
                .config
                .connector
                .import_message(account_id, &mb.label_id, import_flags, &literal)
                .await
            {
                Ok(id) => id,
                Err(e) => {
                    warn!(error = %e, "APPEND upstream import failed; storing locally only");
                    None
                }
            }
        } else {
            None
        };

        let proton_id = proton_id.unwrap_or_else(|| {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!("local-append-{ts}")
        });

        let meta = gluon_rs_mail::MessageEnvelope {
            id: proton_id.clone(),
            address_id: String::new(),
            label_ids: vec![mb.label_id.clone()],
            external_id,
            subject,
            sender,
            to_list,
            cc_list,
            bcc_list,
            reply_tos,
            flags: 0,
            time,
            size: literal.len() as i64,
            unread: if is_unread { 1 } else { 0 },
            is_replied: 0,
            is_replied_all: 0,
            is_forwarded: 0,
            num_attachments: 0,
        };

        let mutation = self.config.mailbox_mutation.clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mb.name);
        let proton_msg_id = ProtonMessageId::from(proton_id.as_str());
        let uid = mutation
            .store_metadata(&scoped_mailbox, &proton_msg_id, meta)
            .await?;
        mutation.store_rfc822(&scoped_mailbox, uid, literal).await?;

        // Apply flags
        let flag_strs: Vec<String> = flags.iter().map(|f| f.as_str().to_string()).collect();
        if !flag_strs.is_empty() {
            mutation
                .set_flags(&scoped_mailbox, uid, flag_strs.clone())
                .await?;
        }

        let status = mutation.mailbox_status(&scoped_mailbox).await?;
        let appenduid_code = format!("APPENDUID {} {}", status.uid_validity, uid);

        // If the target is the currently selected mailbox, update local state and notify
        if self.selected_mailbox.as_deref() == Some(&mb.name) {
            self.selected_mailbox_uids.push(uid);
            self.selected_mailbox_flags.insert(uid, flag_strs.clone());
            self.writer
                .untagged(&format!("{} EXISTS", status.exists))
                .await?;
            self.writer.untagged("0 RECENT").await?;
        }

        info!(
            mailbox = %mb.name,
            uid = uid.value(),
            size = literal_size,
            "APPEND completed"
        );

        self.writer
            .tagged_ok(tag, Some(&appenduid_code), "APPEND completed")
            .await
    }

    /// Get stream halves for TLS upgrade.
    pub fn into_parts(self) -> (R, W) {
        (self.reader.into_inner(), self.writer.into_inner())
    }
}

fn format_copyuid(uid_validity: u32, src_uids: &[ImapUid], dst_uids: &[ImapUid]) -> String {
    let src = src_uids
        .iter()
        .map(|u| u.value().to_string())
        .collect::<Vec<_>>()
        .join(",");
    let dst = dst_uids
        .iter()
        .map(|u| u.value().to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!("COPYUID {} {} {}", uid_validity, src, dst)
}

fn expand_fetch_items(items: &[FetchItem]) -> Vec<FetchItem> {
    let mut result = Vec::new();
    for item in items {
        match item {
            FetchItem::All => {
                result.extend_from_slice(&[
                    FetchItem::Flags,
                    FetchItem::InternalDate,
                    FetchItem::Rfc822Size,
                    FetchItem::Envelope,
                ]);
            }
            FetchItem::Fast => {
                result.extend_from_slice(&[
                    FetchItem::Flags,
                    FetchItem::InternalDate,
                    FetchItem::Rfc822Size,
                ]);
            }
            FetchItem::Full => {
                result.extend_from_slice(&[
                    FetchItem::Flags,
                    FetchItem::InternalDate,
                    FetchItem::Rfc822Size,
                    FetchItem::Envelope,
                    FetchItem::Body,
                ]);
            }
            _ => result.push(item.clone()),
        }
    }
    result
}

fn evaluate_search_key(
    key: &SearchKey,
    uid: ImapUid,
    meta: &Option<gluon_rs_mail::MessageEnvelope>,
    flags: &[String],
    max_uid: ImapUid,
    rfc822_data: Option<&[u8]>,
) -> bool {
    match key {
        SearchKey::All => true,
        SearchKey::Seen => flags.iter().any(|f| f == "\\Seen"),
        SearchKey::Unseen => !flags.iter().any(|f| f == "\\Seen"),
        SearchKey::Flagged => flags.iter().any(|f| f == "\\Flagged"),
        SearchKey::Deleted => flags.iter().any(|f| f == "\\Deleted"),
        SearchKey::Answered => flags.iter().any(|f| f == "\\Answered"),
        SearchKey::Draft => flags.iter().any(|f| f == "\\Draft"),
        SearchKey::Recent => flags.iter().any(|f| f == "\\Recent"),
        SearchKey::New => {
            flags.iter().any(|f| f == "\\Recent") && !flags.iter().any(|f| f == "\\Seen")
        }
        SearchKey::Old => !flags.iter().any(|f| f == "\\Recent"),
        SearchKey::Keyword(kw) => flags.iter().any(|f| f.eq_ignore_ascii_case(kw)),
        SearchKey::Unkeyword(kw) => !flags.iter().any(|f| f.eq_ignore_ascii_case(kw)),
        SearchKey::Subject(s) => meta
            .as_ref()
            .map(|m| m.subject.to_lowercase().contains(&s.to_lowercase()))
            .unwrap_or(false),
        SearchKey::From(s) => meta
            .as_ref()
            .map(|m| {
                m.sender.address.to_lowercase().contains(&s.to_lowercase())
                    || m.sender.name.to_lowercase().contains(&s.to_lowercase())
            })
            .unwrap_or(false),
        SearchKey::To(s) => meta
            .as_ref()
            .map(|m| {
                m.to_list.iter().any(|a| {
                    a.address.to_lowercase().contains(&s.to_lowercase())
                        || a.name.to_lowercase().contains(&s.to_lowercase())
                })
            })
            .unwrap_or(false),
        SearchKey::Cc(s) => meta
            .as_ref()
            .map(|m| {
                m.cc_list.iter().any(|a| {
                    a.address.to_lowercase().contains(&s.to_lowercase())
                        || a.name.to_lowercase().contains(&s.to_lowercase())
                })
            })
            .unwrap_or(false),
        SearchKey::Bcc(s) => meta
            .as_ref()
            .map(|m| {
                m.bcc_list.iter().any(|a| {
                    a.address.to_lowercase().contains(&s.to_lowercase())
                        || a.name.to_lowercase().contains(&s.to_lowercase())
                })
            })
            .unwrap_or(false),
        SearchKey::Header(field, value) => {
            if let Some(data) = rfc822_data {
                let header_section = extract_header_section(data);
                let field_lower = field.to_lowercase();
                let value_lower = value.to_lowercase();
                header_section.lines().any(|line| {
                    if let Some(colon_pos) = line.find(':') {
                        let line_field = line[..colon_pos].trim().to_lowercase();
                        if line_field == field_lower {
                            let line_value = line[colon_pos + 1..].trim().to_lowercase();
                            return line_value.contains(&value_lower);
                        }
                    }
                    false
                })
            } else {
                false
            }
        }
        SearchKey::Body(s) => {
            if let Some(data) = rfc822_data {
                let body = extract_text_section(data);
                String::from_utf8_lossy(&body)
                    .to_lowercase()
                    .contains(&s.to_lowercase())
            } else {
                false
            }
        }
        SearchKey::Text(s) => {
            if let Some(data) = rfc822_data {
                String::from_utf8_lossy(data)
                    .to_lowercase()
                    .contains(&s.to_lowercase())
            } else {
                false
            }
        }
        SearchKey::Before(ts) => meta.as_ref().map(|m| m.time < *ts).unwrap_or(false),
        SearchKey::Since(ts) => meta.as_ref().map(|m| m.time >= *ts).unwrap_or(false),
        SearchKey::On(ts) => {
            // Match if message time is on the same day (within 24 hours starting at ts)
            meta.as_ref()
                .map(|m| m.time >= *ts && m.time < *ts + 86400)
                .unwrap_or(false)
        }
        SearchKey::SentBefore(ts) => {
            let sent_time = rfc822_data
                .and_then(extract_sent_date)
                .or_else(|| meta.as_ref().map(|m| m.time));
            sent_time.map(|t| t < *ts).unwrap_or(false)
        }
        SearchKey::SentSince(ts) => {
            let sent_time = rfc822_data
                .and_then(extract_sent_date)
                .or_else(|| meta.as_ref().map(|m| m.time));
            sent_time.map(|t| t >= *ts).unwrap_or(false)
        }
        SearchKey::SentOn(ts) => {
            let sent_time = rfc822_data
                .and_then(extract_sent_date)
                .or_else(|| meta.as_ref().map(|m| m.time));
            sent_time
                .map(|t| t >= *ts && t < *ts + 86400)
                .unwrap_or(false)
        }
        SearchKey::Larger(size) => meta.as_ref().map(|m| m.size > *size).unwrap_or(false),
        SearchKey::Smaller(size) => meta.as_ref().map(|m| m.size < *size).unwrap_or(false),
        SearchKey::Uid(seq) => seq.contains(uid.value(), max_uid.value()),
        SearchKey::Not(inner) => {
            !evaluate_search_key(inner, uid, meta, flags, max_uid, rfc822_data)
        }
        SearchKey::Or(a, b) => {
            evaluate_search_key(a, uid, meta, flags, max_uid, rfc822_data)
                || evaluate_search_key(b, uid, meta, flags, max_uid, rfc822_data)
        }
    }
}

fn search_key_needs_rfc822(key: &SearchKey) -> bool {
    match key {
        SearchKey::Header(_, _)
        | SearchKey::Body(_)
        | SearchKey::Text(_)
        | SearchKey::SentBefore(_)
        | SearchKey::SentSince(_)
        | SearchKey::SentOn(_) => true,
        SearchKey::Not(inner) => search_key_needs_rfc822(inner),
        SearchKey::Or(left, right) => {
            search_key_needs_rfc822(left) || search_key_needs_rfc822(right)
        }
        _ => false,
    }
}

/// Extract the Date header from RFC822 data and parse it to a unix timestamp.
///
/// Parses common RFC2822 date formats like:
///   "Mon, 14 Nov 2023 22:13:20 +0000"
///   "14 Nov 2023 22:13:20 +0000"
fn extract_sent_date(data: &[u8]) -> Option<i64> {
    let header = extract_header_section(data);
    let date_line = header
        .lines()
        .find(|l| l.to_lowercase().starts_with("date:"))?;
    let date_str = date_line.split_once(':')?.1.trim();
    parse_rfc2822_date(date_str)
}

fn parse_rfc2822_date(s: &str) -> Option<i64> {
    let months = [
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
    ];

    // Strip optional day-of-week prefix (e.g., "Mon, ")
    let s = if let Some(pos) = s.find(',') {
        s[pos + 1..].trim()
    } else {
        s.trim()
    };

    // Expected: "14 Nov 2023 22:13:20 +0000" or "14 Nov 2023 22:13:20 -0500"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }

    let day: u32 = parts[0].parse().ok()?;
    let month = months
        .iter()
        .position(|&m| m.eq_ignore_ascii_case(parts[1]))? as u32
        + 1;
    let year: i32 = parts[2].parse().ok()?;

    let time_parts: Vec<&str> = parts[3].split(':').collect();
    if time_parts.len() < 2 {
        return None;
    }
    let hours: i64 = time_parts[0].parse().ok()?;
    let minutes: i64 = time_parts[1].parse().ok()?;
    let seconds: i64 = if time_parts.len() > 2 {
        time_parts[2].parse().unwrap_or(0)
    } else {
        0
    };

    // Parse timezone offset
    let tz_offset_secs: i64 = if parts.len() > 4 {
        let tz = parts[4];
        if tz.len() >= 4 {
            let sign = if tz.starts_with('-') { -1i64 } else { 1 };
            let tz_digits = tz.trim_start_matches(['+', '-']);
            if tz_digits.len() >= 4 {
                let tz_hours: i64 = tz_digits[..2].parse().unwrap_or(0);
                let tz_mins: i64 = tz_digits[2..4].parse().unwrap_or(0);
                sign * (tz_hours * 3600 + tz_mins * 60)
            } else {
                0
            }
        } else {
            0
        }
    } else {
        0
    };

    // Convert to unix timestamp
    let days_in_month = [31u32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let is_leap = |y: i32| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);

    let mut total_days: i64 = 0;
    for y in 1970..year {
        total_days += if is_leap(y) { 366 } else { 365 };
    }
    for m in 1..month {
        total_days += days_in_month[(m - 1) as usize] as i64;
        if m == 2 && is_leap(year) {
            total_days += 1;
        }
    }
    total_days += (day as i64) - 1;

    let timestamp = total_days * 86400 + hours * 3600 + minutes * 60 + seconds - tz_offset_secs;
    Some(timestamp)
}

fn parse_header_field_names(section: &str) -> Vec<String> {
    if let Some(start) = section.find('(') {
        if let Some(end) = section.find(')') {
            return section[start + 1..end]
                .split_whitespace()
                .map(|s| s.to_uppercase())
                .collect();
        }
    }
    vec![]
}

fn body_section_is_header_only(section: Option<&str>) -> bool {
    let Some(section) = section else {
        return false;
    };
    let upper = section.trim().to_uppercase();
    upper == "HEADER" || upper.starts_with("HEADER.FIELDS")
}

fn build_metadata_header_section(meta: &gluon_rs_mail::MessageEnvelope) -> String {
    let mut out = String::new();

    out.push_str("Date: ");
    out.push_str(rfc822::format_internal_date(meta.time).trim_matches('"'));
    out.push_str("\r\n");

    out.push_str("Subject: ");
    out.push_str(&sanitize_header_value(&meta.subject));
    out.push_str("\r\n");

    out.push_str("From: ");
    out.push_str(&format_header_addresses(std::slice::from_ref(&meta.sender)));
    out.push_str("\r\n");

    if !meta.reply_tos.is_empty() {
        out.push_str("Reply-To: ");
        out.push_str(&format_header_addresses(&meta.reply_tos));
        out.push_str("\r\n");
    }
    if !meta.to_list.is_empty() {
        out.push_str("To: ");
        out.push_str(&format_header_addresses(&meta.to_list));
        out.push_str("\r\n");
    }
    if !meta.cc_list.is_empty() {
        out.push_str("Cc: ");
        out.push_str(&format_header_addresses(&meta.cc_list));
        out.push_str("\r\n");
    }
    if !meta.bcc_list.is_empty() {
        out.push_str("Bcc: ");
        out.push_str(&format_header_addresses(&meta.bcc_list));
        out.push_str("\r\n");
    }
    if let Some(external_id) = meta.external_id.as_deref() {
        if !external_id.is_empty() {
            out.push_str("Message-ID: <");
            out.push_str(&sanitize_header_value(external_id));
            out.push_str(">\r\n");
        }
    }
    out.push_str("\r\n");
    out
}

fn format_header_addresses(addrs: &[gluon_rs_mail::EmailAddress]) -> String {
    addrs
        .iter()
        .map(format_header_address)
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_header_address(addr: &gluon_rs_mail::EmailAddress) -> String {
    let address = sanitize_header_value(&addr.address);
    let name = sanitize_header_value(&addr.name);
    if name.trim().is_empty() {
        return address;
    }
    let escaped_name = name.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\" <{}>", escaped_name, address)
}

fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .map(|c| if c == '\r' || c == '\n' { ' ' } else { c })
        .collect()
}

fn filter_headers_by_fields(header_section: &str, fields: &[String]) -> String {
    let mut result = String::new();
    let mut current_name = String::new();
    let mut current_value = String::new();
    let mut in_header = false;

    for line in header_section.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of previous header
            if in_header {
                current_value.push_str(line);
                current_value.push_str("\r\n");
            }
        } else {
            // Flush previous header if it matches
            if in_header && fields.iter().any(|f| f.eq_ignore_ascii_case(&current_name)) {
                result.push_str(&current_value);
            }
            // Start new header
            if let Some(colon) = line.find(':') {
                current_name = line[..colon].to_string();
                current_value = format!("{}\r\n", line);
                in_header = true;
            } else {
                in_header = false;
            }
        }
    }
    // Flush last header
    if in_header && fields.iter().any(|f| f.eq_ignore_ascii_case(&current_name)) {
        result.push_str(&current_value);
    }
    // Blank line to terminate headers
    result.push_str("\r\n");
    result
}

fn extract_text_section(data: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(data);
    if let Some(pos) = s.find("\r\n\r\n") {
        data[pos + 4..].to_vec()
    } else if let Some(pos) = s.find("\n\n") {
        data[pos + 2..].to_vec()
    } else {
        data.to_vec()
    }
}

fn format_mailbox_name(name: &str) -> String {
    if name.contains(' ') || name.contains('"') || name.contains('\\') || name.is_empty() {
        format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        name.to_string()
    }
}

fn parse_append_address(value: &str) -> gluon_rs_mail::EmailAddress {
    let value = value.trim();
    if let Some(lt) = value.find('<') {
        let name = value[..lt].trim().trim_matches('"').to_string();
        let addr = value[lt + 1..].trim_end_matches('>').trim().to_string();
        gluon_rs_mail::EmailAddress {
            name,
            address: addr,
        }
    } else {
        gluon_rs_mail::EmailAddress {
            name: String::new(),
            address: value.to_string(),
        }
    }
}

fn parse_address_list_header(value: &str) -> Vec<gluon_rs_mail::EmailAddress> {
    value
        .split(',')
        .map(|s| parse_append_address(s.trim()))
        .filter(|a| !a.address.is_empty())
        .collect()
}

fn extract_header_section(data: &[u8]) -> String {
    let s = String::from_utf8_lossy(data);
    if let Some(pos) = s.find("\r\n\r\n") {
        s[..pos + 4].to_string()
    } else if let Some(pos) = s.find("\n\n") {
        s[..pos + 2].to_string()
    } else {
        s.to_string()
    }
}

/// Resolve a mailbox name to its internal_id using a pinned StoreSession.
async fn resolve_mailbox_internal_id(
    session: &mut gluon_rs_mail::StoreSession,
    mailbox_name: &str,
) -> Option<u64> {
    let mailboxes = session.list_upstream_mailboxes().ok()?;
    mailboxes
        .into_iter()
        .find(|mb| mb.name.eq_ignore_ascii_case(mailbox_name))
        .map(|mb| mb.internal_id)
}

/// Build SelectMailboxData from a pinned StoreSession, mirroring the logic in
/// GluonMailMailboxView::select_mailbox_data_fast.
async fn select_data_from_session(
    session: &mut gluon_rs_mail::StoreSession,
    mailbox_internal_id: u64,
) -> Result<super::store::SelectMailboxData> {
    use super::store::{MailboxSnapshot, MailboxStatus, SelectMailboxData};

    let select = session
        .mailbox_select_data(mailbox_internal_id)
        .map_err(|e| super::ImapError::Protocol(format!("store session select: {e}")))?;

    let count = select.entries.len() as u32;
    let mut unseen = 0u32;
    let mut first_unseen_seq = None;
    let mut uids = Vec::with_capacity(select.entries.len());
    let mut flags = HashMap::with_capacity(select.entries.len());
    let mut mod_seq_hash = select.next_uid as u64;

    for (index, entry) in select.entries.iter().enumerate() {
        let uid = ImapUid::from(entry.uid);
        let seen = entry.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen"));
        if !seen {
            unseen += 1;
            if first_unseen_seq.is_none() {
                first_unseen_seq = Some(index as u32 + 1);
            }
        }
        mod_seq_hash = mod_seq_hash.wrapping_mul(1_099_511_628_211);
        mod_seq_hash ^= entry.uid as u64;
        mod_seq_hash ^= entry.flags.len() as u64;
        for flag in &entry.flags {
            for byte in flag.as_bytes() {
                mod_seq_hash = mod_seq_hash.wrapping_mul(1_099_511_628_211);
                mod_seq_hash ^= u64::from(*byte);
            }
        }
        uids.push(uid);
        flags.insert(uid, entry.flags.clone());
    }

    Ok(SelectMailboxData {
        status: MailboxStatus {
            uid_validity: select.uid_validity,
            next_uid: select.next_uid,
            exists: count,
            unseen,
        },
        snapshot: MailboxSnapshot {
            exists: count,
            mod_seq: mod_seq_hash,
        },
        uids,
        flags,
        first_unseen_seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::accounts::AccountHealth;
    use crate::bridge::accounts::{AccountRegistry, AccountRuntimeError, RuntimeAccountRegistry};
    use crate::bridge::auth_router::AuthRouter;
    use crate::imap::gluon_connector::GluonMailConnector;
    use crate::imap::gluon_mailbox_mutation::GluonMailMailboxMutation;
    use crate::imap::gluon_mailbox_view::GluonMailMailboxView;
    use crate::imap::mailbox;
    use crate::imap::mailbox_catalog::RuntimeMailboxCatalog;
    use crate::imap::rfc822;
    use gluon_rs_mail::{
        AccountBootstrap, CacheLayout, CompatibilityTarget, CompatibleStore, GluonKey, NewMailbox,
        NewMessage, StoreBootstrap,
    };
    use gluon_rs_mail::{EmailAddress, MessageEnvelope};
    use tempfile::{tempdir, TempDir};
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    struct MockImapConnector {
        auth_router: AuthRouter,
        runtime_accounts: Arc<RuntimeAccountRegistry>,
    }

    impl MockImapConnector {
        fn new(auth_router: AuthRouter, runtime_accounts: Arc<RuntimeAccountRegistry>) -> Self {
            Self {
                auth_router,
                runtime_accounts,
            }
        }
    }

    #[async_trait::async_trait]
    impl gluon_rs_mail::ImapConnector for MockImapConnector {
        async fn authorize(
            &self,
            username: &str,
            password: &str,
        ) -> gluon_rs_mail::ImapResult<gluon_rs_mail::AuthResult> {
            let route = self
                .auth_router
                .resolve_login(username, password)
                .ok_or(gluon_rs_mail::ImapError::AuthFailed)?;
            // Check account availability, matching ProtonImapConnector behavior
            self.runtime_accounts
                .with_valid_access_token(&route.account_id)
                .await
                .map_err(|e| match e {
                    AccountRuntimeError::AccountUnavailable(_) => {
                        gluon_rs_mail::ImapError::AuthFailed
                    }
                    other => gluon_rs_mail::ImapError::Upstream(other.to_string()),
                })?;
            Ok(gluon_rs_mail::AuthResult {
                account_id: route.account_id.0.clone(),
                primary_email: route.primary_email.clone(),
                mailboxes: Vec::new(),
            })
        }
        async fn get_message_literal(
            &self,
            _account_id: &str,
            _message_id: &str,
        ) -> gluon_rs_mail::ImapResult<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn mark_messages_read(
            &self,
            _account_id: &str,
            _message_ids: &[&str],
            _read: bool,
        ) -> gluon_rs_mail::ImapResult<()> {
            Ok(())
        }
        async fn mark_messages_starred(
            &self,
            _account_id: &str,
            _message_ids: &[&str],
            _starred: bool,
        ) -> gluon_rs_mail::ImapResult<()> {
            Ok(())
        }
        async fn label_messages(
            &self,
            _account_id: &str,
            _message_ids: &[&str],
            _label_id: &str,
        ) -> gluon_rs_mail::ImapResult<()> {
            Ok(())
        }
        async fn unlabel_messages(
            &self,
            _account_id: &str,
            _message_ids: &[&str],
            _label_id: &str,
        ) -> gluon_rs_mail::ImapResult<()> {
            Ok(())
        }
        async fn trash_messages(
            &self,
            _account_id: &str,
            _message_ids: &[&str],
        ) -> gluon_rs_mail::ImapResult<()> {
            Ok(())
        }
        async fn delete_messages(
            &self,
            _account_id: &str,
            _message_ids: &[&str],
        ) -> gluon_rs_mail::ImapResult<()> {
            Ok(())
        }
        async fn import_message(
            &self,
            _account_id: &str,
            _label_id: &str,
            _flags: i64,
            _literal: &[u8],
        ) -> gluon_rs_mail::ImapResult<Option<String>> {
            Ok(None)
        }
        async fn fetch_message_metadata_page(
            &self,
            _account_id: &str,
            _label_id: &str,
            _page: i32,
            _page_size: i32,
        ) -> gluon_rs_mail::ImapResult<gluon_rs_mail::MetadataPage> {
            Ok(gluon_rs_mail::MetadataPage {
                messages: Vec::new(),
                total: 0,
            })
        }
        async fn fetch_user_labels(
            &self,
            _account_id: &str,
        ) -> gluon_rs_mail::ImapResult<Vec<gluon_rs_mail::MailboxInfo>> {
            Ok(Vec::new())
        }
    }

    fn mock_connector(
        auth_router: &AuthRouter,
        runtime_accounts: &Arc<RuntimeAccountRegistry>,
    ) -> Arc<dyn gluon_rs_mail::ImapConnector> {
        Arc::new(MockImapConnector::new(
            auth_router.clone(),
            runtime_accounts.clone(),
        ))
    }

    /// A connector that fails all upstream mutation calls. Used to test
    /// that the session correctly propagates upstream errors.
    struct FailingMockConnector {
        auth_router: AuthRouter,
        runtime_accounts: Arc<RuntimeAccountRegistry>,
    }

    #[async_trait::async_trait]
    impl gluon_rs_mail::ImapConnector for FailingMockConnector {
        async fn authorize(
            &self,
            username: &str,
            password: &str,
        ) -> gluon_rs_mail::ImapResult<gluon_rs_mail::AuthResult> {
            let route = self
                .auth_router
                .resolve_login(username, password)
                .ok_or(gluon_rs_mail::ImapError::AuthFailed)?;
            self.runtime_accounts
                .with_valid_access_token(&route.account_id)
                .await
                .map_err(|e| match e {
                    AccountRuntimeError::AccountUnavailable(_) => {
                        gluon_rs_mail::ImapError::AuthFailed
                    }
                    other => gluon_rs_mail::ImapError::Upstream(other.to_string()),
                })?;
            Ok(gluon_rs_mail::AuthResult {
                account_id: route.account_id.0.clone(),
                primary_email: route.primary_email.clone(),
                mailboxes: Vec::new(),
            })
        }
        async fn get_message_literal(
            &self,
            _a: &str,
            _m: &str,
        ) -> gluon_rs_mail::ImapResult<Option<Vec<u8>>> {
            Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
        }
        async fn mark_messages_read(
            &self,
            _a: &str,
            _i: &[&str],
            _r: bool,
        ) -> gluon_rs_mail::ImapResult<()> {
            Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
        }
        async fn mark_messages_starred(
            &self,
            _a: &str,
            _i: &[&str],
            _s: bool,
        ) -> gluon_rs_mail::ImapResult<()> {
            Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
        }
        async fn label_messages(
            &self,
            _a: &str,
            _i: &[&str],
            _l: &str,
        ) -> gluon_rs_mail::ImapResult<()> {
            Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
        }
        async fn unlabel_messages(
            &self,
            _a: &str,
            _i: &[&str],
            _l: &str,
        ) -> gluon_rs_mail::ImapResult<()> {
            Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
        }
        async fn trash_messages(&self, _a: &str, _i: &[&str]) -> gluon_rs_mail::ImapResult<()> {
            Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
        }
        async fn delete_messages(&self, _a: &str, _i: &[&str]) -> gluon_rs_mail::ImapResult<()> {
            Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
        }
        async fn import_message(
            &self,
            _a: &str,
            _l: &str,
            _f: i64,
            _d: &[u8],
        ) -> gluon_rs_mail::ImapResult<Option<String>> {
            Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
        }
        async fn fetch_message_metadata_page(
            &self,
            _a: &str,
            _l: &str,
            _p: i32,
            _s: i32,
        ) -> gluon_rs_mail::ImapResult<gluon_rs_mail::MetadataPage> {
            Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
        }
        async fn fetch_user_labels(
            &self,
            _a: &str,
        ) -> gluon_rs_mail::ImapResult<Vec<gluon_rs_mail::MailboxInfo>> {
            Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
        }
    }

    fn failing_connector(
        auth_router: &AuthRouter,
        runtime_accounts: &Arc<RuntimeAccountRegistry>,
    ) -> Arc<dyn gluon_rs_mail::ImapConnector> {
        Arc::new(FailingMockConnector {
            auth_router: auth_router.clone(),
            runtime_accounts: runtime_accounts.clone(),
        })
    }

    /// Clone a SessionConfig with a different connector for testing.
    fn with_failing_connector(
        config: &Arc<SessionConfig>,
        auth_router: &AuthRouter,
        runtime_accounts: &Arc<RuntimeAccountRegistry>,
    ) -> Arc<SessionConfig> {
        Arc::new(SessionConfig {
            connector: failing_connector(auth_router, runtime_accounts),
            gluon_connector: config.gluon_connector.clone(),
            mailbox_catalog: config.mailbox_catalog.clone(),
            mailbox_mutation: config.mailbox_mutation.clone(),
            mailbox_view: config.mailbox_view.clone(),
            recent_tracker: config.recent_tracker.clone(),
        })
    }

    fn scoped(account: &str, mailbox: &str) -> ScopedMailboxId {
        ScopedMailboxId::from_parts(Some(account), mailbox)
    }

    fn pid(id: &str) -> ProtonMessageId {
        ProtonMessageId::from(id)
    }

    fn iuid(v: u32) -> ImapUid {
        ImapUid::from(v)
    }

    fn test_session() -> crate::api::types::Session {
        crate::api::types::Session {
            uid: "test-uid".to_string(),
            access_token: "test-token".to_string(),
            refresh_token: "test-refresh".to_string(),
            email: "test@proton.me".to_string(),
            display_name: "Test User".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: Some("dGVzdA==".to_string()),
            bridge_password: Some("bridge-pass-1234".to_string()),
        }
    }

    fn test_gluon_config() -> (
        Arc<SessionConfig>,
        TempDir,
        AuthRouter,
        Arc<RuntimeAccountRegistry>,
    ) {
        let session = test_session();
        let accounts = AccountRegistry::from_single_session(session.clone());
        let auth_router = AuthRouter::new(accounts);
        let runtime_accounts = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        let tempdir = tempdir().expect("tempdir");
        let gluon_store = Arc::new(
            CompatibleStore::open(StoreBootstrap::new(
                CacheLayout::new(tempdir.path().join("gluon")),
                CompatibilityTarget::pinned("2046c95ca745"),
                vec![AccountBootstrap::new(
                    "test-uid",
                    "test-uid",
                    GluonKey::try_from_slice(&[7u8; 32]).expect("key"),
                )],
            ))
            .expect("open store"),
        );
        let config = Arc::new(SessionConfig {
            connector: mock_connector(&auth_router, &runtime_accounts),
            gluon_connector: GluonMailConnector::new(gluon_store.clone()),
            mailbox_catalog: RuntimeMailboxCatalog::new(runtime_accounts.clone()),
            mailbox_mutation: GluonMailMailboxMutation::new(gluon_store.clone()),
            mailbox_view: GluonMailMailboxView::new(gluon_store),
            recent_tracker: RecentTracker::new(),
        });
        (config, tempdir, auth_router, runtime_accounts)
    }

    async fn test_gluon_mail_config() -> (
        Arc<SessionConfig>,
        TempDir,
        AuthRouter,
        Arc<RuntimeAccountRegistry>,
    ) {
        let session = test_session();
        let accounts = AccountRegistry::from_single_session(session.clone());
        let auth_router = AuthRouter::new(accounts);
        let runtime_accounts = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));

        let tempdir = tempdir().expect("tempdir");
        let layout = CacheLayout::new(tempdir.path().join("gluon"));
        let gluon_store = Arc::new(
            CompatibleStore::open(StoreBootstrap::new(
                layout,
                CompatibilityTarget::pinned("2046c95ca745"),
                vec![AccountBootstrap::new(
                    "test-uid",
                    "test-uid",
                    GluonKey::try_from_slice(&[7u8; 32]).expect("key"),
                )],
            ))
            .expect("open store"),
        );

        let mailbox = gluon_store
            .create_mailbox(
                "test-uid",
                &NewMailbox {
                    remote_id: "0".to_string(),
                    name: "INBOX".to_string(),
                    uid_validity: 42,
                    subscribed: true,
                    attributes: Vec::new(),
                    flags: Vec::new(),
                    permanent_flags: vec!["\\Seen".to_string(), "\\Flagged".to_string()],
                },
            )
            .await
            .expect("create mailbox");

        let mut meta = make_meta("msg-1", 1);
        meta.external_id = Some("msg-1@example.test".to_string());
        let blob = b"Date: Tue, 14 Nov 2023 22:13:20 +0000\r\nFrom: Alice <alice@proton.me>\r\nTo: Bob <bob@proton.me>\r\nSubject: Subject msg-1\r\nMessage-ID: <msg-1@example.test>\r\n\r\nsearch-hit-body".to_vec();
        meta.size = blob.len() as i64;
        let header = String::from_utf8_lossy(&blob)
            .split("\r\n\r\n")
            .next()
            .unwrap_or_default()
            .to_string();
        gluon_store
            .append_message(
                "test-uid",
                mailbox.internal_id,
                &NewMessage {
                    internal_id: "internal-1".to_string(),
                    remote_id: meta.id.clone(),
                    flags: mailbox::message_flags(&meta)
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                    blob: blob.clone(),
                    body: "search-hit-body".to_string(),
                    body_structure: rfc822::build_bodystructure(&blob),
                    envelope: rfc822::build_envelope(&meta, &header),
                    size: meta.size,
                    recent: false,
                },
            )
            .await
            .expect("append message");

        let config = Arc::new(SessionConfig {
            connector: mock_connector(&auth_router, &runtime_accounts),
            gluon_connector: GluonMailConnector::new(gluon_store.clone()),
            mailbox_catalog: RuntimeMailboxCatalog::new(runtime_accounts.clone()),
            mailbox_mutation: GluonMailMailboxMutation::new(gluon_store.clone()),
            mailbox_view: GluonMailMailboxView::new(gluon_store),
            recent_tracker: RecentTracker::new(),
        });

        (config, tempdir, auth_router, runtime_accounts)
    }

    fn make_meta(id: &str, unread: i32) -> MessageEnvelope {
        MessageEnvelope {
            id: id.to_string(),
            address_id: "addr-1".to_string(),
            label_ids: vec!["0".to_string()],
            external_id: None,
            subject: format!("Subject {}", id),
            sender: EmailAddress {
                name: "Alice".to_string(),
                address: "alice@proton.me".to_string(),
            },
            to_list: vec![EmailAddress {
                name: "Bob".to_string(),
                address: "bob@proton.me".to_string(),
            }],
            cc_list: vec![],
            bcc_list: vec![],
            reply_tos: vec![],
            flags: 0,
            time: 1700000000,
            size: 1024,
            unread,
            is_replied: 0,
            is_replied_all: 0,
            is_forwarded: 0,
            num_attachments: 0,
        }
    }

    fn metadata_page_response(messages: Vec<MessageEnvelope>, total: i64) -> serde_json::Value {
        let api_messages: Vec<crate::api::types::MessageMetadata> =
            messages.into_iter().map(Into::into).collect();
        serde_json::json!({
            "Code": 1000,
            "Messages": api_messages,
            "Total": total
        })
    }

    async fn seed_gluon_backend_message(
        config: &Arc<SessionConfig>,
        mailbox_name: &str,
        proton_id: &str,
        unread: i32,
        body: &[u8],
    ) -> ImapUid {
        let mut meta = make_meta(proton_id, unread);
        meta.external_id = Some(format!("{proton_id}@example.test"));
        meta.size = body.len() as i64;
        let scoped_mailbox = ScopedMailboxId::from_parts(Some("test-uid"), mailbox_name);
        let pid = ProtonMessageId::from(proton_id);
        let uid = config
            .mailbox_mutation
            .store_metadata(&scoped_mailbox, &pid, meta)
            .await
            .unwrap();
        config
            .mailbox_mutation
            .store_rfc822(&scoped_mailbox, uid, body.to_vec())
            .await
            .unwrap();
        uid
    }

    async fn create_session_pair(
        config: Arc<SessionConfig>,
    ) -> (
        ImapSession<tokio::io::DuplexStream, tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        let (client_read, server_write) = tokio::io::duplex(8192);
        let (server_read, client_write) = tokio::io::duplex(8192);

        let session = ImapSession::new(server_read, server_write, config);
        (session, client_read, client_write)
    }

    async fn prime_selected_state_from_view(
        session: &mut ImapSession<tokio::io::DuplexStream, tokio::io::DuplexStream>,
        config: &Arc<SessionConfig>,
        scoped_mailbox: &ScopedMailboxId,
    ) {
        let snapshot = config
            .mailbox_view
            .mailbox_snapshot(scoped_mailbox)
            .await
            .unwrap();
        session.selected_mailbox_mod_seq = Some(snapshot.mod_seq);
        session.selected_mailbox_uids =
            config.mailbox_view.list_uids(scoped_mailbox).await.unwrap();
        session.selected_mailbox_flags.clear();
        for uid in &session.selected_mailbox_uids {
            let flags = config
                .mailbox_view
                .get_flags(scoped_mailbox, *uid)
                .await
                .unwrap();
            session.selected_mailbox_flags.insert(*uid, flags);
        }
    }

    fn multi_account_compat_config(
        _api_base_url: &str,
    ) -> (
        Arc<SessionConfig>,
        TempDir,
        AuthRouter,
        Arc<RuntimeAccountRegistry>,
    ) {
        let account_a = crate::api::types::Session {
            uid: "uid-a".to_string(),
            access_token: "access-a".to_string(),
            refresh_token: "refresh-a".to_string(),
            email: "alice@proton.me".to_string(),
            display_name: "Alice".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: Some("dGVzdA==".to_string()),
            bridge_password: Some("pass-a".to_string()),
        };
        let account_b = crate::api::types::Session {
            uid: "uid-b".to_string(),
            access_token: "access-b".to_string(),
            refresh_token: "refresh-b".to_string(),
            email: "bob@proton.me".to_string(),
            display_name: "Bob".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: Some("dGVzdA==".to_string()),
            bridge_password: Some("pass-b".to_string()),
        };
        let accounts = AccountRegistry::from_sessions(vec![account_a.clone(), account_b.clone()]);
        let auth_router = AuthRouter::new(accounts);
        let runtime_accounts = Arc::new(RuntimeAccountRegistry::in_memory(vec![
            account_a, account_b,
        ]));
        let tempdir = tempdir().expect("tempdir");
        let gluon_store = Arc::new(
            CompatibleStore::open(StoreBootstrap::new(
                CacheLayout::new(tempdir.path().join("gluon")),
                CompatibilityTarget::pinned("2046c95ca745"),
                vec![
                    AccountBootstrap::new(
                        "uid-a",
                        "uid-a",
                        GluonKey::try_from_slice(&[7u8; 32]).expect("key"),
                    ),
                    AccountBootstrap::new(
                        "uid-b",
                        "uid-b",
                        GluonKey::try_from_slice(&[8u8; 32]).expect("key"),
                    ),
                ],
            ))
            .expect("open store"),
        );
        let config = Arc::new(SessionConfig {
            connector: mock_connector(&auth_router, &runtime_accounts),
            gluon_connector: GluonMailConnector::new(gluon_store.clone()),
            mailbox_catalog: RuntimeMailboxCatalog::new(runtime_accounts.clone()),
            mailbox_mutation: GluonMailMailboxMutation::new(gluon_store.clone()),
            mailbox_view: GluonMailMailboxView::new(gluon_store),
            recent_tracker: RecentTracker::new(),
        });
        (config, tempdir, auth_router, runtime_accounts)
    }

    #[tokio::test]
    async fn test_greet() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.greet().await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("OK IMAP4rev1"));
    }

    #[tokio::test]
    async fn test_capability() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.handle_line("a001 CAPABILITY").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("IMAP4rev1"));
        assert!(response.contains("STARTTLS"));
        assert!(response.contains("UIDPLUS"));
        assert!(response.contains("MOVE"));
        assert!(!response.contains("AUTH=PLAIN"));
        assert!(response.contains("a001 OK"));
    }

    #[tokio::test]
    async fn test_noop() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.handle_line("a001 NOOP").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 OK"));
    }

    #[tokio::test]
    async fn test_noop_selected_emits_exists_on_store_change() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.selected_mailbox_mod_seq = Some(0);
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();

        session.handle_line("a001 NOOP").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("1 EXISTS"));
        assert!(response.contains("a001 OK"));
    }

    #[tokio::test]
    async fn test_noop_selected_emits_exists_on_gluon_connector_create() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.selected_mailbox_mod_seq = Some(0);
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .gluon_connector
            .upsert_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-noop"),
                make_meta("msg-noop", 1),
            )
            .await
            .unwrap();

        session.handle_line("a001 NOOP").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("2 EXISTS"), "response={response}");
        assert!(response.contains("a001 OK"), "response={response}");
    }

    #[tokio::test]
    async fn test_idle_selected_waits_for_done_and_emits_exists() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, mut client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.selected_mailbox_mod_seq = Some(0);
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();

        let idle_task =
            tokio::spawn(async move { session.handle_line("a001 IDLE").await.unwrap() });

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("+ idling"));
        assert!(response.contains("1 EXISTS"));

        tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
            .await
            .unwrap();

        let n = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 OK IDLE terminated"));

        let action = tokio::time::timeout(Duration::from_secs(1), idle_task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(action, SessionAction::Continue));
    }

    #[tokio::test]
    async fn test_idle_emits_exists_when_new_message_arrives_after_start() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, mut client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.selected_mailbox_mod_seq = Some(0);
        session.authenticated_account_id = Some("test-uid".to_string());

        let idle_task =
            tokio::spawn(async move { session.handle_line("a001 IDLE").await.unwrap() });

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("+ idling"), "response={response}");

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();

        let n = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("1 EXISTS"), "response={response}");

        tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
            .await
            .unwrap();

        let _ = tokio::time::timeout(Duration::from_secs(1), idle_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_idle_emits_exists_when_new_message_arrives_after_start_with_gluon_mail_backend() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, mut client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.selected_mailbox_mod_seq = Some(0);
        session.authenticated_account_id = Some("test-uid".to_string());

        let idle_task =
            tokio::spawn(async move { session.handle_line("a001 IDLE").await.unwrap() });

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("+ idling"), "response={response}");

        config
            .gluon_connector
            .upsert_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-idle"),
                make_meta("msg-idle", 1),
            )
            .await
            .unwrap();

        let n = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("2 EXISTS"), "response={response}");

        tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
            .await
            .unwrap();

        let _ = tokio::time::timeout(Duration::from_secs(1), idle_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_idle_emits_expunge_and_exists_on_delete() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, mut client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid1 = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        let _uid2 = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-2"),
                make_meta("msg-2", 1),
            )
            .await
            .unwrap();
        prime_selected_state_from_view(&mut session, &config, &scoped("test-uid", "INBOX")).await;

        let idle_task =
            tokio::spawn(async move { session.handle_line("a001 IDLE").await.unwrap() });

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("+ idling"), "response={response}");

        config
            .mailbox_mutation
            .remove_message(&scoped("test-uid", "INBOX"), uid1)
            .await
            .unwrap();

        let n = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("EXPUNGE"), "response={response}");
        assert!(response.contains("1 EXISTS"), "response={response}");

        tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(1), idle_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_idle_emits_expunge_and_exists_on_gluon_connector_delete() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, mut client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid1 = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-idle-delete-1",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-idle-delete-1\r\n\r\none",
        )
        .await;
        let _uid2 = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-idle-delete-2",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-idle-delete-2\r\n\r\ntwo",
        )
        .await;
        assert_eq!(uid1, iuid(2));
        prime_selected_state_from_view(&mut session, &config, &scoped("test-uid", "INBOX")).await;

        let idle_task =
            tokio::spawn(async move { session.handle_line("a001 IDLE").await.unwrap() });

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("+ idling"), "response={response}");

        config
            .gluon_connector
            .remove_message_by_uid(&scoped("test-uid", "INBOX"), uid1)
            .await
            .unwrap();

        let n = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("EXPUNGE"), "response={response}");
        assert!(response.contains("2 EXISTS"), "response={response}");

        tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(1), idle_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_idle_emits_flag_fetch_on_flag_only_change() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, mut client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        let snapshot = config
            .mailbox_view
            .mailbox_snapshot(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        session.selected_mailbox_mod_seq = Some(snapshot.mod_seq);
        session.selected_mailbox_uids = vec![uid];
        session.selected_mailbox_flags.insert(uid, Vec::new());

        let idle_task =
            tokio::spawn(async move { session.handle_line("a001 IDLE").await.unwrap() });

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("+ idling"), "response={response}");

        config
            .mailbox_mutation
            .set_flags(
                &scoped("test-uid", "INBOX"),
                uid,
                vec!["\\Seen".to_string()],
            )
            .await
            .unwrap();

        let n = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("FETCH (FLAGS (\\Seen))"),
            "response={response}"
        );
        assert!(!response.contains("EXISTS"), "response={response}");

        tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(1), idle_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_idle_emits_flag_fetch_on_gluon_connector_flag_change() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, mut client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-idle-flag",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-idle-flag\r\n\r\nbody",
        )
        .await;
        prime_selected_state_from_view(&mut session, &config, &scoped("test-uid", "INBOX")).await;
        session.selected_mailbox_flags.insert(uid, Vec::new());

        let idle_task =
            tokio::spawn(async move { session.handle_line("a001 IDLE").await.unwrap() });

        let mut buf = vec![0u8; 1024];
        let n = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("+ idling"), "response={response}");

        config
            .gluon_connector
            .update_message_flags(
                &scoped("test-uid", "INBOX"),
                uid,
                vec!["\\Seen".to_string()],
            )
            .await
            .unwrap();

        let n = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("FETCH (FLAGS (\\Seen))"),
            "response={response}"
        );
        assert!(!response.contains("EXISTS"), "response={response}");

        tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(1), idle_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn test_logout() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        let action = session.handle_line("a001 LOGOUT").await.unwrap();
        assert!(matches!(action, SessionAction::Close));

        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("BYE"));
        assert!(response.contains("a001 OK"));
    }

    #[tokio::test]
    async fn test_login_bad_password() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session
            .handle_line("a001 LOGIN test@proton.me wrongpassword")
            .await
            .unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 NO"));
        assert!(response.contains("AUTHENTICATIONFAILED"));
    }

    #[tokio::test]
    async fn test_login_isolation_unavailable_account_does_not_block_other_account() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/users"))
            .and(header("x-pm-uid", "uid-b"))
            .and(header("Authorization", "Bearer access-b"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "User": {
                    "ID": "user-b",
                    "Name": "bob",
                    "DisplayName": "Bob",
                    "Email": "bob@proton.me",
                    "Keys": []
                }
            })))
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, runtime_accounts) =
            multi_account_compat_config(&server.uri());
        runtime_accounts
            .set_health(
                &crate::bridge::types::AccountId("uid-a".to_string()),
                AccountHealth::Unavailable,
            )
            .await
            .unwrap();

        // Unavailable account fails with generic auth failure.
        let (mut unavailable_session, mut unavailable_read, _w1) =
            create_session_pair(config.clone()).await;
        unavailable_session
            .handle_line("a001 LOGIN alice@proton.me pass-a")
            .await
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut unavailable_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("AUTHENTICATIONFAILED"));

        // Healthy account proceeds to login via connector. With the mock
        // connector this succeeds (the full key-unlock flow is not exercised).
        let (mut healthy_session, mut healthy_read, _w2) = create_session_pair(config).await;
        healthy_session
            .handle_line("a001 LOGIN bob@proton.me pass-b")
            .await
            .unwrap();
        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut healthy_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("a001 OK"),
            "healthy account should succeed via mock connector, response={response}"
        );
        assert!(
            !response.contains("AUTHENTICATIONFAILED"),
            "healthy account login should not be blocked, response={response}"
        );
    }

    #[tokio::test]
    async fn test_list_not_authenticated() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.handle_line("a001 LIST \"\" \"*\"").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 NO"));
    }

    #[tokio::test]
    async fn test_select_not_authenticated() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.handle_line("a001 SELECT INBOX").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 NO"));
    }

    #[tokio::test]
    async fn test_status_authenticated() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "Drafts"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();

        session
            .handle_line("a001 STATUS \"Drafts\" (UIDNEXT UIDVALIDITY UNSEEN RECENT MESSAGES)")
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* STATUS \"Drafts\" ("));
        assert!(response.contains("UIDNEXT"));
        assert!(response.contains("UIDVALIDITY"));
        assert!(response.contains("UNSEEN"));
        assert!(response.contains("RECENT 0"));
        assert!(response.contains("MESSAGES 1"));
        assert!(response.contains("a001 OK STATUS completed"));
    }

    #[tokio::test]
    async fn test_status_authenticated_with_gluon_mail_view() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        session
            .handle_line("a001 STATUS \"INBOX\" (UIDNEXT UIDVALIDITY UNSEEN RECENT MESSAGES)")
            .await
            .unwrap();

        let mut buf = vec![0u8; 2048];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("* STATUS \"INBOX\" ("),
            "response={response}"
        );
        assert!(response.contains("UIDNEXT 2"), "response={response}");
        assert!(response.contains("UIDVALIDITY 42"), "response={response}");
        assert!(response.contains("UNSEEN 1"), "response={response}");
        assert!(response.contains("RECENT 0"), "response={response}");
        assert!(response.contains("MESSAGES 1"), "response={response}");
        assert!(
            response.contains("a001 OK STATUS completed"),
            "response={response}"
        );
    }

    #[tokio::test]
    async fn test_check_selected_mailbox() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.selected_mailbox_mod_seq = Some(0);
        session.authenticated_account_id = Some("test-uid".to_string());

        session.handle_line("a001 CHECK").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 OK CHECK completed"));
    }

    #[tokio::test]
    async fn test_bad_command() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.handle_line("a001 BOGUS").await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 BAD"));
    }

    #[tokio::test]
    async fn test_starttls() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        let action = session.handle_line("a001 STARTTLS").await.unwrap();
        assert!(matches!(action, SessionAction::StartTls));

        let mut buf = vec![0u8; 1024];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 OK"));
    }

    #[tokio::test]
    async fn test_select_paginates_metadata_fetch() {
        // This test verifies that SELECT populates the store from metadata.
        // With the connector abstraction, metadata is fetched via the connector.
        // Here we pre-seed the store to test the SELECT response formatting.
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        // Pre-seed the store with messages so SELECT finds them
        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-2"),
                make_meta("msg-2", 1),
            )
            .await
            .unwrap();

        session.handle_line("a001 SELECT INBOX").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("2 EXISTS"), "response={response}");
        assert!(response.contains("a001 OK [READ-WRITE] SELECT completed"));

        let uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        assert_eq!(uids.len(), 2);
    }

    #[tokio::test]
    async fn test_fetch_body_returns_body_item_not_bodystructure() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .store_rfc822(
                &scoped("test-uid", "INBOX"),
                uid,
                b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-1\r\n\r\nbody".to_vec(),
            )
            .await
            .unwrap();

        session.handle_line("a001 FETCH 1 BODY").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains(" FETCH (BODY ("), "response={response}");
        assert!(!response.contains("BODYSTRUCTURE"), "response={response}");
        assert!(response.contains("a001 OK FETCH completed"));
    }

    #[tokio::test]
    async fn test_fetch_body_returns_body_item_not_bodystructure_with_gluon_mail_view() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        session.handle_line("a001 FETCH 1 BODY").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains(" FETCH (BODY ("), "response={response}");
        assert!(!response.contains("BODYSTRUCTURE"), "response={response}");
        assert!(
            response.contains("a001 OK FETCH completed"),
            "response={response}"
        );
    }

    #[tokio::test]
    async fn test_fetch_body_section_returns_empty_literal_when_content_missing() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();

        session
            .handle_line("a001 FETCH 1 BODY[TEXT]")
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("BODY[TEXT] {0}"), "response={response}");
        assert!(response.contains("a001 OK FETCH completed"));
    }

    #[tokio::test]
    async fn test_store_set_flags_syncs_remote_removals() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unread"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0..)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unlabel"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0..)
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        let uid = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .set_flags(
                &scoped("test-uid", "INBOX"),
                uid,
                vec!["\\Seen".to_string(), "\\Flagged".to_string()],
            )
            .await
            .unwrap();

        session.handle_line("a001 STORE 1 FLAGS ()").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("FLAGS ()"), "response={response}");
        assert!(response.contains("a001 OK STORE completed"));

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_store_set_flags_syncs_remote_removals_with_gluon_mail_backend() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unread"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0..)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unlabel"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0..)
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-store-sync",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-store-sync\r\n\r\nstore-body",
        )
        .await;
        config
            .mailbox_mutation
            .set_flags(
                &scoped("test-uid", "INBOX"),
                uid,
                vec!["\\Seen".to_string(), "\\Flagged".to_string()],
            )
            .await
            .unwrap();

        session.handle_line("a001 STORE 2 FLAGS ()").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("* 2 FETCH (FLAGS ())"),
            "response={response}"
        );
        assert!(
            response.contains("a001 OK STORE completed"),
            "response={response}"
        );
        assert!(config
            .mailbox_mutation
            .get_flags(&scoped("test-uid", "INBOX"), uid)
            .await
            .unwrap()
            .is_empty());

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_copy_copies_local_message_and_labels_destination_upstream() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        let src_uid = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();

        session.handle_line("a001 COPY 1 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("COPY completed"), "response={response}");
        assert!(
            response.contains("[COPYUID"),
            "response should contain COPYUID: {response}"
        );

        let inbox_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        assert_eq!(inbox_uids, vec![src_uid]);

        let archive_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "Archive"))
            .await
            .unwrap();
        assert_eq!(archive_uids.len(), 1);
        let archived_proton_id = config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "Archive"), archive_uids[0])
            .await
            .unwrap();
        assert_eq!(archived_proton_id.as_deref(), Some("msg-1"));

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_copy_copies_local_message_and_labels_destination_upstream_with_gluon_mail_backend(
    ) {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/label"))
            .and(body_string_contains("\"LabelID\":\"6\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0..)
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-copy-sync",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-copy-sync\r\n\r\ncopy-body",
        )
        .await;
        assert_eq!(uid, iuid(2));

        session.handle_line("a001 COPY 2 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("COPY completed"), "response={response}");
        assert!(response.contains("[COPYUID"), "response={response}");

        assert_eq!(
            config
                .mailbox_view
                .list_uids(&scoped("test-uid", "INBOX"))
                .await
                .unwrap(),
            vec![iuid(1), iuid(2)]
        );
        assert_eq!(
            config
                .mailbox_view
                .list_uids(&scoped("test-uid", "Archive"))
                .await
                .unwrap(),
            vec![iuid(1)]
        );
        assert_eq!(
            config
                .mailbox_view
                .get_proton_id(&scoped("test-uid", "Archive"), iuid(1))
                .await
                .unwrap()
                .as_deref(),
            Some("msg-copy-sync")
        );

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_copy_copies_local_message_without_api_client() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let src_uid = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();

        session.handle_line("a001 COPY 1 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("COPY completed"), "response={response}");

        let inbox_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        assert_eq!(inbox_uids, vec![src_uid]);

        let archive_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "Archive"))
            .await
            .unwrap();
        assert_eq!(archive_uids.len(), 1);
        let archived_proton_id = config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "Archive"), archive_uids[0])
            .await
            .unwrap();
        assert_eq!(archived_proton_id.as_deref(), Some("msg-1"));
    }

    #[tokio::test]
    async fn test_copy_copies_local_message_without_api_client_with_gluon_mail_backend() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-copy",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-copy\r\n\r\ncopy-body",
        )
        .await;
        assert_eq!(uid, iuid(2));

        session.handle_line("a001 COPY 2 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("COPY completed"), "response={response}");

        let inbox_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        assert_eq!(inbox_uids, vec![iuid(1), iuid(2)]);
        assert_eq!(
            config
                .mailbox_view
                .get_proton_id(&scoped("test-uid", "INBOX"), iuid(2))
                .await
                .unwrap()
                .as_deref(),
            Some("msg-copy")
        );

        let archive_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "Archive"))
            .await
            .unwrap();
        assert_eq!(archive_uids, vec![iuid(1)]);
        assert_eq!(
            config
                .mailbox_view
                .get_proton_id(&scoped("test-uid", "Archive"), iuid(1))
                .await
                .unwrap()
                .as_deref(),
            Some("msg-copy")
        );
    }

    #[tokio::test]
    async fn test_copy_fails_when_upstream_fails() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let fail_config = with_failing_connector(&config, &_auth_router, &_runtime_accounts);
        let (mut session, mut client_read, _client_write) = create_session_pair(fail_config).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();

        session.handle_line("a001 COPY 1 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 NO"), "response={response}");
        assert!(
            response.contains("COPY failed: upstream mutation failed"),
            "response={response}"
        );

        let archive_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "Archive"))
            .await
            .unwrap();
        assert!(archive_uids.is_empty());
    }

    #[tokio::test]
    async fn test_copy_fails_when_upstream_fails_with_gluon_mail_backend() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let fail_config = with_failing_connector(&config, &_auth_router, &_runtime_accounts);
        let (mut session, mut client_read, _client_write) = create_session_pair(fail_config).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-copy-fail",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-copy-fail\r\n\r\ncopy-body",
        )
        .await;
        assert_eq!(uid, iuid(2));

        session.handle_line("a001 COPY 2 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 NO"), "response={response}");
        assert!(
            response.contains("COPY failed: upstream mutation failed"),
            "response={response}"
        );
        assert!(config
            .mailbox_view
            .list_uids(&scoped("test-uid", "Archive"))
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_move_moves_local_message_and_syncs_label_add_remove_upstream() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/label"))
            .and(body_string_contains("\"LabelID\":\"6\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0..)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unlabel"))
            .and(body_string_contains("\"LabelID\":\"0\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0..)
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-2"),
                make_meta("msg-2", 1),
            )
            .await
            .unwrap();

        session.handle_line("a001 MOVE 1 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* 1 EXPUNGE"), "response={response}");
        assert!(response.contains("MOVE completed"), "response={response}");

        let inbox_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        assert_eq!(inbox_uids.len(), 1);
        let inbox_proton_id = config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "INBOX"), inbox_uids[0])
            .await
            .unwrap();
        assert_eq!(inbox_proton_id.as_deref(), Some("msg-2"));

        let archive_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "Archive"))
            .await
            .unwrap();
        assert_eq!(archive_uids.len(), 1);
        let archive_proton_id = config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "Archive"), archive_uids[0])
            .await
            .unwrap();
        assert_eq!(archive_proton_id.as_deref(), Some("msg-1"));

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_move_moves_local_message_and_syncs_label_add_remove_upstream_with_gluon_mail_backend(
    ) {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/label"))
            .and(body_string_contains("\"LabelID\":\"6\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0..)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unlabel"))
            .and(body_string_contains("\"LabelID\":\"0\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0..)
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-move-sync",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-move-sync\r\n\r\nmove-body",
        )
        .await;
        assert_eq!(uid, iuid(2));

        session.handle_line("a001 MOVE 2 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* 2 EXPUNGE"), "response={response}");
        assert!(response.contains("MOVE completed"), "response={response}");
        assert_eq!(
            config
                .mailbox_view
                .list_uids(&scoped("test-uid", "INBOX"))
                .await
                .unwrap(),
            vec![iuid(1)]
        );
        assert_eq!(
            config
                .mailbox_view
                .list_uids(&scoped("test-uid", "Archive"))
                .await
                .unwrap(),
            vec![iuid(1)]
        );
        assert_eq!(
            config
                .mailbox_view
                .get_proton_id(&scoped("test-uid", "Archive"), iuid(1))
                .await
                .unwrap()
                .as_deref(),
            Some("msg-move-sync")
        );

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_move_moves_local_message_without_api_client() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-2"),
                make_meta("msg-2", 1),
            )
            .await
            .unwrap();

        session.handle_line("a001 MOVE 1 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* 1 EXPUNGE"), "response={response}");
        assert!(response.contains("MOVE completed"), "response={response}");

        let inbox_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        assert_eq!(inbox_uids.len(), 1);
        let inbox_proton_id = config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "INBOX"), inbox_uids[0])
            .await
            .unwrap();
        assert_eq!(inbox_proton_id.as_deref(), Some("msg-2"));

        let archive_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "Archive"))
            .await
            .unwrap();
        assert_eq!(archive_uids.len(), 1);
        let archive_proton_id = config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "Archive"), archive_uids[0])
            .await
            .unwrap();
        assert_eq!(archive_proton_id.as_deref(), Some("msg-1"));
    }

    #[tokio::test]
    async fn test_move_moves_local_message_without_api_client_with_gluon_mail_backend() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-move",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-move\r\n\r\nmove-body",
        )
        .await;
        assert_eq!(uid, iuid(2));

        session.handle_line("a001 MOVE 2 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* 2 EXPUNGE"), "response={response}");
        assert!(response.contains("MOVE completed"), "response={response}");

        let inbox_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        assert_eq!(inbox_uids, vec![iuid(1)]);
        assert_eq!(
            config
                .mailbox_view
                .get_proton_id(&scoped("test-uid", "INBOX"), iuid(1))
                .await
                .unwrap()
                .as_deref(),
            Some("msg-1")
        );

        let archive_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "Archive"))
            .await
            .unwrap();
        assert_eq!(archive_uids, vec![iuid(1)]);
        assert_eq!(
            config
                .mailbox_view
                .get_proton_id(&scoped("test-uid", "Archive"), iuid(1))
                .await
                .unwrap()
                .as_deref(),
            Some("msg-move")
        );
    }

    #[tokio::test]
    async fn test_move_fails_when_upstream_fails() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let fail_config = with_failing_connector(&config, &_auth_router, &_runtime_accounts);
        let (mut session, mut client_read, _client_write) = create_session_pair(fail_config).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-2"),
                make_meta("msg-2", 1),
            )
            .await
            .unwrap();

        session.handle_line("a001 MOVE 1 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 NO"), "response={response}");
        assert!(
            response.contains("MOVE failed: upstream mutation failed"),
            "response={response}"
        );

        let inbox_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        assert_eq!(inbox_uids.len(), 2);

        let archive_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "Archive"))
            .await
            .unwrap();
        assert!(archive_uids.is_empty());
    }

    #[tokio::test]
    async fn test_move_fails_when_upstream_fails_with_gluon_mail_backend() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let fail_config = with_failing_connector(&config, &_auth_router, &_runtime_accounts);
        let (mut session, mut client_read, _client_write) = create_session_pair(fail_config).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-move-fail",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-move-fail\r\n\r\nmove-body",
        )
        .await;
        assert_eq!(uid, iuid(2));

        session.handle_line("a001 MOVE 2 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 NO"), "response={response}");
        assert!(
            response.contains("MOVE failed: upstream mutation failed"),
            "response={response}"
        );
        assert_eq!(
            config
                .mailbox_view
                .list_uids(&scoped("test-uid", "INBOX"))
                .await
                .unwrap(),
            vec![iuid(1), iuid(2)]
        );
        assert!(config
            .mailbox_view
            .list_uids(&scoped("test-uid", "Archive"))
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn test_uid_move_uses_uid_selection_and_sequence_expunge_response() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/label"))
            .and(body_string_contains("\"LabelID\":\"6\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0..)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unlabel"))
            .and(body_string_contains("\"LabelID\":\"0\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0..)
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        let uid2 = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-2"),
                make_meta("msg-2", 1),
            )
            .await
            .unwrap();

        session
            .handle_line(&format!("a001 UID MOVE {uid2} Archive"))
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* 2 EXPUNGE"), "response={response}");
        assert!(response.contains("MOVE completed"), "response={response}");

        let inbox_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        assert_eq!(inbox_uids.len(), 1);
        let inbox_proton_id = config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "INBOX"), inbox_uids[0])
            .await
            .unwrap();
        assert_eq!(inbox_proton_id.as_deref(), Some("msg-1"));

        let archive_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "Archive"))
            .await
            .unwrap();
        assert_eq!(archive_uids.len(), 1);
        let archive_proton_id = config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "Archive"), archive_uids[0])
            .await
            .unwrap();
        assert_eq!(archive_proton_id.as_deref(), Some("msg-2"));

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_uid_move_without_api_client_uses_uid_selection() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        let uid2 = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-2"),
                make_meta("msg-2", 1),
            )
            .await
            .unwrap();

        session
            .handle_line(&format!("a001 UID MOVE {uid2} Archive"))
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* 2 EXPUNGE"), "response={response}");
        assert!(response.contains("MOVE completed"), "response={response}");

        let inbox_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        assert_eq!(inbox_uids.len(), 1);
        let inbox_proton_id = config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "INBOX"), inbox_uids[0])
            .await
            .unwrap();
        assert_eq!(inbox_proton_id.as_deref(), Some("msg-1"));

        let archive_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "Archive"))
            .await
            .unwrap();
        assert_eq!(archive_uids.len(), 1);
        let archive_proton_id = config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "Archive"), archive_uids[0])
            .await
            .unwrap();
        assert_eq!(archive_proton_id.as_deref(), Some("msg-2"));
    }

    #[tokio::test]
    async fn test_expunge_syncs_trash_label_upstream() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/label"))
            .and(body_string_contains("\"LabelID\":\"3\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0..)
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        let uid = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .add_flags(
                &scoped("test-uid", "INBOX"),
                uid,
                &[String::from("\\Deleted")],
            )
            .await
            .unwrap();

        session.handle_line("a001 EXPUNGE").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* 1 EXPUNGE"), "response={response}");
        assert!(
            response.contains("a001 OK EXPUNGE completed"),
            "response={response}"
        );

        let inbox_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        assert!(inbox_uids.is_empty());

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_expunge_syncs_trash_label_upstream_with_gluon_mail_backend() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/label"))
            .and(body_string_contains("\"LabelID\":\"3\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0..)
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-expunge-sync",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-expunge-sync\r\n\r\nexpunge-body",
        )
        .await;
        config
            .mailbox_mutation
            .add_flags(
                &scoped("test-uid", "INBOX"),
                uid,
                &[String::from("\\Deleted")],
            )
            .await
            .unwrap();

        session.handle_line("a001 EXPUNGE").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* 2 EXPUNGE"), "response={response}");
        assert!(
            response.contains("a001 OK EXPUNGE completed"),
            "response={response}"
        );
        assert_eq!(
            config
                .mailbox_view
                .list_uids(&scoped("test-uid", "INBOX"))
                .await
                .unwrap(),
            vec![iuid(1)]
        );

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_expunge_without_api_client_with_gluon_mail_backend() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-expunge",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-expunge\r\n\r\nexpunge-body",
        )
        .await;
        config
            .mailbox_mutation
            .add_flags(
                &scoped("test-uid", "INBOX"),
                uid,
                &[String::from("\\Deleted")],
            )
            .await
            .unwrap();

        session.handle_line("a001 EXPUNGE").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* 2 EXPUNGE"), "response={response}");
        assert!(
            response.contains("a001 OK EXPUNGE completed"),
            "response={response}"
        );
        assert_eq!(
            config
                .mailbox_view
                .list_uids(&scoped("test-uid", "INBOX"))
                .await
                .unwrap(),
            vec![iuid(1)]
        );
        assert_eq!(
            config
                .mailbox_view
                .get_proton_id(&scoped("test-uid", "INBOX"), iuid(1))
                .await
                .unwrap()
                .as_deref(),
            Some("msg-1")
        );
    }

    #[tokio::test]
    async fn test_expunge_fails_when_upstream_fails() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let fail_config = with_failing_connector(&config, &_auth_router, &_runtime_accounts);
        let (mut session, mut client_read, _client_write) = create_session_pair(fail_config).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        let uid = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .add_flags(
                &scoped("test-uid", "INBOX"),
                uid,
                &[String::from("\\Deleted")],
            )
            .await
            .unwrap();

        session.handle_line("a001 EXPUNGE").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 NO"), "response={response}");
        assert!(
            response.contains("EXPUNGE failed: upstream mutation failed"),
            "response={response}"
        );

        let inbox_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        assert_eq!(inbox_uids, vec![uid]);
    }

    #[tokio::test]
    async fn test_expunge_fails_when_upstream_fails_with_gluon_mail_backend() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let fail_config = with_failing_connector(&config, &_auth_router, &_runtime_accounts);
        let (mut session, mut client_read, _client_write) = create_session_pair(fail_config).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-expunge-fail",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-expunge-fail\r\n\r\nexpunge-body",
        )
        .await;
        config
            .mailbox_mutation
            .add_flags(
                &scoped("test-uid", "INBOX"),
                uid,
                &[String::from("\\Deleted")],
            )
            .await
            .unwrap();

        session.handle_line("a001 EXPUNGE").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 NO"), "response={response}");
        assert!(
            response.contains("EXPUNGE failed: upstream mutation failed"),
            "response={response}"
        );
        assert_eq!(
            config
                .mailbox_view
                .list_uids(&scoped("test-uid", "INBOX"))
                .await
                .unwrap(),
            vec![iuid(1), iuid(2)]
        );
    }

    #[tokio::test]
    async fn test_uid_expunge_fails_when_upstream_fails() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let fail_config = with_failing_connector(&config, &_auth_router, &_runtime_accounts);
        let (mut session, mut client_read, _client_write) = create_session_pair(fail_config).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        let uid = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .add_flags(
                &scoped("test-uid", "INBOX"),
                uid,
                &[String::from("\\Deleted")],
            )
            .await
            .unwrap();

        session
            .handle_line(&format!("a001 UID EXPUNGE {uid}"))
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a001 NO"), "response={response}");
        assert!(
            response.contains("UID EXPUNGE failed: upstream mutation failed"),
            "response={response}"
        );

        let inbox_uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        assert_eq!(inbox_uids, vec![uid]);
    }

    #[tokio::test]
    async fn test_examine_reports_first_unseen_sequence_number() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 0),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-2"),
                make_meta("msg-2", 1),
            )
            .await
            .unwrap();

        session.handle_line("a001 EXAMINE INBOX").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("OK [UNSEEN 2]"), "response={response}");
        assert!(response.contains("a001 OK [READ-ONLY] EXAMINE completed"));
    }

    #[tokio::test]
    async fn test_examine_reports_first_unseen_sequence_number_with_gluon_mail_backend() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .set_flags(
                &scoped("test-uid", "INBOX"),
                iuid(1),
                vec!["\\Seen".to_string()],
            )
            .await
            .unwrap();
        seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-2",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-2\r\n\r\nbody",
        )
        .await;

        session.handle_line("a001 EXAMINE INBOX").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("OK [UNSEEN 2]"), "response={response}");
        assert!(response.contains("a001 OK [READ-ONLY] EXAMINE completed"));
    }

    #[tokio::test]
    async fn test_fetch_header_fields_uses_metadata_when_rfc822_missing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/mail/v4/messages/msg-1"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .named("no full message fetch for header-only body section")
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();

        session
            .handle_line("a001 FETCH 1 (UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])")
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("BODY[HEADER.FIELDS"));
        assert!(response.contains("Subject: Subject msg-1"));
        assert!(response.contains("From: \"Alice\" <alice@proton.me>"));
        assert!(response.contains("a001 OK FETCH completed"));

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_fetch_multiple_non_peek_body_sections_marks_read_once() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/read"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0..)
            .named("mark read should only happen once per message")
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        let uid = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .store_rfc822(
                &scoped("test-uid", "INBOX"),
                uid,
                b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-1\r\n\r\nbody".to_vec(),
            )
            .await
            .unwrap();

        session
            .handle_line("a001 FETCH 1 (BODY[] BODY[TEXT])")
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("BODY[]"));
        assert!(response.contains("BODY[TEXT]"));
        assert!(response.contains("a001 OK FETCH completed"));

        let flags = config
            .mailbox_view
            .get_flags(&scoped("test-uid", "INBOX"), uid)
            .await
            .unwrap();
        assert!(flags.iter().any(|f| f == "\\Seen"));

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_select_after_examine_resets_read_only_mode() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "Drafts"),
                &pid("msg-2"),
                make_meta("msg-2", 1),
            )
            .await
            .unwrap();

        session.handle_line("a001 EXAMINE INBOX").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        assert!(session.selected_read_only);

        session.handle_line("a002 SELECT Drafts").await.unwrap();
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a002 OK [READ-WRITE] SELECT completed"));
        assert!(!session.selected_read_only);
    }

    #[tokio::test]
    async fn test_select_after_examine_resets_read_only_mode_with_gluon_mail_backend() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        seed_gluon_backend_message(
            &config,
            "Drafts",
            "msg-2",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Draft msg-2\r\n\r\nbody",
        )
        .await;

        session.handle_line("a001 EXAMINE INBOX").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        assert!(session.selected_read_only);

        session.handle_line("a002 SELECT Drafts").await.unwrap();
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("a002 OK [READ-WRITE] SELECT completed"));
        assert!(!session.selected_read_only);
    }

    #[tokio::test]
    async fn test_close_after_examine_deselects_mailbox() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();

        session.handle_line("a001 EXAMINE INBOX").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        assert!(session.selected_read_only);
        assert_eq!(session.state, State::Selected);

        session.handle_line("a002 CLOSE").await.unwrap();
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("a002 OK CLOSE completed"),
            "response={response}"
        );
        assert_eq!(session.state, State::Authenticated);
        assert!(session.selected_mailbox.is_none());
        assert!(!session.selected_read_only);
    }

    #[tokio::test]
    async fn test_examine_fetch_body_does_not_mark_read() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/read"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0)
            .named("read-only fetch must not mark message as read")
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        let uid = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .store_rfc822(
                &scoped("test-uid", "INBOX"),
                uid,
                b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-1\r\n\r\nbody".to_vec(),
            )
            .await
            .unwrap();

        session.handle_line("a001 EXAMINE INBOX").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        assert!(session.selected_read_only);

        session.handle_line("a002 FETCH 1 (BODY[])").await.unwrap();
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("BODY[]"), "response={response}");
        assert!(
            response.contains("a002 OK FETCH completed"),
            "response={response}"
        );

        let flags = config
            .mailbox_view
            .get_flags(&scoped("test-uid", "INBOX"), uid)
            .await
            .unwrap();
        assert!(
            !flags.iter().any(|f| f == "\\Seen"),
            "flags were mutated in read-only mode: {flags:?}"
        );

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_examine_fetch_body_does_not_mark_read_with_gluon_mail_backend() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/read"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(0)
            .named("read-only gluon fetch must not mark message as read")
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        session.handle_line("a001 EXAMINE INBOX").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        assert!(session.selected_read_only);

        session.handle_line("a002 FETCH 1 (BODY[])").await.unwrap();
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("BODY[]"), "response={response}");
        assert!(
            response.contains("a002 OK FETCH completed"),
            "response={response}"
        );

        let flags = config
            .mailbox_view
            .get_flags(&scoped("test-uid", "INBOX"), iuid(1))
            .await
            .unwrap();
        assert!(
            !flags.iter().any(|f| f == "\\Seen"),
            "flags were mutated in read-only mode: {flags:?}"
        );

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_uid_fetch_flags_always_includes_uid() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();

        session
            .handle_line("a001 UID FETCH 1:* (FLAGS)")
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains(&format!("* 1 FETCH (UID {uid} FLAGS (")));
        assert!(response.contains("a001 OK FETCH completed"));
    }

    #[tokio::test]
    async fn test_uid_store_flags_response_includes_uid() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();

        session
            .handle_line("a001 UID STORE 1:* +FLAGS (\\Seen)")
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains(&format!("* 1 FETCH (UID {uid} FLAGS (")));
        assert!(response.contains("\\Seen"));
        assert!(response.contains("a001 OK STORE completed"));
    }

    #[tokio::test]
    async fn test_uid_store_flags_response_includes_uid_with_gluon_mail_backend() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-2",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-2\r\n\r\nbody",
        )
        .await;

        session
            .handle_line(&format!("a001 UID STORE {uid} +FLAGS (\\Seen)"))
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains(&format!("* 2 FETCH (UID {uid} FLAGS (")));
        assert!(response.contains("\\Seen"));
        assert!(response.contains("a001 OK STORE completed"));
        assert_eq!(
            config
                .mailbox_mutation
                .get_flags(&scoped("test-uid", "INBOX"), uid)
                .await
                .unwrap(),
            vec!["\\Seen".to_string()]
        );
    }

    #[tokio::test]
    async fn test_search_text_and_header_use_cached_rfc822() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .store_rfc822(
                &scoped("test-uid", "INBOX"),
                uid,
                b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-1\r\n\r\nsearch-hit-body"
                    .to_vec(),
            )
            .await
            .unwrap();

        session
            .handle_line("a001 SEARCH TEXT \"search-hit-body\"")
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* SEARCH 1"), "response={response}");
        assert!(
            response.contains("a001 OK SEARCH completed"),
            "response={response}"
        );

        session
            .handle_line("a002 SEARCH HEADER Subject \"Subject msg-1\"")
            .await
            .unwrap();
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* SEARCH 1"), "response={response}");
        assert!(
            response.contains("a002 OK SEARCH completed"),
            "response={response}"
        );
    }

    #[tokio::test]
    async fn test_search_text_and_header_use_gluon_mail_rfc822() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        session
            .handle_line("a001 SEARCH TEXT \"search-hit-body\"")
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* SEARCH 1"), "response={response}");
        assert!(
            response.contains("a001 OK SEARCH completed"),
            "response={response}"
        );

        session
            .handle_line("a002 SEARCH HEADER Subject \"Subject msg-1\"")
            .await
            .unwrap();
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* SEARCH 1"), "response={response}");
        assert!(
            response.contains("a002 OK SEARCH completed"),
            "response={response}"
        );
    }

    #[tokio::test]
    async fn test_search_text_and_header_use_gluon_mail_view() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        session
            .handle_line("a001 SEARCH TEXT \"body\"")
            .await
            .unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* SEARCH 1"), "response={response}");
        assert!(
            response.contains("a001 OK SEARCH completed"),
            "response={response}"
        );

        session
            .handle_line("a002 UID SEARCH HEADER Subject \"Subject msg-1\"")
            .await
            .unwrap();
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("* SEARCH 1"), "response={response}");
        assert!(
            response.contains("a002 OK SEARCH completed"),
            "response={response}"
        );
    }

    #[tokio::test]
    async fn test_select_warm_cache_skips_metadata_fetch() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .named("no metadata fetch on warm select")
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();

        session.handle_line("a001 SELECT INBOX").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("1 EXISTS"));
        assert!(response.contains("a001 OK [READ-WRITE] SELECT completed"));

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_select_warm_cache_skips_metadata_fetch_with_gluon_mail_backend() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .named("no metadata fetch on warm select with gluon backend")
            .mount(&server)
            .await;

        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());
        // client field removed; connector handles upstream calls

        session.handle_line("a001 SELECT INBOX").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("1 EXISTS"));
        assert!(response.contains("a001 OK [READ-WRITE] SELECT completed"));

        // server.verify() removed: upstream calls go through connector
    }

    #[tokio::test]
    async fn test_select_reports_first_unseen_sequence_and_permanentflags() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 0),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-2"),
                make_meta("msg-2", 1),
            )
            .await
            .unwrap();

        session.handle_line("a001 SELECT INBOX").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("2 EXISTS"));
        assert!(response.contains(
            "OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] Flags permitted"
        ));
        assert!(response.contains("OK [UNSEEN 2] First unseen"));
        assert!(response.contains("a001 OK [READ-WRITE] SELECT completed"));
    }

    #[tokio::test]
    async fn test_select_reports_first_unseen_sequence_and_permanentflags_with_gluon_mail_backend()
    {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .set_flags(
                &scoped("test-uid", "INBOX"),
                iuid(1),
                vec!["\\Seen".to_string()],
            )
            .await
            .unwrap();
        seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-2",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-2\r\n\r\nbody",
        )
        .await;

        session.handle_line("a001 SELECT INBOX").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("2 EXISTS"));
        assert!(response.contains(
            "OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] Flags permitted"
        ));
        assert!(response.contains("OK [UNSEEN 2] First unseen"));
        assert!(response.contains("a001 OK [READ-WRITE] SELECT completed"));
    }

    #[test]
    fn test_evaluate_search_all() {
        let meta = Some(make_meta("msg-1", 1));
        let flags = vec![];
        assert!(evaluate_search_key(
            &SearchKey::All,
            iuid(1),
            &meta,
            &flags,
            iuid(1),
            None
        ));
    }

    #[test]
    fn test_evaluate_search_seen() {
        let meta = Some(make_meta("msg-1", 0));
        let flags = vec!["\\Seen".to_string()];
        assert!(evaluate_search_key(
            &SearchKey::Seen,
            iuid(1),
            &meta,
            &flags,
            iuid(1),
            None
        ));
        assert!(!evaluate_search_key(
            &SearchKey::Unseen,
            iuid(1),
            &meta,
            &flags,
            iuid(1),
            None
        ));
    }

    #[test]
    fn test_evaluate_search_subject() {
        let meta = Some(make_meta("msg-1", 1));
        let flags = vec![];
        assert!(evaluate_search_key(
            &SearchKey::Subject("Subject".to_string()),
            iuid(1),
            &meta,
            &flags,
            iuid(1),
            None
        ));
        assert!(!evaluate_search_key(
            &SearchKey::Subject("NotFound".to_string()),
            iuid(1),
            &meta,
            &flags,
            iuid(1),
            None
        ));
    }

    #[test]
    fn test_evaluate_search_from() {
        let meta = Some(make_meta("msg-1", 1));
        let flags = vec![];
        assert!(evaluate_search_key(
            &SearchKey::From("alice".to_string()),
            iuid(1),
            &meta,
            &flags,
            iuid(1),
            None
        ));
    }

    #[test]
    fn test_evaluate_search_not() {
        let meta = Some(make_meta("msg-1", 1));
        let flags = vec![];
        assert!(!evaluate_search_key(
            &SearchKey::Not(Box::new(SearchKey::All)),
            iuid(1),
            &meta,
            &flags,
            iuid(1),
            None
        ));
    }

    #[test]
    fn test_format_copyuid() {
        assert_eq!(
            format_copyuid(
                1700000000,
                &[iuid(1), iuid(2), iuid(3)],
                &[iuid(10), iuid(11), iuid(12)]
            ),
            "COPYUID 1700000000 1,2,3 10,11,12"
        );
    }

    #[test]
    fn test_format_copyuid_single() {
        assert_eq!(
            format_copyuid(42, &[iuid(5)], &[iuid(100)]),
            "COPYUID 42 5 100"
        );
    }

    #[test]
    fn test_format_copyuid_empty() {
        assert_eq!(format_copyuid(42, &[], &[]), "COPYUID 42  ");
    }

    #[test]
    fn test_parse_rfc2822_date_basic() {
        // Mon, 14 Nov 2023 22:13:20 +0000
        let ts = parse_rfc2822_date("Mon, 14 Nov 2023 22:13:20 +0000");
        assert_eq!(ts, Some(1700000000));
    }

    #[test]
    fn test_parse_rfc2822_date_no_dow() {
        let ts = parse_rfc2822_date("14 Nov 2023 22:13:20 +0000");
        assert_eq!(ts, Some(1700000000));
    }

    #[test]
    fn test_parse_rfc2822_date_with_timezone() {
        // Same instant but expressed in UTC-5
        let ts = parse_rfc2822_date("Tue, 14 Nov 2023 17:13:20 -0500");
        assert_eq!(ts, Some(1700000000));
    }

    #[test]
    fn test_parse_rfc2822_date_invalid() {
        assert!(parse_rfc2822_date("not a date").is_none());
        assert!(parse_rfc2822_date("").is_none());
    }

    #[test]
    fn test_extract_sent_date() {
        let rfc822 = b"Date: Mon, 14 Nov 2023 22:13:20 +0000\r\nSubject: test\r\n\r\nbody";
        let ts = extract_sent_date(rfc822);
        assert_eq!(ts, Some(1700000000));
    }

    #[test]
    fn test_sent_search_uses_date_header() {
        let meta = Some(make_meta("msg-1", 0));
        let flags = vec![];
        // Meta time is 1700000000 but the Date header says a day earlier
        let rfc822 = b"Date: Mon, 13 Nov 2023 22:13:20 +0000\r\nSubject: test\r\n\r\nbody";
        let day_before_ts = 1700000000 - 86400; // 13 Nov

        // SENTON should match the Date header day, not meta.time
        assert!(evaluate_search_key(
            &SearchKey::SentOn(day_before_ts),
            iuid(1),
            &meta,
            &flags,
            iuid(1),
            Some(rfc822)
        ));
        // Should NOT match meta.time day
        assert!(!evaluate_search_key(
            &SearchKey::SentOn(1700000000),
            iuid(1),
            &meta,
            &flags,
            iuid(1),
            Some(rfc822)
        ));
    }

    #[test]
    fn test_sent_search_falls_back_to_meta_time() {
        let meta = Some(make_meta("msg-1", 0));
        let flags = vec![];
        // No RFC822 data available - should fall back to meta.time
        assert!(evaluate_search_key(
            &SearchKey::SentOn(1700000000),
            iuid(1),
            &meta,
            &flags,
            iuid(1),
            None
        ));
    }

    #[test]
    fn test_idle_timeout_is_30_minutes() {
        assert_eq!(IDLE_TIMEOUT, Duration::from_secs(30 * 60));
    }

    #[tokio::test]
    async fn test_idle_exits_on_done() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, mut client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        // Start IDLE in a spawned task, send DONE after reading continuation
        let handle = tokio::spawn(async move {
            session.handle_line("a001 IDLE").await.unwrap();
            session
        });

        // Read the continuation response
        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("+ idling"), "response={response}");

        // Send DONE to exit IDLE
        tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
            .await
            .unwrap();

        let _session = handle.await.unwrap();
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("a001 OK IDLE terminated"),
            "response={response}"
        );
    }

    #[tokio::test]
    async fn test_unselect_does_not_expunge() {
        let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = config
            .mailbox_mutation
            .store_metadata(
                &scoped("test-uid", "INBOX"),
                &pid("msg-1"),
                make_meta("msg-1", 1),
            )
            .await
            .unwrap();
        config
            .mailbox_mutation
            .add_flags(
                &scoped("test-uid", "INBOX"),
                uid,
                &["\\Deleted".to_string()],
            )
            .await
            .unwrap();

        session.handle_line("a001 UNSELECT").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("a001 OK UNSELECT completed"),
            "response={response}"
        );
        assert!(
            !response.contains("EXPUNGE"),
            "UNSELECT must not expunge: {response}"
        );

        assert_eq!(session.state, State::Authenticated);
        assert!(session.selected_mailbox.is_none());

        // Message should still exist in the store
        let uids = config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap();
        assert_eq!(uids.len(), 1, "message must not be expunged");
    }
}
