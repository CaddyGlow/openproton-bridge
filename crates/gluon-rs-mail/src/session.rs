use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info, warn};

use crate::command::{
    parse_command, Command, FetchItem, ImapFlag, SearchKey, SequenceSet, StatusDataItem,
    StoreAction,
};
use crate::gluon_connector::GluonImapConnector;
use crate::imap_store::{GluonMailboxMutation, GluonMailboxView};
use crate::imap_types::{ImapUid, ScopedMailboxId};
use crate::mailbox::{self as mailbox, GluonMailboxCatalog};
use crate::rfc822;

use crate::imap_error::ImapResult as Result;
use crate::response::ResponseWriter;

use crate::imap_store::ProtonMessageId;

/// RFC 2177 recommends servers terminate IDLE after 30 minutes.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, PartialEq)]
pub enum State {
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
    pub connector: Arc<dyn crate::imap_connector::ImapConnector>,
    pub gluon_connector: Arc<dyn GluonImapConnector>,
    pub mailbox_catalog: Arc<dyn GluonMailboxCatalog>,
    pub mailbox_mutation: Arc<dyn GluonMailboxMutation>,
    pub mailbox_view: Arc<dyn GluonMailboxView>,
    pub recent_tracker: Arc<RecentTracker>,
    pub shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
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
    pub state: State,
    pub config: Arc<SessionConfig>,
    pub selected_mailbox: Option<String>,
    pub selected_mailbox_mod_seq: Option<u64>,
    pub selected_mailbox_uids: Vec<ImapUid>,
    pub selected_mailbox_flags: HashMap<ImapUid, Vec<String>>,
    pub selected_mailbox_internal_id: Option<u64>,
    pub storage_user_id: Option<String>,
    pub selected_read_only: bool,
    pub authenticated_account_id: Option<String>,
    pub user_labels: Vec<mailbox::ResolvedMailbox>,
    pub starttls_available: bool,
    pub connection_id: u64,
    pub recent_uids: HashSet<ImapUid>,
    pub store_session: Option<crate::store::StoreSession>,
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

            // Check for shutdown signal alongside reading the next command
            if let Some(ref mut shutdown_rx) = self.config.shutdown_rx.clone() {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => {
                        self.writer.untagged("BYE server shutting down").await?;
                        return Ok(SessionAction::Close);
                    }
                    result = self.reader.read_line(&mut line) => {
                        let n = result?;
                        if n == 0 {
                            debug!(connection_id = self.connection_id, "client disconnected");
                            return Ok(SessionAction::Close);
                        }
                    }
                }
            } else {
                let n = self.reader.read_line(&mut line).await?;
                if n == 0 {
                    debug!(connection_id = self.connection_id, "client disconnected");
                    return Ok(SessionAction::Close);
                }
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
            Command::Rename {
                ref tag,
                ref source,
                ref dest,
            } => self.cmd_rename(tag, source, dest).await?,
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
            Command::Id {
                ref tag,
                ref params,
            } => self.cmd_id(tag, params).await?,
            Command::Authenticate {
                ref tag,
                ref mechanism,
                ref initial_response,
            } => {
                self.cmd_authenticate(tag, mechanism, initial_response.as_deref())
                    .await?
            }
        }

        Ok(SessionAction::Continue)
    }

    async fn cmd_capability(&mut self, tag: &str) -> Result<()> {
        let caps = if self.state == State::NotAuthenticated {
            if self.starttls_available {
                "CAPABILITY IMAP4rev1 STARTTLS IDLE UIDPLUS MOVE UNSELECT ID AUTH=PLAIN"
            } else {
                "CAPABILITY IMAP4rev1 IDLE UIDPLUS MOVE UNSELECT ID AUTH=PLAIN"
            }
        } else {
            "CAPABILITY IMAP4rev1 IDLE UIDPLUS MOVE UNSELECT ID"
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
        self.do_login(tag, username, password).await
    }

    async fn do_login(&mut self, tag: &str, username: &str, password: &str) -> Result<()> {
        let auth_result = match self.config.connector.authorize(username, password).await {
            Ok(r) => r,
            Err(crate::imap_error::ImapError::AuthFailed) => {
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

    async fn cmd_id(&mut self, tag: &str, params: &Option<Vec<(String, String)>>) -> Result<()> {
        if let Some(params) = params {
            for (key, value) in params {
                debug!(key = %key, value = %value, "IMAP client ID");
            }
        }
        self.writer
            .untagged("ID (\"name\" \"gluon-rs-mail\" \"version\" \"0.1.0\")")
            .await?;
        self.writer.tagged_ok(tag, None, "ID completed").await
    }

    async fn cmd_authenticate(
        &mut self,
        tag: &str,
        mechanism: &str,
        initial_response: Option<&str>,
    ) -> Result<()> {
        if self.state != State::NotAuthenticated {
            return self.writer.tagged_bad(tag, "already authenticated").await;
        }

        match mechanism.to_uppercase().as_str() {
            "PLAIN" => self.authenticate_plain(tag, initial_response).await,
            _ => {
                self.writer
                    .tagged_no(tag, "unsupported authentication mechanism")
                    .await
            }
        }
    }

    async fn authenticate_plain(
        &mut self,
        tag: &str,
        initial_response: Option<&str>,
    ) -> Result<()> {
        let encoded = if let Some(resp) = initial_response {
            resp.to_string()
        } else {
            self.writer.continuation("").await?;
            let mut line = String::new();
            self.reader.read_line(&mut line).await?;
            line.trim().to_string()
        };

        use base64::Engine;
        let decoded = match base64::engine::general_purpose::STANDARD.decode(&encoded) {
            Ok(d) => d,
            Err(_) => {
                return self
                    .writer
                    .tagged_no(tag, "[AUTHENTICATIONFAILED] invalid base64")
                    .await;
            }
        };

        // PLAIN format: authzid\0authcid\0password
        let parts: Vec<&[u8]> = decoded.splitn(3, |b| *b == 0).collect();
        if parts.len() != 3 {
            return self
                .writer
                .tagged_no(tag, "[AUTHENTICATIONFAILED] invalid PLAIN data")
                .await;
        }

        let username = String::from_utf8_lossy(parts[1]);
        let password = String::from_utf8_lossy(parts[2]);

        self.do_login(tag, &username, &password).await
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
            .ok_or_else(|| {
                crate::imap_error::ImapError::Protocol("no mailbox selected".to_string())
            })?;
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

            let mut all = self.all_mailboxes();
            // Merge store mailboxes (dynamically created via CREATE)
            if let Some(ref mut ss) = self.store_session {
                if let Ok(store_mbs) = ss.list_upstream_mailboxes() {
                    for mb in store_mbs {
                        if !all.iter().any(|m| m.name.eq_ignore_ascii_case(&mb.name)) {
                            all.push(mailbox::ResolvedMailbox {
                                name: mb.name.clone(),
                                label_id: mb.name,
                                special_use: None,
                                selectable: true,
                            });
                        }
                    }
                }
            }
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

            // Emit real mailboxes, filtering by visibility
            let account_id = self.authenticated_account_id.clone().unwrap_or_default();
            for mb in &all {
                if Self::matches_list_pattern(&mb.name, &full_pattern) {
                    let vis = self
                        .config
                        .connector
                        .get_mailbox_visibility(&account_id, &mb.label_id)
                        .await?;
                    match vis {
                        crate::imap_types::MailboxVisibility::Hidden => continue,
                        crate::imap_types::MailboxVisibility::HiddenIfEmpty => {
                            let scoped = self.scoped_mailbox_name(&mb.name);
                            let status = self.config.mailbox_view.mailbox_status(&scoped).await;
                            if status.map(|s| s.exists).unwrap_or(0) == 0 {
                                continue;
                            }
                        }
                        crate::imap_types::MailboxVisibility::Visible => {}
                    }
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
            let mut all = self.all_mailboxes();
            if let Some(ref mut ss) = self.store_session {
                if let Ok(store_mbs) = ss.list_upstream_mailboxes() {
                    for mb in store_mbs {
                        if !all.iter().any(|m| m.name.eq_ignore_ascii_case(&mb.name)) {
                            all.push(mailbox::ResolvedMailbox {
                                name: mb.name.clone(),
                                label_id: mb.name,
                                special_use: None,
                                selectable: true,
                            });
                        }
                    }
                }
            }
            for mb in all {
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

        // If mailbox already exists, delete and recreate for idempotent behavior.
        // imaptest expects CREATE to produce a fresh empty mailbox.
        if self.resolve_mailbox(mailbox_name).await.is_some() {
            if mailbox::find_mailbox(mailbox_name).is_some() {
                return self.writer.tagged_ok(tag, None, "CREATE completed").await;
            }
            let scoped = self.scoped_mailbox_name(mailbox_name);
            let _ = self
                .config
                .gluon_connector
                .delete_mailbox(&scoped, true)
                .await;
            self.user_labels.retain(|l| l.name != mailbox_name);
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

    async fn cmd_rename(&mut self, tag: &str, source: &str, dest: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        // Cannot rename system mailboxes (INBOX, etc.)
        if mailbox::find_mailbox(source).is_some() {
            return self
                .writer
                .tagged_no(tag, "[CANNOT] cannot rename system mailbox")
                .await;
        }

        // Verify source exists
        if self.resolve_mailbox(source).await.is_none() {
            return self
                .writer
                .tagged_no(tag, "source mailbox does not exist")
                .await;
        }

        // If dest exists, delete it first (allow overwrite for RENAME)
        if self.resolve_mailbox(dest).await.is_some() {
            if mailbox::find_mailbox(dest).is_some() {
                return self
                    .writer
                    .tagged_no(tag, "destination mailbox already exists")
                    .await;
            }
            let scoped_dest = self.scoped_mailbox_name(dest);
            let _ = self
                .config
                .gluon_connector
                .delete_mailbox(&scoped_dest, true)
                .await;
            self.user_labels.retain(|l| l.name != dest);
        }

        let scoped_source = self.scoped_mailbox_name(source);
        let scoped_dest = self.scoped_mailbox_name(dest);

        if let Err(e) = self
            .config
            .gluon_connector
            .rename_mailbox(&scoped_source, &scoped_dest)
            .await
        {
            return self
                .writer
                .tagged_no(tag, &format!("RENAME failed: {e}"))
                .await;
        }

        // Update session's user_labels: remove old, add new
        self.user_labels.retain(|l| l.name != source);
        self.user_labels.push(mailbox::ResolvedMailbox {
            name: dest.to_string(),
            label_id: dest.to_string(),
            special_use: None,
            selectable: true,
        });

        self.writer.tagged_ok(tag, None, "RENAME completed").await
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
                    attrs.push("RECENT 0".to_string());
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
            FetchItem::Rfc822
            | FetchItem::Rfc822Text
            | FetchItem::BodyStructure
            | FetchItem::Body
            | FetchItem::Envelope => true,
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
                                crate::metadata_parse::parse_metadata_from_rfc822(
                                    &scoped_mailbox,
                                    &message.summary,
                                    data,
                                )
                            });
                            Some(parsed.unwrap_or_else(|| {
                                crate::metadata_parse::fallback_metadata(&scoped_mailbox, &message)
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
                    FetchItem::Rfc822 => {
                        let full_data = rfc822_data.clone().unwrap_or_default();
                        let idx = parts.len();
                        parts.push(format!("RFC822 {{{}}}", full_data.len()));
                        part_literals.insert(idx, full_data);
                        // RFC822 (bare) implicitly sets \Seen
                        if !self.selected_read_only && !has_seen {
                            has_seen = true;
                        }
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
                            crate::imap_error::ImapError::Protocol(format!(
                                "store session flags: {e}"
                            ))
                        })?;
                    let had_seen = previous_flags.iter().any(|flag| flag == "\\Seen");
                    let had_flagged = previous_flags.iter().any(|flag| flag == "\\Flagged");

                    match action {
                        StoreAction::SetFlags | StoreAction::SetFlagsSilent => {
                            ss.set_message_flags(&internal_id, &flag_strings)
                                .map_err(|e| {
                                    crate::imap_error::ImapError::Protocol(format!(
                                        "store session set_flags: {e}"
                                    ))
                                })?;
                        }
                        StoreAction::AddFlags | StoreAction::AddFlagsSilent => {
                            ss.add_message_flags(&internal_id, &flag_strings)
                                .map_err(|e| {
                                    crate::imap_error::ImapError::Protocol(format!(
                                        "store session add_flags: {e}"
                                    ))
                                })?;
                        }
                        StoreAction::RemoveFlags | StoreAction::RemoveFlagsSilent => {
                            ss.remove_message_flags(&internal_id, &flag_strings)
                                .map_err(|e| {
                                    crate::imap_error::ImapError::Protocol(format!(
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
                                    crate::imap_error::ImapError::Protocol(format!(
                                        "store session flags: {e}"
                                    ))
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
                                crate::imap_error::ImapError::Protocol(format!(
                                    "store session flags: {e}"
                                ))
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
                .selected_mailbox_flags
                .get(&uid)
                .cloned()
                .unwrap_or_default();

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

            let max_seq = all_uids.len() as u32;
            let matches = criteria.iter().all(|c| {
                evaluate_search_key(
                    c,
                    uid,
                    seq,
                    max_seq,
                    &meta,
                    &flags,
                    max_uid,
                    rfc822_data.as_deref(),
                )
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

        // Use pinned session for proton_id lookups if available.
        let mailbox_internal_id = self.selected_mailbox_internal_id;
        let mut session = self.store_session.take();

        for (i, &uid) in all_uids.iter().enumerate() {
            if !deleted_uids.contains(&uid) {
                continue;
            }
            let seq = i as u32 + 1 - offset;

            // Sync upstream: permanently delete if in Trash or Spam, otherwise move to Trash.
            if let Some(ref account_id) = self.authenticated_account_id {
                let proton_id = if let (Some(ref mut sess), Some(mb_id)) =
                    (&mut session, mailbox_internal_id)
                {
                    sess.message_remote_id_by_uid(mb_id, uid.value())
                        .ok()
                        .flatten()
                } else {
                    mutation.get_proton_id(&scoped_mailbox, uid).await?
                };
                if let Some(proton_id) = proton_id {
                    let is_trash_or_spam = self
                        .resolve_mailbox(&mailbox)
                        .await
                        .map(|mb| {
                            mb.label_id == crate::well_known::TRASH_LABEL
                                || mb.label_id == crate::well_known::SPAM_LABEL
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

        // Batch remove using pinned session if available, else trait path.
        if let (Some(ref mut sess), Some(mb_id)) = (&mut session, mailbox_internal_id) {
            for &uid in &successfully_expunged_uids {
                if let Ok(Some(internal_id)) = sess.message_internal_id_by_uid(mb_id, uid.value()) {
                    let _ = sess.remove_message_from_mailbox(mb_id, &internal_id);
                }
            }
        } else {
            mutation
                .batch_remove_messages(&scoped_mailbox, &successfully_expunged_uids)
                .await?;
        }

        self.store_session = session;

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
                                mb.label_id == crate::well_known::TRASH_LABEL
                                    || mb.label_id == crate::well_known::SPAM_LABEL
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
        let import_flags =
            crate::well_known::MESSAGE_FLAG_RECEIVED | crate::well_known::MESSAGE_FLAG_IMPORTED;
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

        let meta = crate::imap_types::MessageEnvelope {
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

pub fn format_copyuid(uid_validity: u32, src_uids: &[ImapUid], dst_uids: &[ImapUid]) -> String {
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

pub fn expand_fetch_items(items: &[FetchItem]) -> Vec<FetchItem> {
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

pub fn evaluate_search_key(
    key: &SearchKey,
    uid: ImapUid,
    seq: u32,
    max_seq: u32,
    meta: &Option<crate::imap_types::MessageEnvelope>,
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
        SearchKey::From(s) => {
            let s_lower = s.to_lowercase();
            let meta_match = meta
                .as_ref()
                .map(|m| {
                    m.sender.address.to_lowercase().contains(&s_lower)
                        || m.sender.name.to_lowercase().contains(&s_lower)
                })
                .unwrap_or(false);
            meta_match
                || rfc822_data
                    .map(|d| {
                        let hdr = extract_header_section(d);
                        search_raw_header(&hdr, "from", &s_lower)
                    })
                    .unwrap_or(false)
        }
        SearchKey::To(s) => {
            let s_lower = s.to_lowercase();
            let meta_match = meta
                .as_ref()
                .map(|m| {
                    m.to_list.iter().any(|a| {
                        a.address.to_lowercase().contains(&s_lower)
                            || a.name.to_lowercase().contains(&s_lower)
                    })
                })
                .unwrap_or(false);
            meta_match
                || rfc822_data
                    .map(|d| {
                        let hdr = extract_header_section(d);
                        search_raw_header(&hdr, "to", &s_lower)
                    })
                    .unwrap_or(false)
        }
        SearchKey::Cc(s) => {
            let s_lower = s.to_lowercase();
            let meta_match = meta
                .as_ref()
                .map(|m| {
                    m.cc_list.iter().any(|a| {
                        a.address.to_lowercase().contains(&s_lower)
                            || a.name.to_lowercase().contains(&s_lower)
                    })
                })
                .unwrap_or(false);
            meta_match
                || rfc822_data
                    .map(|d| {
                        let hdr = extract_header_section(d);
                        search_raw_header(&hdr, "cc", &s_lower)
                    })
                    .unwrap_or(false)
        }
        SearchKey::Bcc(s) => {
            let s_lower = s.to_lowercase();
            let meta_match = meta
                .as_ref()
                .map(|m| {
                    m.bcc_list.iter().any(|a| {
                        a.address.to_lowercase().contains(&s_lower)
                            || a.name.to_lowercase().contains(&s_lower)
                    })
                })
                .unwrap_or(false);
            meta_match
                || rfc822_data
                    .map(|d| {
                        let hdr = extract_header_section(d);
                        search_raw_header(&hdr, "bcc", &s_lower)
                    })
                    .unwrap_or(false)
        }
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
        SearchKey::Uid(s) => s.contains(uid.value(), max_uid.value()),
        SearchKey::Sequence(s) => s.contains(seq, max_seq),
        SearchKey::Not(inner) => {
            !evaluate_search_key(inner, uid, seq, max_seq, meta, flags, max_uid, rfc822_data)
        }
        SearchKey::Or(a, b) => {
            evaluate_search_key(a, uid, seq, max_seq, meta, flags, max_uid, rfc822_data)
                || evaluate_search_key(b, uid, seq, max_seq, meta, flags, max_uid, rfc822_data)
        }
    }
}

pub fn search_key_needs_rfc822(key: &SearchKey) -> bool {
    match key {
        SearchKey::Header(_, _)
        | SearchKey::Body(_)
        | SearchKey::Text(_)
        | SearchKey::From(_)
        | SearchKey::To(_)
        | SearchKey::Cc(_)
        | SearchKey::Bcc(_)
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

/// Search raw header for a field containing a substring (case-insensitive).
/// Handles multi-line headers (continuation lines starting with whitespace).
pub fn search_raw_header(header: &str, field_name: &str, value_lower: &str) -> bool {
    let field_prefix = format!("{}:", field_name);
    let mut in_target_field = false;
    let mut full_value = String::new();

    for line in header.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line
            if in_target_field {
                full_value.push(' ');
                full_value.push_str(line.trim());
            }
            continue;
        }
        // New header line: check if previous collected value matches
        if in_target_field && full_value.to_lowercase().contains(value_lower) {
            return true;
        }
        in_target_field = false;
        full_value.clear();

        if line.to_lowercase().starts_with(&field_prefix) {
            in_target_field = true;
            full_value = line[field_prefix.len()..].trim().to_string();
        }
    }
    // Check last field
    if in_target_field && full_value.to_lowercase().contains(value_lower) {
        return true;
    }
    false
}

/// Extract the Date header from RFC822 data and parse it to a date-only
/// unix timestamp (start of day, ignoring time and timezone per RFC 3501 6.4.4).
///
/// For SENTBEFORE/SENTSINCE/SENTON, RFC 3501 says to disregard time and timezone
/// and compare only the date portion.
pub fn extract_sent_date(data: &[u8]) -> Option<i64> {
    let header = extract_header_section(data);
    let date_line = header
        .lines()
        .find(|l| l.to_lowercase().starts_with("date:"))?;
    let date_str = date_line.split_once(':')?.1.trim();
    parse_rfc2822_date_only(date_str)
}

/// Parse an RFC2822 date string, returning the start-of-day timestamp (ignoring time and
/// timezone). This is what RFC 3501 SENTBEFORE/SENTSINCE/SENTON require.
pub fn parse_rfc2822_date_only(s: &str) -> Option<i64> {
    let months = [
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
    ];

    // Strip optional day-of-week prefix (e.g., "Mon, ")
    let s = if let Some(pos) = s.find(',') {
        s[pos + 1..].trim()
    } else {
        s.trim()
    };

    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let day: u32 = parts[0].parse().ok()?;
    let month = months
        .iter()
        .position(|&m| m.eq_ignore_ascii_case(parts[1]))? as u32
        + 1;
    let year: i32 = parts[2].parse().ok()?;

    // Return start of day (00:00:00 UTC) for the given date, ignoring time and timezone
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

    Some(total_days * 86400)
}

pub fn parse_rfc2822_date(s: &str) -> Option<i64> {
    let months = [
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
    ];

    // Strip optional day-of-week prefix (e.g., "Mon, ")
    let s = if let Some(pos) = s.find(',') {
        s[pos + 1..].trim()
    } else {
        s.trim()
    };

    // Expected formats:
    //   "14 Nov 2023 22:13:20 +0000"   (RFC 2822)
    //   "14-Nov-2023 22:13:20 +0000"   (IMAP internal date-time)
    let parts: Vec<&str> = s.split_whitespace().collect();

    // Try to parse IMAP date-time format (DD-Mon-YYYY HH:MM:SS +ZZZZ)
    let (day, month, year, time_idx) = if parts.len() >= 2 && parts[0].contains('-') {
        let date_parts: Vec<&str> = parts[0].split('-').collect();
        if date_parts.len() != 3 {
            return None;
        }
        let d: u32 = date_parts[0].parse().ok()?;
        let m = months
            .iter()
            .position(|&mo| mo.eq_ignore_ascii_case(date_parts[1]))? as u32
            + 1;
        let y: i32 = date_parts[2].parse().ok()?;
        (d, m, y, 1usize)
    } else if parts.len() >= 4 {
        let d: u32 = parts[0].parse().ok()?;
        let m = months
            .iter()
            .position(|&mo| mo.eq_ignore_ascii_case(parts[1]))? as u32
            + 1;
        let y: i32 = parts[2].parse().ok()?;
        (d, m, y, 3usize)
    } else {
        return None;
    };

    if time_idx >= parts.len() {
        return None;
    }
    let time_parts: Vec<&str> = parts[time_idx].split(':').collect();
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
    let tz_idx = time_idx + 1;
    let tz_offset_secs: i64 = if parts.len() > tz_idx {
        let tz = parts[tz_idx];
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

pub fn parse_header_field_names(section: &str) -> Vec<String> {
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

pub fn body_section_is_header_only(section: Option<&str>) -> bool {
    let Some(section) = section else {
        return false;
    };
    let upper = section.trim().to_uppercase();
    // Only HEADER.FIELDS (specific fields) can be satisfied from metadata.
    // Bare "HEADER" needs the full RFC822 data to return all original headers.
    upper.starts_with("HEADER.FIELDS")
}

pub fn build_metadata_header_section(meta: &crate::imap_types::MessageEnvelope) -> String {
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

pub fn format_header_addresses(addrs: &[crate::imap_types::EmailAddress]) -> String {
    addrs
        .iter()
        .map(format_header_address)
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn format_header_address(addr: &crate::imap_types::EmailAddress) -> String {
    let address = sanitize_header_value(&addr.address);
    let name = sanitize_header_value(&addr.name);
    if name.trim().is_empty() {
        return address;
    }
    let escaped_name = name.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\" <{}>", escaped_name, address)
}

pub fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .map(|c| if c == '\r' || c == '\n' { ' ' } else { c })
        .collect()
}

pub fn filter_headers_by_fields(header_section: &str, fields: &[String]) -> String {
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

pub fn extract_text_section(data: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(data);
    if let Some(pos) = s.find("\r\n\r\n") {
        data[pos + 4..].to_vec()
    } else if let Some(pos) = s.find("\n\n") {
        data[pos + 2..].to_vec()
    } else {
        data.to_vec()
    }
}

pub fn format_mailbox_name(name: &str) -> String {
    if name.contains(' ') || name.contains('"') || name.contains('\\') || name.is_empty() {
        format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        name.to_string()
    }
}

pub fn parse_append_address(value: &str) -> crate::imap_types::EmailAddress {
    let value = value.trim();
    if let Some(lt) = value.find('<') {
        let name = value[..lt].trim().trim_matches('"').to_string();
        let addr = value[lt + 1..].trim_end_matches('>').trim().to_string();
        crate::imap_types::EmailAddress {
            name,
            address: addr,
        }
    } else {
        crate::imap_types::EmailAddress {
            name: String::new(),
            address: value.to_string(),
        }
    }
}

pub fn parse_address_list_header(value: &str) -> Vec<crate::imap_types::EmailAddress> {
    value
        .split(',')
        .map(|s| parse_append_address(s.trim()))
        .filter(|a| !a.address.is_empty())
        .collect()
}

pub fn extract_header_section(data: &[u8]) -> String {
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
pub async fn resolve_mailbox_internal_id(
    session: &mut crate::store::StoreSession,
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
pub async fn select_data_from_session(
    session: &mut crate::store::StoreSession,
    mailbox_internal_id: u64,
) -> Result<crate::imap_store::SelectMailboxData> {
    use crate::imap_store::{MailboxSnapshot, MailboxStatus, SelectMailboxData};

    let select = session
        .mailbox_select_data(mailbox_internal_id)
        .map_err(|e| {
            crate::imap_error::ImapError::Protocol(format!("store session select: {e}"))
        })?;

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
