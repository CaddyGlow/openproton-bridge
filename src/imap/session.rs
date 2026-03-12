use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use crate::api::client::ProtonClient;
use crate::api::error::is_auth_error;
use crate::api::messages;
use crate::api::types::{self, MessageFilter};
use crate::bridge::accounts::{AccountRuntimeError, RuntimeAccountRegistry, RuntimeAuthMaterial};
use crate::bridge::auth_router::AuthRouter;
use crate::crypto::encrypt as crypto_encrypt;
use crate::crypto::keys::{self, Keyring};

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
use super::store::MessageStore;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MutationMode {
    #[default]
    Compat,
    Strict,
}

pub struct SessionConfig {
    pub api_base_url: String,
    pub auth_router: AuthRouter,
    pub runtime_accounts: Arc<RuntimeAccountRegistry>,
    pub store: Arc<dyn MessageStore>,
    pub gluon_connector: Arc<dyn GluonImapConnector>,
    pub mailbox_catalog: Arc<dyn GluonMailboxCatalog>,
    pub mailbox_mutation: Arc<dyn GluonMailboxMutation>,
    pub mailbox_view: Arc<dyn GluonMailboxView>,
    pub mutation_mode: MutationMode,
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
    client: Option<ProtonClient>,
    user_keyring: Option<Keyring>,
    addr_keyrings: Option<HashMap<String, Keyring>>,
    primary_address_id: Option<String>,
    selected_mailbox: Option<String>,
    selected_mailbox_mod_seq: Option<u64>,
    selected_mailbox_uids: Vec<u32>,
    selected_mailbox_flags: HashMap<u32, Vec<String>>,
    selected_read_only: bool,
    authenticated_account_id: Option<String>,
    user_labels: Vec<mailbox::ResolvedMailbox>,
    starttls_available: bool,
    connection_id: u64,
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
            client: None,
            user_keyring: None,
            addr_keyrings: None,
            primary_address_id: None,
            selected_mailbox: None,
            selected_mailbox_mod_seq: None,
            selected_mailbox_uids: Vec::new(),
            selected_mailbox_flags: HashMap::new(),
            selected_read_only: false,
            authenticated_account_id: None,
            user_labels: Vec::new(),
            starttls_available,
            connection_id: NEXT_IMAP_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
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

        let auth_route = match self.config.auth_router.resolve_login(username, password) {
            Some(route) => route,
            None => {
                return self
                    .writer
                    .tagged_no(tag, "[AUTHENTICATIONFAILED] invalid credentials")
                    .await;
            }
        };
        let mut account_session = match self
            .config
            .runtime_accounts
            .with_valid_access_token(&auth_route.account_id)
            .await
        {
            Ok(session) => session,
            Err(AccountRuntimeError::AccountUnavailable(_)) => {
                warn!(
                    account_id = %auth_route.account_id.0,
                    "account unavailable during IMAP login"
                );
                return self
                    .writer
                    .tagged_no(tag, "[AUTHENTICATIONFAILED] invalid credentials")
                    .await;
            }
            Err(e) => {
                warn!(
                    account_id = %auth_route.account_id.0,
                    error = %e,
                    "failed to load account session"
                );
                return self
                    .writer
                    .tagged_no(tag, "failed to load account session")
                    .await;
            }
        };

        // Create authenticated ProtonClient
        let mut client = match ProtonClient::authenticated_with_mode(
            account_session.api_mode.base_url(),
            account_session.api_mode,
            &account_session.uid,
            &account_session.access_token,
        ) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "failed to create ProtonClient");
                return self
                    .writer
                    .tagged_no(tag, "internal error creating client")
                    .await;
            }
        };

        // Unlock keys
        let passphrase_b64 = match &account_session.key_passphrase {
            Some(p) => p.clone(),
            None => {
                return self
                    .writer
                    .tagged_no(tag, "no key passphrase in session")
                    .await;
            }
        };

        let mut passphrase = match base64::engine::general_purpose::STANDARD.decode(&passphrase_b64)
        {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "invalid key passphrase encoding");
                return self.writer.tagged_no(tag, "invalid key passphrase").await;
            }
        };

        let auth_material = if let Some(material) = self
            .config
            .runtime_accounts
            .get_auth_material(&auth_route.account_id)
            .await
        {
            material
        } else {
            let user_resp = match crate::api::users::get_user(&client).await {
                Ok(r) => r,
                Err(e) if is_auth_error(&e) => {
                    let refreshed = match self
                        .config
                        .runtime_accounts
                        .refresh_session_if_stale(
                            &auth_route.account_id,
                            Some(&account_session.access_token),
                        )
                        .await
                    {
                        Ok(session) => session,
                        Err(refresh_err) => {
                            passphrase.zeroize();
                            warn!(
                                account_id = %auth_route.account_id.0,
                                error = %refresh_err,
                                "token refresh failed during IMAP login"
                            );
                            return self
                                .writer
                                .tagged_no(tag, "failed to refresh account token")
                                .await;
                        }
                    };
                    account_session = refreshed;
                    client = match ProtonClient::authenticated_with_mode(
                        account_session.api_mode.base_url(),
                        account_session.api_mode,
                        &account_session.uid,
                        &account_session.access_token,
                    ) {
                        Ok(c) => c,
                        Err(err) => {
                            passphrase.zeroize();
                            warn!(error = %err, "failed to recreate ProtonClient after refresh");
                            return self
                                .writer
                                .tagged_no(tag, "internal error creating client")
                                .await;
                        }
                    };

                    match crate::api::users::get_user(&client).await {
                        Ok(r) => r,
                        Err(err) => {
                            passphrase.zeroize();
                            warn!(error = %err, "failed to fetch user info after refresh");
                            return self
                                .writer
                                .tagged_no(tag, "failed to fetch user info")
                                .await;
                        }
                    }
                }
                Err(e) => {
                    passphrase.zeroize();
                    warn!(error = %e, "failed to fetch user info");
                    return self
                        .writer
                        .tagged_no(tag, "failed to fetch user info")
                        .await;
                }
            };

            let addr_resp = match crate::api::users::get_addresses(&client).await {
                Ok(r) => r,
                Err(e) if is_auth_error(&e) => {
                    let refreshed = match self
                        .config
                        .runtime_accounts
                        .refresh_session_if_stale(
                            &auth_route.account_id,
                            Some(&account_session.access_token),
                        )
                        .await
                    {
                        Ok(session) => session,
                        Err(refresh_err) => {
                            passphrase.zeroize();
                            warn!(
                                account_id = %auth_route.account_id.0,
                                error = %refresh_err,
                                "token refresh failed while fetching addresses"
                            );
                            return self
                                .writer
                                .tagged_no(tag, "failed to refresh account token")
                                .await;
                        }
                    };
                    account_session = refreshed;
                    client = match ProtonClient::authenticated_with_mode(
                        account_session.api_mode.base_url(),
                        account_session.api_mode,
                        &account_session.uid,
                        &account_session.access_token,
                    ) {
                        Ok(c) => c,
                        Err(err) => {
                            passphrase.zeroize();
                            warn!(error = %err, "failed to recreate ProtonClient after refresh");
                            return self
                                .writer
                                .tagged_no(tag, "internal error creating client")
                                .await;
                        }
                    };
                    match crate::api::users::get_addresses(&client).await {
                        Ok(r) => r,
                        Err(err) => {
                            passphrase.zeroize();
                            warn!(error = %err, "failed to fetch addresses after refresh");
                            return self
                                .writer
                                .tagged_no(tag, "failed to fetch addresses")
                                .await;
                        }
                    }
                }
                Err(e) => {
                    passphrase.zeroize();
                    warn!(error = %e, "failed to fetch addresses");
                    return self
                        .writer
                        .tagged_no(tag, "failed to fetch addresses")
                        .await;
                }
            };

            let material = Arc::new(RuntimeAuthMaterial {
                user_keys: user_resp.user.keys,
                addresses: addr_resp.addresses,
            });
            let _ = self
                .config
                .runtime_accounts
                .set_auth_material(&auth_route.account_id, material.clone())
                .await;
            material
        };

        let user_keyring = match keys::unlock_user_keys(&auth_material.user_keys, &passphrase) {
            Ok(kr) => kr,
            Err(e) => {
                passphrase.zeroize();
                warn!(error = %e, "failed to unlock user keys");
                return self
                    .writer
                    .tagged_no(tag, "failed to unlock user keys")
                    .await;
            }
        };

        let mut addr_keyrings = HashMap::new();
        for addr in &auth_material.addresses {
            if addr.status != 1 || addr.keys.is_empty() {
                continue;
            }
            match keys::unlock_address_keys(&addr.keys, &passphrase, &user_keyring) {
                Ok(kr) => {
                    addr_keyrings.insert(addr.id.clone(), kr);
                }
                Err(e) => {
                    warn!(address = %addr.email, error = %e, "could not unlock address keys");
                }
            }
        }

        passphrase.zeroize();

        if addr_keyrings.is_empty() {
            return self
                .writer
                .tagged_no(tag, "could not unlock any address keys")
                .await;
        }

        // Fetch user labels/folders (best-effort; failure doesn't block login)
        match messages::get_labels(
            &client,
            &[types::LABEL_TYPE_LABEL, types::LABEL_TYPE_FOLDER],
        )
        .await
        {
            Ok(resp) => {
                let labels = mailbox::labels_to_mailboxes(&resp.labels);
                info!(user_labels = labels.len(), "loaded user labels/folders");
                // Store in shared per-account registry so event worker and other
                // sessions for this account see the same labels.
                self.config.runtime_accounts.set_user_labels(
                    &crate::bridge::types::AccountId(auth_route.account_id.0.clone()),
                    labels.clone(),
                );
                self.user_labels = labels;
            }
            Err(e) => {
                warn!(error = %e, "failed to fetch user labels; continuing with system mailboxes only");
            }
        }

        // Determine primary address: lowest order among enabled addresses with keys
        let primary_addr_id = auth_material
            .addresses
            .iter()
            .filter(|a| a.status == 1 && addr_keyrings.contains_key(&a.id))
            .min_by_key(|a| a.order)
            .map(|a| a.id.clone());

        self.client = Some(client);
        self.user_keyring = Some(user_keyring);
        self.addr_keyrings = Some(addr_keyrings);
        self.primary_address_id = primary_addr_id;
        self.authenticated_account_id = Some(auth_route.account_id.0.clone());
        self.state = State::Authenticated;

        info!(
            service = "imap",
            msg = "IMAP login successful",
            connection_id = self.connection_id,
            email = %auth_route.primary_email,
            "IMAP login successful"
        );
        self.writer.tagged_ok(tag, None, "LOGIN completed").await
    }

    async fn cmd_logout(&mut self, tag: &str) -> Result<()> {
        self.writer.untagged("BYE server logging out").await?;
        self.state = State::Logout;
        self.authenticated_account_id = None;
        self.selected_mailbox = None;
        self.selected_mailbox_mod_seq = None;
        self.selected_mailbox_uids.clear();
        self.selected_mailbox_flags.clear();
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

    fn scoped_mailbox_name(&self, mailbox: &str) -> String {
        match &self.authenticated_account_id {
            Some(account_id) => format!("{account_id}::{mailbox}"),
            None => mailbox.to_string(),
        }
    }

    fn strict_mutation_mode(&self) -> bool {
        self.config.mutation_mode == MutationMode::Strict
    }

    fn resolve_mailbox(&self, name: &str) -> Option<mailbox::ResolvedMailbox> {
        self.config.mailbox_catalog.resolve_mailbox(
            self.authenticated_account_id.as_deref(),
            &self.user_labels,
            name,
        )
    }

    fn all_mailboxes(&self) -> Vec<mailbox::ResolvedMailbox> {
        self.config
            .mailbox_catalog
            .all_mailboxes(self.authenticated_account_id.as_deref(), &self.user_labels)
    }

    fn resolve_target_uids(
        &self,
        all_uids: &[u32],
        sequence: &SequenceSet,
        uid_mode: bool,
    ) -> Vec<u32> {
        if all_uids.is_empty() {
            return Vec::new();
        }

        let max_uid = *all_uids.last().unwrap_or(&0);
        let max_seq = all_uids.len() as u32;

        if uid_mode {
            all_uids
                .iter()
                .filter(|&&uid| sequence.contains(uid, max_uid))
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
        source_mailbox: &str,
        dest_mailbox: &str,
        source_uid: u32,
    ) -> Result<Option<u32>> {
        let mutation = self.config.mailbox_mutation.clone();
        let Some(proton_id) = mutation.get_proton_id(source_mailbox, source_uid).await? else {
            return Ok(None);
        };
        let Some(metadata) = mutation.get_metadata(source_mailbox, source_uid).await? else {
            return Ok(None);
        };

        let dest_uid = mutation
            .store_metadata(dest_mailbox, &proton_id, metadata)
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

    async fn emit_selected_mailbox_exists_update(&mut self) -> Result<()> {
        if self.state != State::Selected {
            return Ok(());
        }
        let Some(mailbox) = self.selected_mailbox.clone() else {
            return Ok(());
        };

        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let snapshot = self
            .config
            .mailbox_view
            .mailbox_snapshot(&scoped_mailbox)
            .await?;
        let previous_mod_seq = self.selected_mailbox_mod_seq.unwrap_or(0);
        let previous_exists = self.selected_mailbox_uids.len() as u32;
        let current_uids = self.config.mailbox_view.list_uids(&scoped_mailbox).await?;
        let mut current_flags: HashMap<u32, Vec<String>> = HashMap::new();
        for uid in &current_uids {
            current_flags.insert(
                *uid,
                self.config
                    .mailbox_view
                    .get_flags(&scoped_mailbox, *uid)
                    .await?,
            );
        }
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
                let current_uid_set: HashSet<u32> = current_uids.iter().copied().collect();
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
        if pattern == "*" {
            return true;
        }
        if pattern == "%" {
            // "%" matches one level -- exclude names containing "/"
            return !name.contains('/');
        }
        name.eq_ignore_ascii_case(pattern)
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

    async fn cmd_list(&mut self, tag: &str, _reference: &str, pattern: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        if pattern.is_empty() {
            self.writer.untagged("LIST (\\Noselect) \"/\" \"\"").await?;
        } else {
            for mb in self.all_mailboxes() {
                if Self::matches_list_pattern(&mb.name, pattern) {
                    self.writer
                        .untagged(&Self::format_list_entry("LIST", &mb))
                        .await?;
                }
            }
        }

        self.writer.tagged_ok(tag, None, "LIST completed").await
    }

    async fn cmd_lsub(&mut self, tag: &str, _reference: &str, pattern: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        if pattern.is_empty() {
            self.writer.untagged("LSUB (\\Noselect) \"/\" \"\"").await?;
        } else {
            for mb in self.all_mailboxes() {
                if Self::matches_list_pattern(&mb.name, pattern) {
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

        // Check if mailbox already exists
        if self.resolve_mailbox(mailbox_name).is_some() {
            return self
                .writer
                .tagged_no(tag, "[ALREADYEXISTS] mailbox already exists")
                .await;
        }

        // Custom mailbox creation is not supported - return NO with CANNOT
        self.writer
            .tagged_no(tag, "[CANNOT] custom mailbox creation not supported")
            .await
    }

    async fn cmd_subscribe(&mut self, tag: &str, mailbox_name: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        // Check if mailbox exists - if so, silently succeed (all mailboxes are subscribed)
        if self.resolve_mailbox(mailbox_name).is_some() {
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
        if self.resolve_mailbox(mailbox_name).is_some() {
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

        let mb = match self.resolve_mailbox(mailbox_name) {
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
            let client = self.client.as_ref().unwrap();

            // Fetch metadata from Proton API
            let filter = MessageFilter {
                label_id: Some(mb.label_id.clone()),
                desc: 1,
                ..Default::default()
            };

            let mut page = 0;
            let mut loaded = 0usize;
            loop {
                let meta_resp =
                    match messages::get_message_metadata(client, &filter, page, 150).await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!(error = %e, page, "failed to fetch message metadata");
                            return self.writer.tagged_no(tag, "failed to fetch messages").await;
                        }
                    };

                if meta_resp.messages.is_empty() {
                    break;
                }

                // Populate store with message metadata
                for meta in &meta_resp.messages {
                    mutation
                        .store_metadata(&scoped_mailbox, &meta.id, meta.clone())
                        .await?;
                }

                loaded = loaded.saturating_add(meta_resp.messages.len());
                let total = usize::try_from(meta_resp.total.max(0)).unwrap_or(usize::MAX);
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

        let status = mutation.mailbox_status(&scoped_mailbox).await?;
        let snapshot = self
            .config
            .mailbox_view
            .mailbox_snapshot(&scoped_mailbox)
            .await?;
        let selected_uids = self.config.mailbox_view.list_uids(&scoped_mailbox).await?;
        let first_unseen_seq = {
            let mut first = None;
            for (index, uid) in selected_uids.iter().enumerate() {
                let flags = self
                    .config
                    .mailbox_view
                    .get_flags(&scoped_mailbox, *uid)
                    .await?;
                if !flags.iter().any(|flag| flag == "\\Seen") {
                    first = Some(index as u32 + 1);
                    break;
                }
            }
            first
        };

        self.writer
            .untagged(&format!("{} EXISTS", status.exists))
            .await?;
        self.writer.untagged("0 RECENT").await?;
        self.writer
            .untagged("FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)")
            .await?;
        self.writer
            .untagged("OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)]")
            .await?;
        self.writer
            .untagged(&format!("OK [UIDVALIDITY {}]", status.uid_validity))
            .await?;
        self.writer
            .untagged(&format!("OK [UIDNEXT {}]", status.next_uid))
            .await?;
        if let Some(first_unseen_seq) = first_unseen_seq {
            self.writer
                .untagged(&format!("OK [UNSEEN {}]", first_unseen_seq))
                .await?;
        }

        self.selected_mailbox = Some(mb.name.to_string());
        self.selected_mailbox_mod_seq = Some(snapshot.mod_seq);
        self.selected_mailbox_uids = selected_uids.clone();
        self.selected_mailbox_flags.clear();
        for uid in &selected_uids {
            self.selected_mailbox_flags.insert(
                *uid,
                self.config
                    .mailbox_view
                    .get_flags(&scoped_mailbox, *uid)
                    .await?,
            );
        }
        self.selected_read_only = false;
        self.state = State::Selected;

        info!(
            service = "imap",
            msg = "mailbox selected",
            mailbox = %mb.name,
            messages = status.exists,
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

        let mb = match self.resolve_mailbox(mailbox_name) {
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
                StatusDataItem::Recent => attrs.push("RECENT 0".to_string()),
                StatusDataItem::UidNext => attrs.push(format!("UIDNEXT {}", status.next_uid)),
                StatusDataItem::UidValidity => {
                    attrs.push(format!("UIDVALIDITY {}", status.uid_validity))
                }
                StatusDataItem::Unseen => attrs.push(format!("UNSEEN {}", status.unseen)),
            }
        }

        self.writer
            .untagged(&format!("STATUS \"{}\" ({})", mb.name, attrs.join(" ")))
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

        let mb = match self.resolve_mailbox(mailbox_name) {
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
            let client = self.client.as_ref().unwrap();

            let filter = MessageFilter {
                label_id: Some(mb.label_id.clone()),
                desc: 1,
                ..Default::default()
            };

            let mut page = 0;
            let mut loaded = 0usize;
            loop {
                let meta_resp =
                    match messages::get_message_metadata(client, &filter, page, 150).await {
                        Ok(r) => r,
                        Err(e) => {
                            warn!(error = %e, page, "failed to fetch message metadata");
                            return self.writer.tagged_no(tag, "failed to fetch messages").await;
                        }
                    };

                if meta_resp.messages.is_empty() {
                    break;
                }

                for meta in &meta_resp.messages {
                    mutation
                        .store_metadata(&scoped_mailbox, &meta.id, meta.clone())
                        .await?;
                }

                loaded = loaded.saturating_add(meta_resp.messages.len());
                let total = usize::try_from(meta_resp.total.max(0)).unwrap_or(usize::MAX);
                if loaded >= total {
                    break;
                }
                page += 1;
            }
        }

        let status = mutation.mailbox_status(&scoped_mailbox).await?;
        let snapshot = self
            .config
            .mailbox_view
            .mailbox_snapshot(&scoped_mailbox)
            .await?;
        let selected_uids = self.config.mailbox_view.list_uids(&scoped_mailbox).await?;
        let first_unseen_seq = {
            let mut first = None;
            for (index, uid) in selected_uids.iter().enumerate() {
                let flags = self
                    .config
                    .mailbox_view
                    .get_flags(&scoped_mailbox, *uid)
                    .await?;
                if !flags.iter().any(|flag| flag == "\\Seen") {
                    first = Some(index as u32 + 1);
                    break;
                }
            }
            first
        };

        self.writer
            .untagged(&format!("{} EXISTS", status.exists))
            .await?;
        self.writer.untagged("0 RECENT").await?;
        self.writer
            .untagged("FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)")
            .await?;
        self.writer
            .untagged(&format!("OK [UIDVALIDITY {}]", status.uid_validity))
            .await?;
        self.writer
            .untagged(&format!("OK [UIDNEXT {}]", status.next_uid))
            .await?;
        if let Some(first_unseen_seq) = first_unseen_seq {
            self.writer
                .untagged(&format!("OK [UNSEEN {}]", first_unseen_seq))
                .await?;
        }

        self.selected_mailbox = Some(mb.name.to_string());
        self.selected_mailbox_mod_seq = Some(snapshot.mod_seq);
        self.selected_mailbox_uids = selected_uids.clone();
        self.selected_mailbox_flags.clear();
        for uid in &selected_uids {
            self.selected_mailbox_flags.insert(
                *uid,
                self.config
                    .mailbox_view
                    .get_flags(&scoped_mailbox, *uid)
                    .await?,
            );
        }
        self.selected_read_only = true;
        self.state = State::Selected;

        info!(
            service = "imap",
            msg = "mailbox examined (read-only)",
            mailbox = %mb.name,
            messages = status.exists,
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

        let mailbox = self.selected_mailbox.as_ref().unwrap().clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let mailbox_view = self.config.mailbox_view.clone();
        let all_uids = self.config.mailbox_view.list_uids(&scoped_mailbox).await?;

        if all_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "FETCH completed").await;
        }

        let max_uid = *all_uids.last().unwrap();
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
            _ => false,
        });

        // Resolve which messages to fetch from current mailbox snapshot.
        let target_messages: Vec<(u32, u32)> = if uid_mode {
            all_uids
                .iter()
                .enumerate()
                .filter(|(_, &uid)| sequence.contains(uid, max_uid))
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

        for (uid, seq) in target_messages {
            let meta = mailbox_view.get_metadata(&scoped_mailbox, uid).await?;
            let flags = mailbox_view.get_flags(&scoped_mailbox, uid).await?;
            let mut has_seen = flags.iter().any(|flag| flag == &seen_flag);

            if needs_body_sections {
                if let Some(ref meta) = meta {
                    debug!(
                        pkg = "gluon/state/mailbox",
                        UID = uid,
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
            let needs_rfc822_load =
                (needs_body_sections && !header_only_body_fetch) || needs_full_rfc822;
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
                                // Mark as read on API
                                if let Some(ref meta) = meta {
                                    if let Some(ref client) = self.client {
                                        if let Err(err) = messages::mark_messages_read(
                                            client,
                                            &[meta.id.as_str()],
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
        mailbox: &str,
        uid: u32,
        proton_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        let mut client = match &self.client {
            Some(c) => c.clone(),
            None => return Ok(None),
        };

        let msg_resp = match messages::get_message(&client, proton_id).await {
            Ok(r) => r,
            Err(e) if is_auth_error(&e) => {
                let Some(account_id) = self
                    .authenticated_account_id
                    .as_ref()
                    .map(|id| crate::bridge::types::AccountId(id.clone()))
                else {
                    warn!(proton_id = %proton_id, error = %e, "auth error without authenticated account");
                    return Ok(None);
                };
                let refreshed = match self
                    .config
                    .runtime_accounts
                    .refresh_session(&account_id)
                    .await
                {
                    Ok(session) => session,
                    Err(refresh_err) => {
                        warn!(
                            account_id = %account_id.0,
                            proton_id = %proton_id,
                            error = %refresh_err,
                            "failed to refresh account token while fetching message"
                        );
                        return Ok(None);
                    }
                };
                client = match ProtonClient::authenticated_with_mode(
                    refreshed.api_mode.base_url(),
                    refreshed.api_mode,
                    &refreshed.uid,
                    &refreshed.access_token,
                ) {
                    Ok(c) => c,
                    Err(err) => {
                        warn!(proton_id = %proton_id, error = %err, "failed to recreate ProtonClient after refresh");
                        return Ok(None);
                    }
                };
                self.client = Some(client.clone());
                match messages::get_message(&client, proton_id).await {
                    Ok(r) => r,
                    Err(err) => {
                        warn!(
                            proton_id = %proton_id,
                            error = %err,
                            "failed to fetch message after token refresh"
                        );
                        return Ok(None);
                    }
                }
            }
            Err(e) => {
                warn!(proton_id = %proton_id, error = %e, "failed to fetch message");
                return Ok(None);
            }
        };
        let msg = &msg_resp.message;

        // Find the right keyring for this message's address
        let keyring = match &self.addr_keyrings {
            Some(c) => c,
            None => return Ok(None),
        };
        let keyring = match keyring.get(&msg.metadata.address_id) {
            Some(kr) => kr,
            None => {
                warn!(
                    address_id = %msg.metadata.address_id,
                    "no keyring for address"
                );
                return Ok(None);
            }
        };

        let data = match rfc822::build_rfc822(&client, keyring, msg).await {
            Ok(d) => d,
            Err(e) => {
                warn!(proton_id = %proton_id, error = %e, "failed to build RFC822");
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

        let mailbox = self.selected_mailbox.as_ref().unwrap().clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let mutation = &self.config.mailbox_mutation;
        let all_uids = self.config.mailbox_view.list_uids(&scoped_mailbox).await?;

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

        for &uid in &target_uids {
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

            // Sync flag changes to Proton API
            if let Some(ref client) = self.client {
                if let Some(proton_id) = mutation.get_proton_id(&scoped_mailbox, uid).await? {
                    let id_ref = proton_id.as_str();
                    let current_flags = mutation.get_flags(&scoped_mailbox, uid).await?;
                    let has_seen = current_flags.iter().any(|flag| flag == "\\Seen");
                    let has_flagged = current_flags.iter().any(|flag| flag == "\\Flagged");

                    if had_seen != has_seen {
                        if has_seen {
                            if let Err(err) = messages::mark_messages_read(client, &[id_ref]).await
                            {
                                warn!(
                                    error = %err,
                                    mailbox = %mailbox,
                                    uid,
                                    proton_id = %proton_id,
                                    "failed to sync seen flag upstream"
                                );
                                if self.strict_mutation_mode() {
                                    return self
                                        .writer
                                        .tagged_no(tag, "STORE failed: upstream mutation failed")
                                        .await;
                                }
                            }
                        } else {
                            if let Err(err) =
                                messages::mark_messages_unread(client, &[id_ref]).await
                            {
                                warn!(
                                    error = %err,
                                    mailbox = %mailbox,
                                    uid,
                                    proton_id = %proton_id,
                                    "failed to sync unseen flag upstream"
                                );
                                if self.strict_mutation_mode() {
                                    return self
                                        .writer
                                        .tagged_no(tag, "STORE failed: upstream mutation failed")
                                        .await;
                                }
                            }
                        }
                    }

                    // \Answered is stored locally but not synced upstream. The Proton
                    // API has no endpoint for toggling the replied flag on existing
                    // messages. The Go bridge also omits this in its STORE handler.

                    if had_flagged != has_flagged {
                        if has_flagged {
                            if let Err(err) =
                                messages::label_messages(client, &[id_ref], types::STARRED_LABEL)
                                    .await
                            {
                                warn!(
                                    error = %err,
                                    mailbox = %mailbox,
                                    uid,
                                    proton_id = %proton_id,
                                    "failed to sync flagged state upstream"
                                );
                                if self.strict_mutation_mode() {
                                    return self
                                        .writer
                                        .tagged_no(tag, "STORE failed: upstream mutation failed")
                                        .await;
                                }
                            }
                        } else {
                            if let Err(err) =
                                messages::unlabel_messages(client, &[id_ref], types::STARRED_LABEL)
                                    .await
                            {
                                warn!(
                                    error = %err,
                                    mailbox = %mailbox,
                                    uid,
                                    proton_id = %proton_id,
                                    "failed to sync unflagged state upstream"
                                );
                                if self.strict_mutation_mode() {
                                    return self
                                        .writer
                                        .tagged_no(tag, "STORE failed: upstream mutation failed")
                                        .await;
                                }
                            }
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

        let mailbox = self.selected_mailbox.as_ref().unwrap().clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let mailbox_view = self.config.mailbox_view.clone();
        let all_uids = mailbox_view.list_uids(&scoped_mailbox).await?;
        let needs_rfc822 = criteria.iter().any(search_key_needs_rfc822);

        let mut results = Vec::new();
        let max_uid = all_uids.last().copied().unwrap_or(0);

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
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let mutation = &self.config.mailbox_mutation;
        let all_uids = self.config.mailbox_view.list_uids(&scoped_mailbox).await?;

        let mut expunged_seqs = Vec::new();
        let mut offset = 0u32;

        for (i, &uid) in all_uids.iter().enumerate() {
            let flags = mutation.get_flags(&scoped_mailbox, uid).await?;
            if flags.iter().any(|f| f == "\\Deleted") {
                let seq = i as u32 + 1 - offset;

                // Permanently delete if already in Trash or Spam, otherwise move to Trash
                if let Some(ref client) = self.client {
                    if let Some(proton_id) = mutation.get_proton_id(&scoped_mailbox, uid).await? {
                        let is_trash_or_spam = self
                            .resolve_mailbox(&mailbox)
                            .map(|mb| {
                                mb.label_id == types::TRASH_LABEL
                                    || mb.label_id == types::SPAM_LABEL
                            })
                            .unwrap_or(false);

                        let result = if is_trash_or_spam {
                            messages::delete_messages(client, &[proton_id.as_str()]).await
                        } else {
                            messages::label_messages(
                                client,
                                &[proton_id.as_str()],
                                types::TRASH_LABEL,
                            )
                            .await
                        };

                        if let Err(err) = result {
                            warn!(
                                error = %err,
                                mailbox = %mailbox,
                                uid,
                                proton_id = %proton_id,
                                permanent = is_trash_or_spam,
                                "failed to sync expunge mutation upstream"
                            );
                            if self.strict_mutation_mode() {
                                if let Some(tag) = tag {
                                    self.writer
                                        .tagged_no(tag, "EXPUNGE failed: upstream mutation failed")
                                        .await?;
                                    return Ok(false);
                                }
                            }
                        }
                    }
                }

                mutation.remove_message(&scoped_mailbox, uid).await?;
                expunged_seqs.push(seq);
                offset += 1;
            }
        }

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
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let mutation = &self.config.mailbox_mutation;
        let all_uids = self.config.mailbox_view.list_uids(&scoped_mailbox).await?;

        if all_uids.is_empty() {
            return self
                .writer
                .tagged_ok(tag, None, "UID EXPUNGE completed")
                .await;
        }

        let max_uid = *all_uids.last().unwrap();
        let mut expunged_seqs = Vec::new();
        let mut offset = 0u32;

        for (i, &uid) in all_uids.iter().enumerate() {
            // Only expunge if UID is in the sequence set AND has \Deleted flag
            if !sequence.contains(uid, max_uid) {
                continue;
            }

            let flags = mutation.get_flags(&scoped_mailbox, uid).await?;
            if flags.iter().any(|f| f == "\\Deleted") {
                let seq = i as u32 + 1 - offset;

                // Permanently delete if in Trash or Spam, otherwise move to Trash
                if let Some(ref client) = self.client {
                    if let Some(proton_id) = mutation.get_proton_id(&scoped_mailbox, uid).await? {
                        let is_trash_or_spam = self
                            .resolve_mailbox(&mailbox)
                            .map(|mb| {
                                mb.label_id == types::TRASH_LABEL
                                    || mb.label_id == types::SPAM_LABEL
                            })
                            .unwrap_or(false);

                        let result = if is_trash_or_spam {
                            messages::delete_messages(client, &[proton_id.as_str()]).await
                        } else {
                            messages::label_messages(
                                client,
                                &[proton_id.as_str()],
                                types::TRASH_LABEL,
                            )
                            .await
                        };

                        if let Err(err) = result {
                            warn!(
                                error = %err,
                                mailbox = %mailbox,
                                uid,
                                proton_id = %proton_id,
                                permanent = is_trash_or_spam,
                                "failed to sync uid expunge mutation upstream"
                            );
                            if self.strict_mutation_mode() {
                                return self
                                    .writer
                                    .tagged_no(tag, "UID EXPUNGE failed: upstream mutation failed")
                                    .await;
                            }
                        }
                    }
                }

                mutation.remove_message(&scoped_mailbox, uid).await?;
                expunged_seqs.push(seq);
                offset += 1;
            }
        }

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

        let dest_mb = match self.resolve_mailbox(dest_name) {
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
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let scoped_dest_mailbox = self.scoped_mailbox_name(&dest_mb.name);
        if scoped_mailbox == scoped_dest_mailbox {
            return self.writer.tagged_ok(tag, None, "COPY completed").await;
        }

        let mutation = &self.config.mailbox_mutation;
        let all_uids = self.config.mailbox_view.list_uids(&scoped_mailbox).await?;

        if all_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "COPY completed").await;
        }

        let target_uids = self.resolve_target_uids(&all_uids, sequence, uid_mode);

        let mut src_uids = Vec::new();
        let mut dst_uids = Vec::new();

        for &uid in &target_uids {
            if let Some(ref client) = self.client {
                if let Some(proton_id) = mutation.get_proton_id(&scoped_mailbox, uid).await? {
                    if let Err(err) =
                        messages::label_messages(client, &[proton_id.as_str()], &dest_mb.label_id)
                            .await
                    {
                        warn!(
                            error = %err,
                            source_mailbox = %mailbox,
                            destination_mailbox = %dest_mb.name,
                            uid,
                            proton_id = %proton_id,
                            "failed to sync copy destination label upstream"
                        );
                        if self.strict_mutation_mode() {
                            return self
                                .writer
                                .tagged_no(tag, "COPY failed: upstream mutation failed")
                                .await;
                        }
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

        let dest_mb = match self.resolve_mailbox(dest_name) {
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
            .unwrap_or_else(|| dest_mb.clone());
        let scoped_source_mailbox = self.scoped_mailbox_name(&mailbox);
        let scoped_dest_mailbox = self.scoped_mailbox_name(&dest_mb.name);
        if scoped_source_mailbox == scoped_dest_mailbox {
            return self.writer.tagged_ok(tag, None, "MOVE completed").await;
        }

        let mutation = &self.config.mailbox_mutation;
        let all_uids = self
            .config
            .mailbox_view
            .list_uids(&scoped_source_mailbox)
            .await?;
        if all_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "MOVE completed").await;
        }

        let target_uids = self.resolve_target_uids(&all_uids, sequence, uid_mode);
        if target_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "MOVE completed").await;
        }

        let target_uid_set: HashSet<u32> = target_uids.iter().copied().collect();
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

            if let Some(ref client) = self.client {
                if let Err(err) =
                    messages::label_messages(client, &[proton_id.as_str()], &dest_mb.label_id).await
                {
                    warn!(
                        error = %err,
                        source_mailbox = %mailbox,
                        destination_mailbox = %dest_mb.name,
                        uid,
                        proton_id = %proton_id,
                        "failed to sync move destination label upstream"
                    );
                    if self.strict_mutation_mode() {
                        return self
                            .writer
                            .tagged_no(tag, "MOVE failed: upstream mutation failed")
                            .await;
                    }
                }

                if source_mb.label_id != dest_mb.label_id {
                    if let Err(err) = messages::unlabel_messages(
                        client,
                        &[proton_id.as_str()],
                        &source_mb.label_id,
                    )
                    .await
                    {
                        warn!(
                            error = %err,
                            source_mailbox = %mailbox,
                            destination_mailbox = %dest_mb.name,
                            uid,
                            proton_id = %proton_id,
                            "failed to sync move source label removal upstream"
                        );
                        if self.strict_mutation_mode() {
                            return self
                                .writer
                                .tagged_no(tag, "MOVE failed: upstream mutation failed")
                                .await;
                        }
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
        _date: &Option<String>,
        literal_size: u32,
    ) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        let mb = match self.resolve_mailbox(mailbox_name) {
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
        let subject = header_text
            .lines()
            .find(|l| l.to_lowercase().starts_with("subject:"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default();
        let from = header_text
            .lines()
            .find(|l| l.to_lowercase().starts_with("from:"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default();
        let time = extract_sent_date(&literal).unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        });

        let is_unread = !flags.iter().any(|f| matches!(f, ImapFlag::Seen));

        // Try to import upstream via Proton API.
        // Use primary address, fall back to first available address with keys.
        let proton_id = self
            .try_import_upstream(&literal, &mb.label_id, is_unread, &mb.name)
            .await;

        let proton_id = proton_id.unwrap_or_else(|| {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!("local-append-{ts}")
        });

        let meta = types::MessageMetadata {
            id: proton_id.clone(),
            address_id: String::new(),
            label_ids: vec![mb.label_id.clone()],
            external_id: None,
            subject,
            sender: types::EmailAddress {
                name: String::new(),
                address: from,
            },
            to_list: vec![],
            cc_list: vec![],
            bcc_list: vec![],
            reply_tos: vec![],
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
        let uid = mutation
            .store_metadata(&scoped_mailbox, &proton_id, meta)
            .await?;
        mutation.store_rfc822(&scoped_mailbox, uid, literal).await?;

        // Apply flags
        let flag_strs: Vec<String> = flags.iter().map(|f| f.as_str().to_string()).collect();
        if !flag_strs.is_empty() {
            mutation.set_flags(&scoped_mailbox, uid, flag_strs).await?;
        }

        let status = mutation.mailbox_status(&scoped_mailbox).await?;
        let appenduid_code = format!("APPENDUID {} {}", status.uid_validity, uid);

        info!(
            mailbox = %mb.name,
            uid,
            size = literal_size,
            "APPEND completed"
        );

        self.writer
            .tagged_ok(tag, Some(&appenduid_code), "APPEND completed")
            .await
    }

    /// Attempt upstream import of an APPEND message. Returns the Proton
    /// message ID on success, or None if import is unavailable or fails.
    async fn try_import_upstream(
        &self,
        literal: &[u8],
        label_id: &str,
        is_unread: bool,
        mailbox_name: &str,
    ) -> Option<String> {
        let client = self.client.as_ref()?;
        let keyrings = self.addr_keyrings.as_ref()?;

        // Use primary address; fall back to first available keyring
        let (addr_id, keyring) = self
            .primary_address_id
            .as_ref()
            .and_then(|id| keyrings.get(id).map(|kr| (id.as_str(), kr)))
            .or_else(|| keyrings.iter().next().map(|(id, kr)| (id.as_str(), kr)))?;

        let encrypted = match crypto_encrypt::encrypt_rfc822(keyring, literal) {
            Ok(enc) => enc,
            Err(e) => {
                warn!(error = %e, "APPEND encryption failed; storing locally only");
                return None;
            }
        };

        let import_flags = types::MESSAGE_FLAG_RECEIVED | types::MESSAGE_FLAG_IMPORTED;
        let metadata = types::ImportMetadata {
            address_id: addr_id.to_string(),
            label_ids: vec![label_id.to_string()],
            unread: is_unread,
            flags: import_flags,
        };

        match messages::import_message(client, &metadata, encrypted).await {
            Ok(res) => {
                info!(
                    message_id = %res.message_id,
                    mailbox = %mailbox_name,
                    "APPEND imported upstream"
                );
                Some(res.message_id)
            }
            Err(e) => {
                warn!(error = %e, "APPEND upstream import failed; storing locally only");
                None
            }
        }
    }

    /// Get stream halves for TLS upgrade.
    pub fn into_parts(self) -> (R, W) {
        (self.reader.into_inner(), self.writer.into_inner())
    }
}

fn format_copyuid(uid_validity: u32, src_uids: &[u32], dst_uids: &[u32]) -> String {
    let src = src_uids
        .iter()
        .map(|u| u.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let dst = dst_uids
        .iter()
        .map(|u| u.to_string())
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
    uid: u32,
    meta: &Option<types::MessageMetadata>,
    flags: &[String],
    max_uid: u32,
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
        SearchKey::Uid(seq) => seq.contains(uid, max_uid),
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

fn build_metadata_header_section(meta: &types::MessageMetadata) -> String {
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

fn format_header_addresses(addrs: &[types::EmailAddress]) -> String {
    addrs
        .iter()
        .map(format_header_address)
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_header_address(addr: &types::EmailAddress) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{EmailAddress, MessageMetadata};
    use crate::bridge::accounts::AccountHealth;
    use crate::bridge::accounts::{AccountRegistry, RuntimeAccountRegistry};
    use crate::bridge::auth_router::AuthRouter;
    use crate::imap::gluon_connector::{GluonMailConnector, StoreBackedConnector};
    use crate::imap::gluon_mailbox_mutation::GluonMailMailboxMutation;
    use crate::imap::gluon_mailbox_view::GluonMailMailboxView;
    use crate::imap::mailbox;
    use crate::imap::mailbox_catalog::RuntimeMailboxCatalog;
    use crate::imap::mailbox_mutation::{GluonMailboxMutation, StoreBackedMailboxMutation};
    use crate::imap::mailbox_view::{GluonMailboxView, StoreBackedMailboxView};
    use crate::imap::rfc822;
    use crate::imap::store::InMemoryStore;
    use gluon_rs_mail::{
        AccountBootstrap, CacheLayout, CompatibilityTarget, CompatibleStore, GluonKey, NewMailbox,
        NewMessage, StoreBootstrap,
    };
    use tempfile::{tempdir, TempDir};
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    fn test_config_with_mode(mutation_mode: MutationMode) -> Arc<SessionConfig> {
        let session = test_session();
        let accounts = AccountRegistry::from_single_session(session.clone());
        let store = InMemoryStore::new();
        let runtime_accounts = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
        Arc::new(SessionConfig {
            api_base_url: "https://mail-api.proton.me".to_string(),
            auth_router: AuthRouter::new(accounts),
            runtime_accounts: runtime_accounts.clone(),
            gluon_connector: StoreBackedConnector::new(store.clone()),
            mailbox_catalog: RuntimeMailboxCatalog::new(runtime_accounts),
            mailbox_mutation: StoreBackedMailboxMutation::new(store.clone()),
            mailbox_view: StoreBackedMailboxView::new(store.clone()),
            store,
            mutation_mode,
        })
    }

    fn test_config() -> Arc<SessionConfig> {
        test_config_with_mode(MutationMode::Compat)
    }

    struct TestGluonMailFixture {
        _tempdir: TempDir,
    }

    fn test_gluon_mail_view_config() -> (Arc<SessionConfig>, TestGluonMailFixture) {
        test_gluon_mail_config(false, MutationMode::Compat)
    }

    fn test_gluon_mail_backend_config() -> (Arc<SessionConfig>, TestGluonMailFixture) {
        test_gluon_mail_backend_config_with_mode(MutationMode::Compat)
    }

    fn test_gluon_mail_backend_config_with_mode(
        mutation_mode: MutationMode,
    ) -> (Arc<SessionConfig>, TestGluonMailFixture) {
        test_gluon_mail_config(true, mutation_mode)
    }

    fn test_gluon_mail_config(
        use_gluon_mutation_backend: bool,
        mutation_mode: MutationMode,
    ) -> (Arc<SessionConfig>, TestGluonMailFixture) {
        let session = test_session();
        let accounts = AccountRegistry::from_single_session(session.clone());
        let store = InMemoryStore::new();
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
            .expect("append message");

        let mailbox_mutation: Arc<dyn GluonMailboxMutation> = if use_gluon_mutation_backend {
            GluonMailMailboxMutation::new(gluon_store.clone())
        } else {
            StoreBackedMailboxMutation::new(store.clone())
        };
        let mailbox_view: Arc<dyn GluonMailboxView> =
            GluonMailMailboxView::new(gluon_store.clone());
        let gluon_connector: Arc<dyn GluonImapConnector> = if use_gluon_mutation_backend {
            GluonMailConnector::new(gluon_store.clone())
        } else {
            StoreBackedConnector::new(store.clone())
        };

        let config = Arc::new(SessionConfig {
            api_base_url: "https://mail-api.proton.me".to_string(),
            auth_router: AuthRouter::new(accounts),
            runtime_accounts: runtime_accounts.clone(),
            gluon_connector,
            mailbox_catalog: RuntimeMailboxCatalog::new(runtime_accounts),
            mailbox_mutation,
            mailbox_view,
            store,
            mutation_mode,
        });

        (config, TestGluonMailFixture { _tempdir: tempdir })
    }

    fn failing_client() -> ProtonClient {
        ProtonClient::authenticated_with_mode(
            "http://127.0.0.1:1",
            crate::api::types::ApiMode::Bridge,
            "test-uid",
            "test-token",
        )
        .unwrap()
    }

    fn make_meta(id: &str, unread: i32) -> MessageMetadata {
        MessageMetadata {
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

    fn metadata_page_response(messages: Vec<MessageMetadata>, total: i64) -> serde_json::Value {
        serde_json::json!({
            "Code": 1000,
            "Messages": messages,
            "Total": total
        })
    }

    async fn seed_gluon_backend_message(
        config: &Arc<SessionConfig>,
        mailbox_name: &str,
        proton_id: &str,
        unread: i32,
        body: &[u8],
    ) -> u32 {
        let mut meta = make_meta(proton_id, unread);
        meta.external_id = Some(format!("{proton_id}@example.test"));
        meta.size = body.len() as i64;
        let scoped_mailbox = format!("test-uid::{mailbox_name}");
        let uid = config
            .mailbox_mutation
            .store_metadata(&scoped_mailbox, proton_id, meta)
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
        scoped_mailbox: &str,
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

    fn multi_account_config(api_base_url: &str) -> Arc<SessionConfig> {
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
        let runtime_accounts = Arc::new(RuntimeAccountRegistry::in_memory(vec![
            account_a, account_b,
        ]));
        let store = InMemoryStore::new();
        Arc::new(SessionConfig {
            api_base_url: api_base_url.to_string(),
            auth_router: AuthRouter::new(accounts),
            runtime_accounts: runtime_accounts.clone(),
            gluon_connector: StoreBackedConnector::new(store.clone()),
            mailbox_catalog: RuntimeMailboxCatalog::new(runtime_accounts.clone()),
            mailbox_mutation: StoreBackedMailboxMutation::new(store.clone()),
            mailbox_view: StoreBackedMailboxView::new(store.clone()),
            store,
            mutation_mode: MutationMode::Compat,
        })
    }

    #[tokio::test]
    async fn test_greet() {
        let config = test_config();
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
        let config = test_config();
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
        let config = test_config();
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
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.selected_mailbox_mod_seq = Some(0);
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
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
        let (config, _fixture) = test_gluon_mail_backend_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.selected_mailbox_mod_seq = Some(0);
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .gluon_connector
            .upsert_metadata("test-uid::INBOX", "msg-noop", make_meta("msg-noop", 1))
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
        let config = test_config();
        let (mut session, mut client_read, mut client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.selected_mailbox_mod_seq = Some(0);
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
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
        let config = test_config();
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
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
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
        let (config, _fixture) = test_gluon_mail_backend_config();
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
            .upsert_metadata("test-uid::INBOX", "msg-idle", make_meta("msg-idle", 1))
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
        let config = test_config();
        let (mut session, mut client_read, mut client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid1 = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        let _uid2 = config
            .store
            .store_metadata("test-uid::INBOX", "msg-2", make_meta("msg-2", 1))
            .await
            .unwrap();
        prime_selected_state_from_view(&mut session, &config, "test-uid::INBOX").await;

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
            .store
            .remove_message("test-uid::INBOX", uid1)
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
        let (config, _fixture) = test_gluon_mail_backend_config();
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
        assert_eq!(uid1, 2);
        prime_selected_state_from_view(&mut session, &config, "test-uid::INBOX").await;

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
            .remove_message_by_uid("test-uid::INBOX", uid1)
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
        let config = test_config();
        let (mut session, mut client_read, mut client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        let snapshot = config
            .store
            .mailbox_snapshot("test-uid::INBOX")
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
            .store
            .set_flags("test-uid::INBOX", uid, vec!["\\Seen".to_string()])
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
        let (config, _fixture) = test_gluon_mail_backend_config();
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
        prime_selected_state_from_view(&mut session, &config, "test-uid::INBOX").await;
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
            .update_message_flags("test-uid::INBOX", uid, vec!["\\Seen".to_string()])
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
        let config = test_config();
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
        let config = test_config();
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

        let config = multi_account_config(&server.uri());
        config
            .runtime_accounts
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

        // Healthy account still proceeds to account-specific processing path.
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
        assert!(response.contains("a001 NO"), "response={response}");
        assert!(
            !response.contains("AUTHENTICATIONFAILED"),
            "healthy account login should reach account-specific processing, response={response}"
        );
    }

    #[tokio::test]
    async fn test_list_not_authenticated() {
        let config = test_config();
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
        let config = test_config();
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
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .store
            .store_metadata("test-uid::Drafts", "msg-1", make_meta("msg-1", 1))
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
        let (config, _fixture) = test_gluon_mail_view_config();
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
        let config = test_config();
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
        let config = test_config();
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
        let config = test_config();
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
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("x-http-method-override", "GET"))
            .and(body_string_contains("\"Page\":0"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(metadata_page_response(vec![make_meta("msg-1", 1)], 2)),
            )
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("x-http-method-override", "GET"))
            .and(body_string_contains("\"Page\":1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(metadata_page_response(vec![make_meta("msg-2", 1)], 2)),
            )
            .expect(1)
            .mount(&server)
            .await;

        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

        session.handle_line("a001 SELECT INBOX").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("2 EXISTS"), "response={response}");
        assert!(response.contains("a001 OK [READ-WRITE] SELECT completed"));

        let uids = config.store.list_uids("test-uid::INBOX").await.unwrap();
        assert_eq!(uids.len(), 2);

        server.verify().await;
    }

    #[tokio::test]
    async fn test_fetch_body_returns_body_item_not_bodystructure() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        config
            .store
            .store_rfc822(
                "test-uid::INBOX",
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
        let (config, _fixture) = test_gluon_mail_view_config();
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
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
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
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unlabel"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(1)
            .mount(&server)
            .await;

        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

        let uid = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        config
            .store
            .set_flags(
                "test-uid::INBOX",
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

        server.verify().await;
    }

    #[tokio::test]
    async fn test_store_set_flags_syncs_remote_removals_with_gluon_mail_backend() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unread"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unlabel"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(1)
            .mount(&server)
            .await;

        let (config, _fixture) = test_gluon_mail_backend_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

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
                "test-uid::INBOX",
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
            .get_flags("test-uid::INBOX", uid)
            .await
            .unwrap()
            .is_empty());

        server.verify().await;
    }

    #[tokio::test]
    async fn test_copy_copies_local_message_and_labels_destination_upstream() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/label"))
            .and(body_string_contains("\"LabelID\":\"6\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(1)
            .mount(&server)
            .await;

        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

        let src_uid = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
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

        let inbox_uids = config.store.list_uids("test-uid::INBOX").await.unwrap();
        assert_eq!(inbox_uids, vec![src_uid]);

        let archive_uids = config.store.list_uids("test-uid::Archive").await.unwrap();
        assert_eq!(archive_uids.len(), 1);
        let archived_proton_id = config
            .store
            .get_proton_id("test-uid::Archive", archive_uids[0])
            .await
            .unwrap();
        assert_eq!(archived_proton_id.as_deref(), Some("msg-1"));

        server.verify().await;
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
            .expect(1)
            .mount(&server)
            .await;

        let (config, _fixture) = test_gluon_mail_backend_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-copy-sync",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-copy-sync\r\n\r\ncopy-body",
        )
        .await;
        assert_eq!(uid, 2);

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
                .list_uids("test-uid::INBOX")
                .await
                .unwrap(),
            vec![1, 2]
        );
        assert_eq!(
            config
                .mailbox_view
                .list_uids("test-uid::Archive")
                .await
                .unwrap(),
            vec![1]
        );
        assert_eq!(
            config
                .mailbox_view
                .get_proton_id("test-uid::Archive", 1)
                .await
                .unwrap()
                .as_deref(),
            Some("msg-copy-sync")
        );

        server.verify().await;
    }

    #[tokio::test]
    async fn test_copy_copies_local_message_without_api_client() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let src_uid = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();

        session.handle_line("a001 COPY 1 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("COPY completed"), "response={response}");

        let inbox_uids = config.store.list_uids("test-uid::INBOX").await.unwrap();
        assert_eq!(inbox_uids, vec![src_uid]);

        let archive_uids = config.store.list_uids("test-uid::Archive").await.unwrap();
        assert_eq!(archive_uids.len(), 1);
        let archived_proton_id = config
            .store
            .get_proton_id("test-uid::Archive", archive_uids[0])
            .await
            .unwrap();
        assert_eq!(archived_proton_id.as_deref(), Some("msg-1"));
    }

    #[tokio::test]
    async fn test_copy_copies_local_message_without_api_client_with_gluon_mail_backend() {
        let (config, _fixture) = test_gluon_mail_backend_config();
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
        assert_eq!(uid, 2);

        session.handle_line("a001 COPY 2 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("COPY completed"), "response={response}");

        let inbox_uids = config
            .mailbox_view
            .list_uids("test-uid::INBOX")
            .await
            .unwrap();
        assert_eq!(inbox_uids, vec![1, 2]);
        assert_eq!(
            config
                .mailbox_view
                .get_proton_id("test-uid::INBOX", 2)
                .await
                .unwrap()
                .as_deref(),
            Some("msg-copy")
        );

        let archive_uids = config
            .mailbox_view
            .list_uids("test-uid::Archive")
            .await
            .unwrap();
        assert_eq!(archive_uids, vec![1]);
        assert_eq!(
            config
                .mailbox_view
                .get_proton_id("test-uid::Archive", 1)
                .await
                .unwrap()
                .as_deref(),
            Some("msg-copy")
        );
    }

    #[tokio::test]
    async fn test_copy_compat_mode_succeeds_when_upstream_fails() {
        let config = test_config_with_mode(MutationMode::Compat);
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(failing_client());

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();

        session.handle_line("a001 COPY 1 Archive").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("COPY completed"), "response={response}");

        let archive_uids = config.store.list_uids("test-uid::Archive").await.unwrap();
        assert_eq!(archive_uids.len(), 1);
    }

    #[tokio::test]
    async fn test_copy_strict_mode_fails_when_upstream_fails() {
        let config = test_config_with_mode(MutationMode::Strict);
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(failing_client());

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
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

        let archive_uids = config.store.list_uids("test-uid::Archive").await.unwrap();
        assert!(archive_uids.is_empty());
    }

    #[tokio::test]
    async fn test_copy_strict_mode_fails_when_upstream_fails_with_gluon_mail_backend() {
        let (config, _fixture) = test_gluon_mail_backend_config_with_mode(MutationMode::Strict);
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(failing_client());

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-copy-fail",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-copy-fail\r\n\r\ncopy-body",
        )
        .await;
        assert_eq!(uid, 2);

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
            .list_uids("test-uid::Archive")
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
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unlabel"))
            .and(body_string_contains("\"LabelID\":\"0\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(1)
            .mount(&server)
            .await;

        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        config
            .store
            .store_metadata("test-uid::INBOX", "msg-2", make_meta("msg-2", 1))
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

        let inbox_uids = config.store.list_uids("test-uid::INBOX").await.unwrap();
        assert_eq!(inbox_uids.len(), 1);
        let inbox_proton_id = config
            .store
            .get_proton_id("test-uid::INBOX", inbox_uids[0])
            .await
            .unwrap();
        assert_eq!(inbox_proton_id.as_deref(), Some("msg-2"));

        let archive_uids = config.store.list_uids("test-uid::Archive").await.unwrap();
        assert_eq!(archive_uids.len(), 1);
        let archive_proton_id = config
            .store
            .get_proton_id("test-uid::Archive", archive_uids[0])
            .await
            .unwrap();
        assert_eq!(archive_proton_id.as_deref(), Some("msg-1"));

        server.verify().await;
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
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unlabel"))
            .and(body_string_contains("\"LabelID\":\"0\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(1)
            .mount(&server)
            .await;

        let (config, _fixture) = test_gluon_mail_backend_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-move-sync",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-move-sync\r\n\r\nmove-body",
        )
        .await;
        assert_eq!(uid, 2);

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
                .list_uids("test-uid::INBOX")
                .await
                .unwrap(),
            vec![1]
        );
        assert_eq!(
            config
                .mailbox_view
                .list_uids("test-uid::Archive")
                .await
                .unwrap(),
            vec![1]
        );
        assert_eq!(
            config
                .mailbox_view
                .get_proton_id("test-uid::Archive", 1)
                .await
                .unwrap()
                .as_deref(),
            Some("msg-move-sync")
        );

        server.verify().await;
    }

    #[tokio::test]
    async fn test_move_moves_local_message_without_api_client() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        config
            .store
            .store_metadata("test-uid::INBOX", "msg-2", make_meta("msg-2", 1))
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

        let inbox_uids = config.store.list_uids("test-uid::INBOX").await.unwrap();
        assert_eq!(inbox_uids.len(), 1);
        let inbox_proton_id = config
            .store
            .get_proton_id("test-uid::INBOX", inbox_uids[0])
            .await
            .unwrap();
        assert_eq!(inbox_proton_id.as_deref(), Some("msg-2"));

        let archive_uids = config.store.list_uids("test-uid::Archive").await.unwrap();
        assert_eq!(archive_uids.len(), 1);
        let archive_proton_id = config
            .store
            .get_proton_id("test-uid::Archive", archive_uids[0])
            .await
            .unwrap();
        assert_eq!(archive_proton_id.as_deref(), Some("msg-1"));
    }

    #[tokio::test]
    async fn test_move_moves_local_message_without_api_client_with_gluon_mail_backend() {
        let (config, _fixture) = test_gluon_mail_backend_config();
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
        assert_eq!(uid, 2);

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
            .list_uids("test-uid::INBOX")
            .await
            .unwrap();
        assert_eq!(inbox_uids, vec![1]);
        assert_eq!(
            config
                .mailbox_view
                .get_proton_id("test-uid::INBOX", 1)
                .await
                .unwrap()
                .as_deref(),
            Some("msg-1")
        );

        let archive_uids = config
            .mailbox_view
            .list_uids("test-uid::Archive")
            .await
            .unwrap();
        assert_eq!(archive_uids, vec![1]);
        assert_eq!(
            config
                .mailbox_view
                .get_proton_id("test-uid::Archive", 1)
                .await
                .unwrap()
                .as_deref(),
            Some("msg-move")
        );
    }

    #[tokio::test]
    async fn test_move_strict_mode_fails_when_upstream_fails() {
        let config = test_config_with_mode(MutationMode::Strict);
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(failing_client());

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        config
            .store
            .store_metadata("test-uid::INBOX", "msg-2", make_meta("msg-2", 1))
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

        let inbox_uids = config.store.list_uids("test-uid::INBOX").await.unwrap();
        assert_eq!(inbox_uids.len(), 2);

        let archive_uids = config.store.list_uids("test-uid::Archive").await.unwrap();
        assert!(archive_uids.is_empty());
    }

    #[tokio::test]
    async fn test_move_strict_mode_fails_when_upstream_fails_with_gluon_mail_backend() {
        let (config, _fixture) = test_gluon_mail_backend_config_with_mode(MutationMode::Strict);
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(failing_client());

        let uid = seed_gluon_backend_message(
            &config,
            "INBOX",
            "msg-move-fail",
            1,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-move-fail\r\n\r\nmove-body",
        )
        .await;
        assert_eq!(uid, 2);

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
                .list_uids("test-uid::INBOX")
                .await
                .unwrap(),
            vec![1, 2]
        );
        assert!(config
            .mailbox_view
            .list_uids("test-uid::Archive")
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
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unlabel"))
            .and(body_string_contains("\"LabelID\":\"0\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(1)
            .mount(&server)
            .await;

        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        let uid2 = config
            .store
            .store_metadata("test-uid::INBOX", "msg-2", make_meta("msg-2", 1))
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

        let inbox_uids = config.store.list_uids("test-uid::INBOX").await.unwrap();
        assert_eq!(inbox_uids.len(), 1);
        let inbox_proton_id = config
            .store
            .get_proton_id("test-uid::INBOX", inbox_uids[0])
            .await
            .unwrap();
        assert_eq!(inbox_proton_id.as_deref(), Some("msg-1"));

        let archive_uids = config.store.list_uids("test-uid::Archive").await.unwrap();
        assert_eq!(archive_uids.len(), 1);
        let archive_proton_id = config
            .store
            .get_proton_id("test-uid::Archive", archive_uids[0])
            .await
            .unwrap();
        assert_eq!(archive_proton_id.as_deref(), Some("msg-2"));

        server.verify().await;
    }

    #[tokio::test]
    async fn test_uid_move_without_api_client_uses_uid_selection() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        let uid2 = config
            .store
            .store_metadata("test-uid::INBOX", "msg-2", make_meta("msg-2", 1))
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

        let inbox_uids = config.store.list_uids("test-uid::INBOX").await.unwrap();
        assert_eq!(inbox_uids.len(), 1);
        let inbox_proton_id = config
            .store
            .get_proton_id("test-uid::INBOX", inbox_uids[0])
            .await
            .unwrap();
        assert_eq!(inbox_proton_id.as_deref(), Some("msg-1"));

        let archive_uids = config.store.list_uids("test-uid::Archive").await.unwrap();
        assert_eq!(archive_uids.len(), 1);
        let archive_proton_id = config
            .store
            .get_proton_id("test-uid::Archive", archive_uids[0])
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
            .expect(1)
            .mount(&server)
            .await;

        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

        let uid = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        config
            .store
            .add_flags("test-uid::INBOX", uid, &[String::from("\\Deleted")])
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

        let inbox_uids = config.store.list_uids("test-uid::INBOX").await.unwrap();
        assert!(inbox_uids.is_empty());

        server.verify().await;
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
            .expect(1)
            .mount(&server)
            .await;

        let (config, _fixture) = test_gluon_mail_backend_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

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
            .add_flags("test-uid::INBOX", uid, &[String::from("\\Deleted")])
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
                .list_uids("test-uid::INBOX")
                .await
                .unwrap(),
            vec![1]
        );

        server.verify().await;
    }

    #[tokio::test]
    async fn test_expunge_without_api_client_with_gluon_mail_backend() {
        let (config, _fixture) = test_gluon_mail_backend_config();
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
            .add_flags("test-uid::INBOX", uid, &[String::from("\\Deleted")])
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
                .list_uids("test-uid::INBOX")
                .await
                .unwrap(),
            vec![1]
        );
        assert_eq!(
            config
                .mailbox_view
                .get_proton_id("test-uid::INBOX", 1)
                .await
                .unwrap()
                .as_deref(),
            Some("msg-1")
        );
    }

    #[tokio::test]
    async fn test_expunge_strict_mode_fails_when_upstream_fails() {
        let config = test_config_with_mode(MutationMode::Strict);
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(failing_client());

        let uid = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        config
            .store
            .add_flags("test-uid::INBOX", uid, &[String::from("\\Deleted")])
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

        let inbox_uids = config.store.list_uids("test-uid::INBOX").await.unwrap();
        assert_eq!(inbox_uids, vec![uid]);
    }

    #[tokio::test]
    async fn test_expunge_strict_mode_fails_when_upstream_fails_with_gluon_mail_backend() {
        let (config, _fixture) = test_gluon_mail_backend_config_with_mode(MutationMode::Strict);
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(failing_client());

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
            .add_flags("test-uid::INBOX", uid, &[String::from("\\Deleted")])
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
                .list_uids("test-uid::INBOX")
                .await
                .unwrap(),
            vec![1, 2]
        );
    }

    #[tokio::test]
    async fn test_uid_expunge_strict_mode_fails_when_upstream_fails() {
        let config = test_config_with_mode(MutationMode::Strict);
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(failing_client());

        let uid = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        config
            .store
            .add_flags("test-uid::INBOX", uid, &[String::from("\\Deleted")])
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

        let inbox_uids = config.store.list_uids("test-uid::INBOX").await.unwrap();
        assert_eq!(inbox_uids, vec![uid]);
    }

    #[tokio::test]
    async fn test_examine_reports_first_unseen_sequence_number() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        config
            .store
            .store_metadata("test-uid::INBOX", "msg-2", make_meta("msg-2", 1))
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
        let (config, _fixture) = test_gluon_mail_backend_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .set_flags("test-uid::INBOX", 1, vec!["\\Seen".to_string()])
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

        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
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

        server.verify().await;
    }

    #[tokio::test]
    async fn test_fetch_multiple_non_peek_body_sections_marks_read_once() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/read"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .expect(1)
            .named("mark read should only happen once per message")
            .mount(&server)
            .await;

        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

        let uid = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        config
            .store
            .store_rfc822(
                "test-uid::INBOX",
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
            .store
            .get_flags("test-uid::INBOX", uid)
            .await
            .unwrap();
        assert!(flags.iter().any(|f| f == "\\Seen"));

        server.verify().await;
    }

    #[tokio::test]
    async fn test_select_after_examine_resets_read_only_mode() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        config
            .store
            .store_metadata("test-uid::Drafts", "msg-2", make_meta("msg-2", 1))
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
        let (config, _fixture) = test_gluon_mail_backend_config();
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
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
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

        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

        let uid = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        config
            .store
            .store_rfc822(
                "test-uid::INBOX",
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
            .store
            .get_flags("test-uid::INBOX", uid)
            .await
            .unwrap();
        assert!(
            !flags.iter().any(|f| f == "\\Seen"),
            "flags were mutated in read-only mode: {flags:?}"
        );

        server.verify().await;
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

        let (config, _fixture) = test_gluon_mail_backend_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

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
            .get_flags("test-uid::INBOX", 1)
            .await
            .unwrap();
        assert!(
            !flags.iter().any(|f| f == "\\Seen"),
            "flags were mutated in read-only mode: {flags:?}"
        );

        server.verify().await;
    }

    #[tokio::test]
    async fn test_uid_fetch_flags_always_includes_uid() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
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
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
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
        let (config, _fixture) = test_gluon_mail_backend_config();
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
                .get_flags("test-uid::INBOX", uid)
                .await
                .unwrap(),
            vec!["\\Seen".to_string()]
        );
    }

    #[tokio::test]
    async fn test_search_text_and_header_use_cached_rfc822() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        config
            .store
            .store_rfc822(
                "test-uid::INBOX",
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
        let (config, _fixture) = test_gluon_mail_view_config();
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
        let (config, _fixture) = test_gluon_mail_view_config();
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

        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
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

        server.verify().await;
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

        let (config, _fixture) = test_gluon_mail_backend_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());
        session.client = Some(
            ProtonClient::authenticated_with_mode(
                &server.uri(),
                crate::api::types::ApiMode::Bridge,
                "test-uid",
                "test-token",
            )
            .unwrap(),
        );

        session.handle_line("a001 SELECT INBOX").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("1 EXISTS"));
        assert!(response.contains("a001 OK [READ-WRITE] SELECT completed"));

        server.verify().await;
    }

    #[tokio::test]
    async fn test_select_reports_first_unseen_sequence_and_permanentflags() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        config
            .store
            .store_metadata("test-uid::INBOX", "msg-2", make_meta("msg-2", 1))
            .await
            .unwrap();

        session.handle_line("a001 SELECT INBOX").await.unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
            .await
            .unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("2 EXISTS"));
        assert!(response
            .contains("OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)]"));
        assert!(response.contains("OK [UNSEEN 2]"));
        assert!(response.contains("a001 OK [READ-WRITE] SELECT completed"));
    }

    #[tokio::test]
    async fn test_select_reports_first_unseen_sequence_and_permanentflags_with_gluon_mail_backend()
    {
        let (config, _fixture) = test_gluon_mail_backend_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Authenticated;
        session.authenticated_account_id = Some("test-uid".to_string());

        config
            .mailbox_mutation
            .set_flags("test-uid::INBOX", 1, vec!["\\Seen".to_string()])
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
        assert!(response
            .contains("OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)]"));
        assert!(response.contains("OK [UNSEEN 2]"));
        assert!(response.contains("a001 OK [READ-WRITE] SELECT completed"));
    }

    #[test]
    fn test_evaluate_search_all() {
        let meta = Some(make_meta("msg-1", 1));
        let flags = vec![];
        assert!(evaluate_search_key(
            &SearchKey::All,
            1,
            &meta,
            &flags,
            1,
            None
        ));
    }

    #[test]
    fn test_evaluate_search_seen() {
        let meta = Some(make_meta("msg-1", 0));
        let flags = vec!["\\Seen".to_string()];
        assert!(evaluate_search_key(
            &SearchKey::Seen,
            1,
            &meta,
            &flags,
            1,
            None
        ));
        assert!(!evaluate_search_key(
            &SearchKey::Unseen,
            1,
            &meta,
            &flags,
            1,
            None
        ));
    }

    #[test]
    fn test_evaluate_search_subject() {
        let meta = Some(make_meta("msg-1", 1));
        let flags = vec![];
        assert!(evaluate_search_key(
            &SearchKey::Subject("Subject".to_string()),
            1,
            &meta,
            &flags,
            1,
            None
        ));
        assert!(!evaluate_search_key(
            &SearchKey::Subject("NotFound".to_string()),
            1,
            &meta,
            &flags,
            1,
            None
        ));
    }

    #[test]
    fn test_evaluate_search_from() {
        let meta = Some(make_meta("msg-1", 1));
        let flags = vec![];
        assert!(evaluate_search_key(
            &SearchKey::From("alice".to_string()),
            1,
            &meta,
            &flags,
            1,
            None
        ));
    }

    #[test]
    fn test_evaluate_search_not() {
        let meta = Some(make_meta("msg-1", 1));
        let flags = vec![];
        assert!(!evaluate_search_key(
            &SearchKey::Not(Box::new(SearchKey::All)),
            1,
            &meta,
            &flags,
            1,
            None
        ));
    }

    #[test]
    fn test_format_copyuid() {
        assert_eq!(
            format_copyuid(1700000000, &[1, 2, 3], &[10, 11, 12]),
            "COPYUID 1700000000 1,2,3 10,11,12"
        );
    }

    #[test]
    fn test_format_copyuid_single() {
        assert_eq!(format_copyuid(42, &[5], &[100]), "COPYUID 42 5 100");
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
            1,
            &meta,
            &flags,
            1,
            Some(rfc822)
        ));
        // Should NOT match meta.time day
        assert!(!evaluate_search_key(
            &SearchKey::SentOn(1700000000),
            1,
            &meta,
            &flags,
            1,
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
            1,
            &meta,
            &flags,
            1,
            None
        ));
    }

    #[test]
    fn test_idle_timeout_is_30_minutes() {
        assert_eq!(IDLE_TIMEOUT, Duration::from_secs(30 * 60));
    }

    #[tokio::test]
    async fn test_idle_exits_on_done() {
        let config = test_config();
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
        let config = test_config();
        let (mut session, mut client_read, _client_write) =
            create_session_pair(config.clone()).await;

        session.state = State::Selected;
        session.selected_mailbox = Some("INBOX".to_string());
        session.authenticated_account_id = Some("test-uid".to_string());

        let uid = config
            .store
            .store_metadata("test-uid::INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        config
            .store
            .add_flags("test-uid::INBOX", uid, &["\\Deleted".to_string()])
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
        let uids = config.store.list_uids("test-uid::INBOX").await.unwrap();
        assert_eq!(uids.len(), 1, "message must not be expunged");
    }
}
