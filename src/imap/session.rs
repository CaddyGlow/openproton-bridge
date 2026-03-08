use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use crate::api::client::ProtonClient;
use crate::api::error::is_auth_error;
use crate::api::messages;
use crate::api::types::{self, MessageFilter};
use crate::bridge::accounts::{AccountRuntimeError, RuntimeAccountRegistry, RuntimeAuthMaterial};
use crate::bridge::auth_router::AuthRouter;
use crate::crypto::keys::{self, Keyring};

use super::command::{
    parse_command, Command, FetchItem, ImapFlag, SearchKey, SequenceSet, StatusDataItem,
    StoreAction,
};
use super::mailbox;
use super::response::ResponseWriter;
use super::rfc822;
use super::store::MessageStore;
use super::Result;

#[derive(Debug, Clone, PartialEq)]
enum State {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

pub struct SessionConfig {
    pub api_base_url: String,
    pub auth_router: AuthRouter,
    pub runtime_accounts: Arc<RuntimeAccountRegistry>,
    pub store: Arc<dyn MessageStore>,
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
    selected_mailbox: Option<String>,
    selected_mailbox_mod_seq: Option<u64>,
    selected_read_only: bool,
    authenticated_account_id: Option<String>,
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
            selected_mailbox: None,
            selected_mailbox_mod_seq: None,
            selected_read_only: false,
            authenticated_account_id: None,
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
        self.greet().await?;

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
            Command::Check { ref tag } => self.cmd_check(tag).await?,
            Command::Examine {
                ref tag,
                ref mailbox,
            } => self.cmd_examine(tag, mailbox).await?,
            Command::UidExpunge {
                ref tag,
                ref sequence,
            } => self.cmd_uid_expunge(tag, sequence).await?,
        }

        Ok(SessionAction::Continue)
    }

    async fn cmd_capability(&mut self, tag: &str) -> Result<()> {
        let caps = if self.state == State::NotAuthenticated {
            if self.starttls_available {
                "CAPABILITY IMAP4rev1 STARTTLS IDLE"
            } else {
                "CAPABILITY IMAP4rev1 IDLE"
            }
        } else {
            "CAPABILITY IMAP4rev1 IDLE"
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

        self.client = Some(client);
        self.user_keyring = Some(user_keyring);
        self.addr_keyrings = Some(addr_keyrings);
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

        self.writer.continuation("idling").await?;
        self.emit_selected_mailbox_exists_update().await?;

        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            let mut line = String::new();
            tokio::select! {
                _ = ticker.tick() => {
                    self.emit_selected_mailbox_exists_update().await?;
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

    async fn emit_selected_mailbox_exists_update(&mut self) -> Result<()> {
        if self.state != State::Selected {
            return Ok(());
        }
        let Some(mailbox) = self.selected_mailbox.clone() else {
            return Ok(());
        };

        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let snapshot = self.config.store.mailbox_snapshot(&scoped_mailbox).await?;
        let previous_mod_seq = self.selected_mailbox_mod_seq.unwrap_or(0);
        if snapshot.mod_seq > previous_mod_seq {
            self.writer
                .untagged(&format!("{} EXISTS", snapshot.exists))
                .await?;
            self.selected_mailbox_mod_seq = Some(snapshot.mod_seq);
        }
        Ok(())
    }

    async fn cmd_list(&mut self, tag: &str, _reference: &str, pattern: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        if pattern.is_empty() {
            // RFC 3501: empty pattern returns hierarchy delimiter
            self.writer.untagged("LIST (\\Noselect) \"/\" \"\"").await?;
        } else {
            let mailboxes = mailbox::system_mailboxes();
            for mb in mailboxes {
                // Simple pattern matching: "*" matches everything, "%" matches one level
                if pattern == "*" || pattern == "%" || mb.name.eq_ignore_ascii_case(pattern) {
                    let mut attrs = Vec::new();
                    if !mb.selectable {
                        attrs.push("\\Noselect");
                    }
                    if let Some(su) = mb.special_use {
                        attrs.push(su);
                    }
                    let attr_str = if attrs.is_empty() {
                        String::new()
                    } else {
                        attrs.join(" ")
                    };
                    self.writer
                        .untagged(&format!("LIST ({}) \"/\" \"{}\"", attr_str, mb.name))
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
            // RFC 3501: empty pattern returns hierarchy delimiter
            self.writer.untagged("LSUB (\\Noselect) \"/\" \"\"").await?;
        } else {
            // All system mailboxes are considered subscribed
            let mailboxes = mailbox::system_mailboxes();
            for mb in mailboxes {
                if pattern == "*" || pattern == "%" || mb.name.eq_ignore_ascii_case(pattern) {
                    let mut attrs = Vec::new();
                    if !mb.selectable {
                        attrs.push("\\Noselect");
                    }
                    if let Some(su) = mb.special_use {
                        attrs.push(su);
                    }
                    let attr_str = if attrs.is_empty() {
                        String::new()
                    } else {
                        attrs.join(" ")
                    };
                    self.writer
                        .untagged(&format!("LSUB ({}) \"/\" \"{}\"", attr_str, mb.name))
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
        if mailbox::find_mailbox(mailbox_name).is_some() {
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
        if mailbox::find_mailbox(mailbox_name).is_some() {
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
        if mailbox::find_mailbox(mailbox_name).is_some() {
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

        let mb = match mailbox::find_mailbox(mailbox_name) {
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

        let store = self.config.store.clone();
        let scoped_mailbox = self.scoped_mailbox_name(mb.name);
        let cached_uids = store.list_uids(&scoped_mailbox).await?;

        if cached_uids.is_empty() {
            let client = self.client.as_ref().unwrap();

            // Fetch metadata from Proton API
            let filter = MessageFilter {
                label_id: Some(mb.label_id.to_string()),
                desc: 1,
                ..Default::default()
            };

            let meta_resp = match messages::get_message_metadata(client, &filter, 0, 150).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "failed to fetch message metadata");
                    return self.writer.tagged_no(tag, "failed to fetch messages").await;
                }
            };

            // Populate store with message metadata
            for meta in &meta_resp.messages {
                let uid = store
                    .store_metadata(&scoped_mailbox, &meta.id, meta.clone())
                    .await?;
                // Initialize flags from metadata
                let flags = mailbox::message_flags(meta);
                let flag_strings: Vec<String> = flags.iter().map(|s| s.to_string()).collect();
                store.set_flags(&scoped_mailbox, uid, flag_strings).await?;
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

        let status = store.mailbox_status(&scoped_mailbox).await?;
        let snapshot = store.mailbox_snapshot(&scoped_mailbox).await?;

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
        if status.unseen > 0 {
            self.writer.untagged("OK [UNSEEN 1]").await?;
        }

        self.selected_mailbox = Some(mb.name.to_string());
        self.selected_mailbox_mod_seq = Some(snapshot.mod_seq);
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

        let mb = match mailbox::find_mailbox(mailbox_name) {
            Some(m) => m,
            None => {
                return self
                    .writer
                    .tagged_no(tag, &format!("mailbox not found: {}", mailbox_name))
                    .await;
            }
        };

        let scoped_mailbox = self.scoped_mailbox_name(mb.name);
        let status = self.config.store.mailbox_status(&scoped_mailbox).await?;

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
        if self.selected_read_only {
            return self.writer.tagged_no(tag, "mailbox is read-only").await;
        }

        // Silently expunge deleted messages
        self.do_expunge(true).await?;

        self.selected_mailbox = None;
        self.selected_mailbox_mod_seq = None;
        self.selected_read_only = false;
        self.state = State::Authenticated;
        self.writer.tagged_ok(tag, None, "CLOSE completed").await
    }

    async fn cmd_check(&mut self, tag: &str) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }
        // Per RFC 3501, CHECK requests a checkpoint of the mailbox.
        // Implementation-dependent; we treat it as a successful no-op.
        self.writer.tagged_ok(tag, None, "CHECK completed").await
    }

    async fn cmd_examine(&mut self, tag: &str, mailbox_name: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        let mb = match mailbox::find_mailbox(mailbox_name) {
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

        let store = self.config.store.clone();
        let scoped_mailbox = self.scoped_mailbox_name(mb.name);
        let cached_uids = store.list_uids(&scoped_mailbox).await?;

        if cached_uids.is_empty() {
            let client = self.client.as_ref().unwrap();

            let filter = MessageFilter {
                label_id: Some(mb.label_id.to_string()),
                desc: 1,
                ..Default::default()
            };

            let meta_resp = match messages::get_message_metadata(client, &filter, 0, 150).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = %e, "failed to fetch message metadata");
                    return self.writer.tagged_no(tag, "failed to fetch messages").await;
                }
            };

            for meta in &meta_resp.messages {
                let uid = store
                    .store_metadata(&scoped_mailbox, &meta.id, meta.clone())
                    .await?;
                let flags = mailbox::message_flags(meta);
                let flag_strings: Vec<String> = flags.iter().map(|s| s.to_string()).collect();
                store.set_flags(&scoped_mailbox, uid, flag_strings).await?;
            }
        }

        let status = store.mailbox_status(&scoped_mailbox).await?;
        let snapshot = store.mailbox_snapshot(&scoped_mailbox).await?;

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
        if status.unseen > 0 {
            self.writer.untagged("OK [UNSEEN 1]").await?;
        }

        self.selected_mailbox = Some(mb.name.to_string());
        self.selected_mailbox_mod_seq = Some(snapshot.mod_seq);
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
        let store = self.config.store.clone();
        let all_uids = store.list_uids(&scoped_mailbox).await?;

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
            let meta = store.get_metadata(&scoped_mailbox, uid).await?;
            let flags = store.get_flags(&scoped_mailbox, uid).await?;
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
            if needs_body_sections && !header_only_body_fetch {
                rfc822_data = store.get_rfc822(&scoped_mailbox, uid).await?;
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
                    FetchItem::BodyStructure | FetchItem::Body => {
                        // Build BODYSTRUCTURE from RFC822 data if available
                        let structure = if let Some(ref data) = rfc822_data {
                            rfc822::build_bodystructure(data)
                        } else if let Some(ref m) = meta {
                            rfc822::simple_text_structure(m.size as usize)
                        } else {
                            rfc822::simple_text_structure(0)
                        };
                        parts.push(format!("BODYSTRUCTURE {}", structure));
                    }
                    FetchItem::BodySection { section, peek } => {
                        let section_tag = match section {
                            Some(s) => format!("BODY[{}]", s),
                            None => "BODY[]".to_string(),
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

                        if !body_data.is_empty() {
                            let idx = parts.len();
                            parts.push(format!("{} {{{}}}", section_tag, body_data.len()));
                            part_literals.insert(idx, body_data);
                        }

                        if !peek {
                            // Set \Seen flag
                            if !has_seen {
                                store
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
                                        let _ = messages::mark_messages_read(
                                            client,
                                            &[meta.id.as_str()],
                                        )
                                        .await;
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
            .store
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
        let store = &self.config.store;
        let all_uids = store.list_uids(&scoped_mailbox).await?;

        if all_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "STORE completed").await;
        }

        let max_uid = *all_uids.last().unwrap();
        let max_seq = all_uids.len() as u32;

        let target_uids: Vec<u32> = if uid_mode {
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
        };

        let flag_strings: Vec<String> = flags.iter().map(|f| f.as_str().to_string()).collect();
        let silent = matches!(
            action,
            StoreAction::SetFlagsSilent
                | StoreAction::AddFlagsSilent
                | StoreAction::RemoveFlagsSilent
        );

        for &uid in &target_uids {
            match action {
                StoreAction::SetFlags | StoreAction::SetFlagsSilent => {
                    store
                        .set_flags(&scoped_mailbox, uid, flag_strings.clone())
                        .await?;
                }
                StoreAction::AddFlags | StoreAction::AddFlagsSilent => {
                    store.add_flags(&scoped_mailbox, uid, &flag_strings).await?;
                }
                StoreAction::RemoveFlags | StoreAction::RemoveFlagsSilent => {
                    store
                        .remove_flags(&scoped_mailbox, uid, &flag_strings)
                        .await?;
                }
            }

            // Sync flag changes to Proton API
            if let Some(ref client) = self.client {
                if let Some(proton_id) = store.get_proton_id(&scoped_mailbox, uid).await? {
                    let id_ref = proton_id.as_str();
                    for flag in flags {
                        let is_add = matches!(
                            action,
                            StoreAction::SetFlags
                                | StoreAction::SetFlagsSilent
                                | StoreAction::AddFlags
                                | StoreAction::AddFlagsSilent
                        );
                        match flag {
                            ImapFlag::Seen => {
                                if is_add {
                                    let _ = messages::mark_messages_read(client, &[id_ref]).await;
                                } else {
                                    let _ = messages::mark_messages_unread(client, &[id_ref]).await;
                                }
                            }
                            ImapFlag::Flagged => {
                                if is_add {
                                    let _ = messages::label_messages(
                                        client,
                                        &[id_ref],
                                        types::STARRED_LABEL,
                                    )
                                    .await;
                                } else {
                                    let _ = messages::unlabel_messages(
                                        client,
                                        &[id_ref],
                                        types::STARRED_LABEL,
                                    )
                                    .await;
                                }
                            }
                            _ => {} // Other flags are local only
                        }
                    }
                }
            }

            if !silent {
                let seq = store.uid_to_seq(&scoped_mailbox, uid).await?.unwrap_or(0);
                let current_flags = store.get_flags(&scoped_mailbox, uid).await?;
                let flag_str = current_flags.join(" ");
                self.writer
                    .untagged(&format!("{} FETCH (FLAGS ({}))", seq, flag_str))
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
        let store = &self.config.store;
        let all_uids = store.list_uids(&scoped_mailbox).await?;

        let mut results = Vec::new();
        let max_uid = all_uids.last().copied().unwrap_or(0);

        for (i, &uid) in all_uids.iter().enumerate() {
            let seq = i as u32 + 1;
            let meta = store.get_metadata(&scoped_mailbox, uid).await?;
            let flags = store.get_flags(&scoped_mailbox, uid).await?;

            // For content-based search (BODY/TEXT/HEADER), we would need to fetch RFC822 data
            // This is expensive so we pass None for now - those searches will return no matches
            let rfc822_data: Option<&[u8]> = None;
            let matches = criteria
                .iter()
                .all(|c| evaluate_search_key(c, uid, &meta, &flags, max_uid, rfc822_data));

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

        self.do_expunge(false).await?;
        self.writer.tagged_ok(tag, None, "EXPUNGE completed").await
    }

    async fn do_expunge(&mut self, silent: bool) -> Result<()> {
        let mailbox = match &self.selected_mailbox {
            Some(m) => m.clone(),
            None => return Ok(()),
        };
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let store = &self.config.store;
        let all_uids = store.list_uids(&scoped_mailbox).await?;

        let mut expunged_seqs = Vec::new();
        let mut offset = 0u32;

        for (i, &uid) in all_uids.iter().enumerate() {
            let flags = store.get_flags(&scoped_mailbox, uid).await?;
            if flags.iter().any(|f| f == "\\Deleted") {
                let seq = i as u32 + 1 - offset;

                // Move to trash via API
                if let Some(ref client) = self.client {
                    if let Some(proton_id) = store.get_proton_id(&scoped_mailbox, uid).await? {
                        let _ = messages::label_messages(
                            client,
                            &[proton_id.as_str()],
                            types::TRASH_LABEL,
                        )
                        .await;
                    }
                }

                store.remove_message(&scoped_mailbox, uid).await?;
                expunged_seqs.push(seq);
                offset += 1;
            }
        }

        if !silent {
            for seq in &expunged_seqs {
                self.writer.untagged(&format!("{} EXPUNGE", seq)).await?;
            }
        }

        Ok(())
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
        let store = &self.config.store;
        let all_uids = store.list_uids(&scoped_mailbox).await?;

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

            let flags = store.get_flags(&scoped_mailbox, uid).await?;
            if flags.iter().any(|f| f == "\\Deleted") {
                let seq = i as u32 + 1 - offset;

                // Move to trash via API
                if let Some(ref client) = self.client {
                    if let Some(proton_id) = store.get_proton_id(&scoped_mailbox, uid).await? {
                        let _ = messages::label_messages(
                            client,
                            &[proton_id.as_str()],
                            types::TRASH_LABEL,
                        )
                        .await;
                    }
                }

                store.remove_message(&scoped_mailbox, uid).await?;
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

        let dest_mb = match mailbox::find_mailbox(dest_name) {
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
        let store = &self.config.store;
        let all_uids = store.list_uids(&scoped_mailbox).await?;

        if all_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "COPY completed").await;
        }

        let max_uid = *all_uids.last().unwrap();
        let max_seq = all_uids.len() as u32;

        let target_uids: Vec<u32> = if uid_mode {
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
        };

        if let Some(ref client) = self.client {
            for &uid in &target_uids {
                if let Some(proton_id) = store.get_proton_id(&scoped_mailbox, uid).await? {
                    let _ =
                        messages::label_messages(client, &[proton_id.as_str()], dest_mb.label_id)
                            .await;
                }
            }
        }

        self.writer.tagged_ok(tag, None, "COPY completed").await
    }

    /// Get stream halves for TLS upgrade.
    pub fn into_parts(self) -> (R, W) {
        (self.reader.into_inner(), self.writer.into_inner())
    }
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
            // Use message time as approximation for sent date
            meta.as_ref().map(|m| m.time < *ts).unwrap_or(false)
        }
        SearchKey::SentSince(ts) => meta.as_ref().map(|m| m.time >= *ts).unwrap_or(false),
        SearchKey::SentOn(ts) => meta
            .as_ref()
            .map(|m| m.time >= *ts && m.time < *ts + 86400)
            .unwrap_or(false),
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
    use crate::imap::store::InMemoryStore;
    use wiremock::matchers::{header, method, path};
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

    fn test_config() -> Arc<SessionConfig> {
        let session = test_session();
        let accounts = AccountRegistry::from_single_session(session.clone());
        Arc::new(SessionConfig {
            api_base_url: "https://mail-api.proton.me".to_string(),
            auth_router: AuthRouter::new(accounts),
            runtime_accounts: Arc::new(RuntimeAccountRegistry::in_memory(vec![session])),
            store: InMemoryStore::new(),
        })
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
        Arc::new(SessionConfig {
            api_base_url: api_base_url.to_string(),
            auth_router: AuthRouter::new(accounts),
            runtime_accounts,
            store: InMemoryStore::new(),
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
}
