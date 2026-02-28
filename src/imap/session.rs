use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use crate::api::client::ProtonClient;
use crate::api::messages;
use crate::api::types::{self, MessageFilter, Session};
use crate::crypto::keys::{self, Keyring};

use super::command::{
    parse_command, Command, FetchItem, ImapFlag, SearchKey, SequenceSet, StoreAction,
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
    pub session: Session,
    pub bridge_password: String,
    pub store: Arc<dyn MessageStore>,
}

/// Sentinel returned to the caller to signal STARTTLS upgrade is needed.
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
}

impl<R, W> ImapSession<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    pub fn new(reader: R, writer: W, config: Arc<SessionConfig>) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer: ResponseWriter::new(writer),
            state: State::NotAuthenticated,
            config,
            client: None,
            user_keyring: None,
            addr_keyrings: None,
            selected_mailbox: None,
        }
    }

    pub async fn greet(&mut self) -> Result<()> {
        self.writer
            .untagged("OK IMAP4rev1 openproton-bridge ready")
            .await
    }

    pub async fn run(&mut self) -> Result<()> {
        self.greet().await?;

        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).await?;
            if n == 0 {
                debug!("client disconnected");
                break;
            }

            let line = line.trim_end().to_string();
            if line.is_empty() {
                continue;
            }

            debug!(line = %line, "received command");

            match self.handle_line(&line).await? {
                SessionAction::Continue => {}
                SessionAction::StartTls => return Ok(()),
                SessionAction::Close => break,
            }
        }

        Ok(())
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
            Command::StartTls { ref tag } => {
                self.cmd_starttls(tag).await?;
                return Ok(SessionAction::StartTls);
            }
            Command::List {
                ref tag,
                ref reference,
                ref pattern,
            } => self.cmd_list(tag, reference, pattern).await?,
            Command::Select {
                ref tag,
                ref mailbox,
            } => self.cmd_select(tag, mailbox).await?,
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
        }

        Ok(SessionAction::Continue)
    }

    async fn cmd_capability(&mut self, tag: &str) -> Result<()> {
        let caps = if self.state == State::NotAuthenticated {
            "CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN"
        } else {
            "CAPABILITY IMAP4rev1"
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

        // Validate credentials: username must match email, password must match bridge password
        // Use constant-time comparison for the password to prevent timing side-channel attacks
        let email_ok = username.eq_ignore_ascii_case(&self.config.session.email);
        let password_ok: bool = password
            .as_bytes()
            .ct_eq(self.config.bridge_password.as_bytes())
            .into();
        if !email_ok || !password_ok {
            return self
                .writer
                .tagged_no(tag, "[AUTHENTICATIONFAILED] invalid credentials")
                .await;
        }

        // Create authenticated ProtonClient
        let client = match ProtonClient::authenticated(
            "https://mail-api.proton.me",
            &self.config.session.uid,
            &self.config.session.access_token,
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
        let passphrase_b64 = match &self.config.session.key_passphrase {
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

        // Fetch user keys and unlock
        let user_resp = match crate::api::users::get_user(&client).await {
            Ok(r) => r,
            Err(e) => {
                passphrase.zeroize();
                warn!(error = %e, "failed to fetch user info");
                return self
                    .writer
                    .tagged_no(tag, "failed to fetch user info")
                    .await;
            }
        };

        let user_keyring = match keys::unlock_user_keys(&user_resp.user.keys, &passphrase) {
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

        let addr_resp = match crate::api::users::get_addresses(&client).await {
            Ok(r) => r,
            Err(e) => {
                passphrase.zeroize();
                warn!(error = %e, "failed to fetch addresses");
                return self
                    .writer
                    .tagged_no(tag, "failed to fetch addresses")
                    .await;
            }
        };

        let mut addr_keyrings = HashMap::new();
        for addr in &addr_resp.addresses {
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
        self.state = State::Authenticated;

        info!(email = %self.config.session.email, "IMAP login successful");
        self.writer.tagged_ok(tag, None, "LOGIN completed").await
    }

    async fn cmd_logout(&mut self, tag: &str) -> Result<()> {
        self.writer.untagged("BYE server logging out").await?;
        self.state = State::Logout;
        self.writer.tagged_ok(tag, None, "LOGOUT completed").await
    }

    async fn cmd_noop(&mut self, tag: &str) -> Result<()> {
        self.writer.tagged_ok(tag, None, "NOOP completed").await
    }

    async fn cmd_starttls(&mut self, tag: &str) -> Result<()> {
        if self.state != State::NotAuthenticated {
            return self
                .writer
                .tagged_bad(tag, "STARTTLS only in not-authenticated state")
                .await;
        }
        self.writer
            .tagged_ok(tag, None, "begin TLS negotiation")
            .await
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
            for mb in &mailboxes {
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

        let store = &self.config.store;

        // Populate store with message metadata
        for meta in &meta_resp.messages {
            let uid = store
                .store_metadata(mb.name, &meta.id, meta.clone())
                .await?;
            // Initialize flags from metadata
            let flags = mailbox::message_flags(meta);
            let flag_strings: Vec<String> = flags.iter().map(|s| s.to_string()).collect();
            store.set_flags(mb.name, uid, flag_strings).await?;
        }

        let status = store.mailbox_status(mb.name).await?;

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
        self.state = State::Selected;

        info!(
            mailbox = %mb.name,
            messages = status.exists,
            "mailbox selected"
        );

        self.writer
            .tagged_ok(tag, Some("READ-WRITE"), "SELECT completed")
            .await
    }

    async fn cmd_close(&mut self, tag: &str) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        // Silently expunge deleted messages
        self.do_expunge(true).await?;

        self.selected_mailbox = None;
        self.state = State::Authenticated;
        self.writer.tagged_ok(tag, None, "CLOSE completed").await
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
        let store = &self.config.store;
        let all_uids = store.list_uids(&mailbox).await?;

        if all_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "FETCH completed").await;
        }

        let max_uid = *all_uids.last().unwrap();
        let max_seq = all_uids.len() as u32;

        // Expand macro items
        let expanded = expand_fetch_items(items);

        // Resolve which UIDs to fetch
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

        for &uid in &target_uids {
            let seq = store.uid_to_seq(&mailbox, uid).await?.unwrap_or(0);
            let meta = store.get_metadata(&mailbox, uid).await?;
            let flags = store.get_flags(&mailbox, uid).await?;

            let mut parts: Vec<String> = Vec::new();
            let mut part_literals: HashMap<usize, Vec<u8>> = HashMap::new();

            let needs_body = expanded
                .iter()
                .any(|i| matches!(i, FetchItem::BodySection { .. }));

            let mut rfc822_data = None;
            if needs_body {
                rfc822_data = store.get_rfc822(&mailbox, uid).await?;
                if rfc822_data.is_none() {
                    // Fetch + decrypt on demand
                    if let Some(ref meta) = meta {
                        rfc822_data = self.fetch_and_cache_rfc822(&mailbox, uid, &meta.id).await?;
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
                        // Minimal BODYSTRUCTURE for compatibility
                        parts.push(
                            "BODYSTRUCTURE (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"8BIT\" 0 0)"
                                .to_string(),
                        );
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
                            if !flags.contains(&"\\Seen".to_string()) {
                                store
                                    .add_flags(&mailbox, uid, &["\\Seen".to_string()])
                                    .await?;
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

        self.writer.flush().await?;
        self.writer.tagged_ok(tag, None, "FETCH completed").await
    }

    async fn fetch_and_cache_rfc822(
        &self,
        mailbox: &str,
        uid: u32,
        proton_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        let client = match &self.client {
            Some(c) => c,
            None => return Ok(None),
        };

        let msg_resp = match messages::get_message(client, proton_id).await {
            Ok(r) => r,
            Err(e) => {
                warn!(proton_id = %proton_id, error = %e, "failed to fetch message");
                return Ok(None);
            }
        };

        let msg = &msg_resp.message;

        // Find the right keyring for this message's address
        let keyring = match &self.addr_keyrings {
            Some(keyrings) => match keyrings.get(&msg.metadata.address_id) {
                Some(kr) => kr,
                None => {
                    warn!(
                        address_id = %msg.metadata.address_id,
                        "no keyring for address"
                    );
                    return Ok(None);
                }
            },
            None => return Ok(None),
        };

        let data = match rfc822::build_rfc822(client, keyring, msg).await {
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

        let mailbox = self.selected_mailbox.as_ref().unwrap().clone();
        let store = &self.config.store;
        let all_uids = store.list_uids(&mailbox).await?;

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
                    store.set_flags(&mailbox, uid, flag_strings.clone()).await?;
                }
                StoreAction::AddFlags | StoreAction::AddFlagsSilent => {
                    store.add_flags(&mailbox, uid, &flag_strings).await?;
                }
                StoreAction::RemoveFlags | StoreAction::RemoveFlagsSilent => {
                    store.remove_flags(&mailbox, uid, &flag_strings).await?;
                }
            }

            // Sync flag changes to Proton API
            if let Some(ref client) = self.client {
                if let Some(proton_id) = store.get_proton_id(&mailbox, uid).await? {
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
                let seq = store.uid_to_seq(&mailbox, uid).await?.unwrap_or(0);
                let current_flags = store.get_flags(&mailbox, uid).await?;
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
        let store = &self.config.store;
        let all_uids = store.list_uids(&mailbox).await?;

        let mut results = Vec::new();
        let max_uid = all_uids.last().copied().unwrap_or(0);

        for (i, &uid) in all_uids.iter().enumerate() {
            let seq = i as u32 + 1;
            let meta = store.get_metadata(&mailbox, uid).await?;
            let flags = store.get_flags(&mailbox, uid).await?;

            let matches = criteria
                .iter()
                .all(|c| evaluate_search_key(c, uid, &meta, &flags, max_uid));

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

        self.do_expunge(false).await?;
        self.writer.tagged_ok(tag, None, "EXPUNGE completed").await
    }

    async fn do_expunge(&mut self, silent: bool) -> Result<()> {
        let mailbox = match &self.selected_mailbox {
            Some(m) => m.clone(),
            None => return Ok(()),
        };
        let store = &self.config.store;
        let all_uids = store.list_uids(&mailbox).await?;

        let mut expunged_seqs = Vec::new();
        let mut offset = 0u32;

        for (i, &uid) in all_uids.iter().enumerate() {
            let flags = store.get_flags(&mailbox, uid).await?;
            if flags.iter().any(|f| f == "\\Deleted") {
                let seq = i as u32 + 1 - offset;

                // Move to trash via API
                if let Some(ref client) = self.client {
                    if let Some(proton_id) = store.get_proton_id(&mailbox, uid).await? {
                        let _ = messages::label_messages(
                            client,
                            &[proton_id.as_str()],
                            types::TRASH_LABEL,
                        )
                        .await;
                    }
                }

                store.remove_message(&mailbox, uid).await?;
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
        let store = &self.config.store;
        let all_uids = store.list_uids(&mailbox).await?;

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
                if let Some(proton_id) = store.get_proton_id(&mailbox, uid).await? {
                    let _ =
                        messages::label_messages(client, &[proton_id.as_str()], dest_mb.label_id)
                            .await;
                }
            }
        }

        self.writer.tagged_ok(tag, None, "COPY completed").await
    }

    /// Get the inner writer (for TLS upgrade).
    pub fn into_parts(self) -> (BufReader<R>, ResponseWriter<W>, Arc<SessionConfig>) {
        (self.reader, self.writer, self.config)
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
) -> bool {
    match key {
        SearchKey::All => true,
        SearchKey::Seen => flags.iter().any(|f| f == "\\Seen"),
        SearchKey::Unseen => !flags.iter().any(|f| f == "\\Seen"),
        SearchKey::Flagged => flags.iter().any(|f| f == "\\Flagged"),
        SearchKey::Deleted => flags.iter().any(|f| f == "\\Deleted"),
        SearchKey::Answered => flags.iter().any(|f| f == "\\Answered"),
        SearchKey::Draft => flags.iter().any(|f| f == "\\Draft"),
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
        SearchKey::Uid(seq) => seq.contains(uid, max_uid),
        SearchKey::Not(inner) => !evaluate_search_key(inner, uid, meta, flags, max_uid),
        SearchKey::Or(a, b) => {
            evaluate_search_key(a, uid, meta, flags, max_uid)
                || evaluate_search_key(b, uid, meta, flags, max_uid)
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
    use crate::imap::store::InMemoryStore;

    fn test_session() -> Session {
        Session {
            uid: "test-uid".to_string(),
            access_token: "test-token".to_string(),
            refresh_token: "test-refresh".to_string(),
            email: "test@proton.me".to_string(),
            display_name: "Test User".to_string(),
            key_passphrase: Some("dGVzdA==".to_string()),
            bridge_password: Some("bridge-pass-1234".to_string()),
        }
    }

    fn test_config() -> Arc<SessionConfig> {
        Arc::new(SessionConfig {
            session: test_session(),
            bridge_password: "bridge-pass-1234".to_string(),
            store: InMemoryStore::new(),
        })
    }

    fn make_meta(id: &str, unread: i32) -> MessageMetadata {
        MessageMetadata {
            id: id.to_string(),
            address_id: "addr-1".to_string(),
            label_ids: vec!["0".to_string()],
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
            time: 1700000000,
            size: 1024,
            unread,
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

    #[test]
    fn test_evaluate_search_all() {
        let meta = Some(make_meta("msg-1", 1));
        let flags = vec![];
        assert!(evaluate_search_key(&SearchKey::All, 1, &meta, &flags, 1));
    }

    #[test]
    fn test_evaluate_search_seen() {
        let meta = Some(make_meta("msg-1", 0));
        let flags = vec!["\\Seen".to_string()];
        assert!(evaluate_search_key(&SearchKey::Seen, 1, &meta, &flags, 1));
        assert!(!evaluate_search_key(
            &SearchKey::Unseen,
            1,
            &meta,
            &flags,
            1
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
            1
        ));
        assert!(!evaluate_search_key(
            &SearchKey::Subject("NotFound".to_string()),
            1,
            &meta,
            &flags,
            1
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
            1
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
            1
        ));
    }
}
