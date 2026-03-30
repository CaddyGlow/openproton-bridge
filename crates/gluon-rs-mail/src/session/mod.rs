mod append;
mod auth;
mod copy_move;
mod expunge;
mod fetch;
mod helpers;
mod idle;
mod mailbox_cmds;
mod misc;
mod search;
mod store;

#[allow(unused_imports)]
pub use append::*;
#[allow(unused_imports)]
pub use auth::*;
#[allow(unused_imports)]
pub use copy_move::*;
#[allow(unused_imports)]
pub use expunge::*;
#[allow(unused_imports)]
pub use fetch::*;
#[allow(unused_imports)]
pub use helpers::*;
#[allow(unused_imports)]
pub use idle::*;
#[allow(unused_imports)]
pub use mailbox_cmds::*;
#[allow(unused_imports)]
pub use misc::*;
#[allow(unused_imports)]
pub use search::*;
#[allow(unused_imports)]
pub use store::*;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::debug;

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

/// IMAP session state machine (RFC 3501 section 3).
#[derive(Debug, Clone, PartialEq)]
pub enum State {
    /// Before LOGIN/AUTHENTICATE.
    NotAuthenticated,
    /// After successful authentication, no mailbox selected.
    Authenticated,
    /// A mailbox is selected.
    Selected,
    /// Session is terminating.
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

/// Shared configuration injected into every IMAP session.
pub struct SessionConfig {
    /// Upstream mail provider (authentication, message fetch/import).
    pub connector: Arc<dyn crate::imap_connector::ImapConnector>,
    /// Store-level connector for message CRUD and update subscriptions.
    pub gluon_connector: Arc<dyn GluonImapConnector>,
    /// Mailbox catalog for LIST/LSUB resolution.
    pub mailbox_catalog: Arc<dyn GluonMailboxCatalog>,
    /// Write-side mailbox operations (flags, metadata, expunge).
    pub mailbox_mutation: Arc<dyn GluonMailboxMutation>,
    /// Read-side mailbox operations (SELECT data, metadata lookup).
    pub mailbox_view: Arc<dyn GluonMailboxView>,
    /// Shared tracker for \Recent flag semantics.
    pub recent_tracker: Arc<RecentTracker>,
    /// Shutdown signal; sessions exit when this fires.
    pub shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    /// Channel for emitting session lifecycle events.
    pub event_tx: Option<tokio::sync::broadcast::Sender<crate::imap_types::SessionEvent>>,
    /// Hierarchy delimiter character (usually '/').
    pub delimiter: char,
    /// Delay after failed login to deter brute-force attacks.
    pub login_jail_time: Duration,
    /// Batching window for IDLE notifications.
    pub idle_bulk_time: Duration,
    /// Resource limits (message size, command length, idle timeout).
    pub limits: crate::imap_types::ImapLimits,
    /// Optional backend for multi-user session management.
    pub backend: Option<Arc<crate::backend::GluonBackend>>,
}

static NEXT_IMAP_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Action returned by the session loop to signal the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAction {
    /// Keep processing commands.
    Continue,
    /// Upgrade the connection to TLS (STARTTLS).
    StartTls,
    /// Terminate the connection.
    Close,
}

/// Per-connection IMAP4rev1 session state machine.
///
/// Generic over `R` (reader) and `W` (writer) so it works with both
/// plain TCP and TLS streams.
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

    fn emit_close_event(&self) {
        if let Some(tx) = &self.config.event_tx {
            let _ = tx.send(crate::imap_types::SessionEvent::Close {
                session_id: self.connection_id,
            });
        }
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
                        self.emit_close_event();
                        return Ok(SessionAction::Close);
                    }
                    result = self.reader.read_line(&mut line) => {
                        let n = result?;
                        if n == 0 {
                            debug!(connection_id = self.connection_id, "client disconnected");
                            self.emit_close_event();
                            return Ok(SessionAction::Close);
                        }
                    }
                }
            } else {
                let n = self.reader.read_line(&mut line).await?;
                if n == 0 {
                    debug!(connection_id = self.connection_id, "client disconnected");
                    self.emit_close_event();
                    return Ok(SessionAction::Close);
                }
            }

            if line.len() > self.config.limits.max_command_length {
                let tag = line.split_whitespace().next().unwrap_or("*").to_string();
                self.writer
                    .tagged_bad(&tag, "command exceeds maximum length")
                    .await?;
                continue;
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
                SessionAction::Close => {
                    self.emit_close_event();
                    return Ok(SessionAction::Close);
                }
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

    /// Get stream halves for TLS upgrade.
    pub fn into_parts(self) -> (R, W) {
        (self.reader.into_inner(), self.writer.into_inner())
    }
}
