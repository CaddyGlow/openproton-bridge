use std::collections::VecDeque;

use async_trait::async_trait;
use tokio::sync::broadcast;
use tracing::info;

use crate::imap_error::ImapResult as Result;
use crate::imap_store::{ProtonMessageId, StoreEvent, StoreEventKind};
use crate::imap_types::{ImapUid, MessageEnvelope, ScopedMailboxId};

/// A mailbox reference with its mod-sequence for ordering updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluonMailbox {
    pub mailbox: ScopedMailboxId,
    pub mod_seq: u64,
}

/// A message reference within a mailbox (UID + optional Proton ID).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluonMessageRef {
    pub mailbox: ScopedMailboxId,
    pub uid: ImapUid,
    pub proton_id: Option<ProtonMessageId>,
    pub mod_seq: u64,
}

/// A newly created message with its target mailbox names and flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluonCreatedMessage {
    pub message: GluonMessageRef,
    pub mailbox_names: Vec<String>,
    pub flags: Option<Vec<String>>,
}

/// Store-level update events consumed by the IMAP session during IDLE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GluonUpdate {
    Noop,
    MessagesCreated {
        messages: Vec<GluonCreatedMessage>,
        ignore_unknown_mailbox_ids: bool,
    },
    MessageUpdated {
        message: GluonMessageRef,
        mailbox_names: Vec<String>,
        flags: Option<Vec<String>>,
        allow_create: bool,
        ignore_unknown_mailbox_ids: bool,
    },
    MessageDeleted {
        message: GluonMessageRef,
    },
    MessageFlagsUpdated {
        message: GluonMessageRef,
        flags: Option<Vec<String>>,
    },
    MessageMailboxesUpdated {
        message: GluonMessageRef,
        mailbox_names: Vec<String>,
        flags: Option<Vec<String>>,
    },
    MailboxCreated {
        mailbox: GluonMailbox,
    },
    MailboxUpdated {
        mailbox: GluonMailbox,
    },
    MailboxUpdatedOrCreated {
        mailbox: GluonMailbox,
    },
    MailboxDeleted {
        mailbox: GluonMailbox,
    },
    MailboxDeletedSilent {
        mailbox: GluonMailbox,
    },
    MailboxIDChanged {
        mailbox: GluonMailbox,
        remote_id: String,
    },
    MessageIDChanged {
        message: GluonMessageRef,
        remote_id: String,
    },
    UIDValidityBumped {
        mailbox: ScopedMailboxId,
        mod_seq: u64,
    },
}

/// Merges store-level events with authored updates, deduplicating echoes.
#[derive(Debug)]
pub struct GluonUpdateReceiver {
    store_events: broadcast::Receiver<StoreEvent>,
    authored_updates: broadcast::Receiver<GluonUpdate>,
    recent_authored: VecDeque<GluonUpdateKey>,
}

impl GluonUpdateReceiver {
    pub fn new(
        store_events: broadcast::Receiver<StoreEvent>,
        authored_updates: broadcast::Receiver<GluonUpdate>,
    ) -> Self {
        Self {
            store_events,
            authored_updates,
            recent_authored: VecDeque::new(),
        }
    }

    pub async fn recv(&mut self) -> std::result::Result<GluonUpdate, broadcast::error::RecvError> {
        loop {
            tokio::select! {
                update = self.authored_updates.recv() => {
                    let update = update?;
                    self.push_authored_keys(update.keys());
                    log_gluon_update("authored", &update);
                    return Ok(update);
                }
                event = self.store_events.recv() => {
                    let event = event?;
                    if let Some(update) = GluonUpdate::from_store_event(event) {
                        let keys = update.keys();
                        if self.consume_matching_authored(&keys) {
                            log_gluon_update("store_mirrored_ignored", &update);
                            continue;
                        }
                        log_gluon_update("store", &update);
                        return Ok(update);
                    }
                }
            }
        }
    }

    fn push_authored_keys(&mut self, keys: Vec<GluonUpdateKey>) {
        const MAX_RECENT_AUTHORED: usize = 64;
        for key in keys {
            if self.recent_authored.len() >= MAX_RECENT_AUTHORED {
                self.recent_authored.pop_front();
            }
            self.recent_authored.push_back(key);
        }
    }

    fn consume_matching_authored(&mut self, keys: &[GluonUpdateKey]) -> bool {
        if keys.is_empty() {
            return false;
        }

        if keys
            .iter()
            .all(|key| self.recent_authored.iter().any(|known| known == key))
        {
            self.recent_authored
                .retain(|known| !keys.iter().any(|key| key == known));
            return true;
        }

        false
    }
}

/// Store connector for the IMAP session: message CRUD, mailbox lifecycle,
/// update subscriptions, and blob I/O.
#[async_trait]
pub trait GluonImapConnector: Send + Sync {
    fn subscribe_updates(&self) -> GluonUpdateReceiver;
    async fn get_message_literal(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> Result<Option<Vec<u8>>>;
    async fn upsert_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        proton_id: &ProtonMessageId,
        metadata: MessageEnvelope,
    ) -> Result<ImapUid>;
    async fn list_uids(&self, mailbox: &ScopedMailboxId) -> Result<Vec<ImapUid>>;
    async fn mailbox_exists(&self, mailbox: &ScopedMailboxId) -> bool;
    async fn create_mailbox(&self, mailbox: &ScopedMailboxId) -> Result<()>;
    async fn rename_mailbox(
        &self,
        source_mailbox: &ScopedMailboxId,
        dest_mailbox: &ScopedMailboxId,
    ) -> Result<()>;
    async fn delete_mailbox(&self, mailbox: &ScopedMailboxId, silent: bool) -> Result<()>;
    async fn remove_message_by_uid(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<()>;
    async fn remove_message_by_proton_id(
        &self,
        mailbox: &ScopedMailboxId,
        proton_id: &ProtonMessageId,
    ) -> Result<()>;
    async fn update_message_flags(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        flags: Vec<String>,
    ) -> Result<()>;
    async fn copy_message(
        &self,
        source_mailbox: &ScopedMailboxId,
        dest_mailbox: &ScopedMailboxId,
        source_uid: ImapUid,
    ) -> Result<Option<ImapUid>>;
    async fn update_message_mailboxes(
        &self,
        proton_id: &ProtonMessageId,
        previous_mailboxes: &[ScopedMailboxId],
        next_mailboxes: &[ScopedMailboxId],
    ) -> Result<()>;
    async fn store_rfc822(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        data: Vec<u8>,
    ) -> Result<()>;

    async fn acquire_store_session(&self, account_id: Option<&str>) -> Result<crate::StoreSession>;

    fn resolve_storage_user_id<'a>(&'a self, account_id: Option<&'a str>) -> &'a str;

    fn read_message_blob(
        &self,
        storage_user_id: &str,
        internal_message_id: &str,
    ) -> Result<Vec<u8>>;

    fn account_paths(&self, storage_user_id: &str) -> Result<crate::AccountPaths>;

    async fn batch_upsert_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        entries: &[(&ProtonMessageId, MessageEnvelope)],
    ) -> Result<Vec<ImapUid>> {
        let mut uids = Vec::with_capacity(entries.len());
        for (proton_id, metadata) in entries {
            uids.push(
                self.upsert_metadata(mailbox, proton_id, metadata.clone())
                    .await?,
            );
        }
        Ok(uids)
    }
}

impl GluonMailbox {
    pub fn new(mailbox: ScopedMailboxId, mod_seq: u64) -> Self {
        Self { mailbox, mod_seq }
    }
}

impl GluonMessageRef {
    pub fn new(
        mailbox: ScopedMailboxId,
        uid: ImapUid,
        proton_id: Option<ProtonMessageId>,
        mod_seq: u64,
    ) -> Self {
        Self {
            mailbox,
            uid,
            proton_id,
            mod_seq,
        }
    }
}

impl GluonUpdate {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Noop => "noop",
            Self::MessagesCreated { .. } => "messages_created",
            Self::MessageUpdated { .. } => "message_updated",
            Self::MessageDeleted { .. } => "message_deleted",
            Self::MessageFlagsUpdated { .. } => "message_flags_updated",
            Self::MessageMailboxesUpdated { .. } => "message_mailboxes_updated",
            Self::MailboxCreated { .. } => "mailbox_created",
            Self::MailboxUpdated { .. } => "mailbox_updated",
            Self::MailboxUpdatedOrCreated { .. } => "mailbox_updated_or_created",
            Self::MailboxDeleted { .. } => "mailbox_deleted",
            Self::MailboxDeletedSilent { .. } => "mailbox_deleted_silent",
            Self::MailboxIDChanged { .. } => "mailbox_id_changed",
            Self::MessageIDChanged { .. } => "message_id_changed",
            Self::UIDValidityBumped { .. } => "uid_validity_bumped",
        }
    }

    pub fn message_count(&self) -> usize {
        match self {
            Self::MessagesCreated { messages, .. } => messages.len(),
            Self::Noop
            | Self::MailboxCreated { .. }
            | Self::MailboxUpdated { .. }
            | Self::MailboxUpdatedOrCreated { .. }
            | Self::MailboxDeleted { .. }
            | Self::MailboxDeletedSilent { .. }
            | Self::MailboxIDChanged { .. }
            | Self::UIDValidityBumped { .. } => 0,
            _ => 1,
        }
    }

    pub fn messages_created(
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        proton_id: Option<ProtonMessageId>,
        flags: Option<Vec<String>>,
        mod_seq: u64,
    ) -> Self {
        let message = GluonMessageRef::new(mailbox.clone(), uid, proton_id, mod_seq);
        Self::MessagesCreated {
            messages: vec![GluonCreatedMessage {
                mailbox_names: vec![mailbox.mailbox_name().to_string()],
                message,
                flags,
            }],
            ignore_unknown_mailbox_ids: false,
        }
    }

    pub fn message_updated(
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        proton_id: Option<ProtonMessageId>,
        flags: Option<Vec<String>>,
        mod_seq: u64,
    ) -> Self {
        let message = GluonMessageRef::new(mailbox.clone(), uid, proton_id, mod_seq);
        Self::MessageUpdated {
            mailbox_names: vec![mailbox.mailbox_name().to_string()],
            flags,
            message,
            allow_create: false,
            ignore_unknown_mailbox_ids: false,
        }
    }

    pub fn message_deleted(
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        proton_id: Option<ProtonMessageId>,
        mod_seq: u64,
    ) -> Self {
        Self::MessageDeleted {
            message: GluonMessageRef::new(mailbox.clone(), uid, proton_id, mod_seq),
        }
    }

    pub fn affected_scoped_mailboxes(&self) -> Vec<ScopedMailboxId> {
        match self {
            Self::Noop => Vec::new(),
            Self::MessagesCreated { messages, .. } => messages
                .iter()
                .flat_map(|msg| {
                    let account_id = msg.message.mailbox.account_id();
                    msg.mailbox_names
                        .iter()
                        .map(move |name| ScopedMailboxId::from_parts(account_id, name))
                })
                .collect(),
            Self::MessageUpdated {
                message,
                mailbox_names,
                ..
            }
            | Self::MessageMailboxesUpdated {
                message,
                mailbox_names,
                ..
            } => {
                let account_id = message.mailbox.account_id();
                mailbox_names
                    .iter()
                    .map(|name| ScopedMailboxId::from_parts(account_id, name))
                    .collect()
            }
            Self::MessageDeleted { message }
            | Self::MessageFlagsUpdated { message, .. }
            | Self::MessageIDChanged { message, .. } => vec![message.mailbox.clone()],
            Self::MailboxCreated { mailbox }
            | Self::MailboxUpdated { mailbox }
            | Self::MailboxUpdatedOrCreated { mailbox }
            | Self::MailboxDeleted { mailbox }
            | Self::MailboxDeletedSilent { mailbox }
            | Self::MailboxIDChanged { mailbox, .. } => vec![mailbox.mailbox.clone()],
            Self::UIDValidityBumped { mailbox, .. } => vec![mailbox.clone()],
        }
    }

    pub fn affects_scoped_mailbox(&self, scoped_mailbox: &ScopedMailboxId) -> bool {
        self.affected_scoped_mailboxes()
            .iter()
            .any(|m| m == scoped_mailbox)
    }

    pub fn account_id(&self) -> Option<&str> {
        match self {
            Self::Noop => None,
            Self::MessagesCreated { messages, .. } => messages
                .first()
                .and_then(|message| message.message.mailbox.account_id()),
            Self::MessageUpdated { message, .. }
            | Self::MessageDeleted { message }
            | Self::MessageFlagsUpdated { message, .. }
            | Self::MessageMailboxesUpdated { message, .. }
            | Self::MessageIDChanged { message, .. } => message.mailbox.account_id(),
            Self::MailboxCreated { mailbox }
            | Self::MailboxUpdated { mailbox }
            | Self::MailboxUpdatedOrCreated { mailbox }
            | Self::MailboxDeleted { mailbox }
            | Self::MailboxDeletedSilent { mailbox }
            | Self::MailboxIDChanged { mailbox, .. } => mailbox.mailbox.account_id(),
            Self::UIDValidityBumped { mailbox, .. } => mailbox.account_id(),
        }
    }

    pub fn from_store_event(event: StoreEvent) -> Option<Self> {
        let mailbox = ScopedMailboxId::parse(&event.mailbox);
        match event.kind {
            StoreEventKind::MailboxCreated => Some(Self::MailboxCreated {
                mailbox: GluonMailbox::new(mailbox, event.mod_seq),
            }),
            StoreEventKind::MessageAdded => Some(Self::messages_created(
                &mailbox,
                ImapUid::from(event.uid?),
                event.proton_id.map(ProtonMessageId::from),
                None,
                event.mod_seq,
            )),
            StoreEventKind::MessageUpdated | StoreEventKind::MessageBodyUpdated => {
                Some(Self::message_updated(
                    &mailbox,
                    ImapUid::from(event.uid?),
                    event.proton_id.map(ProtonMessageId::from),
                    None,
                    event.mod_seq,
                ))
            }
            StoreEventKind::MessageFlagsUpdated => Some(Self::MessageFlagsUpdated {
                message: GluonMessageRef::new(
                    mailbox,
                    ImapUid::from(event.uid?),
                    event.proton_id.map(ProtonMessageId::from),
                    event.mod_seq,
                ),
                flags: None,
            }),
            StoreEventKind::MessageRemoved => Some(Self::message_deleted(
                &mailbox,
                ImapUid::from(event.uid?),
                event.proton_id.map(ProtonMessageId::from),
                event.mod_seq,
            )),
        }
    }

    pub fn keys(&self) -> Vec<GluonUpdateKey> {
        match self {
            Self::Noop => Vec::new(),
            Self::MessagesCreated { messages, .. } => messages
                .iter()
                .map(|message| GluonUpdateKey {
                    scoped_mailbox: message.message.mailbox.clone(),
                    uid: Some(message.message.uid),
                    proton_id: message.message.proton_id.clone(),
                    kind: GluonUpdateKeyKind::MessagesCreated,
                })
                .collect(),
            Self::MessageUpdated { message, .. } => vec![GluonUpdateKey {
                scoped_mailbox: message.mailbox.clone(),
                uid: Some(message.uid),
                proton_id: message.proton_id.clone(),
                kind: GluonUpdateKeyKind::MessageUpdated,
            }],
            Self::MessageDeleted { message } => vec![GluonUpdateKey {
                scoped_mailbox: message.mailbox.clone(),
                uid: Some(message.uid),
                proton_id: message.proton_id.clone(),
                kind: GluonUpdateKeyKind::MessageDeleted,
            }],
            Self::MessageFlagsUpdated { message, .. } => vec![GluonUpdateKey {
                scoped_mailbox: message.mailbox.clone(),
                uid: Some(message.uid),
                proton_id: message.proton_id.clone(),
                kind: GluonUpdateKeyKind::MessageFlagsUpdated,
            }],
            Self::MessageMailboxesUpdated { message, .. } => vec![GluonUpdateKey {
                scoped_mailbox: message.mailbox.clone(),
                uid: Some(message.uid),
                proton_id: message.proton_id.clone(),
                kind: GluonUpdateKeyKind::MessageMailboxesUpdated,
            }],
            Self::MailboxCreated { mailbox } => vec![GluonUpdateKey {
                scoped_mailbox: mailbox.mailbox.clone(),
                uid: None,
                proton_id: None,
                kind: GluonUpdateKeyKind::MailboxCreated,
            }],
            Self::MailboxUpdated { mailbox } => vec![GluonUpdateKey {
                scoped_mailbox: mailbox.mailbox.clone(),
                uid: None,
                proton_id: None,
                kind: GluonUpdateKeyKind::MailboxUpdated,
            }],
            Self::MailboxUpdatedOrCreated { mailbox } => vec![GluonUpdateKey {
                scoped_mailbox: mailbox.mailbox.clone(),
                uid: None,
                proton_id: None,
                kind: GluonUpdateKeyKind::MailboxUpdatedOrCreated,
            }],
            Self::MailboxDeleted { mailbox } => vec![GluonUpdateKey {
                scoped_mailbox: mailbox.mailbox.clone(),
                uid: None,
                proton_id: None,
                kind: GluonUpdateKeyKind::MailboxDeleted,
            }],
            Self::MailboxDeletedSilent { mailbox } => vec![GluonUpdateKey {
                scoped_mailbox: mailbox.mailbox.clone(),
                uid: None,
                proton_id: None,
                kind: GluonUpdateKeyKind::MailboxDeletedSilent,
            }],
            Self::MailboxIDChanged { mailbox, remote_id } => vec![GluonUpdateKey {
                scoped_mailbox: mailbox.mailbox.clone(),
                uid: None,
                proton_id: Some(ProtonMessageId::from(remote_id.as_str())),
                kind: GluonUpdateKeyKind::MailboxIDChanged,
            }],
            Self::MessageIDChanged { message, remote_id } => vec![GluonUpdateKey {
                scoped_mailbox: message.mailbox.clone(),
                uid: Some(message.uid),
                proton_id: Some(ProtonMessageId::from(remote_id.as_str())),
                kind: GluonUpdateKeyKind::MessageIDChanged,
            }],
            Self::UIDValidityBumped { mailbox, .. } => vec![GluonUpdateKey {
                scoped_mailbox: mailbox.clone(),
                uid: None,
                proton_id: None,
                kind: GluonUpdateKeyKind::UIDValidityBumped,
            }],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluonUpdateKey {
    pub scoped_mailbox: ScopedMailboxId,
    pub uid: Option<ImapUid>,
    pub proton_id: Option<ProtonMessageId>,
    pub kind: GluonUpdateKeyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GluonUpdateKeyKind {
    MessagesCreated,
    MessageUpdated,
    MessageDeleted,
    MessageFlagsUpdated,
    MessageMailboxesUpdated,
    MailboxCreated,
    MailboxUpdated,
    MailboxUpdatedOrCreated,
    MailboxDeleted,
    MailboxDeletedSilent,
    MailboxIDChanged,
    MessageIDChanged,
    UIDValidityBumped,
}

fn log_gluon_update(source: &str, update: &GluonUpdate) {
    let keys = update.keys();
    let primary = keys.first();
    let scoped_mailbox = primary
        .map(|key| key.scoped_mailbox.as_str())
        .unwrap_or_default();
    let account_id = update.account_id().unwrap_or_default();
    info!(
        service = "imap",
        pkg = "gluon/user",
        source,
        update_kind = update.kind(),
        account_id,
        update_keys = keys.len(),
        affected_mailboxes = update.affected_scoped_mailboxes().len(),
        message_count = update.message_count(),
        scoped_mailbox,
        uid = ?primary.and_then(|key| key.uid.map(|u| u.value())),
        proton_id = ?primary.and_then(|key| key.proton_id.as_ref().map(|p| p.as_str())),
        "Applying update"
    );
}
