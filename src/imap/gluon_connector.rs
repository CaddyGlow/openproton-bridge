use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use gluon_rs_mail::{CompatibleStore, NewMailbox, UpstreamMailbox};
use tokio::sync::broadcast;
use tracing::{debug, info};

use super::gluon_mailbox_mutation::GluonMailMailboxMutation;
use super::gluon_mailbox_view::GluonMailMailboxView;
use super::mailbox_mutation::GluonMailboxMutation;
use super::mailbox_view::GluonMailboxView;
use super::store::{StoreEvent, StoreEventKind};
use super::types::{ImapUid, ProtonMessageId, ScopedMailboxId};
use super::{ImapError, Result};
use crate::api::types::MessageMetadata;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluonMailbox {
    pub mailbox: ScopedMailboxId,
    pub mod_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluonMessageRef {
    pub mailbox: ScopedMailboxId,
    pub uid: ImapUid,
    pub proton_id: Option<ProtonMessageId>,
    pub mod_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluonCreatedMessage {
    pub message: GluonMessageRef,
    pub mailbox_names: Vec<String>,
    pub flags: Option<Vec<String>>,
}

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

#[derive(Debug)]
pub struct GluonUpdateReceiver {
    store_events: broadcast::Receiver<StoreEvent>,
    authored_updates: broadcast::Receiver<GluonUpdate>,
    recent_authored: VecDeque<GluonUpdateKey>,
}

impl GluonUpdateReceiver {
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
        metadata: MessageMetadata,
    ) -> Result<ImapUid>;
    async fn list_uids(&self, mailbox: &ScopedMailboxId) -> Result<Vec<ImapUid>>;
    fn create_mailbox(&self, mailbox: &ScopedMailboxId) -> Result<()>;
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

    async fn batch_upsert_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        entries: &[(&ProtonMessageId, MessageMetadata)],
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

#[derive(Clone)]
pub struct GluonMailConnector {
    store: Arc<CompatibleStore>,
    view: Arc<dyn GluonMailboxView>,
    mutation: Arc<dyn GluonMailboxMutation>,
    store_events_tx: broadcast::Sender<StoreEvent>,
    authored_tx: broadcast::Sender<GluonUpdate>,
}

impl GluonMailConnector {
    pub fn new(store: Arc<CompatibleStore>) -> Arc<Self> {
        let (store_events_tx, _store_events_rx) = broadcast::channel(16);
        let (authored_tx, _authored_rx) = broadcast::channel(256);
        Arc::new(Self {
            view: GluonMailMailboxView::new(store.clone()),
            mutation: GluonMailMailboxMutation::new(store.clone()),
            store,
            store_events_tx,
            authored_tx,
        })
    }

    fn publish_authored(&self, update: GluonUpdate) {
        log_gluon_update("connector_gluon_mail", &update);
        let _ = self.authored_tx.send(update);
    }

    fn storage_user_id_for_account<'a>(&'a self, account_id: Option<&'a str>) -> &'a str {
        let account_id = account_id.unwrap_or("__default__");
        self.store
            .bootstrap()
            .accounts
            .iter()
            .find(|account| account.account_id == account_id)
            .map(|account| account.storage_user_id.as_str())
            .unwrap_or(account_id)
    }

    fn mailbox_by_name(
        &self,
        storage_user_id: &str,
        mailbox_name: &str,
    ) -> Result<Option<UpstreamMailbox>> {
        match self.store.list_upstream_mailboxes(storage_user_id) {
            Ok(mailboxes) => Ok(mailboxes
                .into_iter()
                .find(|mailbox| mailbox.name.eq_ignore_ascii_case(mailbox_name))),
            Err(gluon_rs_mail::GluonError::IncompatibleSchema { family })
                if family == "Missing" =>
            {
                Ok(None)
            }
            Err(err) => Err(map_mail_error(err)),
        }
    }

    fn ensure_mailbox(&self, mailbox: &ScopedMailboxId) -> Result<(String, UpstreamMailbox)> {
        let account_id = mailbox.account_id();
        let mailbox_name = mailbox.mailbox_name();
        let mailbox_name = if mailbox_name.is_empty() {
            "INBOX"
        } else {
            mailbox_name
        };
        let storage_user_id = self.storage_user_id_for_account(account_id).to_string();
        if let Some(mailbox_state) = self.mailbox_by_name(&storage_user_id, mailbox_name)? {
            debug!(
                service = "imap",
                pkg = "gluon/user",
                account_id = account_id.unwrap_or_default(),
                storage_user_id = %storage_user_id,
                mailbox_name = %mailbox_name,
                "resolved existing Gluon mailbox"
            );
            return Ok((storage_user_id, mailbox_state));
        }

        let created = self
            .store
            .create_mailbox(
                &storage_user_id,
                &NewMailbox {
                    remote_id: mailbox_name.to_string(),
                    name: mailbox_name.to_string(),
                    uid_validity: current_uid_validity(),
                    subscribed: true,
                    attributes: Vec::new(),
                    flags: Vec::new(),
                    permanent_flags: vec![
                        "\\Seen".to_string(),
                        "\\Flagged".to_string(),
                        "\\Answered".to_string(),
                        "\\Draft".to_string(),
                        "\\Deleted".to_string(),
                    ],
                },
            )
            .map_err(map_mail_error)?;
        debug!(
            service = "imap",
            pkg = "gluon/user",
            account_id = account_id.unwrap_or_default(),
            storage_user_id = %storage_user_id,
            mailbox_name = %mailbox_name,
            internal_id = created.internal_id,
            "created Gluon mailbox"
        );
        Ok((storage_user_id, created))
    }
}

#[async_trait]
impl GluonImapConnector for GluonMailConnector {
    fn subscribe_updates(&self) -> GluonUpdateReceiver {
        GluonUpdateReceiver {
            store_events: self.store_events_tx.subscribe(),
            authored_updates: self.authored_tx.subscribe(),
            recent_authored: VecDeque::new(),
        }
    }

    async fn get_message_literal(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> Result<Option<Vec<u8>>> {
        self.view.get_rfc822(mailbox, uid).await
    }

    async fn upsert_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        proton_id: &ProtonMessageId,
        metadata: MessageMetadata,
    ) -> Result<ImapUid> {
        let existing_uid = self.view.get_uid(mailbox, proton_id).await?;
        let uid = self
            .mutation
            .store_metadata(mailbox, proton_id, metadata)
            .await?;
        let flags = self.mutation.get_flags(mailbox, uid).await.ok();

        self.publish_authored(if existing_uid.is_some() {
            GluonUpdate::message_updated(mailbox, uid, Some(proton_id.clone()), flags, 0)
        } else {
            GluonUpdate::messages_created(mailbox, uid, Some(proton_id.clone()), flags, 0)
        });

        Ok(uid)
    }

    async fn list_uids(&self, mailbox: &ScopedMailboxId) -> Result<Vec<ImapUid>> {
        self.view.list_uids(mailbox).await
    }

    fn create_mailbox(&self, mailbox: &ScopedMailboxId) -> Result<()> {
        let _ = self.ensure_mailbox(mailbox)?;
        self.publish_authored(GluonUpdate::MailboxCreated {
            mailbox: GluonMailbox::new(mailbox.clone(), 0),
        });
        Ok(())
    }

    async fn rename_mailbox(
        &self,
        source_mailbox: &ScopedMailboxId,
        dest_mailbox: &ScopedMailboxId,
    ) -> Result<()> {
        if source_mailbox == dest_mailbox {
            return Ok(());
        }

        let source_storage_user_id = self
            .storage_user_id_for_account(source_mailbox.account_id())
            .to_string();

        if let Some(source_mailbox_state) =
            self.mailbox_by_name(&source_storage_user_id, source_mailbox.mailbox_name())?
        {
            self.store
                .rename_mailbox(
                    &source_storage_user_id,
                    source_mailbox_state.internal_id,
                    dest_mailbox.mailbox_name(),
                )
                .map_err(map_mail_error)?;
        } else {
            let _ = self.ensure_mailbox(dest_mailbox)?;
        }

        self.publish_authored(GluonUpdate::MailboxUpdated {
            mailbox: GluonMailbox::new(dest_mailbox.clone(), 0),
        });
        self.publish_authored(GluonUpdate::MailboxDeletedSilent {
            mailbox: GluonMailbox::new(source_mailbox.clone(), 0),
        });
        Ok(())
    }

    async fn delete_mailbox(&self, mailbox: &ScopedMailboxId, silent: bool) -> Result<()> {
        let storage_user_id = self
            .storage_user_id_for_account(mailbox.account_id())
            .to_string();
        if let Some(mailbox_state) =
            self.mailbox_by_name(&storage_user_id, mailbox.mailbox_name())?
        {
            self.store
                .delete_mailbox(&storage_user_id, mailbox_state.internal_id)
                .map_err(map_mail_error)?;
        }

        self.publish_authored(if silent {
            GluonUpdate::MailboxDeletedSilent {
                mailbox: GluonMailbox::new(mailbox.clone(), 0),
            }
        } else {
            GluonUpdate::MailboxDeleted {
                mailbox: GluonMailbox::new(mailbox.clone(), 0),
            }
        });

        Ok(())
    }

    async fn remove_message_by_uid(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<()> {
        let proton_id = self.view.get_proton_id(mailbox, uid).await?;
        self.mutation.remove_message(mailbox, uid).await?;
        self.publish_authored(GluonUpdate::message_deleted(
            mailbox,
            uid,
            proton_id.map(ProtonMessageId::from),
            0,
        ));
        Ok(())
    }

    async fn remove_message_by_proton_id(
        &self,
        mailbox: &ScopedMailboxId,
        proton_id: &ProtonMessageId,
    ) -> Result<()> {
        if let Some(uid) = self.view.get_uid(mailbox, proton_id).await? {
            self.mutation.remove_message(mailbox, uid).await?;
            self.publish_authored(GluonUpdate::message_deleted(
                mailbox,
                uid,
                Some(proton_id.clone()),
                0,
            ));
        }
        Ok(())
    }

    async fn update_message_flags(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        flags: Vec<String>,
    ) -> Result<()> {
        let proton_id = self
            .view
            .get_proton_id(mailbox, uid)
            .await?
            .map(ProtonMessageId::from);
        self.mutation.set_flags(mailbox, uid, flags.clone()).await?;
        self.publish_authored(GluonUpdate::MessageFlagsUpdated {
            message: GluonMessageRef::new(mailbox.clone(), uid, proton_id, 0),
            flags: Some(flags),
        });
        Ok(())
    }

    async fn copy_message(
        &self,
        source_mailbox: &ScopedMailboxId,
        dest_mailbox: &ScopedMailboxId,
        source_uid: ImapUid,
    ) -> Result<Option<ImapUid>> {
        let Some(proton_id_str) = self
            .mutation
            .get_proton_id(source_mailbox, source_uid)
            .await?
        else {
            return Ok(None);
        };
        let proton_id = ProtonMessageId::from(proton_id_str);
        let Some(metadata) = self
            .mutation
            .get_metadata(source_mailbox, source_uid)
            .await?
        else {
            return Ok(None);
        };

        let dest_uid = self
            .mutation
            .store_metadata(dest_mailbox, &proton_id, metadata)
            .await?;

        let flags = self.mutation.get_flags(source_mailbox, source_uid).await?;
        self.mutation
            .set_flags(dest_mailbox, dest_uid, flags.clone())
            .await?;

        if let Some(rfc822) = self.mutation.get_rfc822(source_mailbox, source_uid).await? {
            self.mutation
                .store_rfc822(dest_mailbox, dest_uid, rfc822)
                .await?;
        }

        self.publish_authored(GluonUpdate::messages_created(
            dest_mailbox,
            dest_uid,
            Some(proton_id),
            Some(flags),
            0,
        ));
        Ok(Some(dest_uid))
    }

    async fn update_message_mailboxes(
        &self,
        proton_id: &ProtonMessageId,
        previous_mailboxes: &[ScopedMailboxId],
        next_mailboxes: &[ScopedMailboxId],
    ) -> Result<()> {
        let previous_set: BTreeSet<&str> = previous_mailboxes.iter().map(|m| m.as_str()).collect();
        let next_set: BTreeSet<&str> = next_mailboxes.iter().map(|m| m.as_str()).collect();

        let mut source_mailbox: Option<ScopedMailboxId> = None;
        let mut source_uid = None;
        let mut source_metadata = None;
        let mut source_flags = None;
        let mut source_rfc822 = None;

        for mailbox in previous_mailboxes {
            if let Some(uid) = self.view.get_uid(mailbox, proton_id).await? {
                source_uid = Some(uid);
                source_mailbox = Some(mailbox.clone());
                source_metadata = self.mutation.get_metadata(mailbox, uid).await?;
                source_flags = Some(self.mutation.get_flags(mailbox, uid).await?);
                source_rfc822 = self.mutation.get_rfc822(mailbox, uid).await?;
                break;
            }
        }

        for mailbox in next_mailboxes {
            if previous_set.contains(mailbox.as_str()) {
                continue;
            }
            let (Some(metadata), Some(flags)) = (source_metadata.clone(), source_flags.clone())
            else {
                continue;
            };
            let uid = self
                .mutation
                .store_metadata(mailbox, proton_id, metadata)
                .await?;
            self.mutation.set_flags(mailbox, uid, flags.clone()).await?;
            if let Some(rfc822) = source_rfc822.clone() {
                self.mutation.store_rfc822(mailbox, uid, rfc822).await?;
            }
        }

        for mailbox in previous_mailboxes {
            if next_set.contains(mailbox.as_str()) {
                continue;
            }
            if let Some(uid) = self.view.get_uid(mailbox, proton_id).await? {
                self.mutation.remove_message(mailbox, uid).await?;
            }
        }

        let reference_mailbox = next_mailboxes
            .first()
            .cloned()
            .or_else(|| source_mailbox.clone())
            .or_else(|| previous_mailboxes.first().cloned());
        let reference_uid = if let Some(mailbox) = reference_mailbox.as_ref() {
            self.view.get_uid(mailbox, proton_id).await?
        } else {
            source_uid
        };

        if let (Some(mailbox), Some(uid)) = (reference_mailbox, reference_uid) {
            self.publish_authored(GluonUpdate::MessageMailboxesUpdated {
                message: GluonMessageRef::new(mailbox, uid, Some(proton_id.clone()), 0),
                mailbox_names: next_mailboxes
                    .iter()
                    .map(|m| m.mailbox_name().to_string())
                    .collect(),
                flags: source_flags,
            });
        }

        Ok(())
    }

    async fn store_rfc822(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        data: Vec<u8>,
    ) -> Result<()> {
        self.mutation.store_rfc822(mailbox, uid, data).await
    }

    async fn batch_upsert_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        entries: &[(&ProtonMessageId, MessageMetadata)],
    ) -> Result<Vec<ImapUid>> {
        use super::mailbox as mailbox_mod;

        let uids = self.mutation.batch_store_metadata(mailbox, entries).await?;

        let mut created_messages = Vec::new();

        for (i, (proton_id, metadata)) in entries.iter().enumerate() {
            let uid = uids[i];
            let flags: Vec<String> = mailbox_mod::message_flags(metadata)
                .into_iter()
                .map(str::to_string)
                .collect();

            let message = GluonMessageRef::new(mailbox.clone(), uid, Some((*proton_id).clone()), 0);
            created_messages.push(GluonCreatedMessage {
                mailbox_names: vec![mailbox.mailbox_name().to_string()],
                message,
                flags: Some(flags),
            });
        }

        if !created_messages.is_empty() {
            self.publish_authored(GluonUpdate::MessagesCreated {
                messages: created_messages,
                ignore_unknown_mailbox_ids: true,
            });
        }

        tracing::debug!(mailbox = %mailbox, total = entries.len(), "batch_upsert_metadata");

        Ok(uids)
    }
}

fn current_uid_validity() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

fn map_mail_error(err: gluon_rs_mail::GluonError) -> ImapError {
    ImapError::Protocol(format!("gluon-rs-mail connector failure: {err}"))
}

impl GluonMailbox {
    fn new(mailbox: ScopedMailboxId, mod_seq: u64) -> Self {
        Self { mailbox, mod_seq }
    }
}

impl GluonMessageRef {
    fn new(
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
    fn kind(&self) -> &'static str {
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

    fn message_count(&self) -> usize {
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

    fn messages_created(
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

    fn message_updated(
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

    fn message_deleted(
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

    fn from_store_event(event: StoreEvent) -> Option<Self> {
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

    fn keys(&self) -> Vec<GluonUpdateKey> {
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
struct GluonUpdateKey {
    scoped_mailbox: ScopedMailboxId,
    uid: Option<ImapUid>,
    proton_id: Option<ProtonMessageId>,
    kind: GluonUpdateKeyKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GluonUpdateKeyKind {
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
