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
use super::store::{MessageStore, StoreEvent, StoreEventKind};
use super::{ImapError, Result};
use crate::api::types::MessageMetadata;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluonMailbox {
    pub account_id: Option<String>,
    pub mailbox_name: String,
    pub mod_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GluonMessageRef {
    pub account_id: Option<String>,
    pub mailbox_name: String,
    pub uid: u32,
    pub proton_id: Option<String>,
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
        account_id: Option<String>,
        mailbox_name: Option<String>,
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
    async fn get_message_literal(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>>;
    async fn upsert_metadata(
        &self,
        mailbox: &str,
        proton_id: &str,
        metadata: MessageMetadata,
    ) -> Result<u32>;
    async fn list_uids(&self, mailbox: &str) -> Result<Vec<u32>>;
    fn create_mailbox(&self, mailbox: &str) -> Result<()>;
    async fn rename_mailbox(&self, source_mailbox: &str, dest_mailbox: &str) -> Result<()>;
    async fn delete_mailbox(&self, mailbox: &str, silent: bool) -> Result<()>;
    async fn remove_message_by_uid(&self, mailbox: &str, uid: u32) -> Result<()>;
    async fn remove_message_by_proton_id(&self, mailbox: &str, proton_id: &str) -> Result<()>;
    async fn update_message_flags(&self, mailbox: &str, uid: u32, flags: Vec<String>)
        -> Result<()>;
    async fn copy_message(
        &self,
        source_mailbox: &str,
        dest_mailbox: &str,
        source_uid: u32,
    ) -> Result<Option<u32>>;
    async fn update_message_mailboxes(
        &self,
        proton_id: &str,
        previous_mailboxes: &[String],
        next_mailboxes: &[String],
    ) -> Result<()>;
    async fn store_rfc822(&self, mailbox: &str, uid: u32, data: Vec<u8>) -> Result<()>;

    /// Upsert metadata for a batch of messages into a single mailbox, publishing
    /// a single batched `GluonUpdate` instead of one per message.  Returns the
    /// assigned UID for each entry (in the same order as the input).
    ///
    /// This matches the Go bridge pattern where `MessagesCreated` carries up to
    /// 64 messages in a single gluon update.
    async fn batch_upsert_metadata(
        &self,
        mailbox: &str,
        entries: &[(&str, MessageMetadata)],
    ) -> Result<Vec<u32>> {
        // Default: fall back to individual upserts.
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
pub struct StoreBackedConnector {
    store: Arc<dyn MessageStore>,
    authored_tx: broadcast::Sender<GluonUpdate>,
}

impl StoreBackedConnector {
    pub fn new(store: Arc<dyn MessageStore>) -> Arc<Self> {
        let (authored_tx, _authored_rx) = broadcast::channel(256);
        Arc::new(Self { store, authored_tx })
    }

    fn publish_authored(&self, update: GluonUpdate) {
        log_gluon_update("connector_store_backed", &update);
        let _ = self.authored_tx.send(update);
    }
}

#[async_trait]
impl GluonImapConnector for StoreBackedConnector {
    fn subscribe_updates(&self) -> GluonUpdateReceiver {
        GluonUpdateReceiver {
            store_events: self.store.subscribe_events(),
            authored_updates: self.authored_tx.subscribe(),
            recent_authored: VecDeque::new(),
        }
    }

    async fn get_message_literal(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>> {
        self.store.get_rfc822(mailbox, uid).await
    }

    async fn upsert_metadata(
        &self,
        mailbox: &str,
        proton_id: &str,
        metadata: MessageMetadata,
    ) -> Result<u32> {
        let existing_uid = self.store.get_uid(mailbox, proton_id).await?;
        let uid = self
            .store
            .store_metadata(mailbox, proton_id, metadata)
            .await?;
        let flags = self.store.get_flags(mailbox, uid).await.ok();

        self.publish_authored(if existing_uid.is_some() {
            GluonUpdate::message_updated(mailbox, uid, Some(proton_id.to_string()), flags, 0)
        } else {
            GluonUpdate::messages_created(mailbox, uid, Some(proton_id.to_string()), flags, 0)
        });

        Ok(uid)
    }

    async fn list_uids(&self, mailbox: &str) -> Result<Vec<u32>> {
        self.store.list_uids(mailbox).await
    }

    fn create_mailbox(&self, mailbox: &str) -> Result<()> {
        self.publish_authored(GluonUpdate::MailboxCreated {
            mailbox: GluonMailbox::from_mailbox_name(mailbox, 0),
        });
        Ok(())
    }

    async fn rename_mailbox(&self, source_mailbox: &str, dest_mailbox: &str) -> Result<()> {
        if source_mailbox.eq_ignore_ascii_case(dest_mailbox) {
            return Ok(());
        }

        let source_uids = self.store.list_uids(source_mailbox).await?;
        for uid in source_uids {
            let _ = self.copy_message(source_mailbox, dest_mailbox, uid).await?;
            self.remove_message_by_uid(source_mailbox, uid).await?;
        }

        self.publish_authored(GluonUpdate::MailboxUpdated {
            mailbox: GluonMailbox::from_mailbox_name(dest_mailbox, 0),
        });
        self.publish_authored(GluonUpdate::MailboxDeletedSilent {
            mailbox: GluonMailbox::from_mailbox_name(source_mailbox, 0),
        });
        Ok(())
    }

    async fn delete_mailbox(&self, mailbox: &str, silent: bool) -> Result<()> {
        let uids = self.store.list_uids(mailbox).await?;
        for uid in uids {
            self.remove_message_by_uid(mailbox, uid).await?;
        }

        self.publish_authored(if silent {
            GluonUpdate::MailboxDeletedSilent {
                mailbox: GluonMailbox::from_mailbox_name(mailbox, 0),
            }
        } else {
            GluonUpdate::MailboxDeleted {
                mailbox: GluonMailbox::from_mailbox_name(mailbox, 0),
            }
        });

        Ok(())
    }

    async fn remove_message_by_uid(&self, mailbox: &str, uid: u32) -> Result<()> {
        let proton_id = self.store.get_proton_id(mailbox, uid).await?;
        self.store.remove_message(mailbox, uid).await?;
        self.publish_authored(GluonUpdate::message_deleted(mailbox, uid, proton_id, 0));
        Ok(())
    }

    async fn remove_message_by_proton_id(&self, mailbox: &str, proton_id: &str) -> Result<()> {
        if let Some(uid) = self.store.get_uid(mailbox, proton_id).await? {
            self.store.remove_message(mailbox, uid).await?;
            self.publish_authored(GluonUpdate::message_deleted(
                mailbox,
                uid,
                Some(proton_id.to_string()),
                0,
            ));
        }
        Ok(())
    }

    async fn update_message_flags(
        &self,
        mailbox: &str,
        uid: u32,
        flags: Vec<String>,
    ) -> Result<()> {
        let proton_id = self.store.get_proton_id(mailbox, uid).await?;
        self.store.set_flags(mailbox, uid, flags.clone()).await?;
        self.publish_authored(GluonUpdate::MessageFlagsUpdated {
            message: GluonMessageRef::from_mailbox_name(mailbox, uid, proton_id, 0),
            flags: Some(flags),
        });
        Ok(())
    }

    async fn copy_message(
        &self,
        source_mailbox: &str,
        dest_mailbox: &str,
        source_uid: u32,
    ) -> Result<Option<u32>> {
        let Some(proton_id) = self.store.get_proton_id(source_mailbox, source_uid).await? else {
            return Ok(None);
        };
        let Some(metadata) = self.store.get_metadata(source_mailbox, source_uid).await? else {
            return Ok(None);
        };

        let dest_uid = self
            .store
            .store_metadata(dest_mailbox, &proton_id, metadata)
            .await?;

        let flags = self.store.get_flags(source_mailbox, source_uid).await?;
        self.store
            .set_flags(dest_mailbox, dest_uid, flags.clone())
            .await?;

        if let Some(rfc822) = self.store.get_rfc822(source_mailbox, source_uid).await? {
            self.store
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
        proton_id: &str,
        previous_mailboxes: &[String],
        next_mailboxes: &[String],
    ) -> Result<()> {
        let previous_set: BTreeSet<&str> = previous_mailboxes.iter().map(String::as_str).collect();
        let next_set: BTreeSet<&str> = next_mailboxes.iter().map(String::as_str).collect();

        let mut source_mailbox = None;
        let mut source_uid = None;
        let mut source_metadata = None;
        let mut source_flags = None;
        let mut source_rfc822 = None;

        for mailbox in previous_mailboxes {
            if let Some(uid) = self.store.get_uid(mailbox, proton_id).await? {
                source_uid = Some(uid);
                source_mailbox = Some(mailbox.clone());
                source_metadata = self.store.get_metadata(mailbox, uid).await?;
                source_flags = Some(self.store.get_flags(mailbox, uid).await?);
                source_rfc822 = self.store.get_rfc822(mailbox, uid).await?;
                break;
            }
        }

        for mailbox in next_set.difference(&previous_set) {
            let (Some(metadata), Some(flags)) = (source_metadata.clone(), source_flags.clone())
            else {
                continue;
            };
            let uid = self
                .store
                .store_metadata(mailbox, proton_id, metadata)
                .await?;
            self.store.set_flags(mailbox, uid, flags.clone()).await?;
            if let Some(rfc822) = source_rfc822.clone() {
                self.store.store_rfc822(mailbox, uid, rfc822).await?;
            }
        }

        for mailbox in previous_set.difference(&next_set) {
            if let Some(uid) = self.store.get_uid(mailbox, proton_id).await? {
                self.store.remove_message(mailbox, uid).await?;
            }
        }

        let reference_mailbox = next_mailboxes
            .first()
            .cloned()
            .or_else(|| source_mailbox.clone())
            .or_else(|| previous_mailboxes.first().cloned());
        let reference_uid = if let Some(mailbox) = reference_mailbox.as_deref() {
            self.store.get_uid(mailbox, proton_id).await?
        } else {
            source_uid
        };

        if let (Some(mailbox), Some(uid)) = (reference_mailbox, reference_uid) {
            let scoped = ScopedMailbox::parse(&mailbox);
            self.publish_authored(GluonUpdate::MessageMailboxesUpdated {
                message: GluonMessageRef {
                    account_id: scoped.account_id,
                    mailbox_name: scoped.mailbox_name.clone(),
                    uid,
                    proton_id: Some(proton_id.to_string()),
                    mod_seq: 0,
                },
                mailbox_names: next_mailboxes
                    .iter()
                    .map(|mailbox| ScopedMailbox::parse(mailbox).mailbox_name)
                    .collect(),
                flags: source_flags,
            });
        }

        Ok(())
    }

    async fn store_rfc822(&self, mailbox: &str, uid: u32, data: Vec<u8>) -> Result<()> {
        self.store.store_rfc822(mailbox, uid, data).await
    }

    async fn batch_upsert_metadata(
        &self,
        mailbox: &str,
        entries: &[(&str, MessageMetadata)],
    ) -> Result<Vec<u32>> {
        let mut uids = Vec::with_capacity(entries.len());
        let mut created_messages = Vec::new();
        let mut updated_count = 0usize;

        for (proton_id, metadata) in entries {
            let existing_uid = self.store.get_uid(mailbox, proton_id).await?;
            let uid = self
                .store
                .store_metadata(mailbox, proton_id, metadata.clone())
                .await?;
            let flags = self.store.get_flags(mailbox, uid).await.ok();
            uids.push(uid);

            if existing_uid.is_some() {
                // Existing messages still get individual update events.
                self.publish_authored(GluonUpdate::message_updated(
                    mailbox,
                    uid,
                    Some(proton_id.to_string()),
                    flags,
                    0,
                ));
                updated_count += 1;
            } else {
                let message = GluonMessageRef::from_mailbox_name(
                    mailbox,
                    uid,
                    Some(proton_id.to_string()),
                    0,
                );
                created_messages.push(GluonCreatedMessage {
                    mailbox_names: vec![message.mailbox_name.clone()],
                    message,
                    flags,
                });
            }
        }

        if !created_messages.is_empty() {
            self.publish_authored(GluonUpdate::MessagesCreated {
                messages: created_messages,
                ignore_unknown_mailbox_ids: false,
            });
        }

        tracing::debug!(
            mailbox,
            total = entries.len(),
            created = entries.len() - updated_count,
            updated = updated_count,
            "batch_upsert_metadata"
        );

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

    fn ensure_mailbox(&self, mailbox: &str) -> Result<(String, UpstreamMailbox)> {
        let scoped = ScopedMailbox::parse(mailbox);
        let mailbox_name = if scoped.mailbox_name.is_empty() {
            "INBOX"
        } else {
            scoped.mailbox_name.as_str()
        };
        let storage_user_id = self
            .storage_user_id_for_account(scoped.account_id.as_deref())
            .to_string();
        if let Some(mailbox_state) = self.mailbox_by_name(&storage_user_id, mailbox_name)? {
            debug!(
                service = "imap",
                pkg = "gluon/user",
                account_id = scoped.account_id.as_deref().unwrap_or_default(),
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
            account_id = scoped.account_id.as_deref().unwrap_or_default(),
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

    async fn get_message_literal(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>> {
        self.view.get_rfc822(mailbox, uid).await
    }

    async fn upsert_metadata(
        &self,
        mailbox: &str,
        proton_id: &str,
        metadata: MessageMetadata,
    ) -> Result<u32> {
        let existing_uid = self.view.get_uid(mailbox, proton_id).await?;
        let uid = self
            .mutation
            .store_metadata(mailbox, proton_id, metadata)
            .await?;
        let flags = self.mutation.get_flags(mailbox, uid).await.ok();

        self.publish_authored(if existing_uid.is_some() {
            GluonUpdate::message_updated(mailbox, uid, Some(proton_id.to_string()), flags, 0)
        } else {
            GluonUpdate::messages_created(mailbox, uid, Some(proton_id.to_string()), flags, 0)
        });

        Ok(uid)
    }

    async fn list_uids(&self, mailbox: &str) -> Result<Vec<u32>> {
        self.view.list_uids(mailbox).await
    }

    fn create_mailbox(&self, mailbox: &str) -> Result<()> {
        let _ = self.ensure_mailbox(mailbox)?;
        self.publish_authored(GluonUpdate::MailboxCreated {
            mailbox: GluonMailbox::from_mailbox_name(mailbox, 0),
        });
        Ok(())
    }

    async fn rename_mailbox(&self, source_mailbox: &str, dest_mailbox: &str) -> Result<()> {
        if source_mailbox.eq_ignore_ascii_case(dest_mailbox) {
            return Ok(());
        }

        let source = ScopedMailbox::parse(source_mailbox);
        let dest = ScopedMailbox::parse(dest_mailbox);
        let source_storage_user_id = self
            .storage_user_id_for_account(source.account_id.as_deref())
            .to_string();

        if let Some(source_mailbox_state) =
            self.mailbox_by_name(&source_storage_user_id, &source.mailbox_name)?
        {
            self.store
                .rename_mailbox(
                    &source_storage_user_id,
                    source_mailbox_state.internal_id,
                    &dest.mailbox_name,
                )
                .map_err(map_mail_error)?;
        } else {
            let _ = self.ensure_mailbox(dest_mailbox)?;
        }

        self.publish_authored(GluonUpdate::MailboxUpdated {
            mailbox: GluonMailbox::from_mailbox_name(dest_mailbox, 0),
        });
        self.publish_authored(GluonUpdate::MailboxDeletedSilent {
            mailbox: GluonMailbox::from_mailbox_name(source_mailbox, 0),
        });
        Ok(())
    }

    async fn delete_mailbox(&self, mailbox: &str, silent: bool) -> Result<()> {
        let scoped = ScopedMailbox::parse(mailbox);
        let storage_user_id = self
            .storage_user_id_for_account(scoped.account_id.as_deref())
            .to_string();
        if let Some(mailbox_state) = self.mailbox_by_name(&storage_user_id, &scoped.mailbox_name)? {
            self.store
                .delete_mailbox(&storage_user_id, mailbox_state.internal_id)
                .map_err(map_mail_error)?;
        }

        self.publish_authored(if silent {
            GluonUpdate::MailboxDeletedSilent {
                mailbox: GluonMailbox::from_mailbox_name(mailbox, 0),
            }
        } else {
            GluonUpdate::MailboxDeleted {
                mailbox: GluonMailbox::from_mailbox_name(mailbox, 0),
            }
        });

        Ok(())
    }

    async fn remove_message_by_uid(&self, mailbox: &str, uid: u32) -> Result<()> {
        let proton_id = self.view.get_proton_id(mailbox, uid).await?;
        self.mutation.remove_message(mailbox, uid).await?;
        self.publish_authored(GluonUpdate::message_deleted(mailbox, uid, proton_id, 0));
        Ok(())
    }

    async fn remove_message_by_proton_id(&self, mailbox: &str, proton_id: &str) -> Result<()> {
        if let Some(uid) = self.view.get_uid(mailbox, proton_id).await? {
            self.mutation.remove_message(mailbox, uid).await?;
            self.publish_authored(GluonUpdate::message_deleted(
                mailbox,
                uid,
                Some(proton_id.to_string()),
                0,
            ));
        }
        Ok(())
    }

    async fn update_message_flags(
        &self,
        mailbox: &str,
        uid: u32,
        flags: Vec<String>,
    ) -> Result<()> {
        let proton_id = self.view.get_proton_id(mailbox, uid).await?;
        self.mutation.set_flags(mailbox, uid, flags.clone()).await?;
        self.publish_authored(GluonUpdate::MessageFlagsUpdated {
            message: GluonMessageRef::from_mailbox_name(mailbox, uid, proton_id, 0),
            flags: Some(flags),
        });
        Ok(())
    }

    async fn copy_message(
        &self,
        source_mailbox: &str,
        dest_mailbox: &str,
        source_uid: u32,
    ) -> Result<Option<u32>> {
        let Some(proton_id) = self
            .mutation
            .get_proton_id(source_mailbox, source_uid)
            .await?
        else {
            return Ok(None);
        };
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
        proton_id: &str,
        previous_mailboxes: &[String],
        next_mailboxes: &[String],
    ) -> Result<()> {
        let previous_set: BTreeSet<&str> = previous_mailboxes.iter().map(String::as_str).collect();
        let next_set: BTreeSet<&str> = next_mailboxes.iter().map(String::as_str).collect();

        let mut source_mailbox = None;
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

        for mailbox in next_set.difference(&previous_set) {
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

        for mailbox in previous_set.difference(&next_set) {
            if let Some(uid) = self.view.get_uid(mailbox, proton_id).await? {
                self.mutation.remove_message(mailbox, uid).await?;
            }
        }

        let reference_mailbox = next_mailboxes
            .first()
            .cloned()
            .or_else(|| source_mailbox.clone())
            .or_else(|| previous_mailboxes.first().cloned());
        let reference_uid = if let Some(mailbox) = reference_mailbox.as_deref() {
            self.view.get_uid(mailbox, proton_id).await?
        } else {
            source_uid
        };

        if let (Some(mailbox), Some(uid)) = (reference_mailbox, reference_uid) {
            let scoped = ScopedMailbox::parse(&mailbox);
            self.publish_authored(GluonUpdate::MessageMailboxesUpdated {
                message: GluonMessageRef {
                    account_id: scoped.account_id,
                    mailbox_name: scoped.mailbox_name.clone(),
                    uid,
                    proton_id: Some(proton_id.to_string()),
                    mod_seq: 0,
                },
                mailbox_names: next_mailboxes
                    .iter()
                    .map(|mailbox| ScopedMailbox::parse(mailbox).mailbox_name)
                    .collect(),
                flags: source_flags,
            });
        }

        Ok(())
    }

    async fn store_rfc822(&self, mailbox: &str, uid: u32, data: Vec<u8>) -> Result<()> {
        self.mutation.store_rfc822(mailbox, uid, data).await
    }

    async fn batch_upsert_metadata(
        &self,
        mailbox: &str,
        entries: &[(&str, MessageMetadata)],
    ) -> Result<Vec<u32>> {
        let mut uids = Vec::with_capacity(entries.len());
        let mut created_messages = Vec::new();
        let mut updated_count = 0usize;

        for (proton_id, metadata) in entries {
            let existing_uid = self.view.get_uid(mailbox, proton_id).await?;
            let uid = self
                .mutation
                .store_metadata(mailbox, proton_id, metadata.clone())
                .await?;
            let flags = self.mutation.get_flags(mailbox, uid).await.ok();
            uids.push(uid);

            if existing_uid.is_some() {
                self.publish_authored(GluonUpdate::message_updated(
                    mailbox,
                    uid,
                    Some(proton_id.to_string()),
                    flags,
                    0,
                ));
                updated_count += 1;
            } else {
                let message = GluonMessageRef::from_mailbox_name(
                    mailbox,
                    uid,
                    Some(proton_id.to_string()),
                    0,
                );
                created_messages.push(GluonCreatedMessage {
                    mailbox_names: vec![message.mailbox_name.clone()],
                    message,
                    flags,
                });
            }
        }

        if !created_messages.is_empty() {
            self.publish_authored(GluonUpdate::MessagesCreated {
                messages: created_messages,
                ignore_unknown_mailbox_ids: false,
            });
        }

        tracing::debug!(
            mailbox,
            total = entries.len(),
            created = entries.len() - updated_count,
            updated = updated_count,
            "batch_upsert_metadata"
        );

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
    fn from_mailbox_name(mailbox: &str, mod_seq: u64) -> Self {
        let scoped = ScopedMailbox::parse(mailbox);
        Self {
            account_id: scoped.account_id,
            mailbox_name: scoped.mailbox_name,
            mod_seq,
        }
    }

    fn scoped_mailbox(&self) -> String {
        scoped_mailbox_string(self.account_id.as_deref(), &self.mailbox_name)
    }
}

impl GluonMessageRef {
    fn from_mailbox_name(mailbox: &str, uid: u32, proton_id: Option<String>, mod_seq: u64) -> Self {
        let scoped = ScopedMailbox::parse(mailbox);
        Self {
            account_id: scoped.account_id,
            mailbox_name: scoped.mailbox_name,
            uid,
            proton_id,
            mod_seq,
        }
    }

    fn scoped_mailbox(&self) -> String {
        scoped_mailbox_string(self.account_id.as_deref(), &self.mailbox_name)
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
        mailbox: &str,
        uid: u32,
        proton_id: Option<String>,
        flags: Option<Vec<String>>,
        mod_seq: u64,
    ) -> Self {
        let message = GluonMessageRef::from_mailbox_name(mailbox, uid, proton_id, mod_seq);
        Self::MessagesCreated {
            messages: vec![GluonCreatedMessage {
                mailbox_names: vec![message.mailbox_name.clone()],
                message,
                flags,
            }],
            ignore_unknown_mailbox_ids: false,
        }
    }

    fn message_updated(
        mailbox: &str,
        uid: u32,
        proton_id: Option<String>,
        flags: Option<Vec<String>>,
        mod_seq: u64,
    ) -> Self {
        let message = GluonMessageRef::from_mailbox_name(mailbox, uid, proton_id, mod_seq);
        Self::MessageUpdated {
            mailbox_names: vec![message.mailbox_name.clone()],
            flags,
            message,
            allow_create: false,
            ignore_unknown_mailbox_ids: false,
        }
    }

    fn message_deleted(mailbox: &str, uid: u32, proton_id: Option<String>, mod_seq: u64) -> Self {
        Self::MessageDeleted {
            message: GluonMessageRef::from_mailbox_name(mailbox, uid, proton_id, mod_seq),
        }
    }

    pub fn affected_scoped_mailboxes(&self) -> Vec<String> {
        match self {
            Self::Noop => Vec::new(),
            Self::MessagesCreated { messages, .. } => messages
                .iter()
                .flat_map(|message| {
                    scoped_mailbox_strings(
                        message.message.account_id.as_deref(),
                        &message.mailbox_names,
                    )
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
            } => scoped_mailbox_strings(message.account_id.as_deref(), mailbox_names),
            Self::MessageDeleted { message }
            | Self::MessageFlagsUpdated { message, .. }
            | Self::MessageIDChanged { message, .. } => vec![message.scoped_mailbox()],
            Self::MailboxCreated { mailbox }
            | Self::MailboxUpdated { mailbox }
            | Self::MailboxUpdatedOrCreated { mailbox }
            | Self::MailboxDeleted { mailbox }
            | Self::MailboxDeletedSilent { mailbox }
            | Self::MailboxIDChanged { mailbox, .. } => vec![mailbox.scoped_mailbox()],
            Self::UIDValidityBumped {
                account_id,
                mailbox_name,
                ..
            } => mailbox_name
                .iter()
                .map(|mailbox_name| scoped_mailbox_string(account_id.as_deref(), mailbox_name))
                .collect(),
        }
    }

    pub fn affects_scoped_mailbox(&self, scoped_mailbox: &str) -> bool {
        self.affected_scoped_mailboxes()
            .iter()
            .any(|mailbox| mailbox == scoped_mailbox)
    }

    pub fn account_id(&self) -> Option<&str> {
        match self {
            Self::Noop => None,
            Self::MessagesCreated { messages, .. } => messages
                .first()
                .and_then(|message| message.message.account_id.as_deref()),
            Self::MessageUpdated { message, .. }
            | Self::MessageDeleted { message }
            | Self::MessageFlagsUpdated { message, .. }
            | Self::MessageMailboxesUpdated { message, .. }
            | Self::MessageIDChanged { message, .. } => message.account_id.as_deref(),
            Self::MailboxCreated { mailbox }
            | Self::MailboxUpdated { mailbox }
            | Self::MailboxUpdatedOrCreated { mailbox }
            | Self::MailboxDeleted { mailbox }
            | Self::MailboxDeletedSilent { mailbox }
            | Self::MailboxIDChanged { mailbox, .. } => mailbox.account_id.as_deref(),
            Self::UIDValidityBumped { account_id, .. } => account_id.as_deref(),
        }
    }

    fn from_store_event(event: StoreEvent) -> Option<Self> {
        match event.kind {
            StoreEventKind::MailboxCreated => Some(Self::MailboxCreated {
                mailbox: GluonMailbox::from_mailbox_name(&event.mailbox, event.mod_seq),
            }),
            StoreEventKind::MessageAdded => Some(Self::messages_created(
                &event.mailbox,
                event.uid?,
                event.proton_id,
                None,
                event.mod_seq,
            )),
            StoreEventKind::MessageUpdated | StoreEventKind::MessageBodyUpdated => {
                Some(Self::message_updated(
                    &event.mailbox,
                    event.uid?,
                    event.proton_id,
                    None,
                    event.mod_seq,
                ))
            }
            StoreEventKind::MessageFlagsUpdated => Some(Self::MessageFlagsUpdated {
                message: GluonMessageRef::from_mailbox_name(
                    &event.mailbox,
                    event.uid?,
                    event.proton_id,
                    event.mod_seq,
                ),
                flags: None,
            }),
            StoreEventKind::MessageRemoved => Some(Self::message_deleted(
                &event.mailbox,
                event.uid?,
                event.proton_id,
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
                    scoped_mailbox: message.message.scoped_mailbox(),
                    uid: Some(message.message.uid),
                    proton_id: message.message.proton_id.clone(),
                    kind: GluonUpdateKeyKind::MessagesCreated,
                })
                .collect(),
            Self::MessageUpdated { message, .. } => vec![GluonUpdateKey {
                scoped_mailbox: message.scoped_mailbox(),
                uid: Some(message.uid),
                proton_id: message.proton_id.clone(),
                kind: GluonUpdateKeyKind::MessageUpdated,
            }],
            Self::MessageDeleted { message } => vec![GluonUpdateKey {
                scoped_mailbox: message.scoped_mailbox(),
                uid: Some(message.uid),
                proton_id: message.proton_id.clone(),
                kind: GluonUpdateKeyKind::MessageDeleted,
            }],
            Self::MessageFlagsUpdated { message, .. } => vec![GluonUpdateKey {
                scoped_mailbox: message.scoped_mailbox(),
                uid: Some(message.uid),
                proton_id: message.proton_id.clone(),
                kind: GluonUpdateKeyKind::MessageFlagsUpdated,
            }],
            Self::MessageMailboxesUpdated { message, .. } => vec![GluonUpdateKey {
                scoped_mailbox: message.scoped_mailbox(),
                uid: Some(message.uid),
                proton_id: message.proton_id.clone(),
                kind: GluonUpdateKeyKind::MessageMailboxesUpdated,
            }],
            Self::MailboxCreated { mailbox } => vec![GluonUpdateKey {
                scoped_mailbox: mailbox.scoped_mailbox(),
                uid: None,
                proton_id: None,
                kind: GluonUpdateKeyKind::MailboxCreated,
            }],
            Self::MailboxUpdated { mailbox } => vec![GluonUpdateKey {
                scoped_mailbox: mailbox.scoped_mailbox(),
                uid: None,
                proton_id: None,
                kind: GluonUpdateKeyKind::MailboxUpdated,
            }],
            Self::MailboxUpdatedOrCreated { mailbox } => vec![GluonUpdateKey {
                scoped_mailbox: mailbox.scoped_mailbox(),
                uid: None,
                proton_id: None,
                kind: GluonUpdateKeyKind::MailboxUpdatedOrCreated,
            }],
            Self::MailboxDeleted { mailbox } => vec![GluonUpdateKey {
                scoped_mailbox: mailbox.scoped_mailbox(),
                uid: None,
                proton_id: None,
                kind: GluonUpdateKeyKind::MailboxDeleted,
            }],
            Self::MailboxDeletedSilent { mailbox } => vec![GluonUpdateKey {
                scoped_mailbox: mailbox.scoped_mailbox(),
                uid: None,
                proton_id: None,
                kind: GluonUpdateKeyKind::MailboxDeletedSilent,
            }],
            Self::MailboxIDChanged { mailbox, remote_id } => vec![GluonUpdateKey {
                scoped_mailbox: mailbox.scoped_mailbox(),
                uid: None,
                proton_id: Some(remote_id.clone()),
                kind: GluonUpdateKeyKind::MailboxIDChanged,
            }],
            Self::MessageIDChanged { message, remote_id } => vec![GluonUpdateKey {
                scoped_mailbox: message.scoped_mailbox(),
                uid: Some(message.uid),
                proton_id: Some(remote_id.clone()),
                kind: GluonUpdateKeyKind::MessageIDChanged,
            }],
            Self::UIDValidityBumped {
                account_id,
                mailbox_name,
                ..
            } => vec![GluonUpdateKey {
                scoped_mailbox: scoped_mailbox_string(
                    account_id.as_deref(),
                    mailbox_name.as_deref().unwrap_or(""),
                ),
                uid: None,
                proton_id: None,
                kind: GluonUpdateKeyKind::UIDValidityBumped,
            }],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GluonUpdateKey {
    scoped_mailbox: String,
    uid: Option<u32>,
    proton_id: Option<String>,
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
        uid = ?primary.and_then(|key| key.uid),
        proton_id = ?primary.and_then(|key| key.proton_id.as_deref()),
        "Applying update"
    );
}

fn scoped_mailbox_string(account_id: Option<&str>, mailbox_name: &str) -> String {
    match account_id {
        Some(account_id) if !account_id.is_empty() => format!("{account_id}::{mailbox_name}"),
        _ => mailbox_name.to_string(),
    }
}

fn scoped_mailbox_strings(account_id: Option<&str>, mailbox_names: &[String]) -> Vec<String> {
    mailbox_names
        .iter()
        .map(|mailbox_name| scoped_mailbox_string(account_id, mailbox_name))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopedMailbox {
    account_id: Option<String>,
    mailbox_name: String,
}

impl ScopedMailbox {
    fn parse(mailbox: &str) -> Self {
        match mailbox.split_once("::") {
            Some((account_id, mailbox_name)) if !account_id.is_empty() => Self {
                account_id: Some(account_id.to_string()),
                mailbox_name: mailbox_name.to_string(),
            },
            _ => Self {
                account_id: None,
                mailbox_name: mailbox.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::api::types::MessageMetadata;

    use super::{GluonImapConnector, GluonMailbox, GluonUpdate, StoreBackedConnector};
    use crate::imap::store::{InMemoryStore, MessageStore};

    fn make_meta(id: &str) -> MessageMetadata {
        MessageMetadata {
            id: id.to_string(),
            address_id: "addr-1".to_string(),
            external_id: None,
            label_ids: vec!["0".to_string()],
            subject: format!("Subject {id}"),
            sender: crate::api::types::EmailAddress {
                name: "Alice".to_string(),
                address: "alice@example.com".to_string(),
            },
            to_list: Vec::new(),
            cc_list: Vec::new(),
            bcc_list: Vec::new(),
            reply_tos: Vec::new(),
            flags: 0,
            time: 0,
            size: 0,
            unread: 1,
            is_replied: 0,
            is_replied_all: 0,
            is_forwarded: 0,
            num_attachments: 0,
        }
    }

    #[tokio::test]
    async fn connector_maps_store_events_into_upstream_shaped_updates() {
        let store = InMemoryStore::new();
        let connector = StoreBackedConnector::new(store.clone());
        let mut updates = connector.subscribe_updates();

        let uid = store
            .store_metadata("uid-1::INBOX", "msg-1", make_meta("msg-1"))
            .await
            .unwrap();

        let mailbox_update = updates.recv().await.unwrap();
        assert_eq!(
            mailbox_update,
            GluonUpdate::MailboxCreated {
                mailbox: GluonMailbox {
                    account_id: Some("uid-1".to_string()),
                    mailbox_name: "INBOX".to_string(),
                    mod_seq: 1,
                },
            }
        );

        let message_update = updates.recv().await.unwrap();
        assert_eq!(
            message_update,
            GluonUpdate::MessagesCreated {
                messages: vec![super::GluonCreatedMessage {
                    message: super::GluonMessageRef {
                        account_id: Some("uid-1".to_string()),
                        mailbox_name: "INBOX".to_string(),
                        uid,
                        proton_id: Some("msg-1".to_string()),
                        mod_seq: 1,
                    },
                    mailbox_names: vec!["INBOX".to_string()],
                    flags: None,
                }],
                ignore_unknown_mailbox_ids: false,
            }
        );
    }

    #[tokio::test]
    async fn connector_reads_message_literal_from_store() {
        let store = InMemoryStore::new();
        let connector = StoreBackedConnector::new(store.clone());
        let uid = store
            .store_metadata("uid-1::INBOX", "msg-1", make_meta("msg-1"))
            .await
            .unwrap();
        store
            .store_rfc822("uid-1::INBOX", uid, b"From: a\r\n\r\nbody".to_vec())
            .await
            .unwrap();

        let literal = connector
            .get_message_literal("uid-1::INBOX", uid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(literal, b"From: a\r\n\r\nbody".to_vec());
    }

    #[tokio::test]
    async fn connector_copies_and_removes_messages_via_contract() {
        let store = InMemoryStore::new();
        let connector = StoreBackedConnector::new(store.clone());
        let uid = connector
            .upsert_metadata("uid-1::INBOX", "msg-1", make_meta("msg-1"))
            .await
            .unwrap();
        store
            .store_rfc822("uid-1::INBOX", uid, b"From: a\r\n\r\nbody".to_vec())
            .await
            .unwrap();

        let copied_uid = connector
            .copy_message("uid-1::INBOX", "uid-1::Archive", uid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(copied_uid, 1);
        assert_eq!(
            store.get_uid("uid-1::Archive", "msg-1").await.unwrap(),
            Some(copied_uid)
        );

        connector
            .remove_message_by_proton_id("uid-1::INBOX", "msg-1")
            .await
            .unwrap();
        assert_eq!(store.get_uid("uid-1::INBOX", "msg-1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn authored_updates_are_not_duplicated_by_store_observation() {
        let store = InMemoryStore::new();
        let connector = StoreBackedConnector::new(store);
        let mut updates = connector.subscribe_updates();

        let uid = connector
            .upsert_metadata("uid-1::INBOX", "msg-1", make_meta("msg-1"))
            .await
            .unwrap();

        let mailbox_update = updates.recv().await.unwrap();
        assert_eq!(
            mailbox_update,
            GluonUpdate::MailboxCreated {
                mailbox: GluonMailbox {
                    account_id: Some("uid-1".to_string()),
                    mailbox_name: "INBOX".to_string(),
                    mod_seq: 1,
                },
            }
        );

        let message_update = updates.recv().await.unwrap();
        assert!(matches!(
            message_update,
            GluonUpdate::MessagesCreated { ref messages, .. }
                if messages.len() == 1
                && matches!(
                    &messages[0].message,
                    super::GluonMessageRef {
                        account_id: Some(ref account_id),
                        mailbox_name,
                        uid: message_uid,
                        proton_id: Some(ref proton_id),
                        ..
                    } if account_id == "uid-1"
                        && mailbox_name == "INBOX"
                        && *message_uid == uid
                        && proton_id == "msg-1"
                )
        ));
    }

    #[tokio::test]
    async fn connector_authors_mailbox_topology_updates() {
        use tokio::time::{timeout, Duration};

        let store = InMemoryStore::new();
        let connector = StoreBackedConnector::new(store.clone());
        let mut updates = connector.subscribe_updates();

        connector.create_mailbox("uid-1::Labels/New").unwrap();
        assert_eq!(
            updates.recv().await.unwrap(),
            GluonUpdate::MailboxCreated {
                mailbox: GluonMailbox {
                    account_id: Some("uid-1".to_string()),
                    mailbox_name: "Labels/New".to_string(),
                    mod_seq: 0,
                },
            }
        );

        let uid = connector
            .upsert_metadata("uid-1::Labels/Old", "msg-1", make_meta("msg-1"))
            .await
            .unwrap();
        store
            .store_rfc822("uid-1::Labels/Old", uid, b"From: a\r\n\r\nbody".to_vec())
            .await
            .unwrap();
        let _ = updates.recv().await.unwrap();
        let _ = updates.recv().await.unwrap();

        connector
            .rename_mailbox("uid-1::Labels/Old", "uid-1::Labels/Renamed")
            .await
            .unwrap();

        assert!(store
            .get_uid("uid-1::Labels/Renamed", "msg-1")
            .await
            .unwrap()
            .is_some());
        assert!(store
            .list_uids("uid-1::Labels/Old")
            .await
            .unwrap()
            .is_empty());

        let mut saw_updated = false;
        let mut saw_deleted_silent = false;
        for _ in 0..10 {
            let update = timeout(Duration::from_millis(50), updates.recv())
                .await
                .expect("connector rename update")
                .unwrap();
            saw_updated |= matches!(
                update,
                GluonUpdate::MailboxUpdated { ref mailbox }
                    if mailbox.account_id.as_deref() == Some("uid-1")
                        && mailbox.mailbox_name == "Labels/Renamed"
            );
            saw_deleted_silent |= matches!(
                update,
                GluonUpdate::MailboxDeletedSilent { ref mailbox }
                    if mailbox.account_id.as_deref() == Some("uid-1")
                        && mailbox.mailbox_name == "Labels/Old"
            );
            if saw_updated && saw_deleted_silent {
                break;
            }
        }
        assert!(saw_updated);
        assert!(saw_deleted_silent);
    }

    #[tokio::test]
    async fn connector_updates_message_mailbox_membership() {
        use tokio::time::{timeout, Duration};

        let store = InMemoryStore::new();
        let connector = StoreBackedConnector::new(store.clone());
        let mut updates = connector.subscribe_updates();

        let uid = connector
            .upsert_metadata("uid-1::INBOX", "msg-1", make_meta("msg-1"))
            .await
            .unwrap();
        store
            .store_rfc822("uid-1::INBOX", uid, b"From: a\r\n\r\nbody".to_vec())
            .await
            .unwrap();
        let _ = updates.recv().await.unwrap();
        let _ = updates.recv().await.unwrap();

        connector
            .update_message_mailboxes(
                "msg-1",
                &["uid-1::INBOX".to_string()],
                &["uid-1::INBOX".to_string(), "uid-1::Archive".to_string()],
            )
            .await
            .unwrap();

        let mut saw_mailbox_update = false;
        for _ in 0..6 {
            let update = timeout(Duration::from_millis(50), updates.recv())
                .await
                .expect("connector mailbox membership update")
                .unwrap();
            saw_mailbox_update |= matches!(
                update,
                GluonUpdate::MessageMailboxesUpdated { ref mailbox_names, .. }
                    if mailbox_names == &vec!["INBOX".to_string(), "Archive".to_string()]
            );
            if saw_mailbox_update {
                break;
            }
        }
        assert!(saw_mailbox_update);

        assert!(store
            .get_uid("uid-1::Archive", "msg-1")
            .await
            .unwrap()
            .is_some());
    }
}
