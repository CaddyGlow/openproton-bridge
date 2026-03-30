use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use gluon_rs_mail::{CompatibleStore, NewMailbox, UpstreamMailbox};
use tokio::sync::broadcast;
use tracing::{debug, info};

use super::gluon_mailbox_mutation::GluonMailMailboxMutation;
use super::gluon_mailbox_view::GluonMailMailboxView;
use super::store_helpers::storage_user_id_for_account;

pub use gluon_rs_mail::gluon_connector::{
    GluonCreatedMessage, GluonImapConnector, GluonMailbox, GluonMessageRef, GluonUpdate,
    GluonUpdateReceiver,
};
use gluon_rs_mail::imap_store::{
    GluonMailboxMutation, GluonMailboxView, ProtonMessageId, StoreEvent,
};
use gluon_rs_mail::{ImapUid, MessageEnvelope, ScopedMailboxId};

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
        storage_user_id_for_account(&self.store, account_id.unwrap_or("__default__"))
    }

    async fn mailbox_by_name(
        &self,
        storage_user_id: &str,
        mailbox_name: &str,
    ) -> gluon_rs_mail::ImapResult<Option<UpstreamMailbox>> {
        match self.store.list_upstream_mailboxes(storage_user_id) {
            Ok(mailboxes) => Ok(mailboxes
                .into_iter()
                .find(|mailbox| mailbox.name.eq_ignore_ascii_case(mailbox_name))),
            Err(gluon_rs_mail::GluonError::IncompatibleSchema { family })
                if family == "Missing" =>
            {
                Ok(None)
            }
            Err(err) => Err(super::store_helpers::map_err(err)),
        }
    }

    async fn mailbox_by_name_rw(
        &self,
        storage_user_id: &str,
        mailbox_name: &str,
    ) -> gluon_rs_mail::ImapResult<Option<UpstreamMailbox>> {
        match self.store.list_upstream_mailboxes_rw(storage_user_id) {
            Ok(mailboxes) => Ok(mailboxes
                .into_iter()
                .find(|mailbox| mailbox.name.eq_ignore_ascii_case(mailbox_name))),
            Err(gluon_rs_mail::GluonError::IncompatibleSchema { family })
                if family == "Missing" =>
            {
                Ok(None)
            }
            Err(err) => Err(super::store_helpers::map_err(err)),
        }
    }

    async fn ensure_mailbox(
        &self,
        mailbox: &ScopedMailboxId,
    ) -> gluon_rs_mail::ImapResult<(String, UpstreamMailbox)> {
        let account_id = mailbox.account_id();
        let mailbox_name = mailbox.mailbox_name();
        let mailbox_name = if mailbox_name.is_empty() {
            "INBOX"
        } else {
            mailbox_name
        };
        let storage_user_id = self.storage_user_id_for_account(account_id).to_string();
        if let Some(mailbox_state) = self.mailbox_by_name(&storage_user_id, mailbox_name).await? {
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

        let created = match self.store.create_mailbox(
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
        ) {
            Ok(m) => m,
            Err(_) => {
                // UNIQUE constraint: mailbox was created concurrently, retry lookup via RW conn
                if let Some(mb) = self
                    .mailbox_by_name_rw(&storage_user_id, mailbox_name)
                    .await?
                {
                    return Ok((storage_user_id, mb));
                }
                return Err(gluon_rs_mail::ImapError::Protocol(format!(
                    "gluon-rs-mail connector failure: mailbox creation failed for {mailbox_name}"
                )));
            }
        };
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
        GluonUpdateReceiver::new(
            self.store_events_tx.subscribe(),
            self.authored_tx.subscribe(),
        )
    }

    async fn get_message_literal(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> gluon_rs_mail::ImapResult<Option<Vec<u8>>> {
        self.view.get_rfc822(mailbox, uid).await
    }

    async fn upsert_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        proton_id: &ProtonMessageId,
        metadata: MessageEnvelope,
    ) -> gluon_rs_mail::ImapResult<ImapUid> {
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

    async fn list_uids(
        &self,
        mailbox: &ScopedMailboxId,
    ) -> gluon_rs_mail::ImapResult<Vec<ImapUid>> {
        self.view.list_uids(mailbox).await
    }

    async fn mailbox_exists(&self, mailbox: &ScopedMailboxId) -> bool {
        let storage_user_id = self.storage_user_id_for_account(mailbox.account_id());
        self.mailbox_by_name(storage_user_id, mailbox.mailbox_name())
            .await
            .ok()
            .flatten()
            .is_some()
    }

    async fn create_mailbox(&self, mailbox: &ScopedMailboxId) -> gluon_rs_mail::ImapResult<()> {
        let _ = self.ensure_mailbox(mailbox).await?;
        self.publish_authored(GluonUpdate::MailboxCreated {
            mailbox: GluonMailbox::new(mailbox.clone(), 0),
        });
        Ok(())
    }

    async fn rename_mailbox(
        &self,
        source_mailbox: &ScopedMailboxId,
        dest_mailbox: &ScopedMailboxId,
    ) -> gluon_rs_mail::ImapResult<()> {
        if source_mailbox == dest_mailbox {
            return Ok(());
        }

        let source_storage_user_id = self
            .storage_user_id_for_account(source_mailbox.account_id())
            .to_string();

        if let Some(source_mailbox_state) = self
            .mailbox_by_name(&source_storage_user_id, source_mailbox.mailbox_name())
            .await?
        {
            self.store
                .rename_mailbox(
                    &source_storage_user_id,
                    source_mailbox_state.internal_id,
                    dest_mailbox.mailbox_name(),
                )
                .map_err(super::store_helpers::map_err)?;
        } else {
            let _ = self.ensure_mailbox(dest_mailbox).await?;
        }

        self.publish_authored(GluonUpdate::MailboxUpdated {
            mailbox: GluonMailbox::new(dest_mailbox.clone(), 0),
        });
        self.publish_authored(GluonUpdate::MailboxDeletedSilent {
            mailbox: GluonMailbox::new(source_mailbox.clone(), 0),
        });
        Ok(())
    }

    async fn delete_mailbox(
        &self,
        mailbox: &ScopedMailboxId,
        silent: bool,
    ) -> gluon_rs_mail::ImapResult<()> {
        let storage_user_id = self
            .storage_user_id_for_account(mailbox.account_id())
            .to_string();
        if let Some(mailbox_state) = self
            .mailbox_by_name(&storage_user_id, mailbox.mailbox_name())
            .await?
        {
            self.store
                .delete_mailbox(&storage_user_id, mailbox_state.internal_id)
                .map_err(super::store_helpers::map_err)?;
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

    async fn remove_message_by_uid(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> gluon_rs_mail::ImapResult<()> {
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
    ) -> gluon_rs_mail::ImapResult<()> {
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
    ) -> gluon_rs_mail::ImapResult<()> {
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
    ) -> gluon_rs_mail::ImapResult<Option<ImapUid>> {
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
    ) -> gluon_rs_mail::ImapResult<()> {
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
    ) -> gluon_rs_mail::ImapResult<()> {
        self.mutation.store_rfc822(mailbox, uid, data).await
    }

    async fn batch_upsert_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        entries: &[(&ProtonMessageId, MessageEnvelope)],
    ) -> gluon_rs_mail::ImapResult<Vec<ImapUid>> {
        let uids = self.mutation.batch_store_metadata(mailbox, entries).await?;

        let mut created_messages = Vec::new();

        for (i, (proton_id, metadata)) in entries.iter().enumerate() {
            let uid = uids[i];
            let flags: Vec<String> = gluon_rs_mail::message_flags(metadata)
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

    async fn acquire_store_session(
        &self,
        account_id: Option<&str>,
    ) -> gluon_rs_mail::ImapResult<gluon_rs_mail::StoreSession> {
        let storage_user_id = self.storage_user_id_for_account(account_id);
        self.store.session(storage_user_id).map_err(|e| {
            gluon_rs_mail::ImapError::Protocol(format!("gluon-rs-mail connector failure: {e}"))
        })
    }

    fn resolve_storage_user_id<'a>(&'a self, account_id: Option<&'a str>) -> &'a str {
        self.storage_user_id_for_account(account_id)
    }

    fn read_message_blob(
        &self,
        storage_user_id: &str,
        internal_message_id: &str,
    ) -> gluon_rs_mail::ImapResult<Vec<u8>> {
        self.store
            .read_message_blob(storage_user_id, internal_message_id)
            .map_err(|e| {
                gluon_rs_mail::ImapError::Protocol(format!("gluon-rs-mail connector failure: {e}"))
            })
    }

    fn account_paths(
        &self,
        storage_user_id: &str,
    ) -> gluon_rs_mail::ImapResult<gluon_rs_mail::AccountPaths> {
        self.store.account_paths(storage_user_id).map_err(|e| {
            gluon_rs_mail::ImapError::Protocol(format!("gluon-rs-mail connector failure: {e}"))
        })
    }
}

fn current_uid_validity() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
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
