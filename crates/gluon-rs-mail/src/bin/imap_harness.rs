use std::sync::Arc;

use gluon_rs_mail::gluon_connector::{GluonImapConnector, GluonUpdate, GluonUpdateReceiver};
use gluon_rs_mail::imap_store::{
    GluonMailboxMutation, GluonMailboxView, MailboxSnapshot, MailboxStatus, ProtonMessageId,
    SelectMailboxData,
};
use gluon_rs_mail::mailbox::{GluonMailboxCatalog, ResolvedMailbox};
use gluon_rs_mail::server::run_server_with_tls_config;
use gluon_rs_mail::session::{RecentTracker, SessionConfig};
use gluon_rs_mail::store::{CompatibleStore, StoreSession};
use gluon_rs_mail::{
    AccountBootstrap, AuthResult, CacheLayout, CompatibilityTarget, GluonKey, ImapConnector,
    ImapError, ImapResult, MailboxInfo, MessageEnvelope, MetadataPage, StoreBootstrap,
};
use gluon_rs_mail::{AccountPaths, ImapUid, ScopedMailboxId};

const ACCOUNT_ID: &str = "imaptest-uid";
const EMAIL: &str = "testuser@localhost";
const PASSWORD: &str = "testpass";

// -- ImapConnector: stub that accepts any login, no upstream API --

struct StubImapConnector;

#[async_trait::async_trait]
impl ImapConnector for StubImapConnector {
    async fn authorize(&self, _u: &str, _p: &str) -> ImapResult<AuthResult> {
        Ok(AuthResult {
            account_id: ACCOUNT_ID.into(),
            primary_email: EMAIL.into(),
            mailboxes: vec![],
        })
    }
    async fn get_message_literal(&self, _a: &str, _m: &str) -> ImapResult<Option<Vec<u8>>> {
        Ok(None)
    }
    async fn mark_messages_read(&self, _a: &str, _i: &[&str], _r: bool) -> ImapResult<()> {
        Ok(())
    }
    async fn mark_messages_starred(&self, _a: &str, _i: &[&str], _s: bool) -> ImapResult<()> {
        Ok(())
    }
    async fn label_messages(&self, _a: &str, _i: &[&str], _l: &str) -> ImapResult<()> {
        Ok(())
    }
    async fn unlabel_messages(&self, _a: &str, _i: &[&str], _l: &str) -> ImapResult<()> {
        Ok(())
    }
    async fn trash_messages(&self, _a: &str, _i: &[&str]) -> ImapResult<()> {
        Ok(())
    }
    async fn delete_messages(&self, _a: &str, _i: &[&str]) -> ImapResult<()> {
        Ok(())
    }
    async fn import_message(
        &self,
        _a: &str,
        _l: &str,
        _f: i64,
        _d: &[u8],
    ) -> ImapResult<Option<String>> {
        Ok(None)
    }
    async fn fetch_message_metadata_page(
        &self,
        _a: &str,
        _l: &str,
        _p: i32,
        _s: i32,
    ) -> ImapResult<MetadataPage> {
        Ok(MetadataPage {
            messages: vec![],
            total: 0,
        })
    }
    async fn fetch_user_labels(&self, _a: &str) -> ImapResult<Vec<MailboxInfo>> {
        Ok(vec![])
    }
}

// -- GluonImapConnector: bridges session to the CompatibleStore --

struct StoreConnector {
    store: Arc<CompatibleStore>,
    store_events_tx: tokio::sync::broadcast::Sender<gluon_rs_mail::imap_store::StoreEvent>,
    authored_tx: tokio::sync::broadcast::Sender<GluonUpdate>,
}

impl StoreConnector {
    fn new(store: Arc<CompatibleStore>) -> Arc<Self> {
        let (store_events_tx, _) = tokio::sync::broadcast::channel(16);
        let (authored_tx, _) = tokio::sync::broadcast::channel(256);
        Arc::new(Self {
            store,
            store_events_tx,
            authored_tx,
        })
    }

    fn storage_user_id(&self) -> &str {
        self.store
            .bootstrap()
            .accounts
            .first()
            .map(|a| a.storage_user_id.as_str())
            .unwrap_or(ACCOUNT_ID)
    }

    fn resolve_mailbox_id(&self, mailbox: &ScopedMailboxId) -> Option<u64> {
        let storage_user_id = self.storage_user_id();
        self.store
            .list_upstream_mailboxes(storage_user_id)
            .ok()?
            .into_iter()
            .find(|mb| mb.name.eq_ignore_ascii_case(mailbox.mailbox_name()))
            .map(|mb| mb.internal_id)
    }
}

#[async_trait::async_trait]
impl GluonImapConnector for StoreConnector {
    fn subscribe_updates(&self) -> GluonUpdateReceiver {
        GluonUpdateReceiver::new(
            self.store_events_tx.subscribe(),
            self.authored_tx.subscribe(),
        )
    }

    async fn get_message_literal(
        &self,
        _mailbox: &ScopedMailboxId,
        _uid: ImapUid,
    ) -> ImapResult<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn upsert_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        proton_id: &ProtonMessageId,
        metadata: MessageEnvelope,
    ) -> ImapResult<ImapUid> {
        let storage_user_id = self.storage_user_id();
        let mb_id = self
            .resolve_mailbox_id(mailbox)
            .ok_or_else(|| ImapError::Protocol("mailbox not found".into()))?;
        let msg = gluon_rs_mail::store::NewMessage {
            internal_id: proton_id.to_string(),
            remote_id: proton_id.to_string(),
            flags: vec![],
            blob: vec![],
            body: String::new(),
            body_structure: String::new(),
            envelope: String::new(),
            size: metadata.size,
            recent: false,
        };
        let summary = self
            .store
            .append_message(storage_user_id, mb_id, &msg)
            .map_err(|e| ImapError::Protocol(format!("{e}")))?;
        Ok(ImapUid::from(summary.uid))
    }

    async fn list_uids(&self, mailbox: &ScopedMailboxId) -> ImapResult<Vec<ImapUid>> {
        let storage_user_id = self.storage_user_id();
        let mb_id = match self.resolve_mailbox_id(mailbox) {
            Some(id) => id,
            None => return Ok(vec![]),
        };
        let messages = self
            .store
            .list_upstream_mailbox_messages(storage_user_id, mb_id)
            .map_err(|e| ImapError::Protocol(format!("{e}")))?;
        Ok(messages.into_iter().map(|m| ImapUid::from(m.uid)).collect())
    }

    async fn mailbox_exists(&self, mailbox: &ScopedMailboxId) -> bool {
        self.resolve_mailbox_id(mailbox).is_some()
    }

    async fn create_mailbox(&self, mailbox: &ScopedMailboxId) -> ImapResult<()> {
        let storage_user_id = self.storage_user_id();
        let name = mailbox.mailbox_name();
        self.store
            .create_mailbox(
                storage_user_id,
                &gluon_rs_mail::store::NewMailbox {
                    remote_id: name.to_string(),
                    name: name.to_string(),
                    uid_validity: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as u32,
                    subscribed: true,
                    attributes: vec![],
                    flags: vec![],
                    permanent_flags: vec![
                        "\\Seen".into(),
                        "\\Flagged".into(),
                        "\\Answered".into(),
                        "\\Draft".into(),
                        "\\Deleted".into(),
                    ],
                },
            )
            .map_err(|e| ImapError::Protocol(format!("{e}")))?;
        Ok(())
    }

    async fn rename_mailbox(
        &self,
        source: &ScopedMailboxId,
        dest: &ScopedMailboxId,
    ) -> ImapResult<()> {
        let storage_user_id = self.storage_user_id();
        let mb_id = self
            .resolve_mailbox_id(source)
            .ok_or_else(|| ImapError::Protocol("source mailbox not found".into()))?;
        self.store
            .rename_mailbox(storage_user_id, mb_id, dest.mailbox_name())
            .map_err(|e| ImapError::Protocol(format!("{e}")))?;
        Ok(())
    }

    async fn delete_mailbox(&self, mailbox: &ScopedMailboxId, _silent: bool) -> ImapResult<()> {
        let storage_user_id = self.storage_user_id();
        let mb_id = match self.resolve_mailbox_id(mailbox) {
            Some(id) => id,
            None => return Ok(()),
        };
        self.store
            .delete_mailbox(storage_user_id, mb_id)
            .map_err(|e| ImapError::Protocol(format!("{e}")))?;
        Ok(())
    }

    async fn remove_message_by_uid(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> ImapResult<()> {
        let storage_user_id = self.storage_user_id();
        let mb_id = self
            .resolve_mailbox_id(mailbox)
            .ok_or_else(|| ImapError::Protocol("mailbox not found".into()))?;
        if let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(storage_user_id, mb_id, uid.value())
            .map_err(|e| ImapError::Protocol(format!("{e}")))?
        {
            self.store
                .remove_message_from_mailbox(storage_user_id, mb_id, &internal_id)
                .map_err(|e| ImapError::Protocol(format!("{e}")))?;
        }
        Ok(())
    }

    async fn remove_message_by_proton_id(
        &self,
        _mailbox: &ScopedMailboxId,
        _proton_id: &ProtonMessageId,
    ) -> ImapResult<()> {
        Ok(())
    }

    async fn update_message_flags(
        &self,
        _mailbox: &ScopedMailboxId,
        _uid: ImapUid,
        _flags: Vec<String>,
    ) -> ImapResult<()> {
        Ok(())
    }

    async fn copy_message(
        &self,
        _source: &ScopedMailboxId,
        _dest: &ScopedMailboxId,
        _uid: ImapUid,
    ) -> ImapResult<Option<ImapUid>> {
        Ok(None)
    }

    async fn update_message_mailboxes(
        &self,
        _proton_id: &ProtonMessageId,
        _prev: &[ScopedMailboxId],
        _next: &[ScopedMailboxId],
    ) -> ImapResult<()> {
        Ok(())
    }

    async fn store_rfc822(
        &self,
        _mailbox: &ScopedMailboxId,
        _uid: ImapUid,
        _data: Vec<u8>,
    ) -> ImapResult<()> {
        Ok(())
    }

    async fn acquire_store_session(&self, _account_id: Option<&str>) -> ImapResult<StoreSession> {
        self.store
            .session(self.storage_user_id())
            .map_err(|e| ImapError::Protocol(format!("{e}")))
    }

    fn resolve_storage_user_id<'a>(&'a self, _account_id: Option<&'a str>) -> &'a str {
        self.storage_user_id()
    }

    fn read_message_blob(
        &self,
        storage_user_id: &str,
        internal_message_id: &str,
    ) -> ImapResult<Vec<u8>> {
        self.store
            .read_message_blob(storage_user_id, internal_message_id)
            .map_err(|e| ImapError::Protocol(format!("{e}")))
    }

    fn account_paths(&self, storage_user_id: &str) -> ImapResult<AccountPaths> {
        self.store
            .account_paths(storage_user_id)
            .map_err(|e| ImapError::Protocol(format!("{e}")))
    }
}

// -- GluonMailboxView: reads from CompatibleStore --

struct StoreMailboxView {
    store: Arc<CompatibleStore>,
}

#[async_trait::async_trait]
impl GluonMailboxView for StoreMailboxView {
    async fn get_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> ImapResult<Option<MessageEnvelope>> {
        let storage_user_id = ACCOUNT_ID;
        let Some(mb) = find_mailbox_id(&self.store, mailbox) else {
            return Ok(None);
        };
        let msg = self
            .store
            .message_by_uid(storage_user_id, mb, uid.value())
            .map_err(map_err)?;
        let Some(m) = msg else {
            return Ok(None);
        };
        let blob = self
            .store
            .read_message_blob(storage_user_id, &m.summary.internal_id)
            .unwrap_or_default();
        Ok(gluon_rs_mail::metadata_parse::parse_metadata_from_rfc822(
            mailbox, &m.summary, &blob,
        ))
    }

    async fn get_rfc822(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> ImapResult<Option<Vec<u8>>> {
        let storage_user_id = ACCOUNT_ID;
        let Some(mb) = find_mailbox_id(&self.store, mailbox) else {
            return Ok(None);
        };
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(storage_user_id, mb, uid.value())
            .map_err(map_err)?
        else {
            return Ok(None);
        };
        self.store
            .read_message_blob(storage_user_id, &internal_id)
            .map(Some)
            .map_err(map_err)
    }

    async fn get_flags(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> ImapResult<Vec<String>> {
        let storage_user_id = ACCOUNT_ID;
        let Some(mb) = find_mailbox_id(&self.store, mailbox) else {
            return Ok(vec![]);
        };
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(storage_user_id, mb, uid.value())
            .map_err(map_err)?
        else {
            return Ok(vec![]);
        };
        self.store
            .message_flags_by_internal_id(storage_user_id, &internal_id)
            .map_err(map_err)
    }

    async fn get_proton_id(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> ImapResult<Option<String>> {
        let storage_user_id = ACCOUNT_ID;
        let Some(mb) = find_mailbox_id(&self.store, mailbox) else {
            return Ok(None);
        };
        self.store
            .message_remote_id_by_uid(storage_user_id, mb, uid.value())
            .map_err(map_err)
    }

    async fn list_uids(&self, mailbox: &ScopedMailboxId) -> ImapResult<Vec<ImapUid>> {
        let storage_user_id = ACCOUNT_ID;
        let Some(mb) = find_mailbox_id(&self.store, mailbox) else {
            return Ok(vec![]);
        };
        let msgs = self
            .store
            .list_upstream_mailbox_messages(storage_user_id, mb)
            .map_err(map_err)?;
        Ok(msgs.into_iter().map(|m| ImapUid::from(m.uid)).collect())
    }

    async fn mailbox_status(&self, mailbox: &ScopedMailboxId) -> ImapResult<MailboxStatus> {
        let storage_user_id = ACCOUNT_ID;
        let Some(mb) = find_mailbox_id(&self.store, mailbox) else {
            return Ok(MailboxStatus {
                uid_validity: 1,
                next_uid: 1,
                exists: 0,
                unseen: 0,
            });
        };
        let snapshot = self
            .store
            .mailbox_select_data(storage_user_id, mb)
            .map_err(map_err)?;
        let unseen = snapshot
            .entries
            .iter()
            .filter(|e| !e.flags.iter().any(|f| f == "\\Seen"))
            .count() as u32;
        Ok(MailboxStatus {
            uid_validity: snapshot.uid_validity,
            next_uid: snapshot.next_uid,
            exists: snapshot.entries.len() as u32,
            unseen,
        })
    }

    async fn select_mailbox_data(
        &self,
        mailbox: &ScopedMailboxId,
    ) -> ImapResult<SelectMailboxData> {
        self.select_mailbox_data_fast(mailbox).await
    }

    async fn get_uid(
        &self,
        _mailbox: &ScopedMailboxId,
        _proton_id: &ProtonMessageId,
    ) -> ImapResult<Option<ImapUid>> {
        Ok(None)
    }

    async fn mailbox_snapshot(&self, mailbox: &ScopedMailboxId) -> ImapResult<MailboxSnapshot> {
        let status = self.mailbox_status(mailbox).await?;
        Ok(MailboxSnapshot {
            mod_seq: 0,
            exists: status.exists,
        })
    }

    async fn seq_to_uid(&self, mailbox: &ScopedMailboxId, seq: u32) -> ImapResult<Option<ImapUid>> {
        let uids = self.list_uids(mailbox).await?;
        Ok(uids.into_iter().nth((seq as usize).saturating_sub(1)))
    }

    async fn uid_to_seq(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> ImapResult<Option<u32>> {
        let uids = self.list_uids(mailbox).await?;
        Ok(uids.iter().position(|u| *u == uid).map(|i| i as u32 + 1))
    }

    async fn select_mailbox_data_fast(
        &self,
        mailbox: &ScopedMailboxId,
    ) -> ImapResult<SelectMailboxData> {
        let storage_user_id = ACCOUNT_ID;
        let Some(mb) = find_mailbox_id(&self.store, mailbox) else {
            return Ok(SelectMailboxData {
                status: MailboxStatus {
                    uid_validity: 1,
                    next_uid: 1,
                    exists: 0,
                    unseen: 0,
                },
                uids: vec![],
                flags: std::collections::HashMap::new(),
                first_unseen_seq: None,
                snapshot: gluon_rs_mail::imap_store::MailboxSnapshot {
                    mod_seq: 0,
                    exists: 0,
                },
            });
        };
        let snap = self
            .store
            .mailbox_select_data(storage_user_id, mb)
            .map_err(map_err)?;
        let mut uids = Vec::new();
        let mut flags = std::collections::HashMap::new();
        let mut first_unseen_seq = None;
        for (i, entry) in snap.entries.iter().enumerate() {
            let uid = ImapUid::from(entry.uid);
            uids.push(uid);
            if first_unseen_seq.is_none() && !entry.flags.iter().any(|f| f == "\\Seen") {
                first_unseen_seq = Some(i as u32 + 1);
            }
            flags.insert(uid, entry.flags.clone());
        }
        let unseen = snap
            .entries
            .iter()
            .filter(|e| !e.flags.iter().any(|f| f == "\\Seen"))
            .count() as u32;
        Ok(SelectMailboxData {
            status: MailboxStatus {
                uid_validity: snap.uid_validity,
                next_uid: snap.next_uid,
                exists: uids.len() as u32,
                unseen,
            },
            uids,
            flags,
            first_unseen_seq,
            snapshot: gluon_rs_mail::imap_store::MailboxSnapshot {
                mod_seq: 0,
                exists: snap.entries.len() as u32,
            },
        })
    }
}

// -- GluonMailboxMutation: writes to CompatibleStore --

struct StoreMailboxMutation {
    store: Arc<CompatibleStore>,
}

#[async_trait::async_trait]
impl GluonMailboxMutation for StoreMailboxMutation {
    async fn get_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> ImapResult<Option<MessageEnvelope>> {
        let storage_user_id = ACCOUNT_ID;
        let Some(mb) = find_mailbox_id(&self.store, mailbox) else {
            return Ok(None);
        };
        let msg = self
            .store
            .message_by_uid(storage_user_id, mb, uid.value())
            .map_err(map_err)?;
        let Some(m) = msg else {
            return Ok(None);
        };
        let blob = self
            .store
            .read_message_blob(storage_user_id, &m.summary.internal_id)
            .unwrap_or_default();
        Ok(gluon_rs_mail::metadata_parse::parse_metadata_from_rfc822(
            mailbox, &m.summary, &blob,
        ))
    }

    async fn store_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        proton_id: &ProtonMessageId,
        metadata: MessageEnvelope,
    ) -> ImapResult<ImapUid> {
        let storage_user_id = ACCOUNT_ID;
        let mb = find_mailbox_id(&self.store, mailbox)
            .ok_or_else(|| ImapError::Protocol("mailbox not found".into()))?;
        let msg = gluon_rs_mail::store::NewMessage {
            internal_id: proton_id.to_string(),
            remote_id: proton_id.to_string(),
            flags: vec![],
            blob: vec![],
            body: String::new(),
            body_structure: String::new(),
            envelope: String::new(),
            size: metadata.size,
            recent: false,
        };
        let summary = self
            .store
            .append_message(storage_user_id, mb, &msg)
            .map_err(map_err)?;
        Ok(ImapUid::from(summary.uid))
    }

    async fn store_rfc822(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        data: Vec<u8>,
    ) -> ImapResult<()> {
        let storage_user_id = ACCOUNT_ID;
        let mb = find_mailbox_id(&self.store, mailbox)
            .ok_or_else(|| ImapError::Protocol("mailbox not found".into()))?;
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(storage_user_id, mb, uid.value())
            .map_err(map_err)?
        else {
            return Ok(());
        };
        self.store
            .replace_message_content(
                storage_user_id,
                &internal_id,
                &data,
                "",
                "",
                "",
                data.len() as i64,
            )
            .map_err(map_err)?;
        Ok(())
    }

    async fn get_rfc822(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> ImapResult<Option<Vec<u8>>> {
        let storage_user_id = ACCOUNT_ID;
        let Some(mb) = find_mailbox_id(&self.store, mailbox) else {
            return Ok(None);
        };
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(storage_user_id, mb, uid.value())
            .map_err(map_err)?
        else {
            return Ok(None);
        };
        self.store
            .read_message_blob(storage_user_id, &internal_id)
            .map(Some)
            .map_err(map_err)
    }

    async fn get_flags(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> ImapResult<Vec<String>> {
        let storage_user_id = ACCOUNT_ID;
        let Some(mb) = find_mailbox_id(&self.store, mailbox) else {
            return Ok(vec![]);
        };
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(storage_user_id, mb, uid.value())
            .map_err(map_err)?
        else {
            return Ok(vec![]);
        };
        self.store
            .message_flags_by_internal_id(storage_user_id, &internal_id)
            .map_err(map_err)
    }

    async fn set_flags(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        flags: Vec<String>,
    ) -> ImapResult<()> {
        let storage_user_id = ACCOUNT_ID;
        let mb = find_mailbox_id(&self.store, mailbox)
            .ok_or_else(|| ImapError::Protocol("mailbox not found".into()))?;
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(storage_user_id, mb, uid.value())
            .map_err(map_err)?
        else {
            return Ok(());
        };
        self.store
            .set_message_flags(storage_user_id, &internal_id, &flags)
            .map_err(map_err)
    }

    async fn add_flags(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        flags: &[String],
    ) -> ImapResult<()> {
        let storage_user_id = ACCOUNT_ID;
        let mb = find_mailbox_id(&self.store, mailbox)
            .ok_or_else(|| ImapError::Protocol("mailbox not found".into()))?;
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(storage_user_id, mb, uid.value())
            .map_err(map_err)?
        else {
            return Ok(());
        };
        self.store
            .add_message_flags(storage_user_id, &internal_id, flags)
            .map_err(map_err)
    }

    async fn remove_flags(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        flags: &[String],
    ) -> ImapResult<()> {
        let storage_user_id = ACCOUNT_ID;
        let mb = find_mailbox_id(&self.store, mailbox)
            .ok_or_else(|| ImapError::Protocol("mailbox not found".into()))?;
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(storage_user_id, mb, uid.value())
            .map_err(map_err)?
        else {
            return Ok(());
        };
        self.store
            .remove_message_flags(storage_user_id, &internal_id, flags)
            .map_err(map_err)
    }

    async fn remove_message(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> ImapResult<()> {
        let storage_user_id = ACCOUNT_ID;
        let mb = find_mailbox_id(&self.store, mailbox)
            .ok_or_else(|| ImapError::Protocol("mailbox not found".into()))?;
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(storage_user_id, mb, uid.value())
            .map_err(map_err)?
        else {
            return Ok(());
        };
        self.store
            .remove_message_from_mailbox(storage_user_id, mb, &internal_id)
            .map_err(map_err)
    }

    async fn get_proton_id(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> ImapResult<Option<String>> {
        let storage_user_id = ACCOUNT_ID;
        let Some(mb) = find_mailbox_id(&self.store, mailbox) else {
            return Ok(None);
        };
        self.store
            .message_remote_id_by_uid(storage_user_id, mb, uid.value())
            .map_err(map_err)
    }

    async fn mailbox_status(&self, mailbox: &ScopedMailboxId) -> ImapResult<MailboxStatus> {
        let storage_user_id = ACCOUNT_ID;
        let Some(mb) = find_mailbox_id(&self.store, mailbox) else {
            return Ok(MailboxStatus {
                uid_validity: 1,
                next_uid: 1,
                exists: 0,
                unseen: 0,
            });
        };
        let snap = self
            .store
            .mailbox_select_data(storage_user_id, mb)
            .map_err(map_err)?;
        let unseen = snap
            .entries
            .iter()
            .filter(|e| !e.flags.iter().any(|f| f == "\\Seen"))
            .count() as u32;
        Ok(MailboxStatus {
            uid_validity: snap.uid_validity,
            next_uid: snap.next_uid,
            exists: snap.entries.len() as u32,
            unseen,
        })
    }

    async fn uid_to_seq(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> ImapResult<Option<u32>> {
        let storage_user_id = ACCOUNT_ID;
        let Some(mb) = find_mailbox_id(&self.store, mailbox) else {
            return Ok(None);
        };
        let msgs = self
            .store
            .list_upstream_mailbox_messages(storage_user_id, mb)
            .map_err(map_err)?;
        Ok(msgs
            .iter()
            .position(|m| m.uid == uid.value())
            .map(|i| i as u32 + 1))
    }

    async fn batch_remove_messages(
        &self,
        mailbox: &ScopedMailboxId,
        uids: &[ImapUid],
    ) -> ImapResult<()> {
        for &uid in uids {
            self.remove_message(mailbox, uid).await?;
        }
        Ok(())
    }
}

// -- GluonMailboxCatalog: no dynamic labels --

struct SimpleCatalog;

impl GluonMailboxCatalog for SimpleCatalog {
    fn user_labels(
        &self,
        _account_id: Option<&str>,
        fallback_labels: &[ResolvedMailbox],
    ) -> Vec<ResolvedMailbox> {
        fallback_labels.to_vec()
    }
}

// -- Helpers --

fn find_mailbox_id(store: &CompatibleStore, mailbox: &ScopedMailboxId) -> Option<u64> {
    let storage_user_id = store
        .bootstrap()
        .accounts
        .first()
        .map(|a| a.storage_user_id.as_str())
        .unwrap_or(ACCOUNT_ID);
    let name = mailbox.mailbox_name();
    let name = if name.is_empty() { "INBOX" } else { name };

    if let Some(mb) = store
        .list_upstream_mailboxes(storage_user_id)
        .ok()?
        .into_iter()
        .find(|mb| mb.name.eq_ignore_ascii_case(name))
    {
        return Some(mb.internal_id);
    }

    // Auto-create if not found (matches Go gluon's ensure_mailbox behavior)
    let created = store
        .create_mailbox(
            storage_user_id,
            &gluon_rs_mail::store::NewMailbox {
                remote_id: name.to_string(),
                name: name.to_string(),
                uid_validity: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32,
                subscribed: true,
                attributes: vec![],
                flags: vec![],
                permanent_flags: vec![
                    "\\Seen".into(),
                    "\\Flagged".into(),
                    "\\Answered".into(),
                    "\\Draft".into(),
                    "\\Deleted".into(),
                ],
            },
        )
        .ok()?;
    Some(created.internal_id)
}

fn map_err(e: gluon_rs_mail::GluonError) -> ImapError {
    ImapError::Protocol(format!("gluon-rs-mail: {e}"))
}

fn build_session_config(data_dir: &std::path::Path) -> Arc<SessionConfig> {
    let layout = CacheLayout::new(data_dir.join("gluon"));
    let gluon_store = Arc::new(
        CompatibleStore::open(StoreBootstrap::new(
            layout,
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                ACCOUNT_ID,
                ACCOUNT_ID,
                GluonKey::try_from_slice(&[7u8; 32]).expect("key"),
            )],
        ))
        .expect("open gluon store"),
    );

    Arc::new(SessionConfig {
        connector: Arc::new(StubImapConnector),
        gluon_connector: StoreConnector::new(gluon_store.clone()),
        mailbox_catalog: Arc::new(SimpleCatalog),
        mailbox_mutation: Arc::new(StoreMailboxMutation {
            store: gluon_store.clone(),
        }),
        mailbox_view: Arc::new(StoreMailboxView { store: gluon_store }),
        recent_tracker: RecentTracker::new(),
        shutdown_rx: None,
        event_tx: None,
        delimiter: '/',
        login_jail_time: std::time::Duration::ZERO,
        idle_bulk_time: std::time::Duration::ZERO,
        limits: gluon_rs_mail::imap_types::ImapLimits::default(),
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let port: u16 = std::env::var("IMAP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1143);

    let data_dir = std::env::var_os("IMAP_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let dir = std::env::temp_dir().join("openproton-imaptest");
            std::fs::create_dir_all(&dir).expect("create data dir");
            dir
        });

    let addr = format!("127.0.0.1:{port}");
    let config = build_session_config(&data_dir);

    eprintln!("IMAP harness listening on {addr} (plaintext, no TLS)");
    eprintln!("  user: {EMAIL}");
    eprintln!("  pass: {PASSWORD}");
    eprintln!("  data: {}", data_dir.display());

    run_server_with_tls_config(&addr, config, None).await?;

    Ok(())
}
