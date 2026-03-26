use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use gluon_rs_mail::{
    CompatibleStore, NewMailbox, NewMessage, UpstreamMailbox, UpstreamMailboxMessage,
};
use uuid::Uuid;

use gluon_rs_mail::{EmailAddress, MessageEnvelope};

use super::gluon_mailbox_view::GluonMailMailboxView;
use super::mailbox;
use super::mailbox_mutation::GluonMailboxMutation;
use super::mailbox_view::GluonMailboxView;
use super::rfc822;
use super::store::MailboxStatus;
use super::types::{ImapUid, ProtonMessageId, ScopedMailboxId};
use super::{ImapError, Result};

#[derive(Clone)]
pub struct GluonMailMailboxMutation {
    store: Arc<CompatibleStore>,
    view: Arc<GluonMailMailboxView>,
}

impl GluonMailMailboxMutation {
    pub fn new(store: Arc<CompatibleStore>) -> Arc<Self> {
        Arc::new(Self {
            view: GluonMailMailboxView::new(store.clone()),
            store,
        })
    }

    fn resolve_parts(mailbox: &ScopedMailboxId) -> (&str, &str) {
        let account_id = mailbox.account_id().unwrap_or("__default__");
        let name = mailbox.mailbox_name();
        let name = if name.is_empty() { "INBOX" } else { name };
        (account_id, name)
    }

    fn storage_user_id_for_account<'a>(&'a self, account_id: &'a str) -> &'a str {
        self.store
            .bootstrap()
            .accounts
            .iter()
            .find(|account| account.account_id == account_id)
            .map(|account| account.storage_user_id.as_str())
            .unwrap_or(account_id)
    }

    async fn mailbox_by_name(
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

    async fn ensure_mailbox(&self, mailbox: &ScopedMailboxId) -> Result<(String, UpstreamMailbox)> {
        let (account_id, mailbox_name) = Self::resolve_parts(mailbox);
        let storage_user_id = self.storage_user_id_for_account(account_id).to_string();
        if let Some(mailbox) = self.mailbox_by_name(&storage_user_id, mailbox_name).await? {
            return Ok((storage_user_id, mailbox));
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
        Ok((storage_user_id, created))
    }

    async fn message_by_uid(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> Result<Option<(String, UpstreamMailbox, UpstreamMailboxMessage)>> {
        let (storage_user_id, mailbox_state) = self.ensure_mailbox(mailbox).await?;
        let message = self
            .store
            .message_by_uid(&storage_user_id, mailbox_state.internal_id, uid.value())
            .map_err(map_mail_error)?;
        Ok(message.map(|m| (storage_user_id, mailbox_state, m)))
    }

    fn placeholder_message(
        &self,
        proton_id: &ProtonMessageId,
        meta: &MessageEnvelope,
    ) -> NewMessage {
        let blob = metadata_blob(meta);
        let header = extract_header_section(&blob);
        NewMessage {
            internal_id: Uuid::new_v4().to_string(),
            remote_id: proton_id.as_str().to_string(),
            flags: mailbox::message_flags(meta)
                .into_iter()
                .map(str::to_string)
                .collect(),
            body: String::new(),
            body_structure: rfc822::build_bodystructure(&blob),
            envelope: rfc822::build_envelope(meta, &header),
            size: blob.len() as i64,
            blob,
            recent: false,
        }
    }
}

#[async_trait]
impl GluonMailboxMutation for GluonMailMailboxMutation {
    async fn get_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> Result<Option<MessageEnvelope>> {
        self.view.get_metadata(mailbox, uid).await
    }

    async fn get_proton_id(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> Result<Option<String>> {
        self.view.get_proton_id(mailbox, uid).await
    }

    async fn store_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        proton_id: &ProtonMessageId,
        meta: MessageEnvelope,
    ) -> Result<ImapUid> {
        if let Some(uid) = self.view.get_uid(mailbox, proton_id).await? {
            self.set_flags(
                mailbox,
                uid,
                mailbox::message_flags(&meta)
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            )
            .await?;
            return Ok(uid);
        }

        let (storage_user_id, mailbox_state) = self.ensure_mailbox(mailbox).await?;
        if let Some(internal_message_id) = self
            .store
            .find_message_internal_id_by_remote_id(&storage_user_id, proton_id.as_str())
            .map_err(map_mail_error)?
        {
            let summary = self
                .store
                .add_existing_message_to_mailbox(
                    &storage_user_id,
                    mailbox_state.internal_id,
                    &internal_message_id,
                )
                .map_err(map_mail_error)?;
            self.store
                .set_message_flags(
                    &storage_user_id,
                    &internal_message_id,
                    &mailbox::message_flags(&meta)
                        .into_iter()
                        .map(str::to_string)
                        .collect::<Vec<_>>(),
                )
                .map_err(map_mail_error)?;
            return Ok(ImapUid::from(summary.uid));
        }

        let message = self.placeholder_message(proton_id, &meta);
        self.store
            .append_message(&storage_user_id, mailbox_state.internal_id, &message)
            .map(|summary| ImapUid::from(summary.uid))
            .map_err(map_mail_error)
    }

    async fn store_rfc822(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        data: Vec<u8>,
    ) -> Result<()> {
        let Some((storage_user_id, _mailbox_state, message)) =
            self.message_by_uid(mailbox, uid).await?
        else {
            return Ok(());
        };
        let meta = self
            .view
            .get_metadata(mailbox, uid)
            .await?
            .unwrap_or_else(|| fallback_metadata(&message.summary.remote_id));
        let updated = NewMessage {
            internal_id: message.summary.internal_id.clone(),
            remote_id: message.summary.remote_id.clone(),
            flags: message.summary.flags.clone(),
            body: String::from_utf8_lossy(&extract_text_section(&data)).to_string(),
            body_structure: rfc822::build_bodystructure(&data),
            envelope: rfc822::build_envelope(&meta, &extract_header_section(&data)),
            size: data.len() as i64,
            blob: data,
            recent: message.summary.recent,
        };
        self.store
            .update_message_content(&storage_user_id, &updated.internal_id, &updated)
            .map_err(map_mail_error)
    }

    async fn get_rfc822(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<Option<Vec<u8>>> {
        self.view.get_rfc822(mailbox, uid).await
    }

    async fn set_flags(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        flags: Vec<String>,
    ) -> Result<()> {
        let (storage_user_id, mailbox_state) = self.ensure_mailbox(mailbox).await?;
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(&storage_user_id, mailbox_state.internal_id, uid.value())
            .map_err(map_mail_error)?
        else {
            return Ok(());
        };
        self.store
            .set_message_flags(&storage_user_id, &internal_id, &flags)
            .map_err(map_mail_error)
    }

    async fn add_flags(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        flags: &[String],
    ) -> Result<()> {
        let (storage_user_id, mailbox_state) = self.ensure_mailbox(mailbox).await?;
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(&storage_user_id, mailbox_state.internal_id, uid.value())
            .map_err(map_mail_error)?
        else {
            return Ok(());
        };
        self.store
            .add_message_flags(&storage_user_id, &internal_id, flags)
            .map_err(map_mail_error)
    }

    async fn remove_flags(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        flags: &[String],
    ) -> Result<()> {
        let (storage_user_id, mailbox_state) = self.ensure_mailbox(mailbox).await?;
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(&storage_user_id, mailbox_state.internal_id, uid.value())
            .map_err(map_mail_error)?
        else {
            return Ok(());
        };
        self.store
            .remove_message_flags(&storage_user_id, &internal_id, flags)
            .map_err(map_mail_error)
    }

    async fn get_flags(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<Vec<String>> {
        self.view.get_flags(mailbox, uid).await
    }

    async fn remove_message(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<()> {
        let (storage_user_id, mailbox_state) = self.ensure_mailbox(mailbox).await?;
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(&storage_user_id, mailbox_state.internal_id, uid.value())
            .map_err(map_mail_error)?
        else {
            return Ok(());
        };
        self.store
            .remove_message_from_mailbox(&storage_user_id, mailbox_state.internal_id, &internal_id)
            .map_err(map_mail_error)
    }

    async fn mailbox_status(&self, mailbox: &ScopedMailboxId) -> Result<MailboxStatus> {
        self.view.mailbox_status(mailbox).await
    }

    async fn uid_to_seq(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<Option<u32>> {
        self.view.uid_to_seq(mailbox, uid).await
    }

    async fn batch_remove_messages(
        &self,
        mailbox: &ScopedMailboxId,
        uids: &[ImapUid],
    ) -> Result<()> {
        if uids.is_empty() {
            return Ok(());
        }
        let (storage_user_id, mailbox_state) = self.ensure_mailbox(mailbox).await?;
        let session = self
            .store
            .session(&storage_user_id)
            .map_err(map_mail_error)?;
        for &uid in uids {
            if let Some(internal_id) = session
                .message_internal_id_by_uid(mailbox_state.internal_id, uid.value())
                .map_err(map_mail_error)?
            {
                session
                    .remove_message_from_mailbox(mailbox_state.internal_id, &internal_id)
                    .map_err(map_mail_error)?;
            }
        }
        Ok(())
    }

    async fn batch_store_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        entries: &[(&ProtonMessageId, MessageEnvelope)],
    ) -> Result<Vec<ImapUid>> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }

        let (account_id, mailbox_name) = Self::resolve_parts(mailbox);
        let storage_user_id = self.storage_user_id_for_account(account_id).to_string();
        let mailbox_state = match self.mailbox_by_name(&storage_user_id, mailbox_name).await? {
            Some(m) => m,
            None => {
                return self.default_batch_store_metadata(mailbox, entries).await;
            }
        };

        let conn = self
            .store
            .open_connection_rw(&storage_user_id)
            .map_err(map_mail_error)?;

        let remote_ids: Vec<&str> = entries.iter().map(|(pid, _)| pid.as_str()).collect();

        let existing_uids = self
            .store
            .batch_find_uids_by_remote_id(&conn, mailbox_state.internal_id, &remote_ids)
            .map_err(map_mail_error)?;

        let known_internal_ids = self
            .store
            .batch_find_internal_ids_by_remote_id(&conn, &remote_ids)
            .map_err(map_mail_error)?;

        let mut uids = Vec::with_capacity(entries.len());
        let mut flag_updates: Vec<(String, Vec<String>)> = Vec::new();
        let mut add_to_mailbox: Vec<(String, Vec<String>)> = Vec::new();
        let mut new_messages: Vec<NewMessage> = Vec::new();

        for (proton_id, meta) in entries {
            if let Some(&uid) = existing_uids.get(proton_id.as_str()) {
                let flags: Vec<String> = mailbox::message_flags(meta)
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                if let Some(internal_id) = known_internal_ids.get(proton_id.as_str()) {
                    flag_updates.push((internal_id.clone(), flags));
                }
                uids.push(uid);
            } else if let Some(internal_id) = known_internal_ids.get(proton_id.as_str()) {
                let flags: Vec<String> = mailbox::message_flags(meta)
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                add_to_mailbox.push((internal_id.clone(), flags));
                uids.push(0);
            } else {
                new_messages.push(self.placeholder_message(proton_id, meta));
                uids.push(0);
            }
        }

        if !flag_updates.is_empty() {
            let flag_refs: Vec<(&str, &[String])> = flag_updates
                .iter()
                .map(|(id, flags)| (id.as_str(), flags.as_slice()))
                .collect();
            self.store
                .batch_set_message_flags_on_conn(&conn, &flag_refs)
                .map_err(map_mail_error)?;
        }

        if !add_to_mailbox.is_empty() {
            let ids: Vec<&str> = add_to_mailbox.iter().map(|(id, _)| id.as_str()).collect();
            self.store
                .batch_add_existing_messages_to_mailbox(&conn, mailbox_state.internal_id, &ids)
                .map_err(map_mail_error)?;

            let flag_refs: Vec<(&str, &[String])> = add_to_mailbox
                .iter()
                .map(|(id, flags)| (id.as_str(), flags.as_slice()))
                .collect();
            self.store
                .batch_set_message_flags_on_conn(&conn, &flag_refs)
                .map_err(map_mail_error)?;
        }

        if !new_messages.is_empty() {
            self.store
                .batch_append_messages(
                    &storage_user_id,
                    &conn,
                    mailbox_state.internal_id,
                    &new_messages,
                )
                .map_err(map_mail_error)?;
        }

        drop(conn);

        let snapshot_messages = self
            .store
            .list_upstream_mailbox_messages(&storage_user_id, mailbox_state.internal_id)
            .map_err(map_mail_error)?;
        let uid_by_remote: std::collections::HashMap<&str, u32> = snapshot_messages
            .iter()
            .map(|m| (m.remote_id.as_str(), m.uid))
            .collect();

        for (i, (proton_id, _)) in entries.iter().enumerate() {
            if uids[i] == 0 {
                uids[i] = uid_by_remote.get(proton_id.as_str()).copied().unwrap_or(0);
            }
        }

        Ok(uids.into_iter().map(ImapUid::from).collect())
    }
}

impl GluonMailMailboxMutation {
    async fn default_batch_store_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        entries: &[(&ProtonMessageId, MessageEnvelope)],
    ) -> Result<Vec<ImapUid>> {
        let mut uids = Vec::with_capacity(entries.len());
        for (proton_id, meta) in entries {
            uids.push(
                self.store_metadata(mailbox, proton_id, meta.clone())
                    .await?,
            );
        }
        Ok(uids)
    }
}

fn current_uid_validity() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

fn metadata_blob(meta: &MessageEnvelope) -> Vec<u8> {
    let mut out = String::new();
    out.push_str("From: ");
    out.push_str(&format_header_address(&meta.sender));
    out.push_str("\r\n");
    if !meta.to_list.is_empty() {
        out.push_str("To: ");
        out.push_str(
            &meta
                .to_list
                .iter()
                .map(format_header_address)
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push_str("\r\n");
    }
    out.push_str("Subject: ");
    out.push_str(&meta.subject);
    out.push_str("\r\n");
    if let Some(message_id) = meta.external_id.as_deref() {
        out.push_str("Message-ID: <");
        out.push_str(message_id);
        out.push_str(">\r\n");
    }
    out.push_str("\r\n");
    out.into_bytes()
}

fn format_header_address(address: &EmailAddress) -> String {
    if address.name.trim().is_empty() {
        return address.address.clone();
    }
    format!("{} <{}>", address.name, address.address)
}

fn extract_header_section(data: &[u8]) -> String {
    let s = String::from_utf8_lossy(data);
    if let Some(pos) = s.find("\r\n\r\n") {
        s[..pos].to_string()
    } else if let Some(pos) = s.find("\n\n") {
        s[..pos].to_string()
    } else {
        s.to_string()
    }
}

fn extract_text_section(data: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(data);
    if let Some(pos) = s.find("\r\n\r\n") {
        data[pos + 4..].to_vec()
    } else if let Some(pos) = s.find("\n\n") {
        data[pos + 2..].to_vec()
    } else {
        Vec::new()
    }
}

fn fallback_metadata(proton_id: &str) -> MessageEnvelope {
    MessageEnvelope {
        id: proton_id.to_string(),
        address_id: "addr-1".to_string(),
        label_ids: vec!["0".to_string()],
        external_id: Some(format!("{proton_id}@example.test")),
        subject: proton_id.to_string(),
        sender: EmailAddress {
            name: String::new(),
            address: "unknown@example.test".to_string(),
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

fn map_mail_error(err: gluon_rs_mail::GluonError) -> ImapError {
    ImapError::Protocol(format!("gluon-rs-mail mutation adapter failure: {err}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gluon_rs_mail::{
        AccountBootstrap, CacheLayout, CompatibilityTarget, GluonKey, StoreBootstrap,
    };
    use tempfile::{tempdir, TempDir};

    use super::GluonMailMailboxMutation;
    use crate::imap::mailbox_mutation::GluonMailboxMutation;
    use crate::imap::types::{ImapUid, ProtonMessageId, ScopedMailboxId};
    use gluon_rs_mail::{EmailAddress, MessageEnvelope};

    struct TestFixture {
        _tempdir: TempDir,
        store: Arc<gluon_rs_mail::CompatibleStore>,
    }

    fn open_store() -> TestFixture {
        let tempdir = tempdir().expect("tempdir");
        let store = Arc::new(
            gluon_rs_mail::CompatibleStore::open(StoreBootstrap::new(
                CacheLayout::new(tempdir.path().join("gluon")),
                CompatibilityTarget::pinned("2046c95ca745"),
                vec![AccountBootstrap::new(
                    "account-1",
                    "user-1",
                    GluonKey::try_from_slice(&[7u8; 32]).expect("key"),
                )],
            ))
            .expect("open store"),
        );
        TestFixture {
            _tempdir: tempdir,
            store,
        }
    }

    async fn create_mailbox(store: &gluon_rs_mail::CompatibleStore, name: &str, remote_id: &str) {
        store
            .create_mailbox(
                "user-1",
                &gluon_rs_mail::NewMailbox {
                    remote_id: remote_id.to_string(),
                    name: name.to_string(),
                    uid_validity: 42,
                    subscribed: true,
                    attributes: Vec::new(),
                    flags: Vec::new(),
                    permanent_flags: vec!["\\Seen".to_string(), "\\Flagged".to_string()],
                },
            )
            .await
            .expect("create mailbox");
    }

    fn metadata() -> MessageEnvelope {
        MessageEnvelope {
            id: "msg-1".to_string(),
            address_id: "addr-1".to_string(),
            label_ids: vec!["0".to_string()],
            external_id: Some("msg-1@example.test".to_string()),
            subject: "Mutation Subject".to_string(),
            sender: EmailAddress {
                name: "Alice".to_string(),
                address: "alice@example.test".to_string(),
            },
            to_list: vec![EmailAddress {
                name: "Bob".to_string(),
                address: "bob@example.test".to_string(),
            }],
            cc_list: Vec::new(),
            bcc_list: Vec::new(),
            reply_tos: Vec::new(),
            flags: 0,
            time: 1_700_000_000,
            size: 0,
            unread: 1,
            is_replied: 0,
            is_replied_all: 0,
            is_forwarded: 0,
            num_attachments: 0,
        }
    }

    fn scoped(account: &str, mailbox: &str) -> ScopedMailboxId {
        ScopedMailboxId::from_parts(Some(account), mailbox)
    }

    fn pid(id: &str) -> ProtonMessageId {
        ProtonMessageId::from(id)
    }

    #[tokio::test]
    async fn gluon_mailbox_mutation_writes_flags_and_rfc822() {
        let fixture = open_store();
        create_mailbox(&fixture.store, "INBOX", "0").await;
        let mutation = GluonMailMailboxMutation::new(fixture.store.clone());

        let scoped = scoped("account-1", "INBOX");
        let uid = mutation
            .store_metadata(&scoped, &pid("msg-1"), metadata())
            .await
            .expect("store metadata");
        assert_eq!(uid, ImapUid::from(1u32));

        let blob = b"Date: Tue, 14 Nov 2023 22:13:20 +0000\r\nFrom: Alice <alice@example.test>\r\nTo: Bob <bob@example.test>\r\nSubject: Mutation Subject\r\nMessage-ID: <msg-1@example.test>\r\n\r\nmutation-body".to_vec();
        mutation
            .store_rfc822(&scoped, uid, blob.clone())
            .await
            .expect("store rfc822");
        mutation
            .add_flags(&scoped, uid, &[String::from("\\Seen")])
            .await
            .expect("add flags");

        assert_eq!(
            mutation.get_rfc822(&scoped, uid).await.expect("get rfc822"),
            Some(blob)
        );
        assert_eq!(
            mutation.get_flags(&scoped, uid).await.expect("get flags"),
            vec!["\\Seen".to_string()]
        );
        let status = mutation.mailbox_status(&scoped).await.expect("status");
        assert_eq!(status.exists, 1);
        assert_eq!(status.unseen, 0);
        assert_eq!(status.next_uid, 2);
    }

    #[tokio::test]
    async fn gluon_mailbox_mutation_copies_existing_message_between_mailboxes() {
        let fixture = open_store();
        create_mailbox(&fixture.store, "INBOX", "0").await;
        create_mailbox(&fixture.store, "Archive", "archive").await;
        let mutation = GluonMailMailboxMutation::new(fixture.store.clone());

        let inbox = scoped("account-1", "INBOX");
        let archive = scoped("account-1", "Archive");

        let source_uid = mutation
            .store_metadata(&inbox, &pid("msg-1"), metadata())
            .await
            .expect("store metadata");
        let blob = b"Subject: Mutation Subject\r\n\r\ncopy-body".to_vec();
        mutation
            .store_rfc822(&inbox, source_uid, blob.clone())
            .await
            .expect("store rfc822");

        let archive_uid = mutation
            .store_metadata(&archive, &pid("msg-1"), metadata())
            .await
            .expect("copy metadata");
        assert_eq!(archive_uid, ImapUid::from(1u32));
        assert_eq!(
            mutation
                .get_rfc822(&archive, archive_uid)
                .await
                .expect("archive blob"),
            Some(blob.clone())
        );

        mutation
            .remove_message(&inbox, source_uid)
            .await
            .expect("remove source");
        assert_eq!(
            mutation
                .mailbox_status(&inbox)
                .await
                .expect("inbox status")
                .exists,
            0
        );
        assert_eq!(
            mutation
                .mailbox_status(&archive)
                .await
                .expect("archive status")
                .exists,
            1
        );
        assert_eq!(
            mutation
                .get_rfc822(&archive, archive_uid)
                .await
                .expect("archive blob"),
            Some(blob)
        );
    }
}
