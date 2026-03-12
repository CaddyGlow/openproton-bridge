use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use gluon_rs_mail::{
    CompatibleStore, NewMailbox, NewMessage, UpstreamMailbox, UpstreamMailboxMessage,
};
use uuid::Uuid;

use crate::api::types::{EmailAddress, MessageMetadata};

use super::gluon_mailbox_view::GluonMailMailboxView;
use super::mailbox;
use super::mailbox_mutation::GluonMailboxMutation;
use super::mailbox_view::GluonMailboxView;
use super::rfc822;
use super::store::MailboxStatus;
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

    fn scoped_mailbox_parts(mailbox: &str) -> (&str, &str) {
        match mailbox.split_once("::") {
            Some((account_id, mailbox_name)) if !account_id.is_empty() => {
                let mailbox_name = if mailbox_name.is_empty() {
                    "INBOX"
                } else {
                    mailbox_name
                };
                (account_id, mailbox_name)
            }
            _ => ("__default__", mailbox),
        }
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
        let (account_id, mailbox_name) = Self::scoped_mailbox_parts(mailbox);
        let storage_user_id = self.storage_user_id_for_account(account_id).to_string();
        if let Some(mailbox) = self.mailbox_by_name(&storage_user_id, mailbox_name)? {
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

    fn message_by_uid(
        &self,
        mailbox: &str,
        uid: u32,
    ) -> Result<Option<(String, UpstreamMailbox, UpstreamMailboxMessage)>> {
        let (storage_user_id, mailbox_state) = self.ensure_mailbox(mailbox)?;
        let snapshot = self
            .store
            .mailbox_snapshot(&storage_user_id, mailbox_state.internal_id)
            .map_err(map_mail_error)?;
        Ok(snapshot
            .messages
            .into_iter()
            .find(|message| message.summary.uid == uid)
            .map(|message| (storage_user_id, mailbox_state, message)))
    }

    fn placeholder_message(&self, proton_id: &str, meta: &MessageMetadata) -> NewMessage {
        let blob = metadata_blob(meta);
        let header = extract_header_section(&blob);
        NewMessage {
            internal_id: Uuid::new_v4().to_string(),
            remote_id: proton_id.to_string(),
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
    async fn get_metadata(&self, mailbox: &str, uid: u32) -> Result<Option<MessageMetadata>> {
        self.view.get_metadata(mailbox, uid).await
    }

    async fn get_proton_id(&self, mailbox: &str, uid: u32) -> Result<Option<String>> {
        self.view.get_proton_id(mailbox, uid).await
    }

    async fn store_metadata(
        &self,
        mailbox: &str,
        proton_id: &str,
        meta: MessageMetadata,
    ) -> Result<u32> {
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

        let (storage_user_id, mailbox_state) = self.ensure_mailbox(mailbox)?;
        if let Some(internal_message_id) = self
            .store
            .find_message_internal_id_by_remote_id(&storage_user_id, proton_id)
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
            return Ok(summary.uid);
        }

        let message = self.placeholder_message(proton_id, &meta);
        self.store
            .append_message(&storage_user_id, mailbox_state.internal_id, &message)
            .map(|summary| summary.uid)
            .map_err(map_mail_error)
    }

    async fn store_rfc822(&self, mailbox: &str, uid: u32, data: Vec<u8>) -> Result<()> {
        let Some((storage_user_id, _mailbox_state, message)) = self.message_by_uid(mailbox, uid)?
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

    async fn get_rfc822(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>> {
        self.view.get_rfc822(mailbox, uid).await
    }

    async fn set_flags(&self, mailbox: &str, uid: u32, flags: Vec<String>) -> Result<()> {
        let Some((storage_user_id, _mailbox_state, message)) = self.message_by_uid(mailbox, uid)?
        else {
            return Ok(());
        };
        self.store
            .set_message_flags(&storage_user_id, &message.summary.internal_id, &flags)
            .map_err(map_mail_error)
    }

    async fn add_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()> {
        let Some((storage_user_id, _mailbox_state, message)) = self.message_by_uid(mailbox, uid)?
        else {
            return Ok(());
        };
        self.store
            .add_message_flags(&storage_user_id, &message.summary.internal_id, flags)
            .map_err(map_mail_error)
    }

    async fn remove_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()> {
        let Some((storage_user_id, _mailbox_state, message)) = self.message_by_uid(mailbox, uid)?
        else {
            return Ok(());
        };
        self.store
            .remove_message_flags(&storage_user_id, &message.summary.internal_id, flags)
            .map_err(map_mail_error)
    }

    async fn get_flags(&self, mailbox: &str, uid: u32) -> Result<Vec<String>> {
        self.view.get_flags(mailbox, uid).await
    }

    async fn remove_message(&self, mailbox: &str, uid: u32) -> Result<()> {
        let Some((storage_user_id, mailbox_state, message)) = self.message_by_uid(mailbox, uid)?
        else {
            return Ok(());
        };
        self.store
            .remove_message_from_mailbox(
                &storage_user_id,
                mailbox_state.internal_id,
                &message.summary.internal_id,
            )
            .map_err(map_mail_error)
    }

    async fn mailbox_status(&self, mailbox: &str) -> Result<MailboxStatus> {
        self.view.mailbox_status(mailbox).await
    }

    async fn uid_to_seq(&self, mailbox: &str, uid: u32) -> Result<Option<u32>> {
        self.view.uid_to_seq(mailbox, uid).await
    }
}

fn current_uid_validity() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

fn metadata_blob(meta: &MessageMetadata) -> Vec<u8> {
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

fn fallback_metadata(proton_id: &str) -> MessageMetadata {
    MessageMetadata {
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
    use crate::api::types::{EmailAddress, MessageMetadata};
    use crate::imap::mailbox_mutation::GluonMailboxMutation;

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

    fn create_mailbox(store: &gluon_rs_mail::CompatibleStore, name: &str, remote_id: &str) {
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
            .expect("create mailbox");
    }

    fn metadata() -> MessageMetadata {
        MessageMetadata {
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

    #[tokio::test]
    async fn gluon_mailbox_mutation_writes_flags_and_rfc822() {
        let fixture = open_store();
        create_mailbox(&fixture.store, "INBOX", "0");
        let mutation = GluonMailMailboxMutation::new(fixture.store.clone());

        let uid = mutation
            .store_metadata("account-1::INBOX", "msg-1", metadata())
            .await
            .expect("store metadata");
        assert_eq!(uid, 1);

        let blob = b"Date: Tue, 14 Nov 2023 22:13:20 +0000\r\nFrom: Alice <alice@example.test>\r\nTo: Bob <bob@example.test>\r\nSubject: Mutation Subject\r\nMessage-ID: <msg-1@example.test>\r\n\r\nmutation-body".to_vec();
        mutation
            .store_rfc822("account-1::INBOX", uid, blob.clone())
            .await
            .expect("store rfc822");
        mutation
            .add_flags("account-1::INBOX", uid, &[String::from("\\Seen")])
            .await
            .expect("add flags");

        assert_eq!(
            mutation
                .get_rfc822("account-1::INBOX", uid)
                .await
                .expect("get rfc822"),
            Some(blob)
        );
        assert_eq!(
            mutation
                .get_flags("account-1::INBOX", uid)
                .await
                .expect("get flags"),
            vec!["\\Seen".to_string()]
        );
        let status = mutation
            .mailbox_status("account-1::INBOX")
            .await
            .expect("status");
        assert_eq!(status.exists, 1);
        assert_eq!(status.unseen, 0);
        assert_eq!(status.next_uid, 2);
    }

    #[tokio::test]
    async fn gluon_mailbox_mutation_copies_existing_message_between_mailboxes() {
        let fixture = open_store();
        create_mailbox(&fixture.store, "INBOX", "0");
        create_mailbox(&fixture.store, "Archive", "archive");
        let mutation = GluonMailMailboxMutation::new(fixture.store.clone());

        let source_uid = mutation
            .store_metadata("account-1::INBOX", "msg-1", metadata())
            .await
            .expect("store metadata");
        let blob = b"Subject: Mutation Subject\r\n\r\ncopy-body".to_vec();
        mutation
            .store_rfc822("account-1::INBOX", source_uid, blob.clone())
            .await
            .expect("store rfc822");

        let archive_uid = mutation
            .store_metadata("account-1::Archive", "msg-1", metadata())
            .await
            .expect("copy metadata");
        assert_eq!(archive_uid, 1);
        assert_eq!(
            mutation
                .get_rfc822("account-1::Archive", archive_uid)
                .await
                .expect("archive blob"),
            Some(blob.clone())
        );

        mutation
            .remove_message("account-1::INBOX", source_uid)
            .await
            .expect("remove source");
        assert_eq!(
            mutation
                .mailbox_status("account-1::INBOX")
                .await
                .expect("inbox status")
                .exists,
            0
        );
        assert_eq!(
            mutation
                .mailbox_status("account-1::Archive")
                .await
                .expect("archive status")
                .exists,
            1
        );
        assert_eq!(
            mutation
                .get_rfc822("account-1::Archive", archive_uid)
                .await
                .expect("archive blob"),
            Some(blob)
        );
    }
}
