use std::sync::Arc;

use async_trait::async_trait;

use crate::api::types::MessageMetadata;

use super::store::{MailboxSnapshot, MailboxStatus, MessageStore};
use super::Result;

#[async_trait]
pub trait GluonMailboxView: Send + Sync {
    async fn get_metadata(&self, mailbox: &str, uid: u32) -> Result<Option<MessageMetadata>>;
    async fn get_proton_id(&self, mailbox: &str, uid: u32) -> Result<Option<String>>;
    async fn get_uid(&self, mailbox: &str, proton_id: &str) -> Result<Option<u32>>;
    async fn get_rfc822(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>>;
    async fn list_uids(&self, mailbox: &str) -> Result<Vec<u32>>;
    async fn mailbox_status(&self, mailbox: &str) -> Result<MailboxStatus>;
    async fn mailbox_snapshot(&self, mailbox: &str) -> Result<MailboxSnapshot>;
    async fn get_flags(&self, mailbox: &str, uid: u32) -> Result<Vec<String>>;
    async fn seq_to_uid(&self, mailbox: &str, seq: u32) -> Result<Option<u32>>;
    async fn uid_to_seq(&self, mailbox: &str, uid: u32) -> Result<Option<u32>>;
}

#[derive(Clone)]
pub struct StoreBackedMailboxView {
    store: Arc<dyn MessageStore>,
}

impl StoreBackedMailboxView {
    pub fn new(store: Arc<dyn MessageStore>) -> Arc<Self> {
        Arc::new(Self { store })
    }
}

#[async_trait]
impl GluonMailboxView for StoreBackedMailboxView {
    async fn get_metadata(&self, mailbox: &str, uid: u32) -> Result<Option<MessageMetadata>> {
        self.store.get_metadata(mailbox, uid).await
    }

    async fn get_proton_id(&self, mailbox: &str, uid: u32) -> Result<Option<String>> {
        self.store.get_proton_id(mailbox, uid).await
    }

    async fn get_uid(&self, mailbox: &str, proton_id: &str) -> Result<Option<u32>> {
        self.store.get_uid(mailbox, proton_id).await
    }

    async fn get_rfc822(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>> {
        self.store.get_rfc822(mailbox, uid).await
    }

    async fn list_uids(&self, mailbox: &str) -> Result<Vec<u32>> {
        self.store.list_uids(mailbox).await
    }

    async fn mailbox_status(&self, mailbox: &str) -> Result<MailboxStatus> {
        self.store.mailbox_status(mailbox).await
    }

    async fn mailbox_snapshot(&self, mailbox: &str) -> Result<MailboxSnapshot> {
        self.store.mailbox_snapshot(mailbox).await
    }

    async fn get_flags(&self, mailbox: &str, uid: u32) -> Result<Vec<String>> {
        self.store.get_flags(mailbox, uid).await
    }

    async fn seq_to_uid(&self, mailbox: &str, seq: u32) -> Result<Option<u32>> {
        self.store.seq_to_uid(mailbox, seq).await
    }

    async fn uid_to_seq(&self, mailbox: &str, uid: u32) -> Result<Option<u32>> {
        self.store.uid_to_seq(mailbox, uid).await
    }
}

#[cfg(test)]
mod tests {
    use super::{GluonMailboxView, StoreBackedMailboxView};
    use crate::api::types::{EmailAddress, MessageMetadata};
    use crate::imap::store::{InMemoryStore, MessageStore};

    #[tokio::test]
    async fn store_backed_mailbox_view_reads_store_state() {
        let store = InMemoryStore::new();
        let uid = store
            .store_metadata(
                "uid-1::INBOX",
                "msg-1",
                MessageMetadata {
                    id: "msg-1".to_string(),
                    address_id: "addr-1".to_string(),
                    external_id: None,
                    label_ids: vec!["0".to_string()],
                    subject: "subject".to_string(),
                    sender: EmailAddress {
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
                },
            )
            .await
            .unwrap();
        store
            .store_rfc822("uid-1::INBOX", uid, b"From: a\r\n\r\nbody".to_vec())
            .await
            .unwrap();

        let view = StoreBackedMailboxView::new(store.clone());
        assert_eq!(view.list_uids("uid-1::INBOX").await.unwrap(), vec![uid]);
        assert_eq!(
            view.get_proton_id("uid-1::INBOX", uid).await.unwrap(),
            Some("msg-1".to_string())
        );
        assert!(view
            .get_rfc822("uid-1::INBOX", uid)
            .await
            .unwrap()
            .is_some());
    }
}
