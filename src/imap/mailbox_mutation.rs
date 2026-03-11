use std::sync::Arc;

use async_trait::async_trait;

use crate::api::types::MessageMetadata;

use super::store::{MailboxStatus, MessageStore};
use super::Result;

#[async_trait]
pub trait GluonMailboxMutation: Send + Sync {
    async fn get_metadata(&self, mailbox: &str, uid: u32) -> Result<Option<MessageMetadata>>;
    async fn get_proton_id(&self, mailbox: &str, uid: u32) -> Result<Option<String>>;
    async fn store_metadata(
        &self,
        mailbox: &str,
        proton_id: &str,
        meta: MessageMetadata,
    ) -> Result<u32>;
    async fn store_rfc822(&self, mailbox: &str, uid: u32, data: Vec<u8>) -> Result<()>;
    async fn get_rfc822(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>>;
    async fn set_flags(&self, mailbox: &str, uid: u32, flags: Vec<String>) -> Result<()>;
    async fn add_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()>;
    async fn remove_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()>;
    async fn get_flags(&self, mailbox: &str, uid: u32) -> Result<Vec<String>>;
    async fn remove_message(&self, mailbox: &str, uid: u32) -> Result<()>;
    async fn mailbox_status(&self, mailbox: &str) -> Result<MailboxStatus>;
    async fn uid_to_seq(&self, mailbox: &str, uid: u32) -> Result<Option<u32>>;
}

#[derive(Clone)]
pub struct StoreBackedMailboxMutation {
    store: Arc<dyn MessageStore>,
}

impl StoreBackedMailboxMutation {
    pub fn new(store: Arc<dyn MessageStore>) -> Arc<Self> {
        Arc::new(Self { store })
    }
}

#[async_trait]
impl GluonMailboxMutation for StoreBackedMailboxMutation {
    async fn get_metadata(&self, mailbox: &str, uid: u32) -> Result<Option<MessageMetadata>> {
        self.store.get_metadata(mailbox, uid).await
    }

    async fn get_proton_id(&self, mailbox: &str, uid: u32) -> Result<Option<String>> {
        self.store.get_proton_id(mailbox, uid).await
    }

    async fn store_metadata(
        &self,
        mailbox: &str,
        proton_id: &str,
        meta: MessageMetadata,
    ) -> Result<u32> {
        self.store.store_metadata(mailbox, proton_id, meta).await
    }

    async fn store_rfc822(&self, mailbox: &str, uid: u32, data: Vec<u8>) -> Result<()> {
        self.store.store_rfc822(mailbox, uid, data).await
    }

    async fn get_rfc822(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>> {
        self.store.get_rfc822(mailbox, uid).await
    }

    async fn set_flags(&self, mailbox: &str, uid: u32, flags: Vec<String>) -> Result<()> {
        self.store.set_flags(mailbox, uid, flags).await
    }

    async fn add_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()> {
        self.store.add_flags(mailbox, uid, flags).await
    }

    async fn remove_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()> {
        self.store.remove_flags(mailbox, uid, flags).await
    }

    async fn get_flags(&self, mailbox: &str, uid: u32) -> Result<Vec<String>> {
        self.store.get_flags(mailbox, uid).await
    }

    async fn remove_message(&self, mailbox: &str, uid: u32) -> Result<()> {
        self.store.remove_message(mailbox, uid).await
    }

    async fn mailbox_status(&self, mailbox: &str) -> Result<MailboxStatus> {
        self.store.mailbox_status(mailbox).await
    }

    async fn uid_to_seq(&self, mailbox: &str, uid: u32) -> Result<Option<u32>> {
        self.store.uid_to_seq(mailbox, uid).await
    }
}

#[cfg(test)]
mod tests {
    use super::{GluonMailboxMutation, StoreBackedMailboxMutation};
    use crate::api::types::{EmailAddress, MessageMetadata};
    use crate::imap::store::{InMemoryStore, MessageStore};

    #[tokio::test]
    async fn store_backed_mailbox_mutation_writes_store_state() {
        let store = InMemoryStore::new();
        let mutation = StoreBackedMailboxMutation::new(store.clone());
        let uid = mutation
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
        mutation
            .store_rfc822("uid-1::INBOX", uid, b"From: a\r\n\r\nbody".to_vec())
            .await
            .unwrap();
        mutation
            .add_flags("uid-1::INBOX", uid, &[String::from("\\Seen")])
            .await
            .unwrap();

        assert_eq!(
            store.get_proton_id("uid-1::INBOX", uid).await.unwrap(),
            Some("msg-1".to_string())
        );
        assert_eq!(
            store.get_flags("uid-1::INBOX", uid).await.unwrap(),
            vec!["\\Seen".to_string()]
        );
    }
}
