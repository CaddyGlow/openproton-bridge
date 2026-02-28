use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::api::types::MessageMetadata;

use super::Result;

pub struct MailboxStatus {
    pub uid_validity: u32,
    pub next_uid: u32,
    pub exists: u32,
    pub unseen: u32,
}

#[async_trait]
pub trait MessageStore: Send + Sync {
    async fn store_metadata(
        &self,
        mailbox: &str,
        proton_id: &str,
        meta: MessageMetadata,
    ) -> Result<u32>;
    async fn get_metadata(&self, mailbox: &str, uid: u32) -> Result<Option<MessageMetadata>>;
    async fn get_proton_id(&self, mailbox: &str, uid: u32) -> Result<Option<String>>;
    async fn get_uid(&self, mailbox: &str, proton_id: &str) -> Result<Option<u32>>;
    async fn store_rfc822(&self, mailbox: &str, uid: u32, data: Vec<u8>) -> Result<()>;
    async fn get_rfc822(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>>;
    async fn list_uids(&self, mailbox: &str) -> Result<Vec<u32>>;
    async fn mailbox_status(&self, mailbox: &str) -> Result<MailboxStatus>;
    async fn set_flags(&self, mailbox: &str, uid: u32, flags: Vec<String>) -> Result<()>;
    async fn add_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()>;
    async fn remove_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()>;
    async fn get_flags(&self, mailbox: &str, uid: u32) -> Result<Vec<String>>;
    async fn remove_message(&self, mailbox: &str, uid: u32) -> Result<()>;
    async fn seq_to_uid(&self, mailbox: &str, seq: u32) -> Result<Option<u32>>;
    async fn uid_to_seq(&self, mailbox: &str, uid: u32) -> Result<Option<u32>>;
}

struct MailboxData {
    uid_validity: u32,
    next_uid: u32,
    proton_to_uid: HashMap<String, u32>,
    uid_to_proton: HashMap<u32, String>,
    metadata: HashMap<u32, MessageMetadata>,
    rfc822: HashMap<u32, Vec<u8>>,
    flags: HashMap<u32, Vec<String>>,
    uid_order: Vec<u32>,
}

impl MailboxData {
    fn new() -> Self {
        let uid_validity = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        Self {
            uid_validity,
            next_uid: 1,
            proton_to_uid: HashMap::new(),
            uid_to_proton: HashMap::new(),
            metadata: HashMap::new(),
            rfc822: HashMap::new(),
            flags: HashMap::new(),
            uid_order: Vec::new(),
        }
    }
}

pub struct InMemoryStore {
    mailboxes: RwLock<HashMap<String, MailboxData>>,
}

impl InMemoryStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            mailboxes: RwLock::new(HashMap::new()),
        })
    }
}

#[async_trait]
impl MessageStore for InMemoryStore {
    async fn store_metadata(
        &self,
        mailbox: &str,
        proton_id: &str,
        meta: MessageMetadata,
    ) -> Result<u32> {
        let mut mailboxes = self.mailboxes.write().await;
        let mb = mailboxes
            .entry(mailbox.to_string())
            .or_insert_with(MailboxData::new);

        if let Some(&uid) = mb.proton_to_uid.get(proton_id) {
            mb.metadata.insert(uid, meta);
            return Ok(uid);
        }

        let uid = mb.next_uid;
        mb.next_uid += 1;
        mb.proton_to_uid.insert(proton_id.to_string(), uid);
        mb.uid_to_proton.insert(uid, proton_id.to_string());
        mb.uid_order.push(uid);
        mb.metadata.insert(uid, meta);
        Ok(uid)
    }

    async fn get_metadata(&self, mailbox: &str, uid: u32) -> Result<Option<MessageMetadata>> {
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes
            .get(mailbox)
            .and_then(|mb| mb.metadata.get(&uid).cloned()))
    }

    async fn get_proton_id(&self, mailbox: &str, uid: u32) -> Result<Option<String>> {
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes
            .get(mailbox)
            .and_then(|mb| mb.uid_to_proton.get(&uid).cloned()))
    }

    async fn get_uid(&self, mailbox: &str, proton_id: &str) -> Result<Option<u32>> {
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes
            .get(mailbox)
            .and_then(|mb| mb.proton_to_uid.get(proton_id).copied()))
    }

    async fn store_rfc822(&self, mailbox: &str, uid: u32, data: Vec<u8>) -> Result<()> {
        let mut mailboxes = self.mailboxes.write().await;
        let mb = mailboxes
            .entry(mailbox.to_string())
            .or_insert_with(MailboxData::new);
        mb.rfc822.insert(uid, data);
        Ok(())
    }

    async fn get_rfc822(&self, mailbox: &str, uid: u32) -> Result<Option<Vec<u8>>> {
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes
            .get(mailbox)
            .and_then(|mb| mb.rfc822.get(&uid).cloned()))
    }

    async fn list_uids(&self, mailbox: &str) -> Result<Vec<u32>> {
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes
            .get(mailbox)
            .map(|mb| mb.uid_order.clone())
            .unwrap_or_default())
    }

    async fn mailbox_status(&self, mailbox: &str) -> Result<MailboxStatus> {
        let mailboxes = self.mailboxes.read().await;
        match mailboxes.get(mailbox) {
            Some(mb) => {
                let unseen = mb
                    .flags
                    .values()
                    .filter(|f| !f.iter().any(|flag| flag == "\\Seen"))
                    .count() as u32;
                // Also count messages with no flags entry as unseen unless metadata says read
                let no_flags_unseen = mb
                    .metadata
                    .iter()
                    .filter(|(uid, meta)| !mb.flags.contains_key(uid) && meta.unread != 0)
                    .count() as u32;
                Ok(MailboxStatus {
                    uid_validity: mb.uid_validity,
                    next_uid: mb.next_uid,
                    exists: mb.uid_order.len() as u32,
                    unseen: unseen + no_flags_unseen,
                })
            }
            None => Ok(MailboxStatus {
                uid_validity: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32,
                next_uid: 1,
                exists: 0,
                unseen: 0,
            }),
        }
    }

    async fn set_flags(&self, mailbox: &str, uid: u32, flags: Vec<String>) -> Result<()> {
        let mut mailboxes = self.mailboxes.write().await;
        if let Some(mb) = mailboxes.get_mut(mailbox) {
            mb.flags.insert(uid, flags);
        }
        Ok(())
    }

    async fn add_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()> {
        let mut mailboxes = self.mailboxes.write().await;
        if let Some(mb) = mailboxes.get_mut(mailbox) {
            let entry = mb.flags.entry(uid).or_default();
            for flag in flags {
                if !entry.contains(flag) {
                    entry.push(flag.clone());
                }
            }
        }
        Ok(())
    }

    async fn remove_flags(&self, mailbox: &str, uid: u32, flags: &[String]) -> Result<()> {
        let mut mailboxes = self.mailboxes.write().await;
        if let Some(mb) = mailboxes.get_mut(mailbox) {
            if let Some(current) = mb.flags.get_mut(&uid) {
                current.retain(|f| !flags.contains(f));
            }
        }
        Ok(())
    }

    async fn get_flags(&self, mailbox: &str, uid: u32) -> Result<Vec<String>> {
        let mailboxes = self.mailboxes.read().await;
        if let Some(mb) = mailboxes.get(mailbox) {
            if let Some(flags) = mb.flags.get(&uid) {
                return Ok(flags.clone());
            }
            // Derive from metadata if not explicitly set
            if let Some(meta) = mb.metadata.get(&uid) {
                let mflags = super::mailbox::message_flags(meta);
                return Ok(mflags.iter().map(|s| s.to_string()).collect());
            }
        }
        Ok(Vec::new())
    }

    async fn remove_message(&self, mailbox: &str, uid: u32) -> Result<()> {
        let mut mailboxes = self.mailboxes.write().await;
        if let Some(mb) = mailboxes.get_mut(mailbox) {
            if let Some(proton_id) = mb.uid_to_proton.remove(&uid) {
                mb.proton_to_uid.remove(&proton_id);
            }
            mb.metadata.remove(&uid);
            mb.rfc822.remove(&uid);
            mb.flags.remove(&uid);
            mb.uid_order.retain(|&u| u != uid);
        }
        Ok(())
    }

    async fn seq_to_uid(&self, mailbox: &str, seq: u32) -> Result<Option<u32>> {
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes
            .get(mailbox)
            .and_then(|mb| mb.uid_order.get(seq as usize - 1).copied()))
    }

    async fn uid_to_seq(&self, mailbox: &str, uid: u32) -> Result<Option<u32>> {
        let mailboxes = self.mailboxes.read().await;
        Ok(mailboxes.get(mailbox).and_then(|mb| {
            mb.uid_order
                .iter()
                .position(|&u| u == uid)
                .map(|p| p as u32 + 1)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::EmailAddress;

    fn make_meta(id: &str, unread: i32) -> MessageMetadata {
        MessageMetadata {
            id: id.to_string(),
            address_id: "addr-1".to_string(),
            label_ids: vec!["0".to_string()],
            subject: format!("Subject {}", id),
            sender: EmailAddress {
                name: "Alice".to_string(),
                address: "alice@proton.me".to_string(),
            },
            to_list: vec![],
            cc_list: vec![],
            bcc_list: vec![],
            time: 1700000000,
            size: 1024,
            unread,
            num_attachments: 0,
        }
    }

    #[tokio::test]
    async fn test_store_and_retrieve_metadata() {
        let store = InMemoryStore::new();
        let meta = make_meta("msg-1", 1);
        let uid = store.store_metadata("INBOX", "msg-1", meta).await.unwrap();
        assert_eq!(uid, 1);

        let retrieved = store.get_metadata("INBOX", uid).await.unwrap().unwrap();
        assert_eq!(retrieved.id, "msg-1");
        assert_eq!(retrieved.subject, "Subject msg-1");
    }

    #[tokio::test]
    async fn test_uid_monotonicity() {
        let store = InMemoryStore::new();
        let uid1 = store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        let uid2 = store
            .store_metadata("INBOX", "msg-2", make_meta("msg-2", 0))
            .await
            .unwrap();
        let uid3 = store
            .store_metadata("INBOX", "msg-3", make_meta("msg-3", 0))
            .await
            .unwrap();
        assert_eq!(uid1, 1);
        assert_eq!(uid2, 2);
        assert_eq!(uid3, 3);
    }

    #[tokio::test]
    async fn test_duplicate_proton_id_returns_same_uid() {
        let store = InMemoryStore::new();
        let uid1 = store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        let uid2 = store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        assert_eq!(uid1, uid2);
    }

    #[tokio::test]
    async fn test_proton_id_uid_mapping() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();

        let uid = store.get_uid("INBOX", "msg-1").await.unwrap().unwrap();
        assert_eq!(uid, 1);

        let proton_id = store.get_proton_id("INBOX", 1).await.unwrap().unwrap();
        assert_eq!(proton_id, "msg-1");
    }

    #[tokio::test]
    async fn test_rfc822_store_and_retrieve() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();

        let data = b"From: test\r\nSubject: hi\r\n\r\nbody".to_vec();
        store.store_rfc822("INBOX", 1, data.clone()).await.unwrap();

        let retrieved = store.get_rfc822("INBOX", 1).await.unwrap().unwrap();
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn test_list_uids() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        store
            .store_metadata("INBOX", "msg-2", make_meta("msg-2", 0))
            .await
            .unwrap();

        let uids = store.list_uids("INBOX").await.unwrap();
        assert_eq!(uids, vec![1, 2]);
    }

    #[tokio::test]
    async fn test_mailbox_status() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();
        store
            .store_metadata("INBOX", "msg-2", make_meta("msg-2", 0))
            .await
            .unwrap();

        let status = store.mailbox_status("INBOX").await.unwrap();
        assert_eq!(status.exists, 2);
        assert_eq!(status.next_uid, 3);
        assert_eq!(status.unseen, 1);
    }

    #[tokio::test]
    async fn test_flag_operations() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 1))
            .await
            .unwrap();

        // Set flags
        store
            .set_flags("INBOX", 1, vec!["\\Seen".to_string()])
            .await
            .unwrap();
        let flags = store.get_flags("INBOX", 1).await.unwrap();
        assert_eq!(flags, vec!["\\Seen"]);

        // Add flags
        store
            .add_flags("INBOX", 1, &["\\Flagged".to_string()])
            .await
            .unwrap();
        let flags = store.get_flags("INBOX", 1).await.unwrap();
        assert!(flags.contains(&"\\Seen".to_string()));
        assert!(flags.contains(&"\\Flagged".to_string()));

        // Remove flags
        store
            .remove_flags("INBOX", 1, &["\\Seen".to_string()])
            .await
            .unwrap();
        let flags = store.get_flags("INBOX", 1).await.unwrap();
        assert!(!flags.contains(&"\\Seen".to_string()));
        assert!(flags.contains(&"\\Flagged".to_string()));
    }

    #[tokio::test]
    async fn test_independent_mailboxes() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        store
            .store_metadata("Sent", "msg-2", make_meta("msg-2", 0))
            .await
            .unwrap();

        let inbox_uids = store.list_uids("INBOX").await.unwrap();
        let sent_uids = store.list_uids("Sent").await.unwrap();
        assert_eq!(inbox_uids, vec![1]);
        assert_eq!(sent_uids, vec![1]);
    }

    #[tokio::test]
    async fn test_seq_uid_conversion() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        store
            .store_metadata("INBOX", "msg-2", make_meta("msg-2", 0))
            .await
            .unwrap();

        assert_eq!(store.seq_to_uid("INBOX", 1).await.unwrap(), Some(1));
        assert_eq!(store.seq_to_uid("INBOX", 2).await.unwrap(), Some(2));
        assert_eq!(store.uid_to_seq("INBOX", 1).await.unwrap(), Some(1));
        assert_eq!(store.uid_to_seq("INBOX", 2).await.unwrap(), Some(2));
    }

    #[tokio::test]
    async fn test_remove_message() {
        let store = InMemoryStore::new();
        store
            .store_metadata("INBOX", "msg-1", make_meta("msg-1", 0))
            .await
            .unwrap();
        store
            .store_metadata("INBOX", "msg-2", make_meta("msg-2", 0))
            .await
            .unwrap();

        store.remove_message("INBOX", 1).await.unwrap();

        let uids = store.list_uids("INBOX").await.unwrap();
        assert_eq!(uids, vec![2]);
        assert!(store.get_metadata("INBOX", 1).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_empty_mailbox_status() {
        let store = InMemoryStore::new();
        let status = store.mailbox_status("INBOX").await.unwrap();
        assert_eq!(status.exists, 0);
        assert_eq!(status.next_uid, 1);
        assert_eq!(status.unseen, 0);
    }
}
