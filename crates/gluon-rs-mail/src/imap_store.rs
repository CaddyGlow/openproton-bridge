use std::collections::HashMap;

use async_trait::async_trait;

use crate::imap_error::ImapResult as Result;
use crate::imap_types::{ImapUid, MessageEnvelope, MessageId, ScopedMailboxId};

/// Backwards-compatible alias for code that still uses ProtonMessageId.
pub type ProtonMessageId = MessageId;

pub struct MailboxStatus {
    pub uid_validity: u32,
    pub next_uid: u32,
    pub exists: u32,
    pub unseen: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxSnapshot {
    pub exists: u32,
    pub mod_seq: u64,
}

pub struct SelectMailboxData {
    pub status: MailboxStatus,
    pub snapshot: MailboxSnapshot,
    pub uids: Vec<ImapUid>,
    pub flags: HashMap<ImapUid, Vec<String>>,
    pub first_unseen_seq: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreEventKind {
    MailboxCreated,
    MessageAdded,
    MessageUpdated,
    MessageBodyUpdated,
    MessageFlagsUpdated,
    MessageRemoved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreEvent {
    pub mailbox: String,
    pub uid: Option<u32>,
    pub proton_id: Option<String>,
    pub kind: StoreEventKind,
    pub mod_seq: u64,
}

#[async_trait]
pub trait GluonMailboxView: Send + Sync {
    async fn get_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> Result<Option<MessageEnvelope>>;
    async fn get_proton_id(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> Result<Option<String>>;
    async fn get_uid(
        &self,
        mailbox: &ScopedMailboxId,
        proton_id: &ProtonMessageId,
    ) -> Result<Option<ImapUid>>;
    async fn get_rfc822(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<Option<Vec<u8>>>;
    async fn list_uids(&self, mailbox: &ScopedMailboxId) -> Result<Vec<ImapUid>>;
    async fn mailbox_status(&self, mailbox: &ScopedMailboxId) -> Result<MailboxStatus>;
    async fn mailbox_snapshot(&self, mailbox: &ScopedMailboxId) -> Result<MailboxSnapshot>;
    async fn get_flags(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<Vec<String>>;
    async fn seq_to_uid(&self, mailbox: &ScopedMailboxId, seq: u32) -> Result<Option<ImapUid>>;
    async fn uid_to_seq(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<Option<u32>>;
    async fn select_mailbox_data(&self, mailbox: &ScopedMailboxId) -> Result<SelectMailboxData>;

    /// Fast path: single connection for SELECT data instead of multiple pool.acquire() calls.
    /// Default falls back to `select_mailbox_data`.
    async fn select_mailbox_data_fast(
        &self,
        mailbox: &ScopedMailboxId,
    ) -> Result<SelectMailboxData> {
        self.select_mailbox_data(mailbox).await
    }
}

#[async_trait]
pub trait GluonMailboxMutation: Send + Sync {
    async fn get_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> Result<Option<MessageEnvelope>>;
    async fn get_proton_id(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> Result<Option<String>>;
    async fn store_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        proton_id: &ProtonMessageId,
        meta: MessageEnvelope,
    ) -> Result<ImapUid>;
    async fn store_rfc822(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        data: Vec<u8>,
    ) -> Result<()>;
    async fn get_rfc822(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<Option<Vec<u8>>>;
    async fn set_flags(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        flags: Vec<String>,
    ) -> Result<()>;
    async fn add_flags(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        flags: &[String],
    ) -> Result<()>;
    async fn remove_flags(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        flags: &[String],
    ) -> Result<()>;
    async fn get_flags(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<Vec<String>>;
    async fn remove_message(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<()>;
    async fn mailbox_status(&self, mailbox: &ScopedMailboxId) -> Result<MailboxStatus>;
    async fn uid_to_seq(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<Option<u32>>;

    async fn batch_remove_messages(
        &self,
        mailbox: &ScopedMailboxId,
        uids: &[ImapUid],
    ) -> Result<()> {
        for &uid in uids {
            self.remove_message(mailbox, uid).await?;
        }
        Ok(())
    }

    async fn batch_store_metadata(
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
