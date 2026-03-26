use async_trait::async_trait;

use gluon_rs_mail::MessageEnvelope;

use super::store::{MailboxSnapshot, MailboxStatus, SelectMailboxData};
use super::types::{ImapUid, ProtonMessageId, ScopedMailboxId};
use super::Result;

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
