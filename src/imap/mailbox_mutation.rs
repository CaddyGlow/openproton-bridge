use async_trait::async_trait;

use gluon_rs_mail::MessageEnvelope;

use super::store::MailboxStatus;
use super::types::{ImapUid, ProtonMessageId, ScopedMailboxId};
use super::Result;

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
