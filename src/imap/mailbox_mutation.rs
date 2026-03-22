use async_trait::async_trait;

use crate::api::types::MessageMetadata;

use super::store::MailboxStatus;
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

    async fn batch_store_metadata(
        &self,
        mailbox: &str,
        entries: &[(&str, crate::api::types::MessageMetadata)],
    ) -> Result<Vec<u32>> {
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
