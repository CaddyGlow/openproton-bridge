use async_trait::async_trait;

use crate::api::types::MessageMetadata;

use super::store::{MailboxSnapshot, MailboxStatus};
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
