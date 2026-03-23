use async_trait::async_trait;

use crate::imap_error::ImapResult as Result;
use crate::imap_types::{EmailAddress, MailboxInfo, MessageEnvelope};

/// Result of a successful IMAP LOGIN.
pub struct AuthResult {
    pub account_id: String,
    pub primary_email: String,
    pub mailboxes: Vec<MailboxInfo>,
}

/// Abstraction over the upstream mail provider (e.g., Proton API).
///
/// The IMAP session delegates all upstream operations through this trait,
/// keeping the protocol layer free of API/crypto dependencies.
/// This is the Rust equivalent of Go gluon's `Connector` interface.
#[async_trait]
pub trait ImapConnector: Send + Sync {
    /// Authenticate IMAP credentials. Returns account info on success.
    async fn authorize(&self, username: &str, password: &str) -> Result<AuthResult>;

    /// Fetch and decrypt a full message body (RFC822 bytes) by Proton message ID.
    /// Called on FETCH cache miss when the store doesn't have the body cached.
    async fn get_message_literal(
        &self,
        account_id: &str,
        message_id: &str,
    ) -> Result<Option<Vec<u8>>>;

    /// Mark messages as read/unread upstream.
    async fn mark_messages_read(
        &self,
        account_id: &str,
        message_ids: &[&str],
        read: bool,
    ) -> Result<()>;

    /// Star/unstar messages upstream.
    async fn mark_messages_starred(
        &self,
        account_id: &str,
        message_ids: &[&str],
        starred: bool,
    ) -> Result<()>;

    /// Add messages to a mailbox (label) upstream. Used by COPY.
    async fn label_messages(
        &self,
        account_id: &str,
        message_ids: &[&str],
        label_id: &str,
    ) -> Result<()>;

    /// Remove messages from a mailbox (label) upstream. Used by MOVE.
    async fn unlabel_messages(
        &self,
        account_id: &str,
        message_ids: &[&str],
        label_id: &str,
    ) -> Result<()>;

    /// Move messages to trash.
    async fn trash_messages(
        &self,
        account_id: &str,
        message_ids: &[&str],
    ) -> Result<()>;

    /// Permanently delete messages.
    async fn delete_messages(
        &self,
        account_id: &str,
        message_ids: &[&str],
    ) -> Result<()>;

    /// Encrypt and import a message upstream (APPEND).
    /// Returns the Proton message ID on success.
    async fn import_message(
        &self,
        account_id: &str,
        label_id: &str,
        flags: i64,
        literal: &[u8],
    ) -> Result<Option<String>>;

    /// Fetch a page of message metadata from upstream for initial mailbox population.
    async fn fetch_message_metadata_page(
        &self,
        account_id: &str,
        label_id: &str,
        page: i32,
        page_size: i32,
    ) -> Result<MetadataPage>;

    /// Fetch user labels from upstream.
    async fn fetch_user_labels(&self, account_id: &str) -> Result<Vec<MailboxInfo>>;
}

/// A page of message metadata from the upstream provider.
pub struct MetadataPage {
    pub messages: Vec<MessageEnvelope>,
    pub total: i64,
}
