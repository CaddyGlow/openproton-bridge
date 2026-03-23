pub use gluon_rs_mail::{ImapUid, MessageId, ScopedMailboxId};

/// Backwards-compatible alias for code that still uses ProtonMessageId.
pub type ProtonMessageId = MessageId;
