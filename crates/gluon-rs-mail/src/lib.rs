pub mod db;
pub mod error;
pub mod store;
pub mod target;
pub mod types;

// IMAP protocol modules.
pub mod command;
pub mod imap_error;
pub mod imap_store;
pub mod imap_types;
pub mod response;
pub mod well_known;

pub use db::{SchemaFamily, SchemaProbe};
pub use error::{GluonError, Result};
pub use gluon_rs_core::{
    decode_blob, encode_blob, AccountBootstrap, AccountPaths, CacheLayout, DeferredDeleteManager,
    GluonCoreError, GluonKey,
};
pub use store::{
    CompatibleStore, DeletedSubscription, NewMailbox, NewMessage, UpstreamMailbox,
    UpstreamMailboxMessage, UpstreamMailboxSnapshot, UpstreamMessageSummary,
};
pub use target::CompatibilityTarget;
pub use types::StoreBootstrap;

pub use imap_error::{ImapError, ImapResult};
pub use imap_store::{
    MailboxSnapshot, MailboxStatus, SelectMailboxData, StoreEvent, StoreEventKind,
};
pub use imap_types::{
    EmailAddress, ImapUid, MailboxInfo, MessageEnvelope, MessageId, ScopedMailboxId,
};
