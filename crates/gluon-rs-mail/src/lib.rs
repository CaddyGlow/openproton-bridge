pub mod db;
pub mod error;
pub mod store;
pub mod target;
pub mod types;

// IMAP protocol modules.
pub mod command;
pub mod gluon_connector;
pub mod imap_connector;
pub mod imap_error;
pub mod imap_store;
pub mod imap_types;
pub mod mailbox;
pub mod metadata_parse;
pub mod response;
pub mod rfc822;
pub mod well_known;

pub use db::{SchemaFamily, SchemaProbe};
pub use error::{GluonError, Result};
pub use gluon_rs_core::{
    decode_blob, encode_blob, AccountBootstrap, AccountPaths, CacheLayout, DeferredDeleteManager,
    GluonCoreError, GluonKey,
};
pub use store::{
    CompatibleStore, ConnHandle, DeletedSubscription, NewMailbox, NewMessage, SelectSnapshot,
    SelectSnapshotEntry, StoreSession, UpstreamMailbox, UpstreamMailboxMessage,
    UpstreamMailboxSnapshot, UpstreamMessageSummary,
};
pub use target::CompatibilityTarget;
pub use types::StoreBootstrap;

pub use gluon_connector::{
    GluonCreatedMessage, GluonImapConnector, GluonMailbox, GluonMessageRef, GluonUpdate,
    GluonUpdateReceiver,
};
pub use imap_connector::{AuthResult, ImapConnector, MetadataPage};
pub use imap_error::{ImapError, ImapResult};
pub use imap_store::{
    GluonMailboxMutation, GluonMailboxView, MailboxSnapshot, MailboxStatus, ProtonMessageId,
    SelectMailboxData, StoreEvent, StoreEventKind,
};
pub use imap_types::{
    EmailAddress, ImapUid, MailboxInfo, MessageEnvelope, MessageId, ScopedMailboxId,
};
pub use mailbox::{
    find_mailbox, message_flags, system_mailboxes, GluonMailboxCatalog, ImapMailbox,
    ResolvedMailbox,
};
