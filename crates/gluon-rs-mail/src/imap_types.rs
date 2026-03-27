use std::fmt;

/// IMAP UID within a mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ImapUid(u32);

impl ImapUid {
    pub fn value(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ImapUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for ImapUid {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

/// Scoped mailbox identifier: encapsulates "account_id::mailbox_name".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ScopedMailboxId(String);

impl ScopedMailboxId {
    pub fn from_parts(account_id: Option<&str>, mailbox_name: &str) -> Self {
        match account_id {
            Some(id) if !id.is_empty() => Self(format!("{id}::{mailbox_name}")),
            _ => Self(mailbox_name.to_string()),
        }
    }

    pub fn parse(scoped: &str) -> Self {
        Self(scoped.to_string())
    }

    pub fn account_id(&self) -> Option<&str> {
        self.0
            .split_once("::")
            .filter(|(id, _)| !id.is_empty())
            .map(|(id, _)| id)
    }

    pub fn mailbox_name(&self) -> &str {
        self.0
            .split_once("::")
            .filter(|(id, _)| !id.is_empty())
            .map(|(_, name)| name)
            .unwrap_or(&self.0)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScopedMailboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ScopedMailboxId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for ScopedMailboxId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Remote message identifier (e.g., Proton message ID "xBw1FoGf...").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageId(String);

impl MessageId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for MessageId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for MessageId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Email address (name + address pair).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailAddress {
    pub name: String,
    pub address: String,
}

/// Message metadata envelope. Crate-local equivalent of the upstream API's
/// message metadata, without serde annotations or API-specific naming.
#[derive(Debug, Clone)]
pub struct MessageEnvelope {
    pub id: String,
    pub address_id: String,
    pub label_ids: Vec<String>,
    pub external_id: Option<String>,
    pub subject: String,
    pub sender: EmailAddress,
    pub to_list: Vec<EmailAddress>,
    pub cc_list: Vec<EmailAddress>,
    pub bcc_list: Vec<EmailAddress>,
    pub reply_tos: Vec<EmailAddress>,
    pub flags: i64,
    pub time: i64,
    pub size: i64,
    pub unread: i32,
    pub is_replied: i32,
    pub is_replied_all: i32,
    pub is_forwarded: i32,
    pub num_attachments: i32,
}

/// Controls whether a mailbox appears in LIST responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxVisibility {
    Visible,
    Hidden,
    HiddenIfEmpty,
}

/// Mailbox descriptor. Replaces the protocol-coupled ResolvedMailbox/ImapMailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxInfo {
    pub name: String,
    pub id: String,
    pub special_use: Option<String>,
    pub selectable: bool,
}
