use std::fmt;

/// Scoped mailbox identifier: encapsulates "account_id::mailbox_name".
/// Equivalent to Go's imap.MailboxID but includes account scoping.
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

/// Proton API message identifier (e.g., "xBw1FoGf...").
/// Equivalent to Go's imap.MessageID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtonMessageId(String);

impl ProtonMessageId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProtonMessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ProtonMessageId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for ProtonMessageId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

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
