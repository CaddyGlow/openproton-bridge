use crate::imap_types::MessageEnvelope;
use crate::well_known::{
    ALL_DRAFTS_LABEL, ALL_MAIL_LABEL, ARCHIVE_LABEL, DRAFTS_LABEL, INBOX_LABEL,
    MESSAGE_FLAG_FORWARDED, MESSAGE_FLAG_REPLIED, MESSAGE_FLAG_REPLIED_ALL, SENT_LABEL, SPAM_LABEL,
    STARRED_LABEL, TRASH_LABEL,
};

#[derive(Clone, Copy)]
pub struct ImapMailbox {
    pub name: &'static str,
    pub label_id: &'static str,
    pub special_use: Option<&'static str>,
    pub selectable: bool,
}

#[derive(Debug, Clone)]
pub struct ResolvedMailbox {
    pub name: String,
    pub label_id: String,
    pub special_use: Option<String>,
    pub selectable: bool,
}

impl From<ImapMailbox> for ResolvedMailbox {
    fn from(m: ImapMailbox) -> Self {
        Self {
            name: m.name.to_string(),
            label_id: m.label_id.to_string(),
            special_use: m.special_use.map(String::from),
            selectable: m.selectable,
        }
    }
}

const SYSTEM_MAILBOXES: [ImapMailbox; 8] = [
    ImapMailbox {
        name: "INBOX",
        label_id: INBOX_LABEL,
        special_use: None,
        selectable: true,
    },
    ImapMailbox {
        name: "Sent",
        label_id: SENT_LABEL,
        special_use: Some("\\Sent"),
        selectable: true,
    },
    ImapMailbox {
        name: "Drafts",
        label_id: DRAFTS_LABEL,
        special_use: Some("\\Drafts"),
        selectable: true,
    },
    ImapMailbox {
        name: "Trash",
        label_id: TRASH_LABEL,
        special_use: Some("\\Trash"),
        selectable: true,
    },
    ImapMailbox {
        name: "Spam",
        label_id: SPAM_LABEL,
        special_use: Some("\\Junk"),
        selectable: true,
    },
    ImapMailbox {
        name: "Archive",
        label_id: ARCHIVE_LABEL,
        special_use: Some("\\Archive"),
        selectable: true,
    },
    ImapMailbox {
        name: "Starred",
        label_id: STARRED_LABEL,
        special_use: Some("\\Flagged"),
        selectable: true,
    },
    ImapMailbox {
        name: "All Mail",
        label_id: ALL_MAIL_LABEL,
        special_use: None,
        selectable: false,
    },
];

pub fn system_mailboxes() -> &'static [ImapMailbox] {
    &SYSTEM_MAILBOXES
}

pub fn find_mailbox(name: &str) -> Option<ImapMailbox> {
    system_mailboxes()
        .iter()
        .copied()
        .find(|m| m.name.eq_ignore_ascii_case(name))
}

pub fn message_flags(meta: &MessageEnvelope) -> Vec<&'static str> {
    let mut flags = Vec::new();

    if meta.unread == 0 {
        flags.push("\\Seen");
    }

    if meta.label_ids.iter().any(|l| l == STARRED_LABEL) {
        flags.push("\\Flagged");
    }

    if meta
        .label_ids
        .iter()
        .any(|l| l == DRAFTS_LABEL || l == ALL_DRAFTS_LABEL)
    {
        flags.push("\\Draft");
    }

    if meta.is_replied != 0
        || meta.is_replied_all != 0
        || (meta.flags & (MESSAGE_FLAG_REPLIED | MESSAGE_FLAG_REPLIED_ALL)) != 0
    {
        flags.push("\\Answered");
    }

    if meta.is_forwarded != 0 || (meta.flags & MESSAGE_FLAG_FORWARDED) != 0 {
        flags.push("$Forwarded");
    }

    flags
}

/// Trait for resolving mailbox names to mailbox descriptors.
///
/// Implementations provide user label lookups, while system mailboxes
/// are resolved by the default `resolve_mailbox` and `all_mailboxes` methods.
pub trait GluonMailboxCatalog: Send + Sync {
    fn user_labels(
        &self,
        account_id: Option<&str>,
        fallback_labels: &[ResolvedMailbox],
    ) -> Vec<ResolvedMailbox>;

    fn resolve_mailbox(
        &self,
        account_id: Option<&str>,
        fallback_labels: &[ResolvedMailbox],
        name: &str,
    ) -> Option<ResolvedMailbox> {
        if let Some(mailbox) = find_mailbox(name) {
            return Some(mailbox.into());
        }

        self.user_labels(account_id, fallback_labels)
            .into_iter()
            .find(|mailbox| mailbox.name.eq_ignore_ascii_case(name))
    }

    fn all_mailboxes(
        &self,
        account_id: Option<&str>,
        fallback_labels: &[ResolvedMailbox],
    ) -> Vec<ResolvedMailbox> {
        let mut all: Vec<ResolvedMailbox> = system_mailboxes()
            .iter()
            .map(|mailbox| ResolvedMailbox::from(*mailbox))
            .collect();
        all.extend(self.user_labels(account_id, fallback_labels));
        all
    }
}
