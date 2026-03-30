//! Cross-session state updates.

use crate::imap_types::ImapUid;

#[derive(Debug, Clone)]
pub enum StateUpdate {
    MessageFlagsChanged {
        mailbox: String,
        uid: ImapUid,
        flags: Vec<String>,
    },
    MessageExpunged {
        mailbox: String,
        uid: ImapUid,
    },
    MessageAppended {
        mailbox: String,
        uid: ImapUid,
        flags: Vec<String>,
    },
    MailboxCreated {
        name: String,
    },
    MailboxDeleted {
        name: String,
    },
    MailboxRenamed {
        old_name: String,
        new_name: String,
    },
    UidValidityChanged {
        mailbox: String,
    },
}

impl StateUpdate {
    pub fn affects_mailbox(&self, name: &str) -> bool {
        match self {
            Self::MessageFlagsChanged { mailbox, .. }
            | Self::MessageExpunged { mailbox, .. }
            | Self::MessageAppended { mailbox, .. }
            | Self::UidValidityChanged { mailbox } => mailbox.eq_ignore_ascii_case(name),
            Self::MailboxDeleted { name: n } => n.eq_ignore_ascii_case(name),
            Self::MailboxRenamed { old_name, .. } => old_name.eq_ignore_ascii_case(name),
            Self::MailboxCreated { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn affects_mailbox_message_events() {
        let update = StateUpdate::MessageFlagsChanged {
            mailbox: "INBOX".to_string(),
            uid: ImapUid::from(1u32),
            flags: vec![],
        };
        assert!(update.affects_mailbox("INBOX"));
        assert!(update.affects_mailbox("inbox"));
        assert!(!update.affects_mailbox("Sent"));
    }

    #[test]
    fn affects_mailbox_delete_and_rename() {
        let del = StateUpdate::MailboxDeleted {
            name: "Trash".to_string(),
        };
        assert!(del.affects_mailbox("trash"));
        assert!(!del.affects_mailbox("INBOX"));

        let rename = StateUpdate::MailboxRenamed {
            old_name: "OldName".to_string(),
            new_name: "NewName".to_string(),
        };
        assert!(rename.affects_mailbox("oldname"));
        assert!(!rename.affects_mailbox("NewName"));
    }

    #[test]
    fn mailbox_created_does_not_affect() {
        let created = StateUpdate::MailboxCreated {
            name: "NewBox".to_string(),
        };
        assert!(!created.affects_mailbox("NewBox"));
    }
}
