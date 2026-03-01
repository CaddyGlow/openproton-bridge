use crate::api::types::{self, MessageMetadata, ALL_DRAFTS_LABEL, DRAFTS_LABEL, STARRED_LABEL};

#[derive(Clone, Copy)]
pub struct ImapMailbox {
    pub name: &'static str,
    pub label_id: &'static str,
    pub special_use: Option<&'static str>,
    pub selectable: bool,
}

const SYSTEM_MAILBOXES: [ImapMailbox; 8] = [
    ImapMailbox {
        name: "INBOX",
        label_id: types::INBOX_LABEL,
        special_use: None,
        selectable: true,
    },
    ImapMailbox {
        name: "Sent",
        label_id: types::SENT_LABEL,
        special_use: Some("\\Sent"),
        selectable: true,
    },
    ImapMailbox {
        name: "Drafts",
        label_id: types::DRAFTS_LABEL,
        special_use: Some("\\Drafts"),
        selectable: true,
    },
    ImapMailbox {
        name: "Trash",
        label_id: types::TRASH_LABEL,
        special_use: Some("\\Trash"),
        selectable: true,
    },
    ImapMailbox {
        name: "Spam",
        label_id: types::SPAM_LABEL,
        special_use: Some("\\Junk"),
        selectable: true,
    },
    ImapMailbox {
        name: "Archive",
        label_id: types::ARCHIVE_LABEL,
        special_use: Some("\\Archive"),
        selectable: true,
    },
    ImapMailbox {
        name: "Starred",
        label_id: types::STARRED_LABEL,
        special_use: Some("\\Flagged"),
        selectable: true,
    },
    ImapMailbox {
        name: "All Mail",
        label_id: types::ALL_MAIL_LABEL,
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

pub fn message_flags(meta: &MessageMetadata) -> Vec<&'static str> {
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

    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::EmailAddress;

    fn make_meta(unread: i32, label_ids: Vec<&str>) -> MessageMetadata {
        MessageMetadata {
            id: "msg-1".to_string(),
            address_id: "addr-1".to_string(),
            label_ids: label_ids.into_iter().map(|s| s.to_string()).collect(),
            subject: "Test".to_string(),
            sender: EmailAddress {
                name: "Alice".to_string(),
                address: "alice@proton.me".to_string(),
            },
            to_list: vec![],
            cc_list: vec![],
            bcc_list: vec![],
            time: 1700000000,
            size: 1024,
            unread,
            num_attachments: 0,
        }
    }

    #[test]
    fn test_system_mailboxes_count() {
        assert_eq!(system_mailboxes().len(), 8);
    }

    #[test]
    fn test_system_mailboxes_names() {
        let names: Vec<&str> = system_mailboxes().iter().map(|m| m.name).collect();
        assert!(names.contains(&"INBOX"));
        assert!(names.contains(&"Sent"));
        assert!(names.contains(&"Drafts"));
        assert!(names.contains(&"Trash"));
        assert!(names.contains(&"Spam"));
        assert!(names.contains(&"Archive"));
        assert!(names.contains(&"Starred"));
        assert!(names.contains(&"All Mail"));
    }

    #[test]
    fn test_find_mailbox_inbox_case_insensitive() {
        assert!(find_mailbox("INBOX").is_some());
        assert!(find_mailbox("inbox").is_some());
        assert!(find_mailbox("Inbox").is_some());
    }

    #[test]
    fn test_find_mailbox_sent() {
        let mb = find_mailbox("Sent").unwrap();
        assert_eq!(mb.label_id, "7");
        assert_eq!(mb.special_use, Some("\\Sent"));
    }

    #[test]
    fn test_find_mailbox_not_found() {
        assert!(find_mailbox("NonExistent").is_none());
    }

    #[test]
    fn test_message_flags_read() {
        let meta = make_meta(0, vec!["0"]);
        let flags = message_flags(&meta);
        assert!(flags.contains(&"\\Seen"));
    }

    #[test]
    fn test_message_flags_unread() {
        let meta = make_meta(1, vec!["0"]);
        let flags = message_flags(&meta);
        assert!(!flags.contains(&"\\Seen"));
    }

    #[test]
    fn test_message_flags_starred() {
        let meta = make_meta(1, vec!["0", "10"]);
        let flags = message_flags(&meta);
        assert!(flags.contains(&"\\Flagged"));
    }

    #[test]
    fn test_message_flags_draft() {
        let meta = make_meta(0, vec!["8"]);
        let flags = message_flags(&meta);
        assert!(flags.contains(&"\\Draft"));
    }

    #[test]
    fn test_message_flags_all_drafts() {
        let meta = make_meta(0, vec!["1"]);
        let flags = message_flags(&meta);
        assert!(flags.contains(&"\\Draft"));
    }

    #[test]
    fn test_message_flags_combined() {
        let meta = make_meta(0, vec!["0", "10", "8"]);
        let flags = message_flags(&meta);
        assert!(flags.contains(&"\\Seen"));
        assert!(flags.contains(&"\\Flagged"));
        assert!(flags.contains(&"\\Draft"));
    }

    #[test]
    fn test_all_mail_not_selectable() {
        let mb = find_mailbox("All Mail").unwrap();
        assert!(!mb.selectable);
    }
}
