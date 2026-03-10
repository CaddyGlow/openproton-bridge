use crate::api::types::{
    self, MessageMetadata, ProtonLabel, ALL_DRAFTS_LABEL, DRAFTS_LABEL, LABEL_TYPE_FOLDER,
    LABEL_TYPE_LABEL, MESSAGE_FLAG_FORWARDED, MESSAGE_FLAG_REPLIED, MESSAGE_FLAG_REPLIED_ALL,
    STARRED_LABEL,
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

impl ResolvedMailbox {
    pub fn from_proton_label(label: &ProtonLabel) -> Self {
        let name = match label.label_type {
            LABEL_TYPE_FOLDER => {
                if label.path.is_empty() {
                    format!("Folders/{}", label.name)
                } else {
                    format!("Folders/{}", label.path)
                }
            }
            LABEL_TYPE_LABEL => format!("Labels/{}", label.name),
            _ => label.name.clone(),
        };
        Self {
            name,
            label_id: label.id.clone(),
            special_use: None,
            selectable: true,
        }
    }
}

pub fn labels_to_mailboxes(labels: &[ProtonLabel]) -> Vec<ResolvedMailbox> {
    let mut used_names = std::collections::HashSet::new();
    let reserved_names: std::collections::HashSet<String> = system_mailboxes()
        .iter()
        .map(|mailbox| mailbox.name.to_ascii_lowercase())
        .collect();

    labels
        .iter()
        .filter(|l| l.label_type == LABEL_TYPE_LABEL || l.label_type == LABEL_TYPE_FOLDER)
        .map(ResolvedMailbox::from_proton_label)
        .map(|mut mailbox| {
            let base_name = mailbox.name.trim();
            let base_name = if base_name.is_empty() {
                format!("Label/{}", mailbox.label_id)
            } else {
                base_name.to_string()
            };

            let mut candidate = base_name.clone();
            let mut suffix_round = 0usize;

            loop {
                let candidate_key = candidate.to_ascii_lowercase();
                let conflicts_reserved = reserved_names.contains(&candidate_key);
                let conflicts_used = used_names.contains(&candidate_key);

                if !conflicts_reserved && !conflicts_used {
                    used_names.insert(candidate_key);
                    mailbox.name = candidate;
                    break;
                }

                suffix_round += 1;
                if suffix_round == 1 {
                    candidate =
                        format!("{} ({})", base_name, short_label_suffix(&mailbox.label_id));
                } else {
                    candidate = format!(
                        "{} ({}-{})",
                        base_name,
                        short_label_suffix(&mailbox.label_id),
                        suffix_round
                    );
                }
            }

            mailbox
        })
        .collect()
}

fn short_label_suffix(label_id: &str) -> String {
    let trimmed = label_id.trim();
    if trimmed.is_empty() {
        return "custom".to_string();
    }

    if trimmed.len() <= 8 {
        return trimmed.to_string();
    }

    trimmed[trimmed.len() - 8..].to_string()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::EmailAddress;

    fn make_meta(unread: i32, label_ids: Vec<&str>) -> MessageMetadata {
        MessageMetadata {
            id: "msg-1".to_string(),
            address_id: "addr-1".to_string(),
            label_ids: label_ids.into_iter().map(|s| s.to_string()).collect(),
            external_id: None,
            subject: "Test".to_string(),
            sender: EmailAddress {
                name: "Alice".to_string(),
                address: "alice@proton.me".to_string(),
            },
            to_list: vec![],
            cc_list: vec![],
            bcc_list: vec![],
            reply_tos: vec![],
            flags: 0,
            time: 1700000000,
            size: 1024,
            unread,
            is_replied: 0,
            is_replied_all: 0,
            is_forwarded: 0,
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
    fn test_message_flags_answered_from_boolean_fields() {
        let mut meta = make_meta(1, vec!["0"]);
        meta.is_replied = 1;
        let flags = message_flags(&meta);
        assert!(flags.contains(&"\\Answered"));
    }

    #[test]
    fn test_message_flags_forwarded_from_bitmask_fallback() {
        let mut meta = make_meta(1, vec!["0"]);
        meta.flags = MESSAGE_FLAG_FORWARDED;
        let flags = message_flags(&meta);
        assert!(flags.contains(&"$Forwarded"));
    }

    #[test]
    fn test_all_mail_not_selectable() {
        let mb = find_mailbox("All Mail").unwrap();
        assert!(!mb.selectable);
    }

    #[test]
    fn test_labels_to_mailboxes_folder() {
        let label = ProtonLabel {
            id: "abc123".to_string(),
            name: "Work".to_string(),
            path: "Work".to_string(),
            label_type: LABEL_TYPE_FOLDER,
            parent_id: None,
            color: None,
        };
        let mailboxes = labels_to_mailboxes(&[label]);
        assert_eq!(mailboxes.len(), 1);
        assert_eq!(mailboxes[0].name, "Folders/Work");
        assert_eq!(mailboxes[0].label_id, "abc123");
        assert!(mailboxes[0].selectable);
        assert!(mailboxes[0].special_use.is_none());
    }

    #[test]
    fn test_labels_to_mailboxes_nested_folder() {
        let label = ProtonLabel {
            id: "def456".to_string(),
            name: "Clients".to_string(),
            path: "Work/Clients".to_string(),
            label_type: LABEL_TYPE_FOLDER,
            parent_id: Some("abc123".to_string()),
            color: None,
        };
        let mailboxes = labels_to_mailboxes(&[label]);
        assert_eq!(mailboxes[0].name, "Folders/Work/Clients");
    }

    #[test]
    fn test_labels_to_mailboxes_label() {
        let label = ProtonLabel {
            id: "lbl789".to_string(),
            name: "Important".to_string(),
            path: "Important".to_string(),
            label_type: LABEL_TYPE_LABEL,
            parent_id: None,
            color: Some("#ff0000".to_string()),
        };
        let mailboxes = labels_to_mailboxes(&[label]);
        assert_eq!(mailboxes.len(), 1);
        assert_eq!(mailboxes[0].name, "Labels/Important");
        assert_eq!(mailboxes[0].label_id, "lbl789");
    }

    #[test]
    fn test_labels_to_mailboxes_skips_contact_groups() {
        let labels = vec![
            ProtonLabel {
                id: "l1".to_string(),
                name: "Work".to_string(),
                path: "Work".to_string(),
                label_type: LABEL_TYPE_LABEL,
                parent_id: None,
                color: None,
            },
            ProtonLabel {
                id: "l2".to_string(),
                name: "Friends".to_string(),
                path: "Friends".to_string(),
                label_type: types::LABEL_TYPE_CONTACT_GROUP,
                parent_id: None,
                color: None,
            },
        ];
        let mailboxes = labels_to_mailboxes(&labels);
        assert_eq!(mailboxes.len(), 1);
        assert_eq!(mailboxes[0].name, "Labels/Work");
    }

    #[test]
    fn test_labels_to_mailboxes_avoids_system_name_conflicts() {
        let labels = vec![ProtonLabel {
            id: "lbl-inbox".to_string(),
            name: "INBOX".to_string(),
            path: "INBOX".to_string(),
            label_type: LABEL_TYPE_LABEL,
            parent_id: None,
            color: None,
        }];

        let mailboxes = labels_to_mailboxes(&labels);
        assert_eq!(mailboxes.len(), 1);
        assert_eq!(mailboxes[0].name, "Labels/INBOX");
    }

    #[test]
    fn test_labels_to_mailboxes_deduplicates_case_insensitive_collisions() {
        let labels = vec![
            ProtonLabel {
                id: "lbl-dup-a".to_string(),
                name: "Projects".to_string(),
                path: "Projects".to_string(),
                label_type: LABEL_TYPE_LABEL,
                parent_id: None,
                color: None,
            },
            ProtonLabel {
                id: "lbl-dup-b".to_string(),
                name: "projects".to_string(),
                path: "projects".to_string(),
                label_type: LABEL_TYPE_LABEL,
                parent_id: None,
                color: None,
            },
        ];

        let mailboxes = labels_to_mailboxes(&labels);
        assert_eq!(mailboxes.len(), 2);
        assert_eq!(mailboxes[0].name, "Labels/Projects");
        assert_eq!(mailboxes[1].name, "Labels/projects (bl-dup-b)");
    }

    #[test]
    fn test_resolved_mailbox_from_system() {
        let system = find_mailbox("INBOX").unwrap();
        let resolved: ResolvedMailbox = system.into();
        assert_eq!(resolved.name, "INBOX");
        assert_eq!(resolved.label_id, "0");
        assert!(resolved.special_use.is_none());
        assert!(resolved.selectable);
    }
}
