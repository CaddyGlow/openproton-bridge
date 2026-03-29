//! In-memory mailbox view for a single IMAP session.

use std::collections::{BTreeSet, HashMap};

use crate::imap_store::SelectMailboxData;
use crate::imap_types::ImapUid;

/// Snapshot of a mailbox's state at SELECT time.
/// Updated in-memory as the session performs operations.
#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    pub name: String,
    pub internal_id: u64,
    pub uid_validity: u32,
    pub next_uid: u32,
    pub uids: Vec<ImapUid>,
    pub flags: HashMap<ImapUid, Vec<String>>,
    pub mod_seq: u64,
}

impl SessionSnapshot {
    pub fn from_select_data(name: &str, data: SelectMailboxData, internal_id: u64) -> Self {
        Self {
            name: name.to_string(),
            internal_id,
            uid_validity: data.status.uid_validity,
            next_uid: data.status.next_uid,
            uids: data.uids,
            flags: data.flags,
            mod_seq: data.snapshot.mod_seq,
        }
    }

    pub fn exists(&self) -> u32 {
        self.uids.len() as u32
    }

    pub fn has_uid(&self, uid: ImapUid) -> bool {
        self.uids.contains(&uid)
    }

    pub fn seq_to_uid(&self, seq: u32) -> Option<ImapUid> {
        self.uids.get((seq as usize).checked_sub(1)?).copied()
    }

    pub fn uid_to_seq(&self, uid: ImapUid) -> Option<u32> {
        self.uids
            .iter()
            .position(|u| *u == uid)
            .map(|i| i as u32 + 1)
    }

    pub fn get_flags(&self, uid: ImapUid) -> Option<&Vec<String>> {
        self.flags.get(&uid)
    }

    pub fn set_flags(&mut self, uid: ImapUid, flags: Vec<String>) {
        self.flags.insert(uid, flags);
    }

    pub fn append(&mut self, uid: ImapUid, flags: Vec<String>) {
        self.uids.push(uid);
        self.flags.insert(uid, flags);
    }

    pub fn expunge(&mut self, uid: ImapUid) -> Option<u32> {
        let seq = self.uid_to_seq(uid)?;
        self.uids.retain(|u| *u != uid);
        self.flags.remove(&uid);
        Some(seq)
    }

    pub fn uids_with_flag(&self, flag: &str) -> Vec<ImapUid> {
        self.uids
            .iter()
            .filter(|uid| {
                self.flags
                    .get(uid)
                    .map(|f| f.iter().any(|f| f == flag))
                    .unwrap_or(false)
            })
            .copied()
            .collect()
    }

    pub fn first_unseen_seq(&self) -> Option<u32> {
        for (i, uid) in self.uids.iter().enumerate() {
            if !self
                .flags
                .get(uid)
                .map(|f| f.iter().any(|f| f == "\\Seen"))
                .unwrap_or(false)
            {
                return Some(i as u32 + 1);
            }
        }
        None
    }

    pub fn unseen_count(&self) -> u32 {
        self.uids
            .iter()
            .filter(|uid| {
                !self
                    .flags
                    .get(uid)
                    .map(|f| f.iter().any(|f| f == "\\Seen"))
                    .unwrap_or(false)
            })
            .count() as u32
    }

    pub fn keywords(&self) -> BTreeSet<String> {
        let mut kw = BTreeSet::new();
        for flags in self.flags.values() {
            for f in flags {
                if !f.starts_with('\\') {
                    kw.insert(f.clone());
                }
            }
        }
        kw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imap_store::{MailboxSnapshot as StoreSnapshot, MailboxStatus, SelectMailboxData};

    fn make_select_data(uids: Vec<u32>, flags: HashMap<u32, Vec<String>>) -> SelectMailboxData {
        let imap_uids: Vec<ImapUid> = uids.iter().map(|u| ImapUid::from(*u)).collect();
        let imap_flags: HashMap<ImapUid, Vec<String>> = flags
            .into_iter()
            .map(|(u, f)| (ImapUid::from(u), f))
            .collect();
        SelectMailboxData {
            status: MailboxStatus {
                uid_validity: 42,
                next_uid: uids.last().map(|u| u + 1).unwrap_or(1),
                exists: uids.len() as u32,
                unseen: 0,
            },
            snapshot: StoreSnapshot {
                exists: uids.len() as u32,
                mod_seq: 100,
            },
            uids: imap_uids,
            flags: imap_flags,
            first_unseen_seq: None,
        }
    }

    #[test]
    fn from_select_data_populates_fields() {
        let mut flags = HashMap::new();
        flags.insert(1, vec!["\\Seen".to_string()]);
        flags.insert(2, vec![]);
        let data = make_select_data(vec![1, 2, 3], flags);
        let snap = SessionSnapshot::from_select_data("INBOX", data, 7);
        assert_eq!(snap.name, "INBOX");
        assert_eq!(snap.internal_id, 7);
        assert_eq!(snap.uid_validity, 42);
        assert_eq!(snap.next_uid, 4);
        assert_eq!(snap.exists(), 3);
        assert_eq!(snap.mod_seq, 100);
    }

    #[test]
    fn seq_to_uid_and_back() {
        let data = make_select_data(vec![10, 20, 30], HashMap::new());
        let snap = SessionSnapshot::from_select_data("INBOX", data, 1);
        assert_eq!(snap.seq_to_uid(1), Some(ImapUid::from(10u32)));
        assert_eq!(snap.seq_to_uid(2), Some(ImapUid::from(20u32)));
        assert_eq!(snap.seq_to_uid(3), Some(ImapUid::from(30u32)));
        assert_eq!(snap.seq_to_uid(0), None);
        assert_eq!(snap.seq_to_uid(4), None);
        assert_eq!(snap.uid_to_seq(ImapUid::from(20u32)), Some(2));
        assert_eq!(snap.uid_to_seq(ImapUid::from(99u32)), None);
    }

    #[test]
    fn expunge_removes_and_returns_seq() {
        let data = make_select_data(vec![10, 20, 30], HashMap::new());
        let mut snap = SessionSnapshot::from_select_data("INBOX", data, 1);
        assert_eq!(snap.expunge(ImapUid::from(20u32)), Some(2));
        assert_eq!(snap.exists(), 2);
        assert!(!snap.has_uid(ImapUid::from(20u32)));
        assert_eq!(snap.expunge(ImapUid::from(99u32)), None);
    }

    #[test]
    fn flags_operations() {
        let mut flags = HashMap::new();
        flags.insert(1, vec!["\\Seen".to_string()]);
        flags.insert(2, vec!["\\Flagged".to_string(), "$label1".to_string()]);
        let data = make_select_data(vec![1, 2], flags);
        let mut snap = SessionSnapshot::from_select_data("INBOX", data, 1);

        assert_eq!(
            snap.get_flags(ImapUid::from(1u32)),
            Some(&vec!["\\Seen".to_string()])
        );
        assert_eq!(snap.unseen_count(), 1);
        assert_eq!(snap.first_unseen_seq(), Some(2));

        snap.set_flags(ImapUid::from(2u32), vec!["\\Seen".to_string()]);
        assert_eq!(snap.unseen_count(), 0);
        assert_eq!(snap.first_unseen_seq(), None);

        let kw = snap.keywords();
        assert!(kw.is_empty());
    }

    #[test]
    fn append_adds_uid_and_flags() {
        let data = make_select_data(vec![1], HashMap::new());
        let mut snap = SessionSnapshot::from_select_data("INBOX", data, 1);
        snap.append(ImapUid::from(2u32), vec!["\\Draft".to_string()]);
        assert_eq!(snap.exists(), 2);
        assert!(snap.has_uid(ImapUid::from(2u32)));
        assert_eq!(
            snap.get_flags(ImapUid::from(2u32)),
            Some(&vec!["\\Draft".to_string()])
        );
    }

    #[test]
    fn uids_with_flag_filters_correctly() {
        let mut flags = HashMap::new();
        flags.insert(1, vec!["\\Seen".to_string(), "\\Flagged".to_string()]);
        flags.insert(2, vec!["\\Flagged".to_string()]);
        flags.insert(3, vec![]);
        let data = make_select_data(vec![1, 2, 3], flags);
        let snap = SessionSnapshot::from_select_data("INBOX", data, 1);
        let flagged = snap.uids_with_flag("\\Flagged");
        assert_eq!(flagged.len(), 2);
        assert!(flagged.contains(&ImapUid::from(1u32)));
        assert!(flagged.contains(&ImapUid::from(2u32)));
    }

    #[test]
    fn keywords_collects_non_system_flags() {
        let mut flags = HashMap::new();
        flags.insert(
            1,
            vec![
                "\\Seen".to_string(),
                "$label1".to_string(),
                "$Forwarded".to_string(),
            ],
        );
        flags.insert(2, vec!["$label1".to_string(), "$label2".to_string()]);
        let data = make_select_data(vec![1, 2], flags);
        let snap = SessionSnapshot::from_select_data("INBOX", data, 1);
        let kw = snap.keywords();
        assert_eq!(kw.len(), 3);
        assert!(kw.contains("$label1"));
        assert!(kw.contains("$label2"));
        assert!(kw.contains("$Forwarded"));
    }
}
