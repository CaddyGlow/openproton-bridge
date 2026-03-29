//! Per-session IMAP state machine.

use std::collections::HashSet;

use tokio::sync::broadcast;

use crate::imap_types::ImapUid;

use super::snapshot::SessionSnapshot;
use super::updates::StateUpdate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

pub struct SessionState {
    pub session_id: u64,
    phase: SessionPhase,
    snapshot: Option<SessionSnapshot>,
    read_only: bool,
    recent_uids: HashSet<ImapUid>,
    account_id: Option<String>,
    update_rx: broadcast::Receiver<StateUpdate>,
}

impl SessionState {
    pub fn new(session_id: u64, update_rx: broadcast::Receiver<StateUpdate>) -> Self {
        Self {
            session_id,
            phase: SessionPhase::NotAuthenticated,
            snapshot: None,
            read_only: false,
            recent_uids: HashSet::new(),
            account_id: None,
            update_rx,
        }
    }

    pub fn phase(&self) -> SessionPhase {
        self.phase
    }

    pub fn set_authenticated(&mut self, account_id: String) {
        self.phase = SessionPhase::Authenticated;
        self.account_id = Some(account_id);
    }

    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    pub fn select(&mut self, snapshot: SessionSnapshot) {
        self.snapshot = Some(snapshot);
        self.read_only = false;
        self.phase = SessionPhase::Selected;
    }

    pub fn examine(&mut self, snapshot: SessionSnapshot) {
        self.snapshot = Some(snapshot);
        self.read_only = true;
        self.phase = SessionPhase::Selected;
    }

    pub fn close_mailbox(&mut self) {
        self.snapshot = None;
        self.phase = SessionPhase::Authenticated;
        self.read_only = false;
    }

    pub fn logout(&mut self) {
        self.phase = SessionPhase::Logout;
        self.snapshot = None;
        self.account_id = None;
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn snapshot(&self) -> Option<&SessionSnapshot> {
        self.snapshot.as_ref()
    }

    pub fn snapshot_mut(&mut self) -> Option<&mut SessionSnapshot> {
        self.snapshot.as_mut()
    }

    pub fn recent_uids(&self) -> &HashSet<ImapUid> {
        &self.recent_uids
    }

    pub fn set_recent_uids(&mut self, uids: HashSet<ImapUid>) {
        self.recent_uids = uids;
    }

    pub fn apply_update(&mut self, update: &StateUpdate) {
        let Some(snap) = self.snapshot.as_mut() else {
            return;
        };
        if !update.affects_mailbox(&snap.name) {
            return;
        }
        match update {
            StateUpdate::MessageFlagsChanged { uid, flags, .. } => {
                snap.set_flags(*uid, flags.clone());
            }
            StateUpdate::MessageExpunged { uid, .. } => {
                snap.expunge(*uid);
            }
            StateUpdate::MessageAppended { uid, flags, .. } => {
                snap.append(*uid, flags.clone());
            }
            StateUpdate::MailboxDeleted { .. } | StateUpdate::UidValidityChanged { .. } => {
                self.close_mailbox();
            }
            _ => {}
        }
    }

    pub fn drain_pending_updates(&mut self) -> Vec<StateUpdate> {
        let mut updates = Vec::new();
        while let Ok(update) = self.update_rx.try_recv() {
            updates.push(update);
        }
        updates
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> SessionState {
        let (tx, rx) = broadcast::channel(16);
        let _ = tx; // keep sender alive is not needed for tests
        SessionState::new(1, rx)
    }

    fn make_state_with_tx() -> (SessionState, broadcast::Sender<StateUpdate>) {
        let (tx, rx) = broadcast::channel(16);
        (SessionState::new(1, rx), tx)
    }

    fn make_snapshot(name: &str) -> SessionSnapshot {
        use std::collections::HashMap;
        SessionSnapshot {
            name: name.to_string(),
            internal_id: 1,
            uid_validity: 1,
            next_uid: 10,
            uids: vec![ImapUid::from(1u32), ImapUid::from(2u32)],
            flags: HashMap::new(),
            mod_seq: 1,
        }
    }

    #[test]
    fn initial_phase_is_not_authenticated() {
        let state = make_state();
        assert_eq!(state.phase(), SessionPhase::NotAuthenticated);
        assert!(state.account_id().is_none());
        assert!(state.snapshot().is_none());
    }

    #[test]
    fn authentication_transitions() {
        let mut state = make_state();
        state.set_authenticated("user1".to_string());
        assert_eq!(state.phase(), SessionPhase::Authenticated);
        assert_eq!(state.account_id(), Some("user1"));
    }

    #[test]
    fn select_and_examine() {
        let mut state = make_state();
        state.set_authenticated("user1".to_string());

        state.select(make_snapshot("INBOX"));
        assert_eq!(state.phase(), SessionPhase::Selected);
        assert!(!state.is_read_only());
        assert!(state.snapshot().is_some());

        state.close_mailbox();
        assert_eq!(state.phase(), SessionPhase::Authenticated);

        state.examine(make_snapshot("Sent"));
        assert_eq!(state.phase(), SessionPhase::Selected);
        assert!(state.is_read_only());
    }

    #[test]
    fn logout_clears_state() {
        let mut state = make_state();
        state.set_authenticated("user1".to_string());
        state.select(make_snapshot("INBOX"));
        state.logout();
        assert_eq!(state.phase(), SessionPhase::Logout);
        assert!(state.snapshot().is_none());
        assert!(state.account_id().is_none());
    }

    #[test]
    fn apply_update_flags_changed() {
        let mut state = make_state();
        state.set_authenticated("user1".to_string());
        state.select(make_snapshot("INBOX"));

        let update = StateUpdate::MessageFlagsChanged {
            mailbox: "INBOX".to_string(),
            uid: ImapUid::from(1u32),
            flags: vec!["\\Seen".to_string()],
        };
        state.apply_update(&update);
        let snap = state.snapshot().unwrap();
        assert_eq!(
            snap.get_flags(ImapUid::from(1u32)),
            Some(&vec!["\\Seen".to_string()])
        );
    }

    #[test]
    fn apply_update_expunge() {
        let mut state = make_state();
        state.set_authenticated("user1".to_string());
        state.select(make_snapshot("INBOX"));

        let update = StateUpdate::MessageExpunged {
            mailbox: "INBOX".to_string(),
            uid: ImapUid::from(1u32),
        };
        state.apply_update(&update);
        let snap = state.snapshot().unwrap();
        assert_eq!(snap.exists(), 1);
    }

    #[test]
    fn apply_update_mailbox_deleted_closes() {
        let mut state = make_state();
        state.set_authenticated("user1".to_string());
        state.select(make_snapshot("INBOX"));

        let update = StateUpdate::MailboxDeleted {
            name: "INBOX".to_string(),
        };
        state.apply_update(&update);
        assert_eq!(state.phase(), SessionPhase::Authenticated);
        assert!(state.snapshot().is_none());
    }

    #[test]
    fn apply_update_ignores_other_mailbox() {
        let mut state = make_state();
        state.set_authenticated("user1".to_string());
        state.select(make_snapshot("INBOX"));

        let update = StateUpdate::MessageExpunged {
            mailbox: "Sent".to_string(),
            uid: ImapUid::from(1u32),
        };
        state.apply_update(&update);
        assert_eq!(state.snapshot().unwrap().exists(), 2);
    }

    #[test]
    fn drain_pending_updates() {
        let (mut state, tx) = make_state_with_tx();
        let _ = tx.send(StateUpdate::MailboxCreated {
            name: "Test".to_string(),
        });
        let _ = tx.send(StateUpdate::MailboxDeleted {
            name: "Old".to_string(),
        });
        let updates = state.drain_pending_updates();
        assert_eq!(updates.len(), 2);
    }
}
