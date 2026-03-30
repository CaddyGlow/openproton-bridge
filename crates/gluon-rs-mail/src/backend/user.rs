//! Per-user state and session factory.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use tokio::sync::broadcast;

use crate::gluon_connector::GluonImapConnector;
use crate::imap_connector::ImapConnector;
use crate::imap_types::ImapUid;
use crate::store::CompatibleStore;

use super::state::{SessionState, StateUpdate};

pub struct GluonUser {
    pub user_id: String,
    pub connector: Arc<dyn ImapConnector>,
    pub gluon_connector: Arc<dyn GluonImapConnector>,
    pub store: Arc<CompatibleStore>,
    sessions: RwLock<HashMap<u64, ()>>,
    update_tx: broadcast::Sender<StateUpdate>,
    /// Track which messages each session has in its snapshot.
    /// Used during expunge to prevent deleting messages still visible to other sessions.
    message_refs: RwLock<HashMap<u64, HashSet<(String, ImapUid)>>>,
}

impl GluonUser {
    pub fn new(
        user_id: String,
        connector: Arc<dyn ImapConnector>,
        gluon_connector: Arc<dyn GluonImapConnector>,
        store: Arc<CompatibleStore>,
    ) -> Arc<Self> {
        let (update_tx, _) = broadcast::channel(256);
        Arc::new(Self {
            user_id,
            connector,
            gluon_connector,
            store,
            sessions: RwLock::new(HashMap::new()),
            update_tx,
            message_refs: RwLock::new(HashMap::new()),
        })
    }

    pub fn new_session(&self, session_id: u64) -> SessionState {
        let rx = self.update_tx.subscribe();
        self.sessions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session_id, ());
        SessionState::new(session_id, rx)
    }

    pub fn remove_session(&self, session_id: u64) {
        self.sessions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session_id);
        self.unregister_snapshot(session_id);
    }

    pub fn broadcast_update(&self, update: StateUpdate) {
        let _ = self.update_tx.send(update);
    }

    pub fn session_count(&self) -> usize {
        self.sessions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    // -----------------------------------------------------------------------
    // Multi-session expunge coordination
    // -----------------------------------------------------------------------

    /// Register the set of UIDs visible to a session after SELECT.
    /// Called when a session selects a mailbox.
    pub fn register_snapshot(&self, session_id: u64, mailbox: &str, uids: &[ImapUid]) {
        let entries: HashSet<(String, ImapUid)> = uids
            .iter()
            .map(|&uid| (mailbox.to_ascii_lowercase(), uid))
            .collect();
        self.message_refs
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session_id, entries);
    }

    /// Remove snapshot tracking for a session (CLOSE / LOGOUT).
    pub fn unregister_snapshot(&self, session_id: u64) {
        self.message_refs
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session_id);
    }

    /// Check whether a message can be expunged by the given session.
    ///
    /// Returns `true` if no *other* session references this (mailbox, uid) pair.
    pub fn can_expunge(&self, session_id: u64, mailbox: &str, uid: ImapUid) -> bool {
        let key = (mailbox.to_ascii_lowercase(), uid);
        let refs = self.message_refs.read().unwrap_or_else(|e| e.into_inner());
        for (&sid, entries) in refs.iter() {
            if sid == session_id {
                continue;
            }
            if entries.contains(&key) {
                return false;
            }
        }
        true
    }
}
