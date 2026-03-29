//! Per-user state and session factory.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use tokio::sync::broadcast;

use crate::gluon_connector::GluonImapConnector;
use crate::imap_connector::ImapConnector;
use crate::store::CompatibleStore;

use super::state::SessionState;
use super::updates::StateUpdate;

pub struct GluonUser {
    pub user_id: String,
    pub connector: Arc<dyn ImapConnector>,
    pub gluon_connector: Arc<dyn GluonImapConnector>,
    pub store: Arc<CompatibleStore>,
    sessions: RwLock<HashMap<u64, ()>>,
    update_tx: broadcast::Sender<StateUpdate>,
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
}
