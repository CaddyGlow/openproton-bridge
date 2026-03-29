//! Backend layer: multi-user management, authentication, session state.

pub mod actions;
pub mod snapshot;
pub mod state;
pub mod updates;
pub mod user;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::imap_error::{ImapError, ImapResult};

pub use snapshot::SessionSnapshot;
pub use state::{SessionPhase, SessionState};
pub use updates::StateUpdate;
pub use user::GluonUser;

pub struct BackendConfig {
    pub delimiter: char,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self { delimiter: '/' }
    }
}

pub struct GluonBackend {
    users: RwLock<HashMap<String, Arc<GluonUser>>>,
    config: BackendConfig,
}

impl GluonBackend {
    pub fn new(config: BackendConfig) -> Arc<Self> {
        Arc::new(Self {
            users: RwLock::new(HashMap::new()),
            config,
        })
    }

    pub fn add_user(&self, user: Arc<GluonUser>) {
        self.users
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(user.user_id.clone(), user);
    }

    pub fn remove_user(&self, user_id: &str) -> Option<Arc<GluonUser>> {
        self.users
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(user_id)
    }

    pub fn get_user(&self, user_id: &str) -> Option<Arc<GluonUser>> {
        self.users
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(user_id)
            .cloned()
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> ImapResult<Arc<GluonUser>> {
        let users: Vec<Arc<GluonUser>> = self
            .users
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        for user in users {
            if user.connector.authorize(username, password).await.is_ok() {
                return Ok(user);
            }
        }
        Err(ImapError::AuthFailed)
    }

    pub fn user_count(&self) -> usize {
        self.users.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn delimiter(&self) -> char {
        self.config.delimiter
    }
}
