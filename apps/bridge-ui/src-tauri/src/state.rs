use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize)]
pub struct BridgeSnapshot {
    pub connected: bool,
    pub stream_running: bool,
    pub login_step: String,
    pub last_error: Option<String>,
    pub config_path: Option<String>,
}

impl Default for BridgeSnapshot {
    fn default() -> Self {
        Self {
            connected: false,
            stream_running: false,
            login_step: "idle".to_string(),
            last_error: None,
            config_path: None,
        }
    }
}

#[derive(Clone, Default)]
pub struct AppState {
    snapshot: Arc<RwLock<BridgeSnapshot>>,
}

impl AppState {
    pub async fn snapshot(&self) -> BridgeSnapshot {
        self.snapshot.read().await.clone()
    }

    pub async fn update<F>(&self, mutate: F) -> BridgeSnapshot
    where
        F: FnOnce(&mut BridgeSnapshot),
    {
        let mut guard = self.snapshot.write().await;
        mutate(&mut guard);
        guard.clone()
    }
}
