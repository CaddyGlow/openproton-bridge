use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::Mutex as AsyncMutex;

static REFRESH_LOCKS: OnceLock<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>> = OnceLock::new();

pub fn lock_for_account(account_id: &str) -> Arc<AsyncMutex<()>> {
    let mut locks = REFRESH_LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("token refresh lock map poisoned");
    locks
        .entry(account_id.to_string())
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone()
}
