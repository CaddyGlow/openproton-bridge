use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use openproton_bridge::api::calendar::Calendar;
use openproton_bridge::api::types::{ApiMode, Session};
use openproton_bridge::bridge::accounts::AccountRegistry;
use openproton_bridge::bridge::auth_router::AuthRouter;
use openproton_bridge::dav::server::{run_server_with_listener_and_config, DavSetup};
use openproton_bridge::pim::store::PimStore;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port = std::env::var("OPENPROTON_DAV_HARNESS_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(18080);
    let db_path = std::env::var_os("OPENPROTON_DAV_HARNESS_DB")
        .map(PathBuf::from)
        .unwrap_or_else(default_db_path);

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let contacts_db = db_path.parent().unwrap().join("contacts.db");
    let calendar_db = db_path.parent().unwrap().join("calendar.db");
    let store = Arc::new(PimStore::new(contacts_db, calendar_db)?);
    let session = Session {
        uid: "uid-1".to_string(),
        access_token: String::new(),
        refresh_token: "refresh-token".to_string(),
        email: "alice@proton.me".to_string(),
        display_name: "Alice".to_string(),
        api_mode: ApiMode::Bridge,
        key_passphrase: None,
        bridge_password: Some("secret".to_string()),
    };
    store.upsert_calendar(&Calendar {
        id: "work".to_string(),
        name: "Work".to_string(),
        description: String::new(),
        color: "#3A7AFE".to_string(),
        display: 1,
        calendar_type: 0,
        flags: 0,
    })?;

    let mut pim_stores = HashMap::new();
    pim_stores.insert("uid-1".to_string(), store);
    let setup = DavSetup {
        auth_router: AuthRouter::new(AccountRegistry::from_single_session(session)),
        pim_stores,
        runtime_accounts: None,
        push_subscriptions: None,
        vapid_keys: None,
    };
    let config = setup.into_server_config();

    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("DAV harness listening on http://127.0.0.1:{port}");
    eprintln!("username: alice@proton.me");
    eprintln!("password: secret");
    eprintln!("db: {}", db_path.display());

    run_server_with_listener_and_config(listener, config).await?;
    Ok(())
}

fn default_db_path() -> PathBuf {
    std::env::temp_dir()
        .join("openproton-dav-harness")
        .join("account.db")
}
