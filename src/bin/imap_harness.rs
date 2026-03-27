use std::sync::Arc;

use gluon_rs_mail::{
    AccountBootstrap, AuthResult, CacheLayout, CompatibilityTarget, CompatibleStore, GluonKey,
    ImapConnector, ImapResult, MailboxInfo, MetadataPage, StoreBootstrap,
};
use openproton_bridge::imap::gluon_connector::GluonMailConnector;
use openproton_bridge::imap::gluon_mailbox_mutation::GluonMailMailboxMutation;
use openproton_bridge::imap::gluon_mailbox_view::GluonMailMailboxView;
use openproton_bridge::imap::mailbox_catalog::RuntimeMailboxCatalog;
use openproton_bridge::imap::server::run_server_with_tls_config;
use openproton_bridge::imap::session::SessionConfig;

use openproton_bridge::api::types::{ApiMode, Session};
use openproton_bridge::bridge::accounts::RuntimeAccountRegistry;

const ACCOUNT_ID: &str = "imaptest-uid";
const EMAIL: &str = "testuser@localhost";
const PASSWORD: &str = "testpass";

struct HarnessConnector;

#[async_trait::async_trait]
impl ImapConnector for HarnessConnector {
    async fn authorize(&self, _u: &str, _p: &str) -> ImapResult<AuthResult> {
        Ok(AuthResult {
            account_id: ACCOUNT_ID.into(),
            primary_email: EMAIL.into(),
            mailboxes: vec![],
        })
    }
    async fn get_message_literal(&self, _a: &str, _m: &str) -> ImapResult<Option<Vec<u8>>> {
        Ok(None)
    }
    async fn mark_messages_read(&self, _a: &str, _i: &[&str], _r: bool) -> ImapResult<()> {
        Ok(())
    }
    async fn mark_messages_starred(&self, _a: &str, _i: &[&str], _s: bool) -> ImapResult<()> {
        Ok(())
    }
    async fn label_messages(&self, _a: &str, _i: &[&str], _l: &str) -> ImapResult<()> {
        Ok(())
    }
    async fn unlabel_messages(&self, _a: &str, _i: &[&str], _l: &str) -> ImapResult<()> {
        Ok(())
    }
    async fn trash_messages(&self, _a: &str, _i: &[&str]) -> ImapResult<()> {
        Ok(())
    }
    async fn delete_messages(&self, _a: &str, _i: &[&str]) -> ImapResult<()> {
        Ok(())
    }
    async fn import_message(
        &self,
        _a: &str,
        _l: &str,
        _f: i64,
        _d: &[u8],
    ) -> ImapResult<Option<String>> {
        Ok(None)
    }
    async fn fetch_message_metadata_page(
        &self,
        _a: &str,
        _l: &str,
        _p: i32,
        _s: i32,
    ) -> ImapResult<MetadataPage> {
        Ok(MetadataPage {
            messages: vec![],
            total: 0,
        })
    }
    async fn fetch_user_labels(&self, _a: &str) -> ImapResult<Vec<MailboxInfo>> {
        Ok(vec![])
    }
}

fn build_session_config(data_dir: &std::path::Path) -> Arc<SessionConfig> {
    let session = Session {
        uid: ACCOUNT_ID.to_string(),
        access_token: "unused".to_string(),
        refresh_token: "unused".to_string(),
        email: EMAIL.to_string(),
        display_name: "ImapTest User".to_string(),
        api_mode: ApiMode::Bridge,
        key_passphrase: None,
        bridge_password: Some(PASSWORD.to_string()),
    };

    let runtime_accounts = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));

    let layout = CacheLayout::new(data_dir.join("gluon"));
    let gluon_store = Arc::new(
        CompatibleStore::open(StoreBootstrap::new(
            layout,
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                ACCOUNT_ID,
                ACCOUNT_ID,
                GluonKey::try_from_slice(&[7u8; 32]).expect("key"),
            )],
        ))
        .expect("open gluon store"),
    );

    Arc::new(SessionConfig {
        connector: Arc::new(HarnessConnector),
        gluon_connector: GluonMailConnector::new(gluon_store.clone()),
        mailbox_catalog: RuntimeMailboxCatalog::new(runtime_accounts),
        mailbox_mutation: GluonMailMailboxMutation::new(gluon_store.clone()),
        mailbox_view: GluonMailMailboxView::new(gluon_store),
        recent_tracker: openproton_bridge::imap::session::RecentTracker::new(),
        shutdown_rx: None,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let port: u16 = std::env::var("IMAP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1143);

    let data_dir = std::env::var_os("IMAP_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let dir = std::env::temp_dir().join("openproton-imaptest");
            std::fs::create_dir_all(&dir).expect("create data dir");
            dir
        });

    let addr = format!("127.0.0.1:{port}");
    let config = build_session_config(&data_dir);

    eprintln!("IMAP harness listening on {addr} (plaintext, no TLS)");
    eprintln!("  user: {EMAIL}");
    eprintln!("  pass: {PASSWORD}");
    eprintln!("  data: {}", data_dir.display());

    run_server_with_tls_config(&addr, config, None).await?;

    Ok(())
}
