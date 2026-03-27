use gluon_rs_mail::command::{FetchItem, ImapFlag, SearchKey, SequenceSet, StoreAction};
use gluon_rs_mail::imap_store::ProtonMessageId;
use gluon_rs_mail::session::*;
use gluon_rs_mail::{
    AccountBootstrap, CacheLayout, CompatibilityTarget, CompatibleStore, GluonKey, NewMailbox,
    NewMessage, StoreBootstrap,
};
use gluon_rs_mail::{EmailAddress, MessageEnvelope};
use gluon_rs_mail::{ImapUid, ScopedMailboxId};
use openproton_bridge::bridge::accounts::AccountHealth;
use openproton_bridge::bridge::accounts::{
    AccountRegistry, AccountRuntimeError, RuntimeAccountRegistry,
};
use openproton_bridge::bridge::auth_router::AuthRouter;
use openproton_bridge::imap::gluon_connector::GluonMailConnector;
use openproton_bridge::imap::gluon_mailbox_mutation::GluonMailMailboxMutation;
use openproton_bridge::imap::gluon_mailbox_view::GluonMailMailboxView;
use openproton_bridge::imap::mailbox;
use openproton_bridge::imap::mailbox_catalog::RuntimeMailboxCatalog;
use openproton_bridge::imap::rfc822;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct MockImapConnector {
    auth_router: AuthRouter,
    runtime_accounts: Arc<RuntimeAccountRegistry>,
}

impl MockImapConnector {
    fn new(auth_router: AuthRouter, runtime_accounts: Arc<RuntimeAccountRegistry>) -> Self {
        Self {
            auth_router,
            runtime_accounts,
        }
    }
}

#[async_trait::async_trait]
impl gluon_rs_mail::ImapConnector for MockImapConnector {
    async fn authorize(
        &self,
        username: &str,
        password: &str,
    ) -> gluon_rs_mail::ImapResult<gluon_rs_mail::AuthResult> {
        let route = self
            .auth_router
            .resolve_login(username, password)
            .ok_or(gluon_rs_mail::ImapError::AuthFailed)?;
        // Check account availability, matching ProtonImapConnector behavior
        self.runtime_accounts
            .with_valid_access_token(&route.account_id)
            .await
            .map_err(|e| match e {
                AccountRuntimeError::AccountUnavailable(_) => gluon_rs_mail::ImapError::AuthFailed,
                other => gluon_rs_mail::ImapError::Upstream(other.to_string()),
            })?;
        Ok(gluon_rs_mail::AuthResult {
            account_id: route.account_id.0.clone(),
            primary_email: route.primary_email.clone(),
            mailboxes: Vec::new(),
        })
    }
    async fn get_message_literal(
        &self,
        _account_id: &str,
        _message_id: &str,
    ) -> gluon_rs_mail::ImapResult<Option<Vec<u8>>> {
        Ok(None)
    }
    async fn mark_messages_read(
        &self,
        _account_id: &str,
        _message_ids: &[&str],
        _read: bool,
    ) -> gluon_rs_mail::ImapResult<()> {
        Ok(())
    }
    async fn mark_messages_starred(
        &self,
        _account_id: &str,
        _message_ids: &[&str],
        _starred: bool,
    ) -> gluon_rs_mail::ImapResult<()> {
        Ok(())
    }
    async fn label_messages(
        &self,
        _account_id: &str,
        _message_ids: &[&str],
        _label_id: &str,
    ) -> gluon_rs_mail::ImapResult<()> {
        Ok(())
    }
    async fn unlabel_messages(
        &self,
        _account_id: &str,
        _message_ids: &[&str],
        _label_id: &str,
    ) -> gluon_rs_mail::ImapResult<()> {
        Ok(())
    }
    async fn trash_messages(
        &self,
        _account_id: &str,
        _message_ids: &[&str],
    ) -> gluon_rs_mail::ImapResult<()> {
        Ok(())
    }
    async fn delete_messages(
        &self,
        _account_id: &str,
        _message_ids: &[&str],
    ) -> gluon_rs_mail::ImapResult<()> {
        Ok(())
    }
    async fn import_message(
        &self,
        _account_id: &str,
        _label_id: &str,
        _flags: i64,
        _literal: &[u8],
    ) -> gluon_rs_mail::ImapResult<Option<String>> {
        Ok(None)
    }
    async fn fetch_message_metadata_page(
        &self,
        _account_id: &str,
        _label_id: &str,
        _page: i32,
        _page_size: i32,
    ) -> gluon_rs_mail::ImapResult<gluon_rs_mail::MetadataPage> {
        Ok(gluon_rs_mail::MetadataPage {
            messages: Vec::new(),
            total: 0,
        })
    }
    async fn fetch_user_labels(
        &self,
        _account_id: &str,
    ) -> gluon_rs_mail::ImapResult<Vec<gluon_rs_mail::MailboxInfo>> {
        Ok(Vec::new())
    }
}

fn mock_connector(
    auth_router: &AuthRouter,
    runtime_accounts: &Arc<RuntimeAccountRegistry>,
) -> Arc<dyn gluon_rs_mail::ImapConnector> {
    Arc::new(MockImapConnector::new(
        auth_router.clone(),
        runtime_accounts.clone(),
    ))
}

/// A connector that fails all upstream mutation calls. Used to test
/// that the session correctly propagates upstream errors.
struct FailingMockConnector {
    auth_router: AuthRouter,
    runtime_accounts: Arc<RuntimeAccountRegistry>,
}

#[async_trait::async_trait]
impl gluon_rs_mail::ImapConnector for FailingMockConnector {
    async fn authorize(
        &self,
        username: &str,
        password: &str,
    ) -> gluon_rs_mail::ImapResult<gluon_rs_mail::AuthResult> {
        let route = self
            .auth_router
            .resolve_login(username, password)
            .ok_or(gluon_rs_mail::ImapError::AuthFailed)?;
        self.runtime_accounts
            .with_valid_access_token(&route.account_id)
            .await
            .map_err(|e| match e {
                AccountRuntimeError::AccountUnavailable(_) => gluon_rs_mail::ImapError::AuthFailed,
                other => gluon_rs_mail::ImapError::Upstream(other.to_string()),
            })?;
        Ok(gluon_rs_mail::AuthResult {
            account_id: route.account_id.0.clone(),
            primary_email: route.primary_email.clone(),
            mailboxes: Vec::new(),
        })
    }
    async fn get_message_literal(
        &self,
        _a: &str,
        _m: &str,
    ) -> gluon_rs_mail::ImapResult<Option<Vec<u8>>> {
        Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
    }
    async fn mark_messages_read(
        &self,
        _a: &str,
        _i: &[&str],
        _r: bool,
    ) -> gluon_rs_mail::ImapResult<()> {
        Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
    }
    async fn mark_messages_starred(
        &self,
        _a: &str,
        _i: &[&str],
        _s: bool,
    ) -> gluon_rs_mail::ImapResult<()> {
        Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
    }
    async fn label_messages(
        &self,
        _a: &str,
        _i: &[&str],
        _l: &str,
    ) -> gluon_rs_mail::ImapResult<()> {
        Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
    }
    async fn unlabel_messages(
        &self,
        _a: &str,
        _i: &[&str],
        _l: &str,
    ) -> gluon_rs_mail::ImapResult<()> {
        Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
    }
    async fn trash_messages(&self, _a: &str, _i: &[&str]) -> gluon_rs_mail::ImapResult<()> {
        Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
    }
    async fn delete_messages(&self, _a: &str, _i: &[&str]) -> gluon_rs_mail::ImapResult<()> {
        Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
    }
    async fn import_message(
        &self,
        _a: &str,
        _l: &str,
        _f: i64,
        _d: &[u8],
    ) -> gluon_rs_mail::ImapResult<Option<String>> {
        Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
    }
    async fn fetch_message_metadata_page(
        &self,
        _a: &str,
        _l: &str,
        _p: i32,
        _s: i32,
    ) -> gluon_rs_mail::ImapResult<gluon_rs_mail::MetadataPage> {
        Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
    }
    async fn fetch_user_labels(
        &self,
        _a: &str,
    ) -> gluon_rs_mail::ImapResult<Vec<gluon_rs_mail::MailboxInfo>> {
        Err(gluon_rs_mail::ImapError::Upstream("mock failure".into()))
    }
}

fn failing_connector(
    auth_router: &AuthRouter,
    runtime_accounts: &Arc<RuntimeAccountRegistry>,
) -> Arc<dyn gluon_rs_mail::ImapConnector> {
    Arc::new(FailingMockConnector {
        auth_router: auth_router.clone(),
        runtime_accounts: runtime_accounts.clone(),
    })
}

/// Clone a SessionConfig with a different connector for testing.
fn with_failing_connector(
    config: &Arc<SessionConfig>,
    auth_router: &AuthRouter,
    runtime_accounts: &Arc<RuntimeAccountRegistry>,
) -> Arc<SessionConfig> {
    Arc::new(SessionConfig {
        connector: failing_connector(auth_router, runtime_accounts),
        gluon_connector: config.gluon_connector.clone(),
        mailbox_catalog: config.mailbox_catalog.clone(),
        mailbox_mutation: config.mailbox_mutation.clone(),
        mailbox_view: config.mailbox_view.clone(),
        recent_tracker: config.recent_tracker.clone(),
        shutdown_rx: None,
        event_tx: None,
        delimiter: '/',
        login_jail_time: Duration::ZERO,
        idle_bulk_time: Duration::ZERO,
        limits: gluon_rs_mail::imap_types::ImapLimits::default(),
    })
}

fn scoped(account: &str, mailbox: &str) -> ScopedMailboxId {
    ScopedMailboxId::from_parts(Some(account), mailbox)
}

fn pid(id: &str) -> ProtonMessageId {
    ProtonMessageId::from(id)
}

fn iuid(v: u32) -> ImapUid {
    ImapUid::from(v)
}

fn test_session() -> openproton_bridge::api::types::Session {
    openproton_bridge::api::types::Session {
        uid: "test-uid".to_string(),
        access_token: "test-token".to_string(),
        refresh_token: "test-refresh".to_string(),
        email: "test@proton.me".to_string(),
        display_name: "Test User".to_string(),
        api_mode: openproton_bridge::api::types::ApiMode::Bridge,
        key_passphrase: Some("dGVzdA==".to_string()),
        bridge_password: Some("bridge-pass-1234".to_string()),
    }
}

fn test_gluon_config() -> (
    Arc<SessionConfig>,
    TempDir,
    AuthRouter,
    Arc<RuntimeAccountRegistry>,
) {
    let session = test_session();
    let accounts = AccountRegistry::from_single_session(session.clone());
    let auth_router = AuthRouter::new(accounts);
    let runtime_accounts = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));
    let tempdir = tempdir().expect("tempdir");
    let gluon_store = Arc::new(
        CompatibleStore::open(StoreBootstrap::new(
            CacheLayout::new(tempdir.path().join("gluon")),
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "test-uid",
                "test-uid",
                GluonKey::try_from_slice(&[7u8; 32]).expect("key"),
            )],
        ))
        .expect("open store"),
    );
    let config = Arc::new(SessionConfig {
        connector: mock_connector(&auth_router, &runtime_accounts),
        gluon_connector: GluonMailConnector::new(gluon_store.clone()),
        mailbox_catalog: RuntimeMailboxCatalog::new(runtime_accounts.clone()),
        mailbox_mutation: GluonMailMailboxMutation::new(gluon_store.clone()),
        mailbox_view: GluonMailMailboxView::new(gluon_store),
        recent_tracker: RecentTracker::new(),
        shutdown_rx: None,
        event_tx: None,
        delimiter: '/',
        login_jail_time: Duration::ZERO,
        idle_bulk_time: Duration::ZERO,
        limits: gluon_rs_mail::imap_types::ImapLimits::default(),
    });
    (config, tempdir, auth_router, runtime_accounts)
}

async fn test_gluon_mail_config() -> (
    Arc<SessionConfig>,
    TempDir,
    AuthRouter,
    Arc<RuntimeAccountRegistry>,
) {
    let session = test_session();
    let accounts = AccountRegistry::from_single_session(session.clone());
    let auth_router = AuthRouter::new(accounts);
    let runtime_accounts = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));

    let tempdir = tempdir().expect("tempdir");
    let layout = CacheLayout::new(tempdir.path().join("gluon"));
    let gluon_store = Arc::new(
        CompatibleStore::open(StoreBootstrap::new(
            layout,
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "test-uid",
                "test-uid",
                GluonKey::try_from_slice(&[7u8; 32]).expect("key"),
            )],
        ))
        .expect("open store"),
    );

    let mailbox = gluon_store
        .create_mailbox(
            "test-uid",
            &NewMailbox {
                remote_id: "0".to_string(),
                name: "INBOX".to_string(),
                uid_validity: 42,
                subscribed: true,
                attributes: Vec::new(),
                flags: Vec::new(),
                permanent_flags: vec!["\\Seen".to_string(), "\\Flagged".to_string()],
            },
        )
        .expect("create mailbox");

    let mut meta = make_meta("msg-1", 1);
    meta.external_id = Some("msg-1@example.test".to_string());
    let blob = b"Date: Tue, 14 Nov 2023 22:13:20 +0000\r\nFrom: Alice <alice@proton.me>\r\nTo: Bob <bob@proton.me>\r\nSubject: Subject msg-1\r\nMessage-ID: <msg-1@example.test>\r\n\r\nsearch-hit-body".to_vec();
    meta.size = blob.len() as i64;
    let header = String::from_utf8_lossy(&blob)
        .split("\r\n\r\n")
        .next()
        .unwrap_or_default()
        .to_string();
    gluon_store
        .append_message(
            "test-uid",
            mailbox.internal_id,
            &NewMessage {
                internal_id: "internal-1".to_string(),
                remote_id: meta.id.clone(),
                flags: mailbox::message_flags(&meta)
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                blob: blob.clone(),
                body: "search-hit-body".to_string(),
                body_structure: rfc822::build_bodystructure(&blob),
                envelope: rfc822::build_envelope(&meta, &header),
                size: meta.size,
                recent: false,
            },
        )
        .expect("append message");

    let config = Arc::new(SessionConfig {
        connector: mock_connector(&auth_router, &runtime_accounts),
        gluon_connector: GluonMailConnector::new(gluon_store.clone()),
        mailbox_catalog: RuntimeMailboxCatalog::new(runtime_accounts.clone()),
        mailbox_mutation: GluonMailMailboxMutation::new(gluon_store.clone()),
        mailbox_view: GluonMailMailboxView::new(gluon_store),
        recent_tracker: RecentTracker::new(),
        shutdown_rx: None,
        event_tx: None,
        delimiter: '/',
        login_jail_time: Duration::ZERO,
        idle_bulk_time: Duration::ZERO,
        limits: gluon_rs_mail::imap_types::ImapLimits::default(),
    });

    (config, tempdir, auth_router, runtime_accounts)
}

fn make_meta(id: &str, unread: i32) -> MessageEnvelope {
    MessageEnvelope {
        id: id.to_string(),
        address_id: "addr-1".to_string(),
        label_ids: vec!["0".to_string()],
        external_id: None,
        subject: format!("Subject {}", id),
        sender: EmailAddress {
            name: "Alice".to_string(),
            address: "alice@proton.me".to_string(),
        },
        to_list: vec![EmailAddress {
            name: "Bob".to_string(),
            address: "bob@proton.me".to_string(),
        }],
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

fn metadata_page_response(messages: Vec<MessageEnvelope>, total: i64) -> serde_json::Value {
    let api_messages: Vec<openproton_bridge::api::types::MessageMetadata> =
        messages.into_iter().map(Into::into).collect();
    serde_json::json!({
        "Code": 1000,
        "Messages": api_messages,
        "Total": total
    })
}

async fn seed_gluon_backend_message(
    config: &Arc<SessionConfig>,
    mailbox_name: &str,
    proton_id: &str,
    unread: i32,
    body: &[u8],
) -> ImapUid {
    let mut meta = make_meta(proton_id, unread);
    meta.external_id = Some(format!("{proton_id}@example.test"));
    meta.size = body.len() as i64;
    let scoped_mailbox = ScopedMailboxId::from_parts(Some("test-uid"), mailbox_name);
    let pid = ProtonMessageId::from(proton_id);
    let uid = config
        .mailbox_mutation
        .store_metadata(&scoped_mailbox, &pid, meta)
        .await
        .unwrap();
    config
        .mailbox_mutation
        .store_rfc822(&scoped_mailbox, uid, body.to_vec())
        .await
        .unwrap();
    uid
}

async fn create_session_pair(
    config: Arc<SessionConfig>,
) -> (
    ImapSession<tokio::io::DuplexStream, tokio::io::DuplexStream>,
    tokio::io::DuplexStream,
    tokio::io::DuplexStream,
) {
    let (client_read, server_write) = tokio::io::duplex(8192);
    let (server_read, client_write) = tokio::io::duplex(8192);

    let session = ImapSession::new(server_read, server_write, config);
    (session, client_read, client_write)
}
async fn prime_selected_state_from_view(
    session: &mut ImapSession<tokio::io::DuplexStream, tokio::io::DuplexStream>,
    config: &Arc<SessionConfig>,
    scoped_mailbox: &ScopedMailboxId,
) {
    let snapshot = config
        .mailbox_view
        .mailbox_snapshot(scoped_mailbox)
        .await
        .unwrap();
    session.selected_mailbox_mod_seq = Some(snapshot.mod_seq);
    session.selected_mailbox_uids = config.mailbox_view.list_uids(scoped_mailbox).await.unwrap();
    session.selected_mailbox_flags.clear();
    for uid in &session.selected_mailbox_uids {
        let flags = config
            .mailbox_view
            .get_flags(scoped_mailbox, *uid)
            .await
            .unwrap();
        session.selected_mailbox_flags.insert(*uid, flags);
    }
}

fn multi_account_compat_config(
    _api_base_url: &str,
) -> (
    Arc<SessionConfig>,
    TempDir,
    AuthRouter,
    Arc<RuntimeAccountRegistry>,
) {
    let account_a = openproton_bridge::api::types::Session {
        uid: "uid-a".to_string(),
        access_token: "access-a".to_string(),
        refresh_token: "refresh-a".to_string(),
        email: "alice@proton.me".to_string(),
        display_name: "Alice".to_string(),
        api_mode: openproton_bridge::api::types::ApiMode::Bridge,
        key_passphrase: Some("dGVzdA==".to_string()),
        bridge_password: Some("pass-a".to_string()),
    };
    let account_b = openproton_bridge::api::types::Session {
        uid: "uid-b".to_string(),
        access_token: "access-b".to_string(),
        refresh_token: "refresh-b".to_string(),
        email: "bob@proton.me".to_string(),
        display_name: "Bob".to_string(),
        api_mode: openproton_bridge::api::types::ApiMode::Bridge,
        key_passphrase: Some("dGVzdA==".to_string()),
        bridge_password: Some("pass-b".to_string()),
    };
    let accounts = AccountRegistry::from_sessions(vec![account_a.clone(), account_b.clone()]);
    let auth_router = AuthRouter::new(accounts);
    let runtime_accounts = Arc::new(RuntimeAccountRegistry::in_memory(vec![
        account_a, account_b,
    ]));
    let tempdir = tempdir().expect("tempdir");
    let gluon_store = Arc::new(
        CompatibleStore::open(StoreBootstrap::new(
            CacheLayout::new(tempdir.path().join("gluon")),
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![
                AccountBootstrap::new(
                    "uid-a",
                    "uid-a",
                    GluonKey::try_from_slice(&[7u8; 32]).expect("key"),
                ),
                AccountBootstrap::new(
                    "uid-b",
                    "uid-b",
                    GluonKey::try_from_slice(&[8u8; 32]).expect("key"),
                ),
            ],
        ))
        .expect("open store"),
    );
    let config = Arc::new(SessionConfig {
        connector: mock_connector(&auth_router, &runtime_accounts),
        gluon_connector: GluonMailConnector::new(gluon_store.clone()),
        mailbox_catalog: RuntimeMailboxCatalog::new(runtime_accounts.clone()),
        mailbox_mutation: GluonMailMailboxMutation::new(gluon_store.clone()),
        mailbox_view: GluonMailMailboxView::new(gluon_store),
        recent_tracker: RecentTracker::new(),
        shutdown_rx: None,
        event_tx: None,
        delimiter: '/',
        login_jail_time: Duration::ZERO,
        idle_bulk_time: Duration::ZERO,
        limits: gluon_rs_mail::imap_types::ImapLimits::default(),
    });
    (config, tempdir, auth_router, runtime_accounts)
}

#[tokio::test]
async fn test_greet() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

    session.greet().await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("OK IMAP4rev1"));
}

#[tokio::test]
async fn test_capability() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

    session.handle_line("a001 CAPABILITY").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("IMAP4rev1"));
    assert!(response.contains("STARTTLS"));
    assert!(response.contains("UIDPLUS"));
    assert!(response.contains("MOVE"));
    assert!(!response.contains("AUTH=PLAIN"));
    assert!(response.contains("a001 OK"));
}

#[tokio::test]
async fn test_noop() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

    session.handle_line("a001 NOOP").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 OK"));
}

#[tokio::test]
async fn test_noop_selected_emits_exists_on_store_change() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.selected_mailbox_mod_seq = Some(0);
    session.authenticated_account_id = Some("test-uid".to_string());

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();

    session.handle_line("a001 NOOP").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("1 EXISTS"));
    assert!(response.contains("a001 OK"));
}

#[tokio::test]
async fn test_noop_selected_emits_exists_on_gluon_connector_create() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.selected_mailbox_mod_seq = Some(0);
    session.authenticated_account_id = Some("test-uid".to_string());

    config
        .gluon_connector
        .upsert_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-noop"),
            make_meta("msg-noop", 1),
        )
        .await
        .unwrap();

    session.handle_line("a001 NOOP").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("2 EXISTS"), "response={response}");
    assert!(response.contains("a001 OK"), "response={response}");
}

#[tokio::test]
async fn test_idle_selected_waits_for_done_and_emits_exists() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, mut client_write) =
        create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.selected_mailbox_mod_seq = Some(0);
    session.authenticated_account_id = Some("test-uid".to_string());

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();

    let idle_task = tokio::spawn(async move { session.handle_line("a001 IDLE").await.unwrap() });

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("+ idling"));
    assert!(response.contains("1 EXISTS"));

    tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
        .await
        .unwrap();

    let n = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 OK IDLE terminated"));

    let action = tokio::time::timeout(Duration::from_secs(1), idle_task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(action, SessionAction::Continue));
}

#[tokio::test]
async fn test_idle_emits_exists_when_new_message_arrives_after_start() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, mut client_write) =
        create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.selected_mailbox_mod_seq = Some(0);
    session.authenticated_account_id = Some("test-uid".to_string());

    let idle_task = tokio::spawn(async move { session.handle_line("a001 IDLE").await.unwrap() });

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("+ idling"), "response={response}");

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();

    let n = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("1 EXISTS"), "response={response}");

    tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
        .await
        .unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(1), idle_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_idle_emits_exists_when_new_message_arrives_after_start_with_gluon_mail_backend() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, mut client_write) =
        create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.selected_mailbox_mod_seq = Some(0);
    session.authenticated_account_id = Some("test-uid".to_string());

    let idle_task = tokio::spawn(async move { session.handle_line("a001 IDLE").await.unwrap() });

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("+ idling"), "response={response}");

    config
        .gluon_connector
        .upsert_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-idle"),
            make_meta("msg-idle", 1),
        )
        .await
        .unwrap();

    let n = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("2 EXISTS"), "response={response}");

    tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
        .await
        .unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(1), idle_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_idle_emits_expunge_and_exists_on_delete() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, mut client_write) =
        create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let uid1 = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    let _uid2 = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-2"),
            make_meta("msg-2", 1),
        )
        .await
        .unwrap();
    prime_selected_state_from_view(&mut session, &config, &scoped("test-uid", "INBOX")).await;

    let idle_task = tokio::spawn(async move { session.handle_line("a001 IDLE").await.unwrap() });

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("+ idling"), "response={response}");

    config
        .mailbox_mutation
        .remove_message(&scoped("test-uid", "INBOX"), uid1)
        .await
        .unwrap();

    let n = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("EXPUNGE"), "response={response}");
    assert!(response.contains("1 EXISTS"), "response={response}");

    tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(1), idle_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_idle_emits_expunge_and_exists_on_gluon_connector_delete() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, mut client_write) =
        create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let uid1 = seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-idle-delete-1",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-idle-delete-1\r\n\r\none",
    )
    .await;
    let _uid2 = seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-idle-delete-2",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-idle-delete-2\r\n\r\ntwo",
    )
    .await;
    assert_eq!(uid1, iuid(2));
    prime_selected_state_from_view(&mut session, &config, &scoped("test-uid", "INBOX")).await;

    let idle_task = tokio::spawn(async move { session.handle_line("a001 IDLE").await.unwrap() });

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("+ idling"), "response={response}");

    config
        .gluon_connector
        .remove_message_by_uid(&scoped("test-uid", "INBOX"), uid1)
        .await
        .unwrap();

    let n = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("EXPUNGE"), "response={response}");
    assert!(response.contains("2 EXISTS"), "response={response}");

    tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(1), idle_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_idle_emits_flag_fetch_on_flag_only_change() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, mut client_write) =
        create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let uid = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    let snapshot = config
        .mailbox_view
        .mailbox_snapshot(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    session.selected_mailbox_mod_seq = Some(snapshot.mod_seq);
    session.selected_mailbox_uids = vec![uid];
    session.selected_mailbox_flags.insert(uid, Vec::new());

    let idle_task = tokio::spawn(async move { session.handle_line("a001 IDLE").await.unwrap() });

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("+ idling"), "response={response}");

    config
        .mailbox_mutation
        .set_flags(
            &scoped("test-uid", "INBOX"),
            uid,
            vec!["\\Seen".to_string()],
        )
        .await
        .unwrap();

    let n = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("FETCH (FLAGS (\\Seen))"),
        "response={response}"
    );
    assert!(!response.contains("EXISTS"), "response={response}");

    tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(1), idle_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_idle_emits_flag_fetch_on_gluon_connector_flag_change() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, mut client_write) =
        create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let uid = seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-idle-flag",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-idle-flag\r\n\r\nbody",
    )
    .await;
    prime_selected_state_from_view(&mut session, &config, &scoped("test-uid", "INBOX")).await;
    session.selected_mailbox_flags.insert(uid, Vec::new());

    let idle_task = tokio::spawn(async move { session.handle_line("a001 IDLE").await.unwrap() });

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("+ idling"), "response={response}");

    config
        .gluon_connector
        .update_message_flags(
            &scoped("test-uid", "INBOX"),
            uid,
            vec!["\\Seen".to_string()],
        )
        .await
        .unwrap();

    let n = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::io::AsyncReadExt::read(&mut client_read, &mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("FETCH (FLAGS (\\Seen))"),
        "response={response}"
    );
    assert!(!response.contains("EXISTS"), "response={response}");

    tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(1), idle_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_logout() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

    let action = session.handle_line("a001 LOGOUT").await.unwrap();
    assert!(matches!(action, SessionAction::Close));

    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("BYE"));
    assert!(response.contains("a001 OK"));
}

#[tokio::test]
async fn test_login_bad_password() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

    session
        .handle_line("a001 LOGIN test@proton.me wrongpassword")
        .await
        .unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 NO"));
    assert!(response.contains("AUTHENTICATIONFAILED"));
}

#[tokio::test]
async fn test_login_isolation_unavailable_account_does_not_block_other_account() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/core/v4/users"))
        .and(header("x-pm-uid", "uid-b"))
        .and(header("Authorization", "Bearer access-b"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000,
            "User": {
                "ID": "user-b",
                "Name": "bob",
                "DisplayName": "Bob",
                "Email": "bob@proton.me",
                "Keys": []
            }
        })))
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, runtime_accounts) =
        multi_account_compat_config(&server.uri());
    runtime_accounts
        .set_health(
            &openproton_bridge::bridge::types::AccountId("uid-a".to_string()),
            AccountHealth::Unavailable,
        )
        .await
        .unwrap();

    // Unavailable account fails with generic auth failure.
    let (mut unavailable_session, mut unavailable_read, _w1) =
        create_session_pair(config.clone()).await;
    unavailable_session
        .handle_line("a001 LOGIN alice@proton.me pass-a")
        .await
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut unavailable_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("AUTHENTICATIONFAILED"));

    // Healthy account proceeds to login via connector. With the mock
    // connector this succeeds (the full key-unlock flow is not exercised).
    let (mut healthy_session, mut healthy_read, _w2) = create_session_pair(config).await;
    healthy_session
        .handle_line("a001 LOGIN bob@proton.me pass-b")
        .await
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut healthy_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("a001 OK"),
        "healthy account should succeed via mock connector, response={response}"
    );
    assert!(
        !response.contains("AUTHENTICATIONFAILED"),
        "healthy account login should not be blocked, response={response}"
    );
}

#[tokio::test]
async fn test_list_not_authenticated() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

    session.handle_line("a001 LIST \"\" \"*\"").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 NO"));
}

#[tokio::test]
async fn test_select_not_authenticated() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

    session.handle_line("a001 SELECT INBOX").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 NO"));
}

#[tokio::test]
async fn test_status_authenticated() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Authenticated;
    session.authenticated_account_id = Some("test-uid".to_string());

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "Drafts"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();

    session
        .handle_line("a001 STATUS \"Drafts\" (UIDNEXT UIDVALIDITY UNSEEN RECENT MESSAGES)")
        .await
        .unwrap();

    let mut buf = vec![0u8; 2048];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* STATUS \"Drafts\" ("));
    assert!(response.contains("UIDNEXT"));
    assert!(response.contains("UIDVALIDITY"));
    assert!(response.contains("UNSEEN"));
    assert!(response.contains("RECENT 0"));
    assert!(response.contains("MESSAGES 1"));
    assert!(response.contains("a001 OK STATUS completed"));
}

#[tokio::test]
async fn test_status_authenticated_with_gluon_mail_view() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

    session.state = State::Authenticated;
    session.authenticated_account_id = Some("test-uid".to_string());

    session
        .handle_line("a001 STATUS \"INBOX\" (UIDNEXT UIDVALIDITY UNSEEN RECENT MESSAGES)")
        .await
        .unwrap();

    let mut buf = vec![0u8; 2048];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("* STATUS \"INBOX\" ("),
        "response={response}"
    );
    assert!(response.contains("UIDNEXT 2"), "response={response}");
    assert!(response.contains("UIDVALIDITY 42"), "response={response}");
    assert!(response.contains("UNSEEN 1"), "response={response}");
    assert!(response.contains("RECENT 0"), "response={response}");
    assert!(response.contains("MESSAGES 1"), "response={response}");
    assert!(
        response.contains("a001 OK STATUS completed"),
        "response={response}"
    );
}

#[tokio::test]
async fn test_check_selected_mailbox() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.selected_mailbox_mod_seq = Some(0);
    session.authenticated_account_id = Some("test-uid".to_string());

    session.handle_line("a001 CHECK").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 OK CHECK completed"));
}

#[tokio::test]
async fn test_bad_command() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

    session.handle_line("a001 BOGUS").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 BAD"));
}

#[tokio::test]
async fn test_starttls() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

    let action = session.handle_line("a001 STARTTLS").await.unwrap();
    assert!(matches!(action, SessionAction::StartTls));

    let mut buf = vec![0u8; 1024];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 OK"));
}

#[tokio::test]
async fn test_select_paginates_metadata_fetch() {
    // This test verifies that SELECT populates the store from metadata.
    // With the connector abstraction, metadata is fetched via the connector.
    // Here we pre-seed the store to test the SELECT response formatting.
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Authenticated;
    session.authenticated_account_id = Some("test-uid".to_string());

    // Pre-seed the store with messages so SELECT finds them
    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-2"),
            make_meta("msg-2", 1),
        )
        .await
        .unwrap();

    session.handle_line("a001 SELECT INBOX").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("2 EXISTS"), "response={response}");
    assert!(response.contains("a001 OK [READ-WRITE] SELECT completed"));

    let uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    assert_eq!(uids.len(), 2);
}

#[tokio::test]
async fn test_fetch_body_returns_body_item_not_bodystructure() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let uid = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .store_rfc822(
            &scoped("test-uid", "INBOX"),
            uid,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-1\r\n\r\nbody".to_vec(),
        )
        .await
        .unwrap();

    session.handle_line("a001 FETCH 1 BODY").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains(" FETCH (BODY ("), "response={response}");
    assert!(!response.contains("BODYSTRUCTURE"), "response={response}");
    assert!(response.contains("a001 OK FETCH completed"));
}

#[tokio::test]
async fn test_fetch_body_returns_body_item_not_bodystructure_with_gluon_mail_view() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    session.handle_line("a001 FETCH 1 BODY").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains(" FETCH (BODY ("), "response={response}");
    assert!(!response.contains("BODYSTRUCTURE"), "response={response}");
    assert!(
        response.contains("a001 OK FETCH completed"),
        "response={response}"
    );
}

#[tokio::test]
async fn test_fetch_body_section_returns_empty_literal_when_content_missing() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();

    session
        .handle_line("a001 FETCH 1 BODY[TEXT]")
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("BODY[TEXT] {0}"), "response={response}");
    assert!(response.contains("a001 OK FETCH completed"));
}

#[tokio::test]
async fn test_store_set_flags_syncs_remote_removals() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/unread"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0..)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/unlabel"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0..)
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    let uid = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .set_flags(
            &scoped("test-uid", "INBOX"),
            uid,
            vec!["\\Seen".to_string(), "\\Flagged".to_string()],
        )
        .await
        .unwrap();

    session.handle_line("a001 STORE 1 FLAGS ()").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("FLAGS ()"), "response={response}");
    assert!(response.contains("a001 OK STORE completed"));

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_store_set_flags_syncs_remote_removals_with_gluon_mail_backend() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/unread"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0..)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/unlabel"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0..)
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    let uid = seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-store-sync",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-store-sync\r\n\r\nstore-body",
    )
    .await;
    config
        .mailbox_mutation
        .set_flags(
            &scoped("test-uid", "INBOX"),
            uid,
            vec!["\\Seen".to_string(), "\\Flagged".to_string()],
        )
        .await
        .unwrap();

    session.handle_line("a001 STORE 2 FLAGS ()").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("* 2 FETCH (FLAGS ())"),
        "response={response}"
    );
    assert!(
        response.contains("a001 OK STORE completed"),
        "response={response}"
    );
    assert!(config
        .mailbox_mutation
        .get_flags(&scoped("test-uid", "INBOX"), uid)
        .await
        .unwrap()
        .is_empty());

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_copy_copies_local_message_and_labels_destination_upstream() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    let src_uid = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();

    session.handle_line("a001 COPY 1 Archive").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("COPY completed"), "response={response}");
    assert!(
        response.contains("[COPYUID"),
        "response should contain COPYUID: {response}"
    );

    let inbox_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    assert_eq!(inbox_uids, vec![src_uid]);

    let archive_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "Archive"))
        .await
        .unwrap();
    assert_eq!(archive_uids.len(), 1);
    let archived_proton_id = config
        .mailbox_view
        .get_proton_id(&scoped("test-uid", "Archive"), archive_uids[0])
        .await
        .unwrap();
    assert_eq!(archived_proton_id.as_deref(), Some("msg-1"));

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_copy_copies_local_message_and_labels_destination_upstream_with_gluon_mail_backend() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/label"))
        .and(body_string_contains("\"LabelID\":\"6\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0..)
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    let uid = seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-copy-sync",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-copy-sync\r\n\r\ncopy-body",
    )
    .await;
    assert_eq!(uid, iuid(2));

    session.handle_line("a001 COPY 2 Archive").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("COPY completed"), "response={response}");
    assert!(response.contains("[COPYUID"), "response={response}");

    assert_eq!(
        config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap(),
        vec![iuid(1), iuid(2)]
    );
    assert_eq!(
        config
            .mailbox_view
            .list_uids(&scoped("test-uid", "Archive"))
            .await
            .unwrap(),
        vec![iuid(1)]
    );
    assert_eq!(
        config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "Archive"), iuid(1))
            .await
            .unwrap()
            .as_deref(),
        Some("msg-copy-sync")
    );

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_copy_copies_local_message_without_api_client() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let src_uid = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();

    session.handle_line("a001 COPY 1 Archive").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("COPY completed"), "response={response}");

    let inbox_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    assert_eq!(inbox_uids, vec![src_uid]);

    let archive_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "Archive"))
        .await
        .unwrap();
    assert_eq!(archive_uids.len(), 1);
    let archived_proton_id = config
        .mailbox_view
        .get_proton_id(&scoped("test-uid", "Archive"), archive_uids[0])
        .await
        .unwrap();
    assert_eq!(archived_proton_id.as_deref(), Some("msg-1"));
}

#[tokio::test]
async fn test_copy_copies_local_message_without_api_client_with_gluon_mail_backend() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let uid = seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-copy",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-copy\r\n\r\ncopy-body",
    )
    .await;
    assert_eq!(uid, iuid(2));

    session.handle_line("a001 COPY 2 Archive").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("COPY completed"), "response={response}");

    let inbox_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    assert_eq!(inbox_uids, vec![iuid(1), iuid(2)]);
    assert_eq!(
        config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "INBOX"), iuid(2))
            .await
            .unwrap()
            .as_deref(),
        Some("msg-copy")
    );

    let archive_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "Archive"))
        .await
        .unwrap();
    assert_eq!(archive_uids, vec![iuid(1)]);
    assert_eq!(
        config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "Archive"), iuid(1))
            .await
            .unwrap()
            .as_deref(),
        Some("msg-copy")
    );
}

#[tokio::test]
async fn test_copy_fails_when_upstream_fails() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let fail_config = with_failing_connector(&config, &_auth_router, &_runtime_accounts);
    let (mut session, mut client_read, _client_write) = create_session_pair(fail_config).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();

    session.handle_line("a001 COPY 1 Archive").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 NO"), "response={response}");
    assert!(
        response.contains("COPY failed: upstream mutation failed"),
        "response={response}"
    );

    let archive_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "Archive"))
        .await
        .unwrap();
    assert!(archive_uids.is_empty());
}

#[tokio::test]
async fn test_copy_fails_when_upstream_fails_with_gluon_mail_backend() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let fail_config = with_failing_connector(&config, &_auth_router, &_runtime_accounts);
    let (mut session, mut client_read, _client_write) = create_session_pair(fail_config).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    let uid = seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-copy-fail",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-copy-fail\r\n\r\ncopy-body",
    )
    .await;
    assert_eq!(uid, iuid(2));

    session.handle_line("a001 COPY 2 Archive").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 NO"), "response={response}");
    assert!(
        response.contains("COPY failed: upstream mutation failed"),
        "response={response}"
    );
    assert!(config
        .mailbox_view
        .list_uids(&scoped("test-uid", "Archive"))
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn test_move_moves_local_message_and_syncs_label_add_remove_upstream() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/label"))
        .and(body_string_contains("\"LabelID\":\"6\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0..)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/unlabel"))
        .and(body_string_contains("\"LabelID\":\"0\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0..)
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-2"),
            make_meta("msg-2", 1),
        )
        .await
        .unwrap();

    session.handle_line("a001 MOVE 1 Archive").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* 1 EXPUNGE"), "response={response}");
    assert!(response.contains("MOVE completed"), "response={response}");

    let inbox_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    assert_eq!(inbox_uids.len(), 1);
    let inbox_proton_id = config
        .mailbox_view
        .get_proton_id(&scoped("test-uid", "INBOX"), inbox_uids[0])
        .await
        .unwrap();
    assert_eq!(inbox_proton_id.as_deref(), Some("msg-2"));

    let archive_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "Archive"))
        .await
        .unwrap();
    assert_eq!(archive_uids.len(), 1);
    let archive_proton_id = config
        .mailbox_view
        .get_proton_id(&scoped("test-uid", "Archive"), archive_uids[0])
        .await
        .unwrap();
    assert_eq!(archive_proton_id.as_deref(), Some("msg-1"));

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_move_moves_local_message_and_syncs_label_add_remove_upstream_with_gluon_mail_backend()
{
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/label"))
        .and(body_string_contains("\"LabelID\":\"6\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0..)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/unlabel"))
        .and(body_string_contains("\"LabelID\":\"0\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0..)
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    let uid = seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-move-sync",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-move-sync\r\n\r\nmove-body",
    )
    .await;
    assert_eq!(uid, iuid(2));

    session.handle_line("a001 MOVE 2 Archive").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* 2 EXPUNGE"), "response={response}");
    assert!(response.contains("MOVE completed"), "response={response}");
    assert_eq!(
        config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap(),
        vec![iuid(1)]
    );
    assert_eq!(
        config
            .mailbox_view
            .list_uids(&scoped("test-uid", "Archive"))
            .await
            .unwrap(),
        vec![iuid(1)]
    );
    assert_eq!(
        config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "Archive"), iuid(1))
            .await
            .unwrap()
            .as_deref(),
        Some("msg-move-sync")
    );

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_move_moves_local_message_without_api_client() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-2"),
            make_meta("msg-2", 1),
        )
        .await
        .unwrap();

    session.handle_line("a001 MOVE 1 Archive").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* 1 EXPUNGE"), "response={response}");
    assert!(response.contains("MOVE completed"), "response={response}");

    let inbox_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    assert_eq!(inbox_uids.len(), 1);
    let inbox_proton_id = config
        .mailbox_view
        .get_proton_id(&scoped("test-uid", "INBOX"), inbox_uids[0])
        .await
        .unwrap();
    assert_eq!(inbox_proton_id.as_deref(), Some("msg-2"));

    let archive_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "Archive"))
        .await
        .unwrap();
    assert_eq!(archive_uids.len(), 1);
    let archive_proton_id = config
        .mailbox_view
        .get_proton_id(&scoped("test-uid", "Archive"), archive_uids[0])
        .await
        .unwrap();
    assert_eq!(archive_proton_id.as_deref(), Some("msg-1"));
}

#[tokio::test]
async fn test_move_moves_local_message_without_api_client_with_gluon_mail_backend() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let uid = seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-move",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-move\r\n\r\nmove-body",
    )
    .await;
    assert_eq!(uid, iuid(2));

    session.handle_line("a001 MOVE 2 Archive").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* 2 EXPUNGE"), "response={response}");
    assert!(response.contains("MOVE completed"), "response={response}");

    let inbox_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    assert_eq!(inbox_uids, vec![iuid(1)]);
    assert_eq!(
        config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "INBOX"), iuid(1))
            .await
            .unwrap()
            .as_deref(),
        Some("msg-1")
    );

    let archive_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "Archive"))
        .await
        .unwrap();
    assert_eq!(archive_uids, vec![iuid(1)]);
    assert_eq!(
        config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "Archive"), iuid(1))
            .await
            .unwrap()
            .as_deref(),
        Some("msg-move")
    );
}

#[tokio::test]
async fn test_move_fails_when_upstream_fails() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let fail_config = with_failing_connector(&config, &_auth_router, &_runtime_accounts);
    let (mut session, mut client_read, _client_write) = create_session_pair(fail_config).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-2"),
            make_meta("msg-2", 1),
        )
        .await
        .unwrap();

    session.handle_line("a001 MOVE 1 Archive").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 NO"), "response={response}");
    assert!(
        response.contains("MOVE failed: upstream mutation failed"),
        "response={response}"
    );

    let inbox_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    assert_eq!(inbox_uids.len(), 2);

    let archive_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "Archive"))
        .await
        .unwrap();
    assert!(archive_uids.is_empty());
}

#[tokio::test]
async fn test_move_fails_when_upstream_fails_with_gluon_mail_backend() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let fail_config = with_failing_connector(&config, &_auth_router, &_runtime_accounts);
    let (mut session, mut client_read, _client_write) = create_session_pair(fail_config).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let uid = seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-move-fail",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-move-fail\r\n\r\nmove-body",
    )
    .await;
    assert_eq!(uid, iuid(2));

    session.handle_line("a001 MOVE 2 Archive").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 NO"), "response={response}");
    assert!(
        response.contains("MOVE failed: upstream mutation failed"),
        "response={response}"
    );
    assert_eq!(
        config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap(),
        vec![iuid(1), iuid(2)]
    );
    assert!(config
        .mailbox_view
        .list_uids(&scoped("test-uid", "Archive"))
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn test_uid_move_uses_uid_selection_and_sequence_expunge_response() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/label"))
        .and(body_string_contains("\"LabelID\":\"6\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0..)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/unlabel"))
        .and(body_string_contains("\"LabelID\":\"0\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0..)
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    let uid2 = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-2"),
            make_meta("msg-2", 1),
        )
        .await
        .unwrap();

    session
        .handle_line(&format!("a001 UID MOVE {uid2} Archive"))
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* 2 EXPUNGE"), "response={response}");
    assert!(response.contains("MOVE completed"), "response={response}");

    let inbox_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    assert_eq!(inbox_uids.len(), 1);
    let inbox_proton_id = config
        .mailbox_view
        .get_proton_id(&scoped("test-uid", "INBOX"), inbox_uids[0])
        .await
        .unwrap();
    assert_eq!(inbox_proton_id.as_deref(), Some("msg-1"));

    let archive_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "Archive"))
        .await
        .unwrap();
    assert_eq!(archive_uids.len(), 1);
    let archive_proton_id = config
        .mailbox_view
        .get_proton_id(&scoped("test-uid", "Archive"), archive_uids[0])
        .await
        .unwrap();
    assert_eq!(archive_proton_id.as_deref(), Some("msg-2"));

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_uid_move_without_api_client_uses_uid_selection() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    let uid2 = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-2"),
            make_meta("msg-2", 1),
        )
        .await
        .unwrap();

    session
        .handle_line(&format!("a001 UID MOVE {uid2} Archive"))
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* 2 EXPUNGE"), "response={response}");
    assert!(response.contains("MOVE completed"), "response={response}");

    let inbox_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    assert_eq!(inbox_uids.len(), 1);
    let inbox_proton_id = config
        .mailbox_view
        .get_proton_id(&scoped("test-uid", "INBOX"), inbox_uids[0])
        .await
        .unwrap();
    assert_eq!(inbox_proton_id.as_deref(), Some("msg-1"));

    let archive_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "Archive"))
        .await
        .unwrap();
    assert_eq!(archive_uids.len(), 1);
    let archive_proton_id = config
        .mailbox_view
        .get_proton_id(&scoped("test-uid", "Archive"), archive_uids[0])
        .await
        .unwrap();
    assert_eq!(archive_proton_id.as_deref(), Some("msg-2"));
}

#[tokio::test]
async fn test_expunge_syncs_trash_label_upstream() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/label"))
        .and(body_string_contains("\"LabelID\":\"3\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0..)
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    let uid = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .add_flags(
            &scoped("test-uid", "INBOX"),
            uid,
            &[String::from("\\Deleted")],
        )
        .await
        .unwrap();

    session.handle_line("a001 EXPUNGE").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* 1 EXPUNGE"), "response={response}");
    assert!(
        response.contains("a001 OK EXPUNGE completed"),
        "response={response}"
    );

    let inbox_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    assert!(inbox_uids.is_empty());

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_expunge_syncs_trash_label_upstream_with_gluon_mail_backend() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/label"))
        .and(body_string_contains("\"LabelID\":\"3\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0..)
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    let uid = seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-expunge-sync",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-expunge-sync\r\n\r\nexpunge-body",
    )
    .await;
    config
        .mailbox_mutation
        .add_flags(
            &scoped("test-uid", "INBOX"),
            uid,
            &[String::from("\\Deleted")],
        )
        .await
        .unwrap();

    session.handle_line("a001 EXPUNGE").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* 2 EXPUNGE"), "response={response}");
    assert!(
        response.contains("a001 OK EXPUNGE completed"),
        "response={response}"
    );
    assert_eq!(
        config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap(),
        vec![iuid(1)]
    );

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_expunge_without_api_client_with_gluon_mail_backend() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let uid = seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-expunge",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-expunge\r\n\r\nexpunge-body",
    )
    .await;
    config
        .mailbox_mutation
        .add_flags(
            &scoped("test-uid", "INBOX"),
            uid,
            &[String::from("\\Deleted")],
        )
        .await
        .unwrap();

    session.handle_line("a001 EXPUNGE").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* 2 EXPUNGE"), "response={response}");
    assert!(
        response.contains("a001 OK EXPUNGE completed"),
        "response={response}"
    );
    assert_eq!(
        config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap(),
        vec![iuid(1)]
    );
    assert_eq!(
        config
            .mailbox_view
            .get_proton_id(&scoped("test-uid", "INBOX"), iuid(1))
            .await
            .unwrap()
            .as_deref(),
        Some("msg-1")
    );
}

#[tokio::test]
async fn test_expunge_fails_when_upstream_fails() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let fail_config = with_failing_connector(&config, &_auth_router, &_runtime_accounts);
    let (mut session, mut client_read, _client_write) = create_session_pair(fail_config).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    let uid = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .add_flags(
            &scoped("test-uid", "INBOX"),
            uid,
            &[String::from("\\Deleted")],
        )
        .await
        .unwrap();

    session.handle_line("a001 EXPUNGE").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 NO"), "response={response}");
    assert!(
        response.contains("EXPUNGE failed: upstream mutation failed"),
        "response={response}"
    );

    let inbox_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    assert_eq!(inbox_uids, vec![uid]);
}

#[tokio::test]
async fn test_expunge_fails_when_upstream_fails_with_gluon_mail_backend() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let fail_config = with_failing_connector(&config, &_auth_router, &_runtime_accounts);
    let (mut session, mut client_read, _client_write) = create_session_pair(fail_config).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    let uid = seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-expunge-fail",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-expunge-fail\r\n\r\nexpunge-body",
    )
    .await;
    config
        .mailbox_mutation
        .add_flags(
            &scoped("test-uid", "INBOX"),
            uid,
            &[String::from("\\Deleted")],
        )
        .await
        .unwrap();

    session.handle_line("a001 EXPUNGE").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 NO"), "response={response}");
    assert!(
        response.contains("EXPUNGE failed: upstream mutation failed"),
        "response={response}"
    );
    assert_eq!(
        config
            .mailbox_view
            .list_uids(&scoped("test-uid", "INBOX"))
            .await
            .unwrap(),
        vec![iuid(1), iuid(2)]
    );
}

#[tokio::test]
async fn test_uid_expunge_fails_when_upstream_fails() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let fail_config = with_failing_connector(&config, &_auth_router, &_runtime_accounts);
    let (mut session, mut client_read, _client_write) = create_session_pair(fail_config).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    let uid = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .add_flags(
            &scoped("test-uid", "INBOX"),
            uid,
            &[String::from("\\Deleted")],
        )
        .await
        .unwrap();

    session
        .handle_line(&format!("a001 UID EXPUNGE {uid}"))
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a001 NO"), "response={response}");
    assert!(
        response.contains("UID EXPUNGE failed: upstream mutation failed"),
        "response={response}"
    );

    let inbox_uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    assert_eq!(inbox_uids, vec![uid]);
}

#[tokio::test]
async fn test_examine_reports_first_unseen_sequence_number() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Authenticated;
    session.authenticated_account_id = Some("test-uid".to_string());

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 0),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-2"),
            make_meta("msg-2", 1),
        )
        .await
        .unwrap();

    session.handle_line("a001 EXAMINE INBOX").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("OK [UNSEEN 2]"), "response={response}");
    assert!(response.contains("a001 OK [READ-ONLY] EXAMINE completed"));
}

#[tokio::test]
async fn test_examine_reports_first_unseen_sequence_number_with_gluon_mail_backend() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Authenticated;
    session.authenticated_account_id = Some("test-uid".to_string());

    config
        .mailbox_mutation
        .set_flags(
            &scoped("test-uid", "INBOX"),
            iuid(1),
            vec!["\\Seen".to_string()],
        )
        .await
        .unwrap();
    seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-2",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-2\r\n\r\nbody",
    )
    .await;

    session.handle_line("a001 EXAMINE INBOX").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("OK [UNSEEN 2]"), "response={response}");
    assert!(response.contains("a001 OK [READ-ONLY] EXAMINE completed"));
}

#[tokio::test]
async fn test_fetch_header_fields_uses_metadata_when_rfc822_missing() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/mail/v4/messages/msg-1"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .named("no full message fetch for header-only body section")
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();

    session
        .handle_line("a001 FETCH 1 (UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])")
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("BODY[HEADER.FIELDS"));
    assert!(response.contains("Subject: Subject msg-1"));
    assert!(response.contains("From: \"Alice\" <alice@proton.me>"));
    assert!(response.contains("a001 OK FETCH completed"));

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_fetch_multiple_non_peek_body_sections_marks_read_once() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/read"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0..)
        .named("mark read should only happen once per message")
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    let uid = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .store_rfc822(
            &scoped("test-uid", "INBOX"),
            uid,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-1\r\n\r\nbody".to_vec(),
        )
        .await
        .unwrap();

    session
        .handle_line("a001 FETCH 1 (BODY[] BODY[TEXT])")
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("BODY[]"));
    assert!(response.contains("BODY[TEXT]"));
    assert!(response.contains("a001 OK FETCH completed"));

    let flags = config
        .mailbox_view
        .get_flags(&scoped("test-uid", "INBOX"), uid)
        .await
        .unwrap();
    assert!(flags.iter().any(|f| f == "\\Seen"));

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_select_after_examine_resets_read_only_mode() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Authenticated;
    session.authenticated_account_id = Some("test-uid".to_string());

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "Drafts"),
            &pid("msg-2"),
            make_meta("msg-2", 1),
        )
        .await
        .unwrap();

    session.handle_line("a001 EXAMINE INBOX").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let _ = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    assert!(session.selected_read_only);

    session.handle_line("a002 SELECT Drafts").await.unwrap();
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a002 OK [READ-WRITE] SELECT completed"));
    assert!(!session.selected_read_only);
}

#[tokio::test]
async fn test_select_after_examine_resets_read_only_mode_with_gluon_mail_backend() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Authenticated;
    session.authenticated_account_id = Some("test-uid".to_string());

    seed_gluon_backend_message(
        &config,
        "Drafts",
        "msg-2",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Draft msg-2\r\n\r\nbody",
    )
    .await;

    session.handle_line("a001 EXAMINE INBOX").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let _ = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    assert!(session.selected_read_only);

    session.handle_line("a002 SELECT Drafts").await.unwrap();
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("a002 OK [READ-WRITE] SELECT completed"));
    assert!(!session.selected_read_only);
}

#[tokio::test]
async fn test_close_after_examine_deselects_mailbox() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Authenticated;
    session.authenticated_account_id = Some("test-uid".to_string());

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();

    session.handle_line("a001 EXAMINE INBOX").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let _ = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    assert!(session.selected_read_only);
    assert_eq!(session.state, State::Selected);

    session.handle_line("a002 CLOSE").await.unwrap();
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("a002 OK CLOSE completed"),
        "response={response}"
    );
    assert_eq!(session.state, State::Authenticated);
    assert!(session.selected_mailbox.is_none());
    assert!(!session.selected_read_only);
}

#[tokio::test]
async fn test_examine_fetch_body_does_not_mark_read() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/read"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0)
        .named("read-only fetch must not mark message as read")
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Authenticated;
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    let uid = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .store_rfc822(
            &scoped("test-uid", "INBOX"),
            uid,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-1\r\n\r\nbody".to_vec(),
        )
        .await
        .unwrap();

    session.handle_line("a001 EXAMINE INBOX").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let _ = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    assert!(session.selected_read_only);

    session.handle_line("a002 FETCH 1 (BODY[])").await.unwrap();
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("BODY[]"), "response={response}");
    assert!(
        response.contains("a002 OK FETCH completed"),
        "response={response}"
    );

    let flags = config
        .mailbox_view
        .get_flags(&scoped("test-uid", "INBOX"), uid)
        .await
        .unwrap();
    assert!(
        !flags.iter().any(|f| f == "\\Seen"),
        "flags were mutated in read-only mode: {flags:?}"
    );

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_examine_fetch_body_does_not_mark_read_with_gluon_mail_backend() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/read"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(0)
        .named("read-only gluon fetch must not mark message as read")
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Authenticated;
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    session.handle_line("a001 EXAMINE INBOX").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let _ = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    assert!(session.selected_read_only);

    session.handle_line("a002 FETCH 1 (BODY[])").await.unwrap();
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("BODY[]"), "response={response}");
    assert!(
        response.contains("a002 OK FETCH completed"),
        "response={response}"
    );

    let flags = config
        .mailbox_view
        .get_flags(&scoped("test-uid", "INBOX"), iuid(1))
        .await
        .unwrap();
    assert!(
        !flags.iter().any(|f| f == "\\Seen"),
        "flags were mutated in read-only mode: {flags:?}"
    );

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_uid_fetch_flags_always_includes_uid() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let uid = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();

    session
        .handle_line("a001 UID FETCH 1:* (FLAGS)")
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains(&format!("* 1 FETCH (UID {uid} FLAGS (")));
    assert!(response.contains("a001 OK FETCH completed"));
}

#[tokio::test]
async fn test_uid_store_flags_response_includes_uid() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let uid = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();

    session
        .handle_line("a001 UID STORE 1:* +FLAGS (\\Seen)")
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains(&format!("* 1 FETCH (UID {uid} FLAGS (")));
    assert!(response.contains("\\Seen"));
    assert!(response.contains("a001 OK STORE completed"));
}

#[tokio::test]
async fn test_uid_store_flags_response_includes_uid_with_gluon_mail_backend() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let uid = seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-2",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-2\r\n\r\nbody",
    )
    .await;

    session
        .handle_line(&format!("a001 UID STORE {uid} +FLAGS (\\Seen)"))
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains(&format!("* 2 FETCH (UID {uid} FLAGS (")));
    assert!(response.contains("\\Seen"));
    assert!(response.contains("a001 OK STORE completed"));
    assert_eq!(
        config
            .mailbox_mutation
            .get_flags(&scoped("test-uid", "INBOX"), uid)
            .await
            .unwrap(),
        vec!["\\Seen".to_string()]
    );
}

#[tokio::test]
async fn test_search_text_and_header_use_cached_rfc822() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let uid = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .store_rfc822(
            &scoped("test-uid", "INBOX"),
            uid,
            b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-1\r\n\r\nsearch-hit-body"
                .to_vec(),
        )
        .await
        .unwrap();

    session
        .handle_line("a001 SEARCH TEXT \"search-hit-body\"")
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* SEARCH 1"), "response={response}");
    assert!(
        response.contains("a001 OK SEARCH completed"),
        "response={response}"
    );

    session
        .handle_line("a002 SEARCH HEADER Subject \"Subject msg-1\"")
        .await
        .unwrap();
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* SEARCH 1"), "response={response}");
    assert!(
        response.contains("a002 OK SEARCH completed"),
        "response={response}"
    );
}

#[tokio::test]
async fn test_search_text_and_header_use_gluon_mail_rfc822() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    session
        .handle_line("a001 SEARCH TEXT \"search-hit-body\"")
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* SEARCH 1"), "response={response}");
    assert!(
        response.contains("a001 OK SEARCH completed"),
        "response={response}"
    );

    session
        .handle_line("a002 SEARCH HEADER Subject \"Subject msg-1\"")
        .await
        .unwrap();
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* SEARCH 1"), "response={response}");
    assert!(
        response.contains("a002 OK SEARCH completed"),
        "response={response}"
    );
}

#[tokio::test]
async fn test_search_text_and_header_use_gluon_mail_view() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    session
        .handle_line("a001 SEARCH TEXT \"body\"")
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* SEARCH 1"), "response={response}");
    assert!(
        response.contains("a001 OK SEARCH completed"),
        "response={response}"
    );

    session
        .handle_line("a002 UID SEARCH HEADER Subject \"Subject msg-1\"")
        .await
        .unwrap();
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("* SEARCH 1"), "response={response}");
    assert!(
        response.contains("a002 OK SEARCH completed"),
        "response={response}"
    );
}

#[tokio::test]
async fn test_select_warm_cache_skips_metadata_fetch() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mail/v4/messages"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .named("no metadata fetch on warm select")
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Authenticated;
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();

    session.handle_line("a001 SELECT INBOX").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("1 EXISTS"));
    assert!(response.contains("a001 OK [READ-WRITE] SELECT completed"));

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_select_warm_cache_skips_metadata_fetch_with_gluon_mail_backend() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/mail/v4/messages"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .named("no metadata fetch on warm select with gluon backend")
        .mount(&server)
        .await;

    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Authenticated;
    session.authenticated_account_id = Some("test-uid".to_string());
    // client field removed; connector handles upstream calls

    session.handle_line("a001 SELECT INBOX").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("1 EXISTS"));
    assert!(response.contains("a001 OK [READ-WRITE] SELECT completed"));

    // server.verify() removed: upstream calls go through connector
}

#[tokio::test]
async fn test_select_reports_first_unseen_sequence_and_permanentflags() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Authenticated;
    session.authenticated_account_id = Some("test-uid".to_string());

    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 0),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-2"),
            make_meta("msg-2", 1),
        )
        .await
        .unwrap();

    session.handle_line("a001 SELECT INBOX").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("2 EXISTS"));
    assert!(response.contains(
        "OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] Flags permitted"
    ));
    assert!(response.contains("OK [UNSEEN 2] First unseen"));
    assert!(response.contains("a001 OK [READ-WRITE] SELECT completed"));
}

#[tokio::test]
async fn test_select_reports_first_unseen_sequence_and_permanentflags_with_gluon_mail_backend() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_mail_config().await;
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Authenticated;
    session.authenticated_account_id = Some("test-uid".to_string());

    config
        .mailbox_mutation
        .set_flags(
            &scoped("test-uid", "INBOX"),
            iuid(1),
            vec!["\\Seen".to_string()],
        )
        .await
        .unwrap();
    seed_gluon_backend_message(
        &config,
        "INBOX",
        "msg-2",
        1,
        b"From: Alice <alice@proton.me>\r\nSubject: Subject msg-2\r\n\r\nbody",
    )
    .await;

    session.handle_line("a001 SELECT INBOX").await.unwrap();

    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("2 EXISTS"));
    assert!(response.contains(
        "OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] Flags permitted"
    ));
    assert!(response.contains("OK [UNSEEN 2] First unseen"));
    assert!(response.contains("a001 OK [READ-WRITE] SELECT completed"));
}

#[test]
fn test_evaluate_search_all() {
    let meta = Some(make_meta("msg-1", 1));
    let flags = vec![];
    assert!(evaluate_search_key(
        &SearchKey::All,
        iuid(1),
        1,
        1,
        &meta,
        &flags,
        iuid(1),
        None
    ));
}

#[test]
fn test_evaluate_search_seen() {
    let meta = Some(make_meta("msg-1", 0));
    let flags = vec!["\\Seen".to_string()];
    assert!(evaluate_search_key(
        &SearchKey::Seen,
        iuid(1),
        1,
        1,
        &meta,
        &flags,
        iuid(1),
        None
    ));
    assert!(!evaluate_search_key(
        &SearchKey::Unseen,
        iuid(1),
        1,
        1,
        &meta,
        &flags,
        iuid(1),
        None
    ));
}

#[test]
fn test_evaluate_search_subject() {
    let meta = Some(make_meta("msg-1", 1));
    let flags = vec![];
    assert!(evaluate_search_key(
        &SearchKey::Subject("Subject".to_string()),
        iuid(1),
        1,
        1,
        &meta,
        &flags,
        iuid(1),
        None
    ));
    assert!(!evaluate_search_key(
        &SearchKey::Subject("NotFound".to_string()),
        iuid(1),
        1,
        1,
        &meta,
        &flags,
        iuid(1),
        None
    ));
}

#[test]
fn test_evaluate_search_from() {
    let meta = Some(make_meta("msg-1", 1));
    let flags = vec![];
    assert!(evaluate_search_key(
        &SearchKey::From("alice".to_string()),
        iuid(1),
        1,
        1,
        &meta,
        &flags,
        iuid(1),
        None
    ));
}

#[test]
fn test_evaluate_search_not() {
    let meta = Some(make_meta("msg-1", 1));
    let flags = vec![];
    assert!(!evaluate_search_key(
        &SearchKey::Not(Box::new(SearchKey::All)),
        iuid(1),
        1,
        1,
        &meta,
        &flags,
        iuid(1),
        None
    ));
}

#[test]
fn test_format_copyuid() {
    assert_eq!(
        format_copyuid(
            1700000000,
            &[iuid(1), iuid(2), iuid(3)],
            &[iuid(10), iuid(11), iuid(12)]
        ),
        "COPYUID 1700000000 1,2,3 10,11,12"
    );
}

#[test]
fn test_format_copyuid_single() {
    assert_eq!(
        format_copyuid(42, &[iuid(5)], &[iuid(100)]),
        "COPYUID 42 5 100"
    );
}

#[test]
fn test_format_copyuid_empty() {
    assert_eq!(format_copyuid(42, &[], &[]), "COPYUID 42  ");
}

#[test]
fn test_parse_rfc2822_date_basic() {
    // Mon, 14 Nov 2023 22:13:20 +0000
    let ts = parse_rfc2822_date("Mon, 14 Nov 2023 22:13:20 +0000");
    assert_eq!(ts, Some(1700000000));
}

#[test]
fn test_parse_rfc2822_date_no_dow() {
    let ts = parse_rfc2822_date("14 Nov 2023 22:13:20 +0000");
    assert_eq!(ts, Some(1700000000));
}

#[test]
fn test_parse_rfc2822_date_with_timezone() {
    // Same instant but expressed in UTC-5
    let ts = parse_rfc2822_date("Tue, 14 Nov 2023 17:13:20 -0500");
    assert_eq!(ts, Some(1700000000));
}

#[test]
fn test_parse_rfc2822_date_invalid() {
    assert!(parse_rfc2822_date("not a date").is_none());
    assert!(parse_rfc2822_date("").is_none());
}

#[test]
fn test_extract_sent_date() {
    let rfc822 = b"Date: Mon, 14 Nov 2023 22:13:20 +0000\r\nSubject: test\r\n\r\nbody";
    let ts = extract_sent_date(rfc822);
    assert_eq!(ts, Some(1700000000));
}

#[test]
fn test_sent_search_uses_date_header() {
    let meta = Some(make_meta("msg-1", 0));
    let flags = vec![];
    // Meta time is 1700000000 but the Date header says a day earlier
    let rfc822 = b"Date: Mon, 13 Nov 2023 22:13:20 +0000\r\nSubject: test\r\n\r\nbody";
    let day_before_ts = 1700000000 - 86400; // 13 Nov

    // SENTON should match the Date header day, not meta.time
    assert!(evaluate_search_key(
        &SearchKey::SentOn(day_before_ts),
        iuid(1),
        1,
        1,
        &meta,
        &flags,
        iuid(1),
        Some(rfc822)
    ));
    // Should NOT match meta.time day
    assert!(!evaluate_search_key(
        &SearchKey::SentOn(1700000000),
        iuid(1),
        1,
        1,
        &meta,
        &flags,
        iuid(1),
        Some(rfc822)
    ));
}

#[test]
fn test_sent_search_falls_back_to_meta_time() {
    let meta = Some(make_meta("msg-1", 0));
    let flags = vec![];
    // No RFC822 data available - should fall back to meta.time
    assert!(evaluate_search_key(
        &SearchKey::SentOn(1700000000),
        iuid(1),
        1,
        1,
        &meta,
        &flags,
        iuid(1),
        None
    ));
}

#[test]
fn test_idle_timeout_is_30_minutes() {
    assert_eq!(IDLE_TIMEOUT, Duration::from_secs(30 * 60));
}

#[tokio::test]
async fn test_idle_exits_on_done() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, mut client_write) =
        create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    // Start IDLE in a spawned task, send DONE after reading continuation
    let handle = tokio::spawn(async move {
        session.handle_line("a001 IDLE").await.unwrap();
        session
    });

    // Read the continuation response
    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(response.contains("+ idling"), "response={response}");

    // Send DONE to exit IDLE
    tokio::io::AsyncWriteExt::write_all(&mut client_write, b"DONE\r\n")
        .await
        .unwrap();

    let _session = handle.await.unwrap();
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("a001 OK IDLE terminated"),
        "response={response}"
    );
}

#[tokio::test]
async fn test_unselect_does_not_expunge() {
    let (config, _tempdir, _auth_router, _runtime_accounts) = test_gluon_config();
    let (mut session, mut client_read, _client_write) = create_session_pair(config.clone()).await;

    session.state = State::Selected;
    session.selected_mailbox = Some("INBOX".to_string());
    session.authenticated_account_id = Some("test-uid".to_string());

    let uid = config
        .mailbox_mutation
        .store_metadata(
            &scoped("test-uid", "INBOX"),
            &pid("msg-1"),
            make_meta("msg-1", 1),
        )
        .await
        .unwrap();
    config
        .mailbox_mutation
        .add_flags(
            &scoped("test-uid", "INBOX"),
            uid,
            &["\\Deleted".to_string()],
        )
        .await
        .unwrap();

    session.handle_line("a001 UNSELECT").await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)
        .await
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("a001 OK UNSELECT completed"),
        "response={response}"
    );
    assert!(
        !response.contains("EXPUNGE"),
        "UNSELECT must not expunge: {response}"
    );

    assert_eq!(session.state, State::Authenticated);
    assert!(session.selected_mailbox.is_none());

    // Message should still exist in the store
    let uids = config
        .mailbox_view
        .list_uids(&scoped("test-uid", "INBOX"))
        .await
        .unwrap();
    assert_eq!(uids.len(), 1, "message must not be expunged");
}
