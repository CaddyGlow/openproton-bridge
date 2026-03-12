use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use gluon_rs_mail::{
    AccountBootstrap, CacheLayout, CompatibilityTarget, CompatibleStore, GluonKey, NewMailbox,
    NewMessage, StoreBootstrap,
};
use openproton_bridge::api::types::{
    Address, AddressKey, ApiMode, EmailAddress, MessageMetadata, Session, UserKey,
};
use openproton_bridge::bridge::accounts::RuntimeAuthMaterial;
use openproton_bridge::bridge::events::VaultCheckpointStore;
use openproton_bridge::bridge::mail_runtime::{
    self, DavTlsMode, ImapMutationBackend, ImapReadBackend, MailRuntimeConfig,
    MailRuntimeTransition,
};
use openproton_bridge::bridge::session_manager::SessionManager;
use openproton_bridge::bridge::types::{
    AccountId, CheckpointSyncState, EventCheckpoint, EventCheckpointStore,
};
use openproton_bridge::imap::store::new_runtime_message_store;
use openproton_bridge::paths::RuntimePaths;
use openproton_bridge::vault;
use sequoia_openpgp as openpgp;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::crypto::Password;
use sequoia_openpgp::serialize::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_meta(id: &str) -> MessageMetadata {
    MessageMetadata {
        id: id.to_string(),
        address_id: "addr-1".to_string(),
        label_ids: vec!["0".to_string()],
        external_id: None,
        subject: format!("Subject {id}"),
        sender: EmailAddress {
            name: "Alice".to_string(),
            address: "alice@proton.me".to_string(),
        },
        to_list: vec![],
        cc_list: vec![],
        bcc_list: vec![],
        reply_tos: vec![],
        flags: 0,
        time: 1700000000,
        size: 1024,
        unread: 1,
        is_replied: 0,
        is_replied_all: 0,
        is_forwarded: 0,
        num_attachments: 0,
    }
}

fn runtime_event_message_json(
    message_id: &str,
    label_ids: &[&str],
    unread: i32,
) -> serde_json::Value {
    serde_json::json!({
        "Code": 1000,
        "Message": {
            "ID": message_id,
            "AddressID": "addr-1",
            "LabelIDs": label_ids,
            "Subject": "Event Subject",
            "Sender": {"Name": "Alice", "Address": "alice@proton.me"},
            "ToList": [],
            "CCList": [],
            "BCCList": [],
            "Time": 1700000000,
            "Size": 100,
            "Unread": unread,
            "NumAttachments": 0,
            "Header": "From: alice@proton.me\r\n",
            "Body": "body",
            "MIMEType": "text/plain",
            "Attachments": []
        }
    })
}

fn runtime_metadata_json(message_id: &str, label_ids: &[&str], unread: i32) -> serde_json::Value {
    serde_json::json!({
        "ID": message_id,
        "AddressID": "addr-1",
        "LabelIDs": label_ids,
        "Subject": "Runtime Resync Subject",
        "Sender": {"Name": "Alice", "Address": "alice@proton.me"},
        "ToList": [],
        "CCList": [],
        "BCCList": [],
        "Time": 1700000000,
        "Size": 100,
        "Unread": unread,
        "NumAttachments": 0
    })
}

#[tokio::test]
async fn be026_runtime_store_writes_gluon_layout_without_json_mailbox_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let account_map = HashMap::from([("account-1".to_string(), "user-1".to_string())]);
    let store = new_runtime_message_store(temp.path().to_path_buf(), account_map)
        .expect("create runtime message store");
    let mailbox = "account-1::INBOX";

    let uid = store
        .store_metadata(mailbox, "msg-1", make_meta("msg-1"))
        .await
        .expect("store metadata");
    assert_eq!(uid, 1);
    store
        .store_rfc822(mailbox, uid, b"From: alice\r\n\r\nhello".to_vec())
        .await
        .expect("store rfc822");

    let account_store_dir = temp.path().join("backend").join("store").join("user-1");
    let account_db_path = temp.path().join("backend").join("db").join("user-1.db");
    assert!(
        account_db_path.exists(),
        "runtime store must write sqlite mailbox index data"
    );
    assert!(
        account_store_dir.join("00000001.msg").exists(),
        "runtime store must write gluon message blobs"
    );
    let conn = rusqlite::Connection::open(&account_db_path).expect("open sqlite db");
    let row_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM openproton_mailboxes", [], |row| {
            row.get(0)
        })
        .expect("query sqlite mailbox row count");
    assert_eq!(row_count, 1);

    let root_json_files = fs::read_dir(temp.path())
        .expect("read runtime store root")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    assert!(
        root_json_files.is_empty(),
        "runtime store root should not contain JSON mailbox files: {root_json_files:?}"
    );
}

fn is_cfg_test_guarded(source: &str, marker: &str) -> bool {
    let Some(index) = source.find(marker) else {
        return false;
    };
    let prefix = &source[..index];
    let mut lines = prefix.lines().rev();
    let previous_non_empty = lines.find(|line| !line.trim().is_empty());
    matches!(previous_non_empty, Some(line) if line.trim() == "#[cfg(test)]")
}

fn runtime_test_session() -> Session {
    Session {
        uid: "uid-gluon-runtime".to_string(),
        access_token: "live-access-token".to_string(),
        refresh_token: "refresh-token".to_string(),
        email: "runtime@proton.me".to_string(),
        display_name: "Runtime Test".to_string(),
        api_mode: ApiMode::Bridge,
        key_passphrase: Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"test-passphrase",
        )),
        bridge_password: Some("bridge-password".to_string()),
    }
}

fn generate_test_cert_armored(password: &str) -> String {
    let (cert, _) = CertBuilder::general_purpose(None, Some("runtime@test.local"))
        .set_password(Some(Password::from(password)))
        .generate()
        .expect("generate test cert");

    let mut armored_buf = Vec::new();
    let mut armor_writer =
        openpgp::armor::Writer::new(&mut armored_buf, openpgp::armor::Kind::SecretKey)
            .expect("armor writer");
    cert.as_tsk()
        .serialize(&mut armor_writer)
        .expect("serialize test cert");
    armor_writer.finalize().expect("finalize armor");

    String::from_utf8(armored_buf).expect("armor utf8")
}

fn runtime_auth_material_fixture(passphrase: &str, email: &str) -> RuntimeAuthMaterial {
    let user_key = UserKey {
        id: "user-key-1".to_string(),
        private_key: generate_test_cert_armored(passphrase),
        token: None,
        signature: None,
        primary: Some(1),
        flags: None,
        active: 1,
    };
    let address_key = AddressKey {
        id: "addr-key-1".to_string(),
        private_key: generate_test_cert_armored(passphrase),
        token: None,
        signature: None,
        primary: Some(1),
        flags: None,
        active: 1,
    };
    let address = Address {
        id: "addr-1".to_string(),
        email: email.to_string(),
        status: 1,
        receive: 1,
        send: 1,
        address_type: 1,
        order: 0,
        display_name: "Runtime Test".to_string(),
        keys: vec![address_key],
    };

    RuntimeAuthMaterial {
        user_keys: vec![user_key],
        addresses: vec![address],
    }
}

fn seed_runtime_gluon_store_with_flags(
    runtime_paths: &RuntimePaths,
    session: &Session,
    flags: &[&str],
) {
    let gluon_root = runtime_paths
        .gluon_paths(Some("gluon"))
        .root()
        .to_path_buf();
    let store = CompatibleStore::open(StoreBootstrap::new(
        CacheLayout::new(gluon_root),
        CompatibilityTarget::pinned("2046c95ca745"),
        vec![AccountBootstrap::new(
            &session.uid,
            &session.uid,
            GluonKey::try_from_slice(&[7u8; 32]).expect("gluon key"),
        )],
    ))
    .expect("open compatible store");

    let mailbox = store
        .create_mailbox(
            &session.uid,
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
        .expect("create runtime inbox");

    let blob = b"Date: Tue, 14 Nov 2023 22:13:20 +0000\r\nFrom: Alice <alice@proton.me>\r\nTo: Runtime <runtime@proton.me>\r\nSubject: Runtime Subject\r\nMessage-ID: <runtime-msg-1@example.test>\r\n\r\nruntime-body".to_vec();
    store
        .append_message(
            &session.uid,
            mailbox.internal_id,
            &NewMessage {
                internal_id: "internal-runtime-1".to_string(),
                remote_id: "runtime-msg-1".to_string(),
                flags: flags.iter().map(|flag| (*flag).to_string()).collect(),
                blob,
                body: "runtime-body".to_string(),
                body_structure: "(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 12 1 NIL NIL NIL)"
                    .to_string(),
                envelope: "(\"Tue, 14 Nov 2023 22:13:20 +0000\" \"Runtime Subject\" ((NIL NIL \"alice\" \"proton.me\")) ((NIL NIL \"alice\" \"proton.me\")) ((NIL NIL \"alice\" \"proton.me\")) ((NIL NIL \"runtime\" \"proton.me\")) NIL NIL NIL \"<runtime-msg-1@example.test>\")".to_string(),
                size: 190,
                recent: false,
            },
        )
        .expect("append runtime message");
}

fn seed_runtime_gluon_store(runtime_paths: &RuntimePaths, session: &Session) {
    seed_runtime_gluon_store_with_flags(runtime_paths, session, &["\\Seen"]);
}

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind temp port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

async fn free_port_excluding(excluded: &[u16]) -> u16 {
    loop {
        let candidate = free_port().await;
        if !excluded.contains(&candidate) {
            return candidate;
        }
    }
}

async fn connect_with_retry(port: u16) -> TcpStream {
    let addr = format!("127.0.0.1:{port}");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);

    loop {
        match TcpStream::connect(&addr).await {
            Ok(stream) => return stream,
            Err(err) if tokio::time::Instant::now() < deadline => {
                let _ = err;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(err) => panic!("connect to {addr} failed: {err}"),
        }
    }
}

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read line");
    line
}

async fn read_until_tag(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    terminal_tag: &str,
) -> String {
    let mut response = String::new();
    loop {
        let line = read_line(reader).await;
        if line.is_empty() {
            break;
        }
        response.push_str(&line);
        if line.starts_with(terminal_tag) {
            break;
        }
    }
    response
}

async fn read_chunk_with_timeout(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    timeout: std::time::Duration,
) -> String {
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout, tokio::io::AsyncReadExt::read(reader, &mut buf))
        .await
        .expect("read timeout")
        .expect("read chunk");
    String::from_utf8_lossy(&buf[..n]).to_string()
}

fn runtime_test_config(imap_port: u16, smtp_port: u16, api_base_url: String) -> MailRuntimeConfig {
    MailRuntimeConfig {
        bind_host: "127.0.0.1".to_string(),
        imap_port,
        smtp_port,
        dav_enable: false,
        dav_port: 8080,
        dav_tls_mode: DavTlsMode::None,
        disable_tls: false,
        use_ssl_for_imap: false,
        use_ssl_for_smtp: false,
        api_base_url,
        imap_read_backend: ImapReadBackend::GluonMailReadOnly,
        imap_mutation_backend: ImapMutationBackend::GluonMail,
        event_poll_interval: std::time::Duration::from_secs(30),
        pim_reconcile_tick_interval: std::time::Duration::from_secs(60),
        pim_contacts_reconcile_interval: std::time::Duration::from_secs(300),
        pim_calendar_reconcile_interval: std::time::Duration::from_secs(300),
        pim_calendar_horizon_reconcile_interval: std::time::Duration::from_secs(300),
    }
}

async fn seed_runtime_auth(runtime: &mail_runtime::MailRuntimeHandle, session: &Session) {
    runtime
        .runtime_accounts()
        .set_auth_material(
            &AccountId(session.uid.clone()),
            Arc::new(runtime_auth_material_fixture(
                "test-passphrase",
                &session.email,
            )),
        )
        .await
        .expect("seed runtime auth material");
}

async fn login_and_select_inbox(
    imap_port: u16,
) -> (
    BufReader<tokio::net::tcp::OwnedReadHalf>,
    tokio::net::tcp::OwnedWriteHalf,
) {
    let stream = connect_with_retry(imap_port).await;
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);

    let greeting = read_line(&mut reader).await;
    assert!(greeting.contains("OK IMAP4rev1"), "{greeting}");

    write
        .write_all(b"a001 LOGIN runtime@proton.me bridge-password\r\n")
        .await
        .expect("write login");
    write.flush().await.expect("flush login");
    let login = read_until_tag(&mut reader, "a001 ").await;
    assert!(login.contains("a001 OK"), "{login}");

    write
        .write_all(b"a002 SELECT INBOX\r\n")
        .await
        .expect("write select");
    write.flush().await.expect("flush select");
    let select = read_until_tag(&mut reader, "a002 ").await;
    assert!(select.contains("1 EXISTS"), "{select}");
    assert!(select.contains("a002 OK"), "{select}");

    (reader, write)
}

async fn mount_runtime_event_mocks(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/core/v4/events/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000,
            "EventID": "event-0",
            "Refresh": 0,
            "Events": []
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/core/v4/events/event-0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000,
            "EventID": "event-0",
            "Refresh": 0,
            "Events": []
        })))
        .mount(server)
        .await;
}

#[test]
fn be028_persistent_json_store_paths_are_test_only() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let store_src = fs::read_to_string(root.join("src/imap/store.rs")).expect("read store.rs");

    assert!(
        is_cfg_test_guarded(&store_src, "pub struct PersistentStore"),
        "PersistentStore must be cfg(test)-guarded in src/imap/store.rs"
    );
    assert!(
        is_cfg_test_guarded(&store_src, "impl PersistentStore"),
        "PersistentStore impl must be cfg(test)-guarded in src/imap/store.rs"
    );
    assert!(
        is_cfg_test_guarded(&store_src, "impl MessageStore for PersistentStore"),
        "MessageStore impl for PersistentStore must be cfg(test)-guarded in src/imap/store.rs"
    );

    let main_src = fs::read_to_string(root.join("src/main.rs")).expect("read main.rs");
    let grpc_src =
        fs::read_to_string(root.join("src/frontend/grpc/mod.rs")).expect("read grpc/mod.rs");
    assert!(
        !main_src.contains("PersistentStore"),
        "main runtime path must not reference PersistentStore"
    );
    assert!(
        !grpc_src.contains("PersistentStore"),
        "grpc runtime path must not reference PersistentStore"
    );
}

#[tokio::test]
async fn be030_mail_runtime_supports_offline_login_with_gluon_defaults() {
    let temp = tempfile::tempdir().expect("tempdir");
    let runtime_paths = RuntimePaths::resolve(Some(temp.path())).expect("runtime paths");
    let session = runtime_test_session();
    vault::save_session(&session, runtime_paths.settings_dir()).expect("save session");
    vault::set_gluon_key_by_account_id(runtime_paths.settings_dir(), &session.uid, vec![7u8; 32])
        .expect("save gluon key");
    seed_runtime_gluon_store(&runtime_paths, &session);

    let imap_port = free_port().await;
    let smtp_port = free_port_excluding(&[imap_port]).await;
    let config = runtime_test_config(
        imap_port,
        smtp_port,
        "https://mail-api.proton.me".to_string(),
    );

    let session_manager = Arc::new(SessionManager::new(
        runtime_paths.settings_dir().to_path_buf(),
    ));
    session_manager
        .seed_session(session.clone())
        .await
        .expect("seed live runtime session");
    let runtime = mail_runtime::start(
        runtime_paths,
        session_manager,
        config,
        MailRuntimeTransition::Startup,
        None,
    )
    .await
    .expect("start mail runtime");
    seed_runtime_auth(&runtime, &session).await;

    let stream = connect_with_retry(imap_port).await;
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);

    let greeting = read_line(&mut reader).await;
    assert!(greeting.contains("OK IMAP4rev1"), "{greeting}");

    write
        .write_all(b"a001 LOGIN runtime@proton.me bridge-password\r\n")
        .await
        .expect("write login");
    write.flush().await.expect("flush login");

    let response = read_until_tag(&mut reader, "a001 ").await;
    assert!(response.contains("a001 OK"), "{response}");
    assert!(response.contains("LOGIN completed"), "{response}");

    write
        .write_all(b"a002 LIST \"\" \"*\"\r\n")
        .await
        .expect("write list");
    write.flush().await.expect("flush list");

    let list = read_until_tag(&mut reader, "a002 ").await;
    assert!(list.contains("* LIST"), "{list}");
    assert!(list.contains("INBOX"), "{list}");
    assert!(list.contains("a002 OK"), "{list}");

    write
        .write_all(b"a003 SELECT INBOX\r\n")
        .await
        .expect("write select");
    write.flush().await.expect("flush select");

    let select = read_until_tag(&mut reader, "a003 ").await;
    assert!(select.contains("1 EXISTS"), "{select}");
    assert!(select.contains("a003 OK"), "{select}");

    write
        .write_all(b"a004 FETCH 1 (BODY[])\r\n")
        .await
        .expect("write fetch");
    write.flush().await.expect("flush fetch");

    let fetch = read_until_tag(&mut reader, "a004 ").await;
    assert!(fetch.contains("BODY[]"), "{fetch}");
    assert!(fetch.contains("Runtime Subject"), "{fetch}");
    assert!(fetch.contains("runtime-body"), "{fetch}");
    assert!(fetch.contains("a004 OK FETCH completed"), "{fetch}");

    write
        .write_all(b"a005 SEARCH SUBJECT \"Runtime Subject\"\r\n")
        .await
        .expect("write search");
    write.flush().await.expect("flush search");

    let search = read_until_tag(&mut reader, "a005 ").await;
    assert!(search.contains("* SEARCH 1"), "{search}");
    assert!(search.contains("a005 OK SEARCH completed"), "{search}");

    runtime.stop().await.expect("stop runtime");
}

#[tokio::test]
async fn be030_mail_runtime_idle_emits_flag_fetch_with_gluon_defaults() {
    let temp = tempfile::tempdir().expect("tempdir");
    let runtime_paths = RuntimePaths::resolve(Some(temp.path())).expect("runtime paths");
    let session = runtime_test_session();
    vault::save_session(&session, runtime_paths.settings_dir()).expect("save session");
    vault::set_gluon_key_by_account_id(runtime_paths.settings_dir(), &session.uid, vec![7u8; 32])
        .expect("save gluon key");
    seed_runtime_gluon_store(&runtime_paths, &session);

    let imap_port = free_port().await;
    let smtp_port = free_port_excluding(&[imap_port]).await;
    let config = runtime_test_config(
        imap_port,
        smtp_port,
        "https://mail-api.proton.me".to_string(),
    );

    let session_manager = Arc::new(SessionManager::new(
        runtime_paths.settings_dir().to_path_buf(),
    ));
    session_manager
        .seed_session(session.clone())
        .await
        .expect("seed live runtime session");
    let runtime = mail_runtime::start(
        runtime_paths,
        session_manager,
        config,
        MailRuntimeTransition::Startup,
        None,
    )
    .await
    .expect("start mail runtime");
    seed_runtime_auth(&runtime, &session).await;

    let scoped_mailbox = format!("{}::INBOX", session.uid);
    let uid = runtime
        .imap_connector()
        .list_uids(&scoped_mailbox)
        .await
        .expect("list runtime uids")
        .into_iter()
        .next()
        .expect("seeded runtime uid");

    let stream = connect_with_retry(imap_port).await;
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);

    let greeting = read_line(&mut reader).await;
    assert!(greeting.contains("OK IMAP4rev1"), "{greeting}");

    write
        .write_all(b"a001 LOGIN runtime@proton.me bridge-password\r\n")
        .await
        .expect("write login");
    write.flush().await.expect("flush login");

    let login = read_until_tag(&mut reader, "a001 ").await;
    assert!(login.contains("a001 OK"), "{login}");

    write
        .write_all(b"a002 SELECT INBOX\r\n")
        .await
        .expect("write select");
    write.flush().await.expect("flush select");

    let select = read_until_tag(&mut reader, "a002 ").await;
    assert!(select.contains("1 EXISTS"), "{select}");
    assert!(select.contains("a002 OK"), "{select}");

    write.write_all(b"a003 IDLE\r\n").await.expect("write idle");
    write.flush().await.expect("flush idle");

    let continuation =
        read_chunk_with_timeout(&mut reader, std::time::Duration::from_secs(1)).await;
    assert!(continuation.contains("+ idling"), "{continuation}");

    runtime
        .imap_connector()
        .update_message_flags(
            &scoped_mailbox,
            uid,
            vec!["\\Seen".to_string(), "\\Flagged".to_string()],
        )
        .await
        .expect("update runtime flags");

    let update = read_chunk_with_timeout(&mut reader, std::time::Duration::from_secs(1)).await;
    assert!(update.contains("FETCH (FLAGS ("), "{update}");
    assert!(update.contains("\\Flagged"), "{update}");
    assert!(!update.contains("EXISTS"), "{update}");

    write.write_all(b"DONE\r\n").await.expect("write done");
    write.flush().await.expect("flush done");

    let done = read_until_tag(&mut reader, "a003 ").await;
    assert!(done.contains("a003 OK IDLE terminated"), "{done}");

    runtime.stop().await.expect("stop runtime");
}

#[tokio::test]
async fn be030_mail_runtime_store_syncs_upstream_with_gluon_defaults() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/unread"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/unlabel"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_runtime_event_mocks(&server).await;

    let temp = tempfile::tempdir().expect("tempdir");
    let runtime_paths = RuntimePaths::resolve(Some(temp.path())).expect("runtime paths");
    let session = runtime_test_session();
    vault::save_session(&session, runtime_paths.settings_dir()).expect("save session");
    vault::set_gluon_key_by_account_id(runtime_paths.settings_dir(), &session.uid, vec![7u8; 32])
        .expect("save gluon key");
    seed_runtime_gluon_store(&runtime_paths, &session);

    let imap_port = free_port().await;
    let smtp_port = free_port_excluding(&[imap_port]).await;
    let config = runtime_test_config(imap_port, smtp_port, server.uri());

    let session_manager = Arc::new(SessionManager::new(
        runtime_paths.settings_dir().to_path_buf(),
    ));
    session_manager
        .seed_session(session.clone())
        .await
        .expect("seed live runtime session");
    let runtime = mail_runtime::start(
        runtime_paths,
        session_manager,
        config,
        MailRuntimeTransition::Startup,
        None,
    )
    .await
    .expect("start mail runtime");
    seed_runtime_auth(&runtime, &session).await;

    let scoped_mailbox = format!("{}::INBOX", session.uid);
    let uid = runtime
        .imap_connector()
        .list_uids(&scoped_mailbox)
        .await
        .expect("list runtime uids")
        .into_iter()
        .next()
        .expect("seeded runtime uid");
    runtime
        .imap_connector()
        .update_message_flags(
            &scoped_mailbox,
            uid,
            vec!["\\Seen".to_string(), "\\Flagged".to_string()],
        )
        .await
        .expect("seed initial runtime flags");

    let (mut reader, mut write) = login_and_select_inbox(imap_port).await;

    write
        .write_all(b"a003 STORE 1 FLAGS ()\r\n")
        .await
        .expect("write store");
    write.flush().await.expect("flush store");
    let store = read_until_tag(&mut reader, "a003 ").await;
    assert!(store.contains("* 1 FETCH (FLAGS ())"), "{store}");
    assert!(store.contains("a003 OK STORE completed"), "{store}");

    server.verify().await;
    runtime.stop().await.expect("stop runtime");
}

#[tokio::test]
async fn be030_mail_runtime_copy_syncs_upstream_with_gluon_defaults() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/label"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_runtime_event_mocks(&server).await;

    let temp = tempfile::tempdir().expect("tempdir");
    let runtime_paths = RuntimePaths::resolve(Some(temp.path())).expect("runtime paths");
    let session = runtime_test_session();
    vault::save_session(&session, runtime_paths.settings_dir()).expect("save session");
    vault::set_gluon_key_by_account_id(runtime_paths.settings_dir(), &session.uid, vec![7u8; 32])
        .expect("save gluon key");
    seed_runtime_gluon_store(&runtime_paths, &session);

    let imap_port = free_port().await;
    let smtp_port = free_port_excluding(&[imap_port]).await;
    let config = runtime_test_config(imap_port, smtp_port, server.uri());

    let session_manager = Arc::new(SessionManager::new(
        runtime_paths.settings_dir().to_path_buf(),
    ));
    session_manager
        .seed_session(session.clone())
        .await
        .expect("seed live runtime session");
    let runtime = mail_runtime::start(
        runtime_paths,
        session_manager,
        config,
        MailRuntimeTransition::Startup,
        None,
    )
    .await
    .expect("start mail runtime");
    seed_runtime_auth(&runtime, &session).await;

    let scoped_inbox = format!("{}::INBOX", session.uid);
    let inbox_uid = runtime
        .imap_connector()
        .list_uids(&scoped_inbox)
        .await
        .expect("list runtime inbox uids")
        .into_iter()
        .next()
        .expect("seeded inbox uid");
    assert_eq!(inbox_uid, 1);

    let (mut reader, mut write) = login_and_select_inbox(imap_port).await;

    write
        .write_all(b"a003 COPY 1 Archive\r\n")
        .await
        .expect("write copy");
    write.flush().await.expect("flush copy");
    let copy = read_until_tag(&mut reader, "a003 ").await;
    assert!(copy.contains("[COPYUID"), "{copy}");
    assert!(copy.contains("COPY completed"), "{copy}");

    let scoped_archive = format!("{}::Archive", session.uid);
    assert_eq!(
        runtime
            .imap_connector()
            .list_uids(&scoped_inbox)
            .await
            .expect("list inbox after copy"),
        vec![1]
    );
    assert_eq!(
        runtime
            .imap_connector()
            .list_uids(&scoped_archive)
            .await
            .expect("list archive after copy"),
        vec![1]
    );
    let archive_literal = runtime
        .imap_connector()
        .get_message_literal(&scoped_archive, 1)
        .await
        .expect("archive literal result")
        .expect("archive literal");
    let archive_body = String::from_utf8_lossy(&archive_literal);
    assert!(archive_body.contains("Runtime Subject"), "{archive_body}");

    server.verify().await;
    runtime.stop().await.expect("stop runtime");
}

#[tokio::test]
async fn be030_mail_runtime_expunge_syncs_upstream_with_gluon_defaults() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/label"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_runtime_event_mocks(&server).await;

    let temp = tempfile::tempdir().expect("tempdir");
    let runtime_paths = RuntimePaths::resolve(Some(temp.path())).expect("runtime paths");
    let session = runtime_test_session();
    vault::save_session(&session, runtime_paths.settings_dir()).expect("save session");
    vault::set_gluon_key_by_account_id(runtime_paths.settings_dir(), &session.uid, vec![7u8; 32])
        .expect("save gluon key");
    seed_runtime_gluon_store(&runtime_paths, &session);

    let imap_port = free_port().await;
    let smtp_port = free_port_excluding(&[imap_port]).await;
    let config = runtime_test_config(imap_port, smtp_port, server.uri());

    let session_manager = Arc::new(SessionManager::new(
        runtime_paths.settings_dir().to_path_buf(),
    ));
    session_manager
        .seed_session(session.clone())
        .await
        .expect("seed live runtime session");
    let runtime = mail_runtime::start(
        runtime_paths,
        session_manager,
        config,
        MailRuntimeTransition::Startup,
        None,
    )
    .await
    .expect("start mail runtime");
    seed_runtime_auth(&runtime, &session).await;

    let scoped_inbox = format!("{}::INBOX", session.uid);
    let inbox_uid = runtime
        .imap_connector()
        .list_uids(&scoped_inbox)
        .await
        .expect("list runtime inbox uids")
        .into_iter()
        .next()
        .expect("seeded inbox uid");
    runtime
        .imap_connector()
        .update_message_flags(
            &scoped_inbox,
            inbox_uid,
            vec!["\\Seen".to_string(), "\\Deleted".to_string()],
        )
        .await
        .expect("mark message deleted");

    let (mut reader, mut write) = login_and_select_inbox(imap_port).await;

    write
        .write_all(b"a003 EXPUNGE\r\n")
        .await
        .expect("write expunge");
    write.flush().await.expect("flush expunge");
    let expunge = read_until_tag(&mut reader, "a003 ").await;
    assert!(expunge.contains("* 1 EXPUNGE"), "{expunge}");
    assert!(expunge.contains("a003 OK EXPUNGE completed"), "{expunge}");

    assert!(runtime
        .imap_connector()
        .list_uids(&scoped_inbox)
        .await
        .expect("list inbox after expunge")
        .is_empty());

    server.verify().await;
    runtime.stop().await.expect("stop runtime");
}

#[tokio::test]
async fn be030_mail_runtime_move_syncs_upstream_with_gluon_defaults() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/label"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/mail/v4/messages/unlabel"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_runtime_event_mocks(&server).await;

    let temp = tempfile::tempdir().expect("tempdir");
    let runtime_paths = RuntimePaths::resolve(Some(temp.path())).expect("runtime paths");
    let session = runtime_test_session();
    vault::save_session(&session, runtime_paths.settings_dir()).expect("save session");
    vault::set_gluon_key_by_account_id(runtime_paths.settings_dir(), &session.uid, vec![7u8; 32])
        .expect("save gluon key");
    seed_runtime_gluon_store(&runtime_paths, &session);

    let imap_port = free_port().await;
    let smtp_port = free_port_excluding(&[imap_port]).await;
    let config = runtime_test_config(imap_port, smtp_port, server.uri());

    let session_manager = Arc::new(SessionManager::new(
        runtime_paths.settings_dir().to_path_buf(),
    ));
    session_manager
        .seed_session(session.clone())
        .await
        .expect("seed live runtime session");
    let runtime = mail_runtime::start(
        runtime_paths,
        session_manager,
        config,
        MailRuntimeTransition::Startup,
        None,
    )
    .await
    .expect("start mail runtime");
    seed_runtime_auth(&runtime, &session).await;

    let scoped_inbox = format!("{}::INBOX", session.uid);
    let inbox_uid = runtime
        .imap_connector()
        .list_uids(&scoped_inbox)
        .await
        .expect("list runtime inbox uids")
        .into_iter()
        .next()
        .expect("seeded inbox uid");
    assert_eq!(inbox_uid, 1);

    let (mut reader, mut write) = login_and_select_inbox(imap_port).await;

    write
        .write_all(b"a003 MOVE 1 Archive\r\n")
        .await
        .expect("write move");
    write.flush().await.expect("flush move");
    let move_response = read_until_tag(&mut reader, "a003 ").await;
    assert!(move_response.contains("* 1 EXPUNGE"), "{move_response}");
    assert!(move_response.contains("MOVE completed"), "{move_response}");

    let scoped_archive = format!("{}::Archive", session.uid);
    assert!(runtime
        .imap_connector()
        .list_uids(&scoped_inbox)
        .await
        .expect("list inbox after move")
        .is_empty());
    assert_eq!(
        runtime
            .imap_connector()
            .list_uids(&scoped_archive)
            .await
            .expect("list archive after move"),
        vec![1]
    );
    let archive_literal = runtime
        .imap_connector()
        .get_message_literal(&scoped_archive, 1)
        .await
        .expect("archive literal result")
        .expect("archive literal");
    let archive_body = String::from_utf8_lossy(&archive_literal);
    assert!(archive_body.contains("Runtime Subject"), "{archive_body}");

    server.verify().await;
    runtime.stop().await.expect("stop runtime");
}

#[tokio::test]
async fn be030_mail_runtime_event_update_reaches_idle_with_gluon_defaults() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/core/v4/events/event-0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000,
            "EventID": "event-1",
            "More": 0,
            "Refresh": 0,
            "Events": [{"Messages": [{"ID": "msg-2", "Action": 1}]}]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/core/v4/events/event-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000,
            "EventID": "event-1",
            "More": 0,
            "Refresh": 0,
            "Events": []
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/mail/v4/messages/msg-2"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(runtime_event_message_json(
                "msg-2",
                &["0"],
                1,
            )),
        )
        .expect(1)
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().expect("tempdir");
    let runtime_paths = RuntimePaths::resolve(Some(temp.path())).expect("runtime paths");
    let session = runtime_test_session();
    vault::save_session(&session, runtime_paths.settings_dir()).expect("save session");
    vault::set_gluon_key_by_account_id(runtime_paths.settings_dir(), &session.uid, vec![7u8; 32])
        .expect("save gluon key");
    VaultCheckpointStore::new(runtime_paths.settings_dir().to_path_buf())
        .save_checkpoint(
            &AccountId(session.uid.clone()),
            &EventCheckpoint {
                last_event_id: "event-0".to_string(),
                last_event_ts: Some(1_700_000_000),
                sync_state: Some(CheckpointSyncState::Ok),
            },
        )
        .expect("save runtime checkpoint");
    seed_runtime_gluon_store(&runtime_paths, &session);

    let imap_port = free_port().await;
    let smtp_port = free_port_excluding(&[imap_port]).await;
    let mut config = runtime_test_config(imap_port, smtp_port, server.uri());
    config.event_poll_interval = std::time::Duration::from_millis(500);

    let session_manager = Arc::new(SessionManager::new(
        runtime_paths.settings_dir().to_path_buf(),
    ));
    session_manager
        .seed_session(session.clone())
        .await
        .expect("seed live runtime session");
    let runtime = mail_runtime::start(
        runtime_paths,
        session_manager,
        config,
        MailRuntimeTransition::Startup,
        None,
    )
    .await
    .expect("start mail runtime");
    seed_runtime_auth(&runtime, &session).await;

    let (mut reader, mut write) = login_and_select_inbox(imap_port).await;

    write.write_all(b"a003 IDLE\r\n").await.expect("write idle");
    write.flush().await.expect("flush idle");

    let continuation =
        read_chunk_with_timeout(&mut reader, std::time::Duration::from_secs(1)).await;
    assert!(continuation.contains("+ idling"), "{continuation}");

    let update = read_chunk_with_timeout(&mut reader, std::time::Duration::from_secs(4)).await;
    assert!(update.contains("2 EXISTS"), "{update}");

    let scoped_inbox = format!("{}::INBOX", session.uid);
    assert_eq!(
        runtime
            .imap_connector()
            .list_uids(&scoped_inbox)
            .await
            .expect("list inbox after event"),
        vec![1, 2]
    );

    write.write_all(b"DONE\r\n").await.expect("write done");
    write.flush().await.expect("flush done");
    let done = read_until_tag(&mut reader, "a003 ").await;
    assert!(done.contains("a003 OK IDLE terminated"), "{done}");

    server.verify().await;
    runtime.stop().await.expect("stop runtime");
}

#[tokio::test]
async fn be030_mail_runtime_event_delete_surfaces_via_noop_with_gluon_defaults() {
    let server = MockServer::start().await;
    let event_zero_polls = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/core/v4/events/event-0"))
        .respond_with({
            let event_zero_polls = event_zero_polls.clone();
            move |_req: &wiremock::Request| {
                let poll = event_zero_polls.fetch_add(1, Ordering::SeqCst);
                if poll == 0 {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "Code": 1000,
                        "EventID": "event-0",
                        "More": 0,
                        "Refresh": 0,
                        "Events": []
                    }))
                } else {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "Code": 1000,
                        "EventID": "event-1",
                        "More": 0,
                        "Refresh": 0,
                        "Events": [{"Messages": [{"ID": "runtime-msg-1", "Action": 0}]}]
                    }))
                }
            }
        })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/core/v4/events/event-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000,
            "EventID": "event-1",
            "More": 0,
            "Refresh": 0,
            "Events": []
        })))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().expect("tempdir");
    let runtime_paths = RuntimePaths::resolve(Some(temp.path())).expect("runtime paths");
    let session = runtime_test_session();
    vault::save_session(&session, runtime_paths.settings_dir()).expect("save session");
    vault::set_gluon_key_by_account_id(runtime_paths.settings_dir(), &session.uid, vec![7u8; 32])
        .expect("save gluon key");
    VaultCheckpointStore::new(runtime_paths.settings_dir().to_path_buf())
        .save_checkpoint(
            &AccountId(session.uid.clone()),
            &EventCheckpoint {
                last_event_id: "event-0".to_string(),
                last_event_ts: Some(1_700_000_000),
                sync_state: Some(CheckpointSyncState::Ok),
            },
        )
        .expect("save runtime checkpoint");
    seed_runtime_gluon_store(&runtime_paths, &session);

    let imap_port = free_port().await;
    let smtp_port = free_port_excluding(&[imap_port]).await;
    let mut config = runtime_test_config(imap_port, smtp_port, server.uri());
    config.event_poll_interval = std::time::Duration::from_millis(100);

    let session_manager = Arc::new(SessionManager::new(
        runtime_paths.settings_dir().to_path_buf(),
    ));
    session_manager
        .seed_session(session.clone())
        .await
        .expect("seed live runtime session");
    let runtime = mail_runtime::start(
        runtime_paths,
        session_manager,
        config,
        MailRuntimeTransition::Startup,
        None,
    )
    .await
    .expect("start mail runtime");
    seed_runtime_auth(&runtime, &session).await;

    let (mut reader, mut write) = login_and_select_inbox(imap_port).await;
    tokio::time::sleep(std::time::Duration::from_millis(350)).await;

    write.write_all(b"a003 NOOP\r\n").await.expect("write noop");
    write.flush().await.expect("flush noop");
    let noop = read_until_tag(&mut reader, "a003 ").await;
    assert!(noop.contains("* 1 EXPUNGE"), "{noop}");
    assert!(noop.contains("* 0 EXISTS"), "{noop}");
    assert!(noop.contains("a003 OK NOOP completed"), "{noop}");

    let scoped_inbox = format!("{}::INBOX", session.uid);
    assert!(runtime
        .imap_connector()
        .list_uids(&scoped_inbox)
        .await
        .expect("list inbox after delete event")
        .is_empty());

    server.verify().await;
    runtime.stop().await.expect("stop runtime");
}

#[tokio::test]
async fn be030_mail_runtime_refresh_resync_surfaces_via_noop_with_gluon_defaults() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/core/v4/events/event-0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000,
            "EventID": "event-1",
            "More": 0,
            "Refresh": 1,
            "Events": []
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/core/v4/events/event-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000,
            "EventID": "event-1",
            "More": 0,
            "Refresh": 0,
            "Events": []
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/mail/v4/messages"))
        .and(header("x-http-method-override", "GET"))
        .and(body_partial_json(serde_json::json!({
            "EndID": serde_json::Value::Null
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000,
            "Total": 1,
            "Messages": [runtime_metadata_json("msg-resync-2", &["0"], 1)]
        })))
        .expect(7)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/core/v4/addresses"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "Code": 1000,
            "Addresses": [{
                "ID": "addr-1",
                "Email": "runtime@proton.me",
                "Status": 1,
                "Receive": 1,
                "Send": 1,
                "Type": 1,
                "DisplayName": "Runtime Test",
                "Keys": []
            }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().expect("tempdir");
    let runtime_paths = RuntimePaths::resolve(Some(temp.path())).expect("runtime paths");
    let session = runtime_test_session();
    vault::save_session(&session, runtime_paths.settings_dir()).expect("save session");
    vault::set_gluon_key_by_account_id(runtime_paths.settings_dir(), &session.uid, vec![7u8; 32])
        .expect("save gluon key");
    VaultCheckpointStore::new(runtime_paths.settings_dir().to_path_buf())
        .save_checkpoint(
            &AccountId(session.uid.clone()),
            &EventCheckpoint {
                last_event_id: "event-0".to_string(),
                last_event_ts: Some(1_700_000_000),
                sync_state: Some(CheckpointSyncState::Ok),
            },
        )
        .expect("save runtime checkpoint");
    seed_runtime_gluon_store(&runtime_paths, &session);

    let imap_port = free_port().await;
    let smtp_port = free_port_excluding(&[imap_port]).await;
    let mut config = runtime_test_config(imap_port, smtp_port, server.uri());
    config.event_poll_interval = std::time::Duration::from_millis(100);

    let session_manager = Arc::new(SessionManager::new(
        runtime_paths.settings_dir().to_path_buf(),
    ));
    session_manager
        .seed_session(session.clone())
        .await
        .expect("seed live runtime session");
    let runtime = mail_runtime::start(
        runtime_paths,
        session_manager,
        config,
        MailRuntimeTransition::Startup,
        None,
    )
    .await
    .expect("start mail runtime");
    seed_runtime_auth(&runtime, &session).await;

    let (mut reader, mut write) = login_and_select_inbox(imap_port).await;
    tokio::time::sleep(std::time::Duration::from_millis(650)).await;

    write.write_all(b"a003 NOOP\r\n").await.expect("write noop");
    write.flush().await.expect("flush noop");
    let noop = read_until_tag(&mut reader, "a003 ").await;
    assert!(noop.contains("* 2 EXISTS"), "{noop}");
    assert!(noop.contains("a003 OK NOOP completed"), "{noop}");

    let scoped_inbox = format!("{}::INBOX", session.uid);
    assert_eq!(
        runtime
            .imap_connector()
            .list_uids(&scoped_inbox)
            .await
            .expect("list inbox after refresh resync"),
        vec![1, 2]
    );

    server.verify().await;
    runtime.stop().await.expect("stop runtime");
}
