use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use openproton_bridge::api::types::{ApiMode, Session};
use openproton_bridge::api::types::{EmailAddress, MessageMetadata};
use openproton_bridge::bridge::mail_runtime::{
    self, DavTlsMode, ImapMutationBackend, ImapReadBackend, MailRuntimeConfig,
    MailRuntimeTransition,
};
use openproton_bridge::bridge::session_manager::SessionManager;
use openproton_bridge::imap::store::new_runtime_message_store;
use openproton_bridge::paths::RuntimePaths;
use openproton_bridge::vault;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

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
async fn be030_mail_runtime_starts_imap_listener_with_gluon_defaults() {
    let temp = tempfile::tempdir().expect("tempdir");
    let runtime_paths = RuntimePaths::resolve(Some(temp.path())).expect("runtime paths");
    let session = runtime_test_session();
    vault::save_session(&session, runtime_paths.settings_dir()).expect("save session");
    vault::set_gluon_key_by_account_id(runtime_paths.settings_dir(), &session.uid, vec![7u8; 32])
        .expect("save gluon key");

    let imap_port = free_port().await;
    let smtp_port = free_port_excluding(&[imap_port]).await;
    let config = MailRuntimeConfig {
        bind_host: "127.0.0.1".to_string(),
        imap_port,
        smtp_port,
        dav_enable: false,
        dav_port: 8080,
        dav_tls_mode: DavTlsMode::None,
        disable_tls: false,
        use_ssl_for_imap: false,
        use_ssl_for_smtp: false,
        imap_read_backend: ImapReadBackend::GluonMailReadOnly,
        imap_mutation_backend: ImapMutationBackend::GluonMail,
        event_poll_interval: std::time::Duration::from_secs(30),
        pim_reconcile_tick_interval: std::time::Duration::from_secs(60),
        pim_contacts_reconcile_interval: std::time::Duration::from_secs(300),
        pim_calendar_reconcile_interval: std::time::Duration::from_secs(300),
        pim_calendar_horizon_reconcile_interval: std::time::Duration::from_secs(300),
    };

    let session_manager = Arc::new(SessionManager::new(
        runtime_paths.settings_dir().to_path_buf(),
    ));
    session_manager
        .seed_session(session)
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

    let stream = connect_with_retry(imap_port).await;
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);

    let greeting = read_line(&mut reader).await;
    assert!(greeting.contains("OK IMAP4rev1"), "{greeting}");

    write
        .write_all(b"a001 CAPABILITY\r\n")
        .await
        .expect("write capability");
    write.flush().await.expect("flush capability");

    let response = read_until_tag(&mut reader, "a001 ").await;
    assert!(response.contains("* CAPABILITY IMAP4rev1"), "{response}");
    assert!(response.contains("a001 OK"), "{response}");

    runtime.stop().await.expect("stop runtime");
}
