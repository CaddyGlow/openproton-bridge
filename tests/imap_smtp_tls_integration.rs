use std::sync::Arc;

use gluon_rs_mail::{
    AccountBootstrap, CacheLayout, CompatibilityTarget, CompatibleStore, GluonKey, StoreBootstrap,
};
use gluon_rs_mail::{AuthResult, ImapConnector, ImapResult, MailboxInfo, MetadataPage};
use openproton_bridge::api::types::{ApiMode, Session};
use openproton_bridge::bridge::accounts::{AccountRegistry, RuntimeAccountRegistry};
use openproton_bridge::bridge::auth_router::AuthRouter;
use openproton_bridge::imap::gluon_connector::GluonMailConnector;
use openproton_bridge::imap::gluon_mailbox_mutation::GluonMailMailboxMutation;
use openproton_bridge::imap::gluon_mailbox_view::GluonMailMailboxView;
use openproton_bridge::imap::mailbox_catalog::RuntimeMailboxCatalog;
use openproton_bridge::imap::server::{run_server_with_tls_config as run_imap_server, ImapServer};
use openproton_bridge::imap::session::SessionConfig;
use openproton_bridge::smtp::server::{run_server_with_tls_config as run_smtp_server, SmtpServer};
use openproton_bridge::smtp::session::SmtpSessionConfig;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

fn test_session() -> Session {
    Session {
        uid: "uid-parity".to_string(),
        access_token: "access-token".to_string(),
        refresh_token: "refresh-token".to_string(),
        email: "alice@proton.me".to_string(),
        display_name: "Alice".to_string(),
        api_mode: ApiMode::Bridge,
        key_passphrase: Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"test-passphrase",
        )),
        bridge_password: Some("testbridge1234ab".to_string()),
    }
}

struct StubConnector;

#[async_trait::async_trait]
impl ImapConnector for StubConnector {
    async fn authorize(&self, _u: &str, _p: &str) -> ImapResult<AuthResult> {
        Ok(AuthResult {
            account_id: "test-uid".into(),
            primary_email: "test@proton.me".into(),
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

fn test_imap_config() -> (Arc<SessionConfig>, TempDir) {
    let session = test_session();
    let accounts = AccountRegistry::from_single_session(session.clone());
    let runtime_accounts = Arc::new(RuntimeAccountRegistry::in_memory(vec![session]));

    let tempdir = tempfile::tempdir().expect("tempdir");
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

    let config = Arc::new(SessionConfig {
        api_base_url: "https://mail-api.proton.me".to_string(),
        auth_router: AuthRouter::new(accounts),
        runtime_accounts: runtime_accounts.clone(),
        connector: Arc::new(StubConnector),
        gluon_connector: GluonMailConnector::new(gluon_store.clone()),
        mailbox_catalog: RuntimeMailboxCatalog::new(runtime_accounts),
        mailbox_mutation: GluonMailMailboxMutation::new(gluon_store.clone()),
        mailbox_view: GluonMailMailboxView::new(gluon_store),
    });
    (config, tempdir)
}

fn test_smtp_config() -> Arc<SmtpSessionConfig> {
    let session = test_session();
    let accounts = AccountRegistry::from_single_session(session.clone());
    Arc::new(SmtpSessionConfig {
        api_base_url: "https://mail-api.proton.me".to_string(),
        auth_router: AuthRouter::new(accounts),
        runtime_accounts: Arc::new(RuntimeAccountRegistry::in_memory(vec![session])),
    })
}

async fn find_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn read_line(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    line
}

async fn read_until_prefix(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    terminal_prefix: &str,
) -> String {
    let mut response = String::new();
    loop {
        let line = read_line(reader).await;
        if line.is_empty() {
            break;
        }
        response.push_str(&line);
        if line.starts_with(terminal_prefix) {
            break;
        }
    }
    response
}

fn tls_connector_from_cert(cert_pem: &[u8]) -> TlsConnector {
    let mut cert_reader = cert_pem;
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .expect("parse cert pem");

    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert).expect("add root cert");
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    TlsConnector::from(Arc::new(tls_config))
}

#[tokio::test]
async fn imap_starttls_upgrade_and_capability_reflects_tls_state() {
    let tmp = tempfile::tempdir().unwrap();
    let cert_dir = tmp.path().join("imap-tls");
    let server = ImapServer::new().with_tls(&cert_dir).unwrap();
    let tls_config = server.tls_config();
    let cert_pem = std::fs::read(cert_dir.join("cert.pem")).unwrap();

    let port = find_available_port().await;
    let addr = format!("127.0.0.1:{port}");
    let (config, _gluon_dir) = test_imap_config();
    let addr_clone = addr.clone();
    let server_handle = tokio::spawn(async move {
        let _ = run_imap_server(&addr_clone, config, tls_config).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let stream = TcpStream::connect(&addr).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);

    let greeting = read_line(&mut reader).await;
    assert!(greeting.contains("IMAP4rev1"));

    write.write_all(b"a001 CAPABILITY\r\n").await.unwrap();
    write.flush().await.unwrap();
    let pre_tls_capability = read_until_prefix(&mut reader, "a001 ").await;
    assert!(pre_tls_capability.contains("STARTTLS"));
    assert!(pre_tls_capability.contains("UIDPLUS"));

    write.write_all(b"a002 STARTTLS\r\n").await.unwrap();
    write.flush().await.unwrap();
    let starttls_ok = read_line(&mut reader).await;
    assert!(starttls_ok.starts_with("a002 OK"), "{starttls_ok}");

    let read = reader.into_inner();
    let stream = write.reunite(read).unwrap();

    let connector = tls_connector_from_cert(&cert_pem);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, stream).await.unwrap();
    let (tls_read, mut tls_write) = tokio::io::split(tls_stream);
    let mut tls_reader = BufReader::new(tls_read);

    tls_write.write_all(b"a003 CAPABILITY\r\n").await.unwrap();
    tls_write.flush().await.unwrap();

    let mut post_tls = String::new();
    loop {
        let mut line = String::new();
        tls_reader.read_line(&mut line).await.unwrap();
        if line.is_empty() {
            break;
        }
        post_tls.push_str(&line);
        if line.starts_with("a003 ") {
            break;
        }
    }

    assert!(!post_tls.contains("STARTTLS"), "{post_tls}");
    assert!(
        !post_tls.contains("openproton-bridge ready"),
        "unexpected post-STARTTLS greeting: {post_tls}"
    );

    server_handle.abort();
}

#[tokio::test]
async fn smtp_starttls_upgrade_and_auth_login_behavior() {
    let tmp = tempfile::tempdir().unwrap();
    let cert_dir = tmp.path().join("smtp-tls");
    let server = SmtpServer::new().with_tls(&cert_dir).unwrap();
    let tls_config = server.tls_config();
    let cert_pem = std::fs::read(cert_dir.join("cert.pem")).unwrap();

    let port = find_available_port().await;
    let addr = format!("127.0.0.1:{port}");
    let config = test_smtp_config();
    let addr_clone = addr.clone();
    let server_handle = tokio::spawn(async move {
        let _ = run_smtp_server(&addr_clone, config, tls_config).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let stream = TcpStream::connect(&addr).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);

    let greeting = read_line(&mut reader).await;
    assert!(greeting.starts_with("220"));

    write.write_all(b"EHLO localhost\r\n").await.unwrap();
    write.flush().await.unwrap();
    let pre_tls_ehlo = read_until_prefix(&mut reader, "250 ").await;
    assert!(pre_tls_ehlo.contains("STARTTLS"), "{pre_tls_ehlo}");
    assert!(pre_tls_ehlo.contains("AUTH PLAIN LOGIN"), "{pre_tls_ehlo}");

    write.write_all(b"STARTTLS\r\n").await.unwrap();
    write.flush().await.unwrap();
    let starttls_ready = read_line(&mut reader).await;
    assert!(starttls_ready.starts_with("220"), "{starttls_ready}");

    let read = reader.into_inner();
    let stream = write.reunite(read).unwrap();

    let connector = tls_connector_from_cert(&cert_pem);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, stream).await.unwrap();
    let (tls_read, mut tls_write) = tokio::io::split(tls_stream);
    let mut tls_reader = BufReader::new(tls_read);

    tls_write.write_all(b"EHLO localhost\r\n").await.unwrap();
    tls_write.flush().await.unwrap();
    let mut post_tls_ehlo = String::new();
    loop {
        let mut line = String::new();
        tls_reader.read_line(&mut line).await.unwrap();
        if line.is_empty() {
            break;
        }
        post_tls_ehlo.push_str(&line);
        if line.starts_with("250 ") {
            break;
        }
    }

    assert!(!post_tls_ehlo.contains("STARTTLS"), "{post_tls_ehlo}");
    assert!(
        post_tls_ehlo.contains("AUTH PLAIN LOGIN"),
        "{post_tls_ehlo}"
    );

    // AUTH LOGIN interactive flow with wrong password should fail at credential check.
    tls_write.write_all(b"AUTH LOGIN\r\n").await.unwrap();
    tls_write.flush().await.unwrap();
    let username_prompt = {
        let mut line = String::new();
        tls_reader.read_line(&mut line).await.unwrap();
        line
    };
    assert!(username_prompt.starts_with("334"), "{username_prompt}");

    let username = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"alice@proton.me",
    );
    tls_write
        .write_all(format!("{username}\r\n").as_bytes())
        .await
        .unwrap();
    tls_write.flush().await.unwrap();

    let password_prompt = {
        let mut line = String::new();
        tls_reader.read_line(&mut line).await.unwrap();
        line
    };
    assert!(password_prompt.starts_with("334"), "{password_prompt}");

    let wrong_password = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"wrong-password",
    );
    tls_write
        .write_all(format!("{wrong_password}\r\n").as_bytes())
        .await
        .unwrap();
    tls_write.flush().await.unwrap();

    let auth_result = {
        let mut line = String::new();
        tls_reader.read_line(&mut line).await.unwrap();
        line
    };
    assert!(auth_result.starts_with("535"), "{auth_result}");

    // AUTH LOGIN with initial username should request only password and then fail.
    tls_write
        .write_all(format!("AUTH LOGIN {username}\r\n").as_bytes())
        .await
        .unwrap();
    tls_write.flush().await.unwrap();
    let password_prompt_with_initial = {
        let mut line = String::new();
        tls_reader.read_line(&mut line).await.unwrap();
        line
    };
    assert!(
        password_prompt_with_initial.starts_with("334"),
        "{password_prompt_with_initial}"
    );

    tls_write
        .write_all(format!("{wrong_password}\r\n").as_bytes())
        .await
        .unwrap();
    tls_write.flush().await.unwrap();
    let auth_result_with_initial = {
        let mut line = String::new();
        tls_reader.read_line(&mut line).await.unwrap();
        line
    };
    assert!(
        auth_result_with_initial.starts_with("535"),
        "{auth_result_with_initial}"
    );

    server_handle.abort();
}

#[tokio::test]
async fn capabilities_without_tls_do_not_advertise_starttls() {
    let imap_port = find_available_port().await;
    let smtp_port = find_available_port().await;

    let imap_addr = format!("127.0.0.1:{imap_port}");
    let smtp_addr = format!("127.0.0.1:{smtp_port}");

    let imap_handle = {
        let (config, _gluon_dir) = test_imap_config();
        let addr = imap_addr.clone();
        tokio::spawn(async move {
            let _ = run_imap_server(&addr, config, None).await;
        })
    };

    let smtp_handle = {
        let config = test_smtp_config();
        let addr = smtp_addr.clone();
        tokio::spawn(async move {
            let _ = run_smtp_server(&addr, config, None).await;
        })
    };

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // IMAP capability should not advertise STARTTLS when TLS is disabled.
    let imap_stream = TcpStream::connect(&imap_addr).await.unwrap();
    let (imap_read, mut imap_write) = imap_stream.into_split();
    let mut imap_reader = BufReader::new(imap_read);
    let _ = read_line(&mut imap_reader).await;
    imap_write.write_all(b"a001 CAPABILITY\r\n").await.unwrap();
    imap_write.flush().await.unwrap();
    let imap_capability = read_until_prefix(&mut imap_reader, "a001 ").await;
    assert!(!imap_capability.contains("STARTTLS"), "{imap_capability}");
    assert!(imap_capability.contains("UIDPLUS"), "{imap_capability}");

    // SMTP EHLO should not advertise STARTTLS but still advertise AUTH methods.
    let smtp_stream = TcpStream::connect(&smtp_addr).await.unwrap();
    let (smtp_read, mut smtp_write) = smtp_stream.into_split();
    let mut smtp_reader = BufReader::new(smtp_read);
    let _ = read_line(&mut smtp_reader).await;
    smtp_write.write_all(b"EHLO localhost\r\n").await.unwrap();
    smtp_write.flush().await.unwrap();
    let smtp_ehlo = read_until_prefix(&mut smtp_reader, "250 ").await;
    assert!(!smtp_ehlo.contains("STARTTLS"), "{smtp_ehlo}");
    assert!(smtp_ehlo.contains("AUTH PLAIN LOGIN"), "{smtp_ehlo}");

    imap_handle.abort();
    smtp_handle.abort();
}
