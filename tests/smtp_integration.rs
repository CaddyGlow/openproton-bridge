use std::sync::Arc;

use openproton_bridge::api::types::Session;
use openproton_bridge::smtp::server::run_server;
use openproton_bridge::smtp::session::SmtpSessionConfig;

use tokio::net::TcpListener;
fn test_session() -> Session {
    Session {
        uid: "test-uid".to_string(),
        access_token: "test-token".to_string(),
        refresh_token: "test-refresh".to_string(),
        email: "alice@proton.me".to_string(),
        display_name: "Alice".to_string(),
        key_passphrase: Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"test-passphrase",
        )),
        bridge_password: Some("testbridge1234ab".to_string()),
    }
}

/// Find an available port for testing.
async fn find_available_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[tokio::test]
async fn test_smtp_connect_ehlo_quit() {
    let port = find_available_port().await;
    let addr = format!("127.0.0.1:{}", port);

    let config = Arc::new(SmtpSessionConfig {
        session: test_session(),
        bridge_password: "testbridge1234ab".to_string(),
    });

    // Start server in background
    let addr_clone = addr.clone();
    let server_handle = tokio::spawn(async move {
        let _ = run_server(&addr_clone, config).await;
    });

    // Give server time to bind
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Connect with raw TCP and test EHLO/QUIT
    let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (read, mut write) = stream.split();
    let mut reader = BufReader::new(read);

    // Read greeting
    let mut greeting = String::new();
    reader.read_line(&mut greeting).await.unwrap();
    assert!(greeting.starts_with("220"), "greeting: {}", greeting);

    // Send EHLO
    write.write_all(b"EHLO localhost\r\n").await.unwrap();
    write.flush().await.unwrap();

    // Read EHLO response (multiline)
    let mut ehlo_response = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        ehlo_response.push_str(&line);
        if line.starts_with("250 ") {
            break;
        }
    }
    assert!(
        ehlo_response.contains("AUTH PLAIN"),
        "ehlo: {}",
        ehlo_response
    );

    // Send QUIT
    write.write_all(b"QUIT\r\n").await.unwrap();
    write.flush().await.unwrap();

    let mut quit_resp = String::new();
    reader.read_line(&mut quit_resp).await.unwrap();
    assert!(quit_resp.starts_with("221"), "quit: {}", quit_resp);

    server_handle.abort();
}

#[tokio::test]
async fn test_smtp_auth_failure() {
    let port = find_available_port().await;
    let addr = format!("127.0.0.1:{}", port);

    let config = Arc::new(SmtpSessionConfig {
        session: test_session(),
        bridge_password: "testbridge1234ab".to_string(),
    });

    let addr_clone = addr.clone();
    let server_handle = tokio::spawn(async move {
        let _ = run_server(&addr_clone, config).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (read, mut write) = stream.split();
    let mut reader = BufReader::new(read);

    // Read greeting
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();

    // EHLO
    write.write_all(b"EHLO localhost\r\n").await.unwrap();
    write.flush().await.unwrap();
    loop {
        let mut l = String::new();
        reader.read_line(&mut l).await.unwrap();
        if l.starts_with("250 ") {
            break;
        }
    }

    // AUTH with wrong password
    let bad_auth = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"\0alice@proton.me\0wrongpassword",
    );
    write
        .write_all(format!("AUTH PLAIN {}\r\n", bad_auth).as_bytes())
        .await
        .unwrap();
    write.flush().await.unwrap();

    let mut auth_resp = String::new();
    reader.read_line(&mut auth_resp).await.unwrap();
    assert!(
        auth_resp.starts_with("535"),
        "auth should fail: {}",
        auth_resp
    );

    write.write_all(b"QUIT\r\n").await.unwrap();
    write.flush().await.unwrap();

    server_handle.abort();
}
