use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::bridge::auth_router::AuthRouter;
use crate::pim::store::PimStore;

use super::auth::{resolve_basic_auth, DavAuthError};
use super::caldav;
use super::carddav;
use super::discovery;
use super::error::{DavError, Result};
use super::http::{
    not_implemented_response, parse_request_head, split_head_from_buffer, DavRequest, DavResponse,
};
use super::propfind;
use super::report;

#[derive(Clone)]
pub struct DavServerConfig {
    pub auth_router: AuthRouter,
    pub pim_stores: HashMap<String, Arc<PimStore>>,
}

impl Default for DavServerConfig {
    fn default() -> Self {
        Self {
            auth_router: AuthRouter::default(),
            pim_stores: HashMap::new(),
        }
    }
}

pub struct DavServer {
    listener: TcpListener,
    config: Arc<DavServerConfig>,
}

impl DavServer {
    pub fn from_listener(listener: TcpListener, config: DavServerConfig) -> Self {
        Self {
            listener,
            config: Arc::new(config),
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub fn spawn(self) -> DavServerHandle {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let join = tokio::spawn(self.run(shutdown_rx));
        DavServerHandle {
            shutdown_tx: Some(shutdown_tx),
            join,
        }
    }

    pub async fn run(self, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                accepted = self.listener.accept() => {
                    let (stream, _addr) = accepted?;
                    spawn_connection_handler(stream, self.config.clone());
                }
            }
        }

        Ok(())
    }
}

pub struct DavServerHandle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: JoinHandle<Result<()>>,
}

impl DavServerHandle {
    pub async fn stop(mut self) -> Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        self.wait().await
    }

    pub async fn wait(self) -> Result<()> {
        match self.join.await {
            Ok(result) => result,
            Err(err) => Err(DavError::Io(std::io::Error::other(format!(
                "dav task join error: {err}"
            )))),
        }
    }
}

pub async fn run_server(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    run_server_with_listener(listener).await
}

pub async fn run_server_with_listener(listener: TcpListener) -> Result<()> {
    run_server_with_listener_and_config(listener, DavServerConfig::default()).await
}

pub async fn run_server_with_listener_and_config(
    listener: TcpListener,
    config: DavServerConfig,
) -> Result<()> {
    let listener_addr = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    tracing::info!(addr = %listener_addr, "DAV placeholder server listening");
    let config = Arc::new(config);

    loop {
        let (stream, _addr) = listener.accept().await?;
        spawn_connection_handler(stream, config.clone());
    }
}

fn spawn_connection_handler(stream: TcpStream, config: Arc<DavServerConfig>) {
    tokio::spawn(async move {
        if let Err(err) = handle_connection(stream, config).await {
            tracing::warn!(error = %err, "dav placeholder request failed");
        }
    });
}

pub async fn handle_connection(mut stream: TcpStream, config: Arc<DavServerConfig>) -> Result<()> {
    let mut buffer = vec![0_u8; 4096];
    let mut received = Vec::with_capacity(4096);

    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            return Err(DavError::InvalidRequest(
                "client disconnected before request",
            ));
        }

        received.extend_from_slice(&buffer[..n]);
        match split_head_from_buffer(&received) {
            Ok(head_end) => {
                let request = parse_request_head(&received[..head_end])?;
                let content_length = request
                    .headers
                    .get("content-length")
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                if received.len() < head_end + content_length {
                    continue;
                }
                let body = &received[head_end..head_end + content_length];
                let response = route_request(&request, body, &config)?;
                let wire = response.to_bytes();
                stream.write_all(&wire).await?;
                stream.flush().await?;
                return Ok(());
            }
            Err(DavError::InvalidRequest("incomplete headers")) => continue,
            Err(err) => {
                let status = err.status_line();
                let wire =
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                stream.write_all(wire.as_bytes()).await?;
                stream.flush().await?;
                return Err(err);
            }
        }
    }
}

fn route_request(
    request: &DavRequest,
    body: &[u8],
    config: &DavServerConfig,
) -> Result<DavResponse> {
    let method = request.method.to_ascii_uppercase();
    let path_without_query = request
        .path
        .split('?')
        .next()
        .unwrap_or(request.path.as_str());

    if let Some(response) = discovery::discovery_redirect(path_without_query) {
        return Ok(response);
    }

    match method.as_str() {
        "OPTIONS" => Ok(options_response()),
        "PROPFIND" | "REPORT" | "GET" | "HEAD" | "PUT" | "DELETE" | "MKCALENDAR" => {
            if !path_without_query.starts_with("/dav") {
                return Ok(not_found_response());
            }
            let auth = match resolve_basic_auth(&request.headers, &config.auth_router) {
                Ok(auth) => auth,
                Err(DavAuthError::MissingAuthorization)
                | Err(DavAuthError::InvalidAuthorization)
                | Err(DavAuthError::InvalidCredentials) => return Ok(unauthorized_response()),
            };

            if method == "PROPFIND" {
                return propfind::handle_propfind(&request.path, &request.headers, &auth);
            }

            let Some(store) = config.pim_stores.get(&auth.account_id.0) else {
                return Ok(service_unavailable_response());
            };
            if method == "REPORT" {
                if let Some(response) = report::handle_report(&request.path, body, &auth, store)? {
                    return Ok(response);
                }
                return Ok(not_found_response());
            }
            if let Some(response) = carddav::handle_request(
                &method,
                &request.path,
                &request.headers,
                body,
                &auth,
                store,
            )? {
                return Ok(response);
            }
            if let Some(response) = caldav::handle_request(
                &method,
                &request.path,
                &request.headers,
                body,
                &auth,
                store,
            )? {
                return Ok(response);
            }

            Ok(not_found_response())
        }
        _ => Ok(not_implemented_response()),
    }
}

fn options_response() -> DavResponse {
    DavResponse {
        status: "200 OK",
        headers: vec![
            ("DAV", "1, 2, calendar-access, addressbook".to_string()),
            (
                "Allow",
                "OPTIONS, PROPFIND, REPORT, MKCALENDAR, GET, HEAD, PUT, DELETE".to_string(),
            ),
            ("Content-Type", "text/plain; charset=utf-8".to_string()),
        ],
        body: b"OpenProton DAV\n".to_vec(),
    }
}

fn unauthorized_response() -> DavResponse {
    DavResponse {
        status: "401 Unauthorized",
        headers: vec![
            (
                "WWW-Authenticate",
                "Basic realm=\"openproton-bridge\"".to_string(),
            ),
            ("Content-Type", "text/plain; charset=utf-8".to_string()),
        ],
        body: b"authentication required\n".to_vec(),
    }
}

fn not_found_response() -> DavResponse {
    DavResponse {
        status: "404 Not Found",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"not found\n".to_vec(),
    }
}

fn service_unavailable_response() -> DavResponse {
    DavResponse {
        status: "503 Service Unavailable",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"account store unavailable\n".to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use crate::api::types::Session;
    use crate::bridge::accounts::AccountRegistry;
    use crate::bridge::auth_router::AuthRouter;
    use crate::pim::store::PimStore;

    use super::{handle_connection, route_request, DavServer, DavServerConfig, Result};
    use crate::dav::http::parse_request_head;

    fn auth_router() -> AuthRouter {
        let session = Session {
            uid: "uid-1".to_string(),
            access_token: String::new(),
            refresh_token: "refresh-token".to_string(),
            email: "alice@proton.me".to_string(),
            display_name: "Alice".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: Some("secret".to_string()),
        };
        AuthRouter::new(AccountRegistry::from_single_session(session))
    }

    #[tokio::test]
    async fn unknown_methods_still_return_501() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let server = DavServer::from_listener(
            listener,
            DavServerConfig {
                auth_router: auth_router(),
                pim_stores: HashMap::new(),
            },
        );
        let addr = server.local_addr()?;
        let handle = server.spawn();

        let mut client = tokio::net::TcpStream::connect(addr).await?;
        client
            .write_all(b"PATCH /dav/anything HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;

        let mut response = vec![0_u8; 512];
        let n = client.read(&mut response).await?;
        let wire = String::from_utf8_lossy(&response[..n]);

        assert!(wire.starts_with("HTTP/1.1 501 Not Implemented\r\n"));
        assert!(wire.contains("DAV: 1, 2, calendar-access, addressbook\r\n"));

        handle.stop().await?;
        Ok(())
    }

    #[test]
    fn propfind_without_auth_returns_401() {
        let request = parse_request_head(
            b"PROPFIND /dav/principals/me/ HTTP/1.1\r\nHost: localhost\r\nDepth: 0\r\n\r\n",
        )
        .expect("request should parse");
        let response = route_request(
            &request,
            &[],
            &DavServerConfig {
                auth_router: auth_router(),
                pim_stores: HashMap::new(),
            },
        )
        .expect("router should succeed");
        assert_eq!(response.status, "401 Unauthorized");
    }

    #[tokio::test]
    async fn propfind_with_auth_returns_multistatus() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = Arc::new(DavServerConfig {
            auth_router: auth_router(),
            pim_stores: HashMap::new(),
        });
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_connection(stream, config)
                .await
                .expect("handle request");
        });

        let mut client = tokio::net::TcpStream::connect(addr).await?;
        let authorization = BASE64_STANDARD.encode("alice@proton.me:secret");
        let request = format!(
            "PROPFIND /dav/principals/me/ HTTP/1.1\r\nHost: localhost\r\nDepth: 0\r\nAuthorization: Basic {authorization}\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await?;

        let mut response = vec![0_u8; 2048];
        let n = client.read(&mut response).await?;
        let wire = String::from_utf8_lossy(&response[..n]);
        assert!(wire.starts_with("HTTP/1.1 207 Multi-Status\r\n"));
        assert!(wire.contains("<d:multistatus"));

        server.await.expect("server task");
        Ok(())
    }

    #[tokio::test]
    async fn carddav_put_get_delete_roundtrip() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let store = Arc::new(PimStore::new(tmp.path().join("account.db")).expect("store"));
        let mut pim_stores = HashMap::new();
        pim_stores.insert("uid-1".to_string(), store);

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = Arc::new(DavServerConfig {
            auth_router: auth_router(),
            pim_stores,
        });

        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (stream, _) = listener.accept().await.expect("accept");
                handle_connection(stream, config.clone())
                    .await
                    .expect("handle");
            }
        });

        let auth = BASE64_STANDARD.encode("alice@proton.me:secret");
        let body = "BEGIN:VCARD\nVERSION:3.0\nUID:c1\nFN:Alice\nEMAIL:alice@proton.me\nEND:VCARD\n";
        let put = format!(
            "PUT /dav/uid-1/addressbooks/default/c1.vcf HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let mut client = tokio::net::TcpStream::connect(addr).await?;
        client.write_all(put.as_bytes()).await?;
        let mut response = vec![0; 1024];
        let n = client.read(&mut response).await?;
        assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 201 Created\r\n"));

        let get = format!(
            "GET /dav/uid-1/addressbooks/default/c1.vcf HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\n\r\n"
        );
        let mut client = tokio::net::TcpStream::connect(addr).await?;
        client.write_all(get.as_bytes()).await?;
        let mut response = vec![0; 2048];
        let n = client.read(&mut response).await?;
        let wire = String::from_utf8_lossy(&response[..n]);
        assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(wire.contains("BEGIN:VCARD"));

        let delete = format!(
            "DELETE /dav/uid-1/addressbooks/default/c1.vcf HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\n\r\n"
        );
        let mut client = tokio::net::TcpStream::connect(addr).await?;
        client.write_all(delete.as_bytes()).await?;
        let mut response = vec![0; 512];
        let n = client.read(&mut response).await?;
        assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 204 No Content\r\n"));

        server.await.expect("server");
        Ok(())
    }

    #[tokio::test]
    async fn caldav_put_get_delete_roundtrip() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let store = Arc::new(PimStore::new(tmp.path().join("account.db")).expect("store"));
        let mut pim_stores = HashMap::new();
        pim_stores.insert("uid-1".to_string(), store);

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = Arc::new(DavServerConfig {
            auth_router: auth_router(),
            pim_stores,
        });

        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (stream, _) = listener.accept().await.expect("accept");
                handle_connection(stream, config.clone())
                    .await
                    .expect("handle");
            }
        });

        let auth = BASE64_STANDARD.encode("alice@proton.me:secret");
        let body = "BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\nUID:event-1\nDTSTART:20260305T120000Z\nDTEND:20260305T130000Z\nSUMMARY:Test\nEND:VEVENT\nEND:VCALENDAR\n";
        let put = format!(
            "PUT /dav/uid-1/calendars/default/e1.ics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let mut client = tokio::net::TcpStream::connect(addr).await?;
        client.write_all(put.as_bytes()).await?;
        let mut response = vec![0; 1024];
        let n = client.read(&mut response).await?;
        assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 201 Created\r\n"));

        let get = format!(
            "GET /dav/uid-1/calendars/default/e1.ics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\n\r\n"
        );
        let mut client = tokio::net::TcpStream::connect(addr).await?;
        client.write_all(get.as_bytes()).await?;
        let mut response = vec![0; 2048];
        let n = client.read(&mut response).await?;
        let wire = String::from_utf8_lossy(&response[..n]);
        assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(wire.contains("BEGIN:VCALENDAR"));

        let delete = format!(
            "DELETE /dav/uid-1/calendars/default/e1.ics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\n\r\n"
        );
        let mut client = tokio::net::TcpStream::connect(addr).await?;
        client.write_all(delete.as_bytes()).await?;
        let mut response = vec![0; 512];
        let n = client.read(&mut response).await?;
        assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 204 No Content\r\n"));

        server.await.expect("server");
        Ok(())
    }

    #[tokio::test]
    async fn report_addressbook_query_lists_contacts() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let store = Arc::new(PimStore::new(tmp.path().join("account.db")).expect("store"));
        let mut pim_stores = HashMap::new();
        pim_stores.insert("uid-1".to_string(), store);

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = Arc::new(DavServerConfig {
            auth_router: auth_router(),
            pim_stores,
        });

        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept");
                handle_connection(stream, config.clone())
                    .await
                    .expect("handle");
            }
        });

        let auth = BASE64_STANDARD.encode("alice@proton.me:secret");
        let card = "BEGIN:VCARD\nVERSION:3.0\nUID:c1\nFN:Alice\nEMAIL:alice@proton.me\nEND:VCARD\n";
        let put = format!(
            "PUT /dav/uid-1/addressbooks/default/c1.vcf HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\nContent-Length: {}\r\n\r\n{}",
            card.len(),
            card
        );
        let mut client = tokio::net::TcpStream::connect(addr).await?;
        client.write_all(put.as_bytes()).await?;
        let mut response = vec![0; 1024];
        let _ = client.read(&mut response).await?;

        let report_body =
            r#"<card:addressbook-query xmlns:card="urn:ietf:params:xml:ns:carddav"/>"#;
        let report = format!(
            "REPORT /dav/uid-1/addressbooks/default/ HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\nContent-Length: {}\r\n\r\n{}",
            report_body.len(),
            report_body
        );
        let mut client = tokio::net::TcpStream::connect(addr).await?;
        client.write_all(report.as_bytes()).await?;
        let mut response = vec![0; 4096];
        let n = client.read(&mut response).await?;
        let wire = String::from_utf8_lossy(&response[..n]);
        assert!(wire.starts_with("HTTP/1.1 207 Multi-Status\r\n"));
        assert!(wire.contains("/dav/uid-1/addressbooks/default/c1.vcf"));

        server.await.expect("server");
        Ok(())
    }

    #[tokio::test]
    async fn mkcalendar_creates_named_calendar_collection() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let store = Arc::new(PimStore::new(tmp.path().join("account.db")).expect("store"));
        let mut pim_stores = HashMap::new();
        pim_stores.insert("uid-1".to_string(), store);

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = Arc::new(DavServerConfig {
            auth_router: auth_router(),
            pim_stores,
        });

        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.expect("accept");
                handle_connection(stream, config.clone())
                    .await
                    .expect("handle");
            }
        });

        let auth = BASE64_STANDARD.encode("alice@proton.me:secret");
        let mkcalendar = format!(
            "MKCALENDAR /dav/uid-1/calendars/work/ HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\n\r\n"
        );
        let mut client = tokio::net::TcpStream::connect(addr).await?;
        client.write_all(mkcalendar.as_bytes()).await?;
        let mut response = vec![0; 1024];
        let n = client.read(&mut response).await?;
        assert!(String::from_utf8_lossy(&response[..n]).starts_with("HTTP/1.1 201 Created\r\n"));

        let get = format!(
            "GET /dav/uid-1/calendars/work/ HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\n\r\n"
        );
        let mut client = tokio::net::TcpStream::connect(addr).await?;
        client.write_all(get.as_bytes()).await?;
        let mut response = vec![0; 1024];
        let n = client.read(&mut response).await?;
        let wire = String::from_utf8_lossy(&response[..n]);
        assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(wire.contains("calendar events="));

        server.await.expect("server");
        Ok(())
    }
}
