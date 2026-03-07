use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, RwLock};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

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

const MAX_DAV_BODY_BYTES: usize = 1_048_576;
const DAV_CAPABILITIES_HEADER: &str = "1, 2, calendar-access, addressbook";

static DAV_METRICS: LazyLock<DavServerMetrics> = LazyLock::new(DavServerMetrics::default);
static RUNTIME_TLS_CONFIG: OnceLock<RwLock<Option<Arc<rustls::ServerConfig>>>> = OnceLock::new();

#[derive(Debug, Default, Clone, Copy)]
struct DavAccountMetrics {
    requests: u64,
    errors: u64,
}

#[derive(Debug, Default)]
struct DavServerMetrics {
    requests_total: AtomicU64,
    errors_total: AtomicU64,
    auth_failures_total: AtomicU64,
    rejected_paths_total: AtomicU64,
    total_latency_ms: AtomicU64,
    per_account: Mutex<HashMap<String, DavAccountMetrics>>,
}

impl DavServerMetrics {
    fn record_request(&self, account_id: Option<&str>, status: &str, latency_ms: u64) {
        let requests_total = self.requests_total.fetch_add(1, Ordering::Relaxed) + 1;
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        let status_code = parse_status_code(status).unwrap_or(500);
        if status_code >= 400 {
            self.errors_total.fetch_add(1, Ordering::Relaxed);
        }

        if let Some(account_id) = account_id.filter(|value| !value.is_empty()) {
            if let Ok(mut per_account) = self.per_account.lock() {
                let entry = per_account.entry(account_id.to_string()).or_default();
                entry.requests = entry.requests.saturating_add(1);
                if status_code >= 400 {
                    entry.errors = entry.errors.saturating_add(1);
                }
            }
        }

        if requests_total.is_multiple_of(100) {
            self.log_snapshot(requests_total);
        }
    }

    fn record_auth_failure(&self) {
        self.auth_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_rejected_path(&self) {
        self.rejected_paths_total.fetch_add(1, Ordering::Relaxed);
    }

    fn log_snapshot(&self, requests_total: u64) {
        let errors_total = self.errors_total.load(Ordering::Relaxed);
        let auth_failures_total = self.auth_failures_total.load(Ordering::Relaxed);
        let rejected_paths_total = self.rejected_paths_total.load(Ordering::Relaxed);
        let total_latency_ms = self.total_latency_ms.load(Ordering::Relaxed);
        let avg_latency_ms = if requests_total == 0 {
            0
        } else {
            total_latency_ms / requests_total
        };

        let mut highest_error_rate_account = String::new();
        let mut highest_error_rate = 0.0f64;
        if let Ok(per_account) = self.per_account.lock() {
            for (account_id, metrics) in per_account.iter() {
                if metrics.requests == 0 {
                    continue;
                }
                let error_rate = metrics.errors as f64 / metrics.requests as f64;
                if error_rate > highest_error_rate {
                    highest_error_rate = error_rate;
                    highest_error_rate_account = account_id.clone();
                }
            }
        }

        tracing::info!(
            requests_total,
            errors_total,
            auth_failures_total,
            rejected_paths_total,
            avg_latency_ms,
            highest_error_rate_account = if highest_error_rate_account.is_empty() {
                "n/a"
            } else {
                highest_error_rate_account.as_str()
            },
            highest_error_rate = format!("{highest_error_rate:.3}"),
            "DAV metrics snapshot"
        );
    }
}

fn runtime_tls_config_store() -> &'static RwLock<Option<Arc<rustls::ServerConfig>>> {
    RUNTIME_TLS_CONFIG.get_or_init(|| RwLock::new(None))
}

fn install_runtime_tls_config(config: Option<Arc<rustls::ServerConfig>>) {
    let mut guard = runtime_tls_config_store()
        .write()
        .expect("runtime tls config lock poisoned");
    *guard = config;
}

pub fn clear_runtime_tls_config() {
    install_runtime_tls_config(None);
}

fn runtime_tls_config() -> Option<Arc<rustls::ServerConfig>> {
    runtime_tls_config_store()
        .read()
        .expect("runtime tls config lock poisoned")
        .clone()
}

pub fn install_runtime_tls_config_from_dir(cert_dir: &Path) -> Result<()> {
    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");

    if !cert_path.exists() || !key_path.exists() {
        generate_self_signed_cert(cert_dir)?;
    }

    let cert_pem = std::fs::read(&cert_path)
        .map_err(|err| DavError::Tls(format!("failed to read {}: {err}", cert_path.display())))?;
    let key_pem = std::fs::read(&key_path)
        .map_err(|err| DavError::Tls(format!("failed to read {}: {err}", key_path.display())))?;

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|err| DavError::Tls(format!("invalid cert pem: {err}")))?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|err| DavError::Tls(format!("invalid key pem: {err}")))?
        .ok_or_else(|| DavError::Tls("no private key found in PEM".to_string()))?;

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| DavError::Tls(err.to_string()))?;
    install_runtime_tls_config(Some(Arc::new(tls_config)));
    Ok(())
}

fn generate_self_signed_cert(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)
        .map_err(|err| DavError::Tls(format!("failed to create {}: {err}", dir.display())))?;
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .map_err(|err| DavError::Tls(err.to_string()))?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    std::fs::write(dir.join("cert.pem"), cert_pem)
        .map_err(|err| DavError::Tls(format!("failed to write cert.pem: {err}")))?;
    std::fs::write(dir.join("key.pem"), key_pem)
        .map_err(|err| DavError::Tls(format!("failed to write key.pem: {err}")))?;
    Ok(())
}

#[derive(Clone, Default)]
pub struct DavServerConfig {
    pub auth_router: AuthRouter,
    pub pim_stores: HashMap<String, Arc<PimStore>>,
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
                    spawn_connection_handler(stream, self.config.clone(), None);
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
    run_server_with_listener_and_config_and_tls_config(listener, config, runtime_tls_config()).await
}

pub async fn run_server_with_listener_and_config_and_tls_config(
    listener: TcpListener,
    config: DavServerConfig,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let listener_addr = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    tracing::info!(
        addr = %listener_addr,
        tls = if tls_config.is_some() { "on" } else { "off" },
        "DAV server listening"
    );
    let config = Arc::new(config);

    loop {
        let (stream, _addr) = listener.accept().await?;
        spawn_connection_handler(stream, config.clone(), tls_config.clone());
    }
}

fn spawn_connection_handler(
    stream: TcpStream,
    config: Arc<DavServerConfig>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) {
    tokio::spawn(async move {
        if let Some(tls_config) = tls_config {
            let acceptor = TlsAcceptor::from(tls_config);
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(err) = handle_connection_io(tls_stream, config).await {
                        tracing::warn!(error = %err, "dav request failed");
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "dav tls handshake failed");
                }
            }
            return;
        }

        if let Err(err) = handle_connection(stream, config).await {
            tracing::warn!(error = %err, "dav request failed");
        }
    });
}

pub async fn handle_connection(stream: TcpStream, config: Arc<DavServerConfig>) -> Result<()> {
    handle_connection_io(stream, config).await
}

async fn handle_connection_io<S>(mut stream: S, config: Arc<DavServerConfig>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
                if content_length > MAX_DAV_BODY_BYTES {
                    let mut response = payload_too_large_response();
                    add_default_dav_headers(&mut response);
                    DAV_METRICS.record_request(
                        account_id_hint(path_without_query(&request.path)),
                        response.status,
                        0,
                    );
                    let wire = response.to_bytes();
                    stream.write_all(&wire).await?;
                    stream.flush().await?;
                    return Ok(());
                }
                if received.len() < head_end + content_length {
                    continue;
                }
                let body = &received[head_end..head_end + content_length];
                let started = Instant::now();
                let mut response = route_request(&request, body, &config)?;
                add_default_dav_headers(&mut response);
                let elapsed_ms = started.elapsed().as_millis() as u64;
                let account_hint = account_id_hint(path_without_query(&request.path));
                DAV_METRICS.record_request(account_hint, response.status, elapsed_ms);
                if response.status.starts_with("401") {
                    DAV_METRICS.record_auth_failure();
                }
                tracing::info!(
                    method = %request.method,
                    path = %request.path,
                    account_id = account_hint.unwrap_or("n/a"),
                    status = response.status,
                    elapsed_ms,
                    "DAV request handled"
                );
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
    if !is_safe_path(path_without_query) {
        DAV_METRICS.record_rejected_path();
        return Ok(DavResponse {
            status: "400 Bad Request",
            headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
            body: b"invalid path\n".to_vec(),
        });
    }

    if let Some(response) = discovery::discovery_redirect(path_without_query) {
        return Ok(response);
    }

    match method.as_str() {
        "OPTIONS" => Ok(options_response()),
        "PROPFIND" | "PROPPATCH" | "REPORT" | "GET" | "HEAD" | "PUT" | "DELETE" | "MKCALENDAR" => {
            if !path_without_query.starts_with("/dav") {
                return Ok(not_found_response());
            }
            let auth = match resolve_basic_auth(&request.headers, &config.auth_router) {
                Ok(auth) => auth,
                Err(err @ DavAuthError::MissingAuthorization)
                | Err(err @ DavAuthError::InvalidAuthorization)
                | Err(err @ DavAuthError::InvalidCredentials) => {
                    tracing::debug!(
                        method = %request.method,
                        path = %request.path,
                        auth_error = ?err,
                        has_authorization = request.headers.contains_key("authorization"),
                        header_names = ?request.headers.keys().collect::<Vec<_>>(),
                        "dav auth rejected request"
                    );
                    return Ok(unauthorized_response());
                }
            };

            if method == "PROPFIND" {
                let store = config.pim_stores.get(&auth.account_id.0);
                return propfind::handle_propfind_with_store(
                    &request.path,
                    &request.headers,
                    &auth,
                    store,
                );
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
            ("DAV", DAV_CAPABILITIES_HEADER.to_string()),
            (
                "Allow",
                "OPTIONS, PROPFIND, PROPPATCH, REPORT, MKCALENDAR, GET, HEAD, PUT, DELETE"
                    .to_string(),
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

fn payload_too_large_response() -> DavResponse {
    DavResponse {
        status: "413 Payload Too Large",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"request body too large\n".to_vec(),
    }
}

fn is_safe_path(path: &str) -> bool {
    if path.is_empty() || !path.starts_with('/') || path.contains('\0') || path.contains('\\') {
        return false;
    }
    let Some(decoded) = decode_percent_path(path) else {
        return false;
    };
    if decoded.contains('\0') || decoded.contains('\\') || decoded.contains("//") {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return false;
    }
    !decoded
        .split('/')
        .any(|segment| segment == ".." || segment == ".")
}

fn decode_percent_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;

    while idx < bytes.len() {
        if bytes[idx] == b'%' {
            let high = hex_value(*bytes.get(idx + 1)?)?;
            let low = hex_value(*bytes.get(idx + 2)?)?;
            out.push((high << 4) | low);
            idx += 3;
            continue;
        }
        out.push(bytes[idx]);
        idx += 1;
    }

    String::from_utf8(out).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn account_id_hint(path: &str) -> Option<&str> {
    let mut segments = path
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty());
    if segments.next()? != "dav" {
        return None;
    }
    let account_id = segments.next()?;
    if account_id.eq_ignore_ascii_case("principals") {
        return None;
    }
    Some(account_id)
}

fn path_without_query(path: &str) -> &str {
    path.split_once('?').map(|(head, _)| head).unwrap_or(path)
}

fn parse_status_code(status: &str) -> Option<u16> {
    status.split_whitespace().next()?.parse::<u16>().ok()
}

fn add_default_dav_headers(response: &mut DavResponse) {
    let has_dav = response
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("dav"));
    if !has_dav {
        response
            .headers
            .push(("DAV", DAV_CAPABILITIES_HEADER.to_string()));
    }

    let has_server = response
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("server"));
    if !has_server {
        response
            .headers
            .push(("Server", "openproton-bridge-dav".to_string()));
    }

    let has_ms_author_via = response
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("ms-author-via"));
    if !has_ms_author_via {
        response.headers.push(("MS-Author-Via", "DAV".to_string()));
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

    #[test]
    fn rejects_traversal_paths() {
        let request = parse_request_head(
            b"GET /dav/uid-1/addressbooks/default/../x HTTP/1.1\r\nHost: localhost\r\n\r\n",
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
        .expect("route should succeed");
        assert_eq!(response.status, "400 Bad Request");
    }

    #[test]
    fn rejects_percent_encoded_dot_segments() {
        let request = parse_request_head(
            b"GET /dav/uid-1/addressbooks/default/%2e%2e/x HTTP/1.1\r\nHost: localhost\r\n\r\n",
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
        .expect("route should succeed");
        assert_eq!(response.status, "400 Bad Request");
    }

    #[test]
    fn allows_percent_encoded_dots_in_regular_segments() {
        let request = parse_request_head(
            b"GET /dav/uid-1/addressbooks/default/c1%2Evcf HTTP/1.1\r\nHost: localhost\r\n\r\n",
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
        .expect("route should succeed");
        assert_eq!(response.status, "401 Unauthorized");
    }

    #[test]
    fn rejects_invalid_percent_encoding() {
        let request = parse_request_head(
            b"GET /dav/uid-1/addressbooks/default/c1%ZZ.vcf HTTP/1.1\r\nHost: localhost\r\n\r\n",
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
        .expect("route should succeed");
        assert_eq!(response.status, "400 Bad Request");
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

    #[tokio::test]
    async fn proppatch_updates_calendar_metadata() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let store = Arc::new(PimStore::new(tmp.path().join("account.db")).expect("store"));
        store
            .upsert_calendar(&crate::api::calendar::Calendar {
                id: "work".to_string(),
                name: "Work".to_string(),
                description: "".to_string(),
                color: "#3A7AFE".to_string(),
                display: 1,
                calendar_type: 0,
                flags: 0,
            })
            .expect("seed calendar");
        let mut pim_stores = HashMap::new();
        pim_stores.insert("uid-1".to_string(), store.clone());

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let config = Arc::new(DavServerConfig {
            auth_router: auth_router(),
            pim_stores,
        });

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            handle_connection(stream, config).await.expect("handle");
        });

        let auth = BASE64_STANDARD.encode("alice@proton.me:secret");
        let body = r#"<?xml version="1.0" encoding="utf-8"?><d:propertyupdate xmlns:d="DAV:" xmlns:ical="http://apple.com/ns/ical/"><d:set><d:prop><d:displayname>Renamed</d:displayname><ical:calendar-color>#FF9500</ical:calendar-color></d:prop></d:set></d:propertyupdate>"#;
        let request = format!(
            "PROPPATCH /dav/uid-1/calendars/work/ HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {auth}\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let mut client = tokio::net::TcpStream::connect(addr).await?;
        client.write_all(request.as_bytes()).await?;
        let mut response = vec![0; 2048];
        let n = client.read(&mut response).await?;
        let wire = String::from_utf8_lossy(&response[..n]);
        assert!(wire.starts_with("HTTP/1.1 207 Multi-Status\r\n"));

        let updated = store
            .get_calendar("work", false)
            .expect("lookup calendar")
            .expect("calendar exists");
        assert_eq!(updated.name, "Renamed");
        assert_eq!(updated.color, "#FF9500");

        server.await.expect("server");
        Ok(())
    }

    #[tokio::test]
    async fn oversized_body_returns_413() -> Result<()> {
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
        let request =
            "PUT /dav/uid-1/addressbooks/default/big.vcf HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1048577\r\n\r\n";
        client.write_all(request.as_bytes()).await?;
        let mut response = vec![0_u8; 1024];
        let n = client.read(&mut response).await?;
        let wire = String::from_utf8_lossy(&response[..n]);
        assert!(wire.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
        assert!(wire.contains("request body too large"));

        server.await.expect("server task");
        Ok(())
    }
}
