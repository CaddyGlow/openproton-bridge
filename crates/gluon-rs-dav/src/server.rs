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

use crate::auth::{resolve_basic_auth, DavAuthError, DavAuthenticator};
use crate::discovery;
use crate::error::{DavError, Result};
use crate::http::{
    not_implemented_response, options_response, parse_request_head, payload_too_large_response,
    split_head_from_buffer, unauthorized_response, DavRequest, DavResponse,
};
use crate::types::{account_id_hint, is_safe_path, parse_status_code, path_without_query};

const MAX_DAV_BODY_BYTES: usize = 1_048_576;
const DAV_CAPABILITIES_HEADER: &str =
    "1, 2, calendar-access, addressbook, sync-collection, webdav-push";

static DAV_METRICS: LazyLock<DavServerMetrics> = LazyLock::new(DavServerMetrics::default);
static RUNTIME_TLS_CONFIG: OnceLock<RwLock<Option<Arc<rustls::ServerConfig>>>> = OnceLock::new();

/// Trait for routing DAV requests to protocol-specific handlers.
///
/// Implemented by CardDAV and CalDAV protocol crates.
#[async_trait::async_trait]
pub trait DavRequestRouter: Send + Sync {
    /// Try to handle this request. Return `None` if the request is not for this router.
    async fn route_request(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
        account_id: &str,
        primary_email: &str,
    ) -> Result<Option<DavResponse>>;
}

pub struct DavServerConfig {
    pub authenticator: Arc<dyn DavAuthenticator>,
    pub routers: Vec<Arc<dyn DavRequestRouter>>,
}

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

        if let Err(err) = handle_connection_io(stream, config).await {
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
                let mut response = route_request(&request, body, &config).await?;
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

async fn route_request(
    request: &DavRequest,
    body: &[u8],
    config: &DavServerConfig,
) -> Result<DavResponse> {
    let method = request.method.to_ascii_uppercase();
    let path_no_query = request
        .path
        .split('?')
        .next()
        .unwrap_or(request.path.as_str());
    if !is_safe_path(path_no_query) {
        DAV_METRICS.record_rejected_path();
        return Ok(DavResponse {
            status: "400 Bad Request",
            headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
            body: b"invalid path\n".to_vec(),
        });
    }

    if let Some(response) = discovery::discovery_redirect(path_no_query) {
        return Ok(response);
    }

    match method.as_str() {
        "OPTIONS" => Ok(options_response()),
        "PROPFIND" | "PROPPATCH" | "REPORT" | "GET" | "HEAD" | "PUT" | "DELETE" | "POST"
        | "MKCALENDAR" => {
            if !path_no_query.starts_with("/dav") {
                return Ok(crate::http::not_found_response());
            }
            let auth = match resolve_basic_auth(&request.headers, config.authenticator.as_ref()) {
                Ok(auth) => auth,
                Err(DavAuthError::MissingAuthorization)
                | Err(DavAuthError::InvalidAuthorization)
                | Err(DavAuthError::InvalidCredentials) => {
                    tracing::debug!(
                        method = %request.method,
                        path = %request.path,
                        has_authorization = request.headers.contains_key("authorization"),
                        "dav auth rejected request"
                    );
                    return Ok(unauthorized_response());
                }
            };

            for router in &config.routers {
                if let Some(response) = router
                    .route_request(
                        &method,
                        &request.path,
                        &request.headers,
                        body,
                        &auth.account_id,
                        &auth.primary_email,
                    )
                    .await?
                {
                    return Ok(response);
                }
            }

            Ok(crate::http::not_found_response())
        }
        _ => Ok(not_implemented_response()),
    }
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
