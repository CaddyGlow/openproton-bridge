use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::imap_types::SessionEvent;

use crate::imap_error::ImapResult as Result;
use crate::session::{ImapSession, SessionAction, SessionConfig};

const DEFAULT_MAX_CONNECTIONS_PER_IP: usize = 10;
const RATE_WINDOW_SECS: u64 = 60;

fn max_connections_per_ip() -> usize {
    std::env::var("IMAP_MAX_CONNECTIONS_PER_IP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_CONNECTIONS_PER_IP)
}

fn rate_limit_disabled() -> bool {
    std::env::var("IMAP_DISABLE_RATE_LIMIT").is_ok()
}
static RUNTIME_TLS_CONFIG: OnceLock<RwLock<Option<Arc<rustls::ServerConfig>>>> = OnceLock::new();

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

/// Low-level IMAP server builder for TLS configuration.
pub struct ImapServer {
    tls_config: Option<Arc<rustls::ServerConfig>>,
}

impl Default for ImapServer {
    fn default() -> Self {
        Self::new()
    }
}

impl ImapServer {
    pub fn new() -> Self {
        Self { tls_config: None }
    }

    pub fn with_tls(mut self, cert_dir: &Path) -> Result<Self> {
        let cert_path = cert_dir.join("cert.pem");
        let key_path = cert_dir.join("key.pem");

        if !cert_path.exists() || !key_path.exists() {
            info!("generating self-signed TLS certificate");
            generate_self_signed_cert(cert_dir)?;
        }

        let cert_pem = std::fs::read(&cert_path)
            .map_err(|e| crate::imap_error::ImapError::Tls(e.to_string()))?;
        let key_pem = std::fs::read(&key_path)
            .map_err(|e| crate::imap_error::ImapError::Tls(e.to_string()))?;

        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &cert_pem[..])
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| crate::imap_error::ImapError::Tls(e.to_string()))?;

        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .map_err(|e| crate::imap_error::ImapError::Tls(e.to_string()))?
            .ok_or_else(|| {
                crate::imap_error::ImapError::Tls("no private key found in PEM".to_string())
            })?;

        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| crate::imap_error::ImapError::Tls(e.to_string()))?;

        self.tls_config = Some(Arc::new(tls_config));
        install_runtime_tls_config(self.tls_config.clone());
        Ok(self)
    }

    pub fn tls_config(&self) -> Option<Arc<rustls::ServerConfig>> {
        self.tls_config.clone()
    }
}

struct RateLimiter {
    connections: HashMap<IpAddr, Vec<Instant>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    fn check(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_WINDOW_SECS);

        let timestamps = self.connections.entry(ip).or_default();
        timestamps.retain(|t| now.duration_since(*t) < window);

        if timestamps.len() >= max_connections_per_ip() {
            return false;
        }

        timestamps.push(now);
        true
    }
}

/// Start an IMAP server on `addr` using the global TLS config.
pub async fn run_server(addr: &str, config: Arc<SessionConfig>) -> Result<()> {
    run_server_with_tls_config(addr, config, runtime_tls_config()).await
}

pub async fn run_server_with_listener(
    listener: TcpListener,
    config: Arc<SessionConfig>,
) -> Result<()> {
    run_server_with_listener_and_tls_config(listener, config, runtime_tls_config()).await
}

pub async fn run_server_with_listener_and_tls_config(
    listener: TcpListener,
    config: Arc<SessionConfig>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    run_server_from_listener(listener, config, tls_config).await
}

pub async fn run_server_with_listener_implicit_tls(
    listener: TcpListener,
    config: Arc<SessionConfig>,
) -> Result<()> {
    run_server_with_listener_and_tls_config_implicit_tls(listener, config, runtime_tls_config())
        .await
}

pub async fn run_server_with_listener_and_tls_config_implicit_tls(
    listener: TcpListener,
    config: Arc<SessionConfig>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    run_server_from_listener_implicit_tls(listener, config, tls_config).await
}

/// Start an IMAP server on `addr` with an explicit TLS config.
pub async fn run_server_with_tls_config(
    addr: &str,
    config: Arc<SessionConfig>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    run_server_from_listener(listener, config, tls_config).await
}

async fn run_server_from_listener(
    listener: TcpListener,
    config: Arc<SessionConfig>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));
    let listener_addr = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    info!(
        pkg = "imap/server",
        msg = "IMAP server listening",
        addr = %listener_addr,
        "IMAP server listening"
    );

    loop {
        let (stream, peer) = listener.accept().await?;

        // Rate limit by IP
        if !rate_limit_disabled() {
            let mut limiter = rate_limiter.lock().await;
            if !limiter.check(peer.ip()) {
                warn!(peer = %peer, "rate limited, dropping connection");
                drop(stream);
                continue;
            }
        }

        info!(
            pkg = "imap/server",
            msg = "new IMAP connection",
            peer = %peer,
            "new IMAP connection"
        );

        let config = config.clone();
        let tls_config = tls_config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, config, tls_config).await {
                error!(
                    pkg = "imap/server",
                    msg = "connection error",
                    peer = %peer,
                    error = %e,
                    "connection error"
                );
            }
            info!(
                pkg = "imap/server",
                msg = "connection closed",
                peer = %peer,
                "connection closed"
            );
        });
    }
}

async fn run_server_from_listener_implicit_tls(
    listener: TcpListener,
    config: Arc<SessionConfig>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));
    let listener_addr = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    info!(
        pkg = "imap/server",
        msg = "IMAP implicit TLS server listening",
        addr = %listener_addr,
        "IMAP implicit TLS server listening"
    );

    let tls_config = tls_config.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "IMAP implicit TLS requested without TLS configuration",
        )
    })?;
    let acceptor = TlsAcceptor::from(tls_config);

    loop {
        let (stream, peer) = listener.accept().await?;

        {
            let mut limiter = rate_limiter.lock().await;
            if !limiter.check(peer.ip()) {
                warn!(peer = %peer, "rate limited, dropping connection");
                drop(stream);
                continue;
            }
        }

        info!(
            pkg = "imap/server",
            msg = "new IMAP implicit TLS connection",
            peer = %peer,
            "new IMAP implicit TLS connection"
        );

        let config = config.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection_implicit_tls(stream, config, acceptor).await {
                error!(
                    pkg = "imap/server",
                    msg = "implicit TLS connection error",
                    peer = %peer,
                    error = %e,
                    "implicit TLS connection error"
                );
            }
            info!(
                pkg = "imap/server",
                msg = "connection closed",
                peer = %peer,
                "connection closed"
            );
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    config: Arc<SessionConfig>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<()> {
    let (read, write) = stream.into_split();
    let mut session = ImapSession::with_starttls(read, write, config.clone(), tls_config.is_some());
    let action = session.run().await?;
    let (read, write) = session.into_parts();
    let stream = write.reunite(read).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "failed to reunite IMAP stream halves",
        )
    })?;

    if matches!(action, SessionAction::StartTls) {
        let Some(tls_config) = tls_config else {
            return Ok(());
        };
        let acceptor = TlsAcceptor::from(tls_config);
        let tls_stream = acceptor
            .accept(stream)
            .await
            .map_err(|err| crate::imap_error::ImapError::Tls(err.to_string()))?;
        let (read, write) = tokio::io::split(tls_stream);
        let mut tls_session = ImapSession::with_starttls(read, write, config, false);
        let _ = tls_session.run_after_starttls().await?;
    }

    Ok(())
}

async fn handle_connection_implicit_tls(
    stream: TcpStream,
    config: Arc<SessionConfig>,
    acceptor: TlsAcceptor,
) -> Result<()> {
    let tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|err| crate::imap_error::ImapError::Tls(err.to_string()))?;
    let (read, write) = tokio::io::split(tls_stream);
    let mut session = ImapSession::with_starttls(read, write, config, false);
    let _ = session.run().await?;
    Ok(())
}

/// High-level IMAP server with graceful shutdown, event streaming,
/// connection metrics, and panic recovery.
pub struct GluonServer {
    default_config: Arc<SessionConfig>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    event_tx: tokio::sync::broadcast::Sender<SessionEvent>,
    connections_total: Arc<AtomicU64>,
    connection_times: Arc<Mutex<VecDeque<Instant>>>,
    panic_handler: Option<Arc<dyn Fn(String) + Send + Sync>>,
}

impl GluonServer {
    /// Create a new server with the given session config.
    pub fn new(config: Arc<SessionConfig>) -> Self {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (event_tx, _) = tokio::sync::broadcast::channel(256);
        Self {
            default_config: config,
            tls_config: None,
            shutdown_tx,
            shutdown_rx,
            event_tx,
            connections_total: Arc::new(AtomicU64::new(0)),
            connection_times: Arc::new(Mutex::new(VecDeque::new())),
            panic_handler: None,
        }
    }

    /// Enable TLS using certs from `cert_dir` (generates self-signed if absent).
    pub fn with_tls(mut self, cert_dir: &Path) -> Result<Self> {
        let server = ImapServer::new().with_tls(cert_dir)?;
        self.tls_config = server.tls_config();
        Ok(self)
    }

    /// Subscribe to session lifecycle events (login, logout, select, close).
    pub fn subscribe_events(&self) -> tokio::sync::broadcast::Receiver<SessionEvent> {
        self.event_tx.subscribe()
    }

    /// Total number of connections accepted since server start.
    pub fn get_total_connections(&self) -> u64 {
        self.connections_total.load(Ordering::Relaxed)
    }

    /// Number of connections accepted within the given time window.
    pub fn get_rolling_connection_count(&self, window: Duration) -> usize {
        let times = self.connection_times.try_lock();
        match times {
            Ok(times) => {
                let cutoff = Instant::now() - window;
                times.iter().filter(|t| **t >= cutoff).count()
            }
            Err(_) => 0,
        }
    }

    /// Register a callback invoked when a session task panics.
    pub fn with_panic_handler(mut self, handler: impl Fn(String) + Send + Sync + 'static) -> Self {
        self.panic_handler = Some(Arc::new(handler));
        self
    }

    /// Returns a config with the shutdown receiver injected.
    fn session_config(&self) -> Arc<SessionConfig> {
        Arc::new(SessionConfig {
            connector: self.default_config.connector.clone(),
            gluon_connector: self.default_config.gluon_connector.clone(),
            mailbox_catalog: self.default_config.mailbox_catalog.clone(),
            mailbox_mutation: self.default_config.mailbox_mutation.clone(),
            mailbox_view: self.default_config.mailbox_view.clone(),
            recent_tracker: self.default_config.recent_tracker.clone(),
            shutdown_rx: Some(self.shutdown_rx.clone()),
            event_tx: Some(self.event_tx.clone()),
            delimiter: self.default_config.delimiter,
            login_jail_time: self.default_config.login_jail_time,
            idle_bulk_time: self.default_config.idle_bulk_time,
            limits: self.default_config.limits.clone(),
            backend: self.default_config.backend.clone(),
        })
    }

    /// Bind to `addr` and start accepting IMAP connections.
    pub async fn serve(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        self.serve_listener(listener).await
    }

    /// Accept IMAP connections from an already-bound listener.
    pub async fn serve_listener(&self, listener: TcpListener) -> Result<()> {
        let config = self.session_config();
        let tls_config = self.tls_config.clone();
        let mut shutdown_rx = self.shutdown_rx.clone();
        let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));

        let listener_addr = listener
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        info!(
            pkg = "imap/server",
            msg = "GluonServer listening",
            addr = %listener_addr,
            "GluonServer listening"
        );

        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    info!(pkg = "imap/server", "GluonServer shutting down");
                    return Ok(());
                }
                result = listener.accept() => {
                    let (stream, peer) = result?;

                    if !rate_limit_disabled() {
                        let mut limiter = rate_limiter.lock().await;
                        if !limiter.check(peer.ip()) {
                            warn!(peer = %peer, "rate limited, dropping connection");
                            drop(stream);
                            continue;
                        }
                    }

                    info!(
                        pkg = "imap/server",
                        peer = %peer,
                        "new GluonServer connection"
                    );

                    self.connections_total.fetch_add(1, Ordering::Relaxed);
                    {
                        let mut times = self.connection_times.lock().await;
                        times.push_back(Instant::now());
                        // Trim old entries beyond 1 hour
                        let cutoff = Instant::now() - Duration::from_secs(3600);
                        while times.front().map(|t| *t < cutoff).unwrap_or(false) {
                            times.pop_front();
                        }
                    }

                    let config = config.clone();
                    let tls_config = tls_config.clone();
                    let panic_handler = self.panic_handler.clone();
                    let inner_handle = tokio::spawn(async move {
                        handle_connection(stream, config, tls_config).await
                    });
                    tokio::spawn(async move {
                        match inner_handle.await {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                error!(
                                    pkg = "imap/server",
                                    peer = %peer,
                                    error = %e,
                                    "connection error"
                                );
                            }
                            Err(join_err) if join_err.is_panic() => {
                                let panic_val = join_err.into_panic();
                                let msg = if let Some(s) = panic_val.downcast_ref::<String>() {
                                    s.clone()
                                } else if let Some(s) = panic_val.downcast_ref::<&str>() {
                                    s.to_string()
                                } else {
                                    "unknown panic".to_string()
                                };
                                error!(
                                    pkg = "imap/server",
                                    peer = %peer,
                                    panic = %msg,
                                    "session panicked"
                                );
                                if let Some(handler) = &panic_handler {
                                    handler(msg);
                                }
                            }
                            Err(join_err) => {
                                error!(
                                    pkg = "imap/server",
                                    peer = %peer,
                                    error = %join_err,
                                    "session task cancelled"
                                );
                            }
                        }
                    });
                }
            }
        }
    }

    /// Signal all sessions and the accept loop to shut down.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Generate a self-signed TLS certificate and key, writing them to `dir`.
fn generate_self_signed_cert(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| crate::imap_error::ImapError::Tls(e.to_string()))?;

    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .map_err(|e| crate::imap_error::ImapError::Tls(e.to_string()))?;

    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    std::fs::write(dir.join("cert.pem"), cert_pem)
        .map_err(|e| crate::imap_error::ImapError::Tls(e.to_string()))?;
    std::fs::write(dir.join("key.pem"), key_pem)
        .map_err(|e| crate::imap_error::ImapError::Tls(e.to_string()))?;

    info!("self-signed certificate written to {}", dir.display());
    Ok(())
}
