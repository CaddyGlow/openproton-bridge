use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Instant;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use super::session::{ImapSession, SessionAction, SessionConfig};
use super::Result;

const MAX_CONNECTIONS_PER_IP: usize = 10;
const RATE_WINDOW_SECS: u64 = 60;
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

        let cert_pem =
            std::fs::read(&cert_path).map_err(|e| super::ImapError::Tls(e.to_string()))?;
        let key_pem = std::fs::read(&key_path).map_err(|e| super::ImapError::Tls(e.to_string()))?;

        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &cert_pem[..])
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| super::ImapError::Tls(e.to_string()))?;

        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .map_err(|e| super::ImapError::Tls(e.to_string()))?
            .ok_or_else(|| super::ImapError::Tls("no private key found in PEM".to_string()))?;

        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| super::ImapError::Tls(e.to_string()))?;

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

        if timestamps.len() >= MAX_CONNECTIONS_PER_IP {
            return false;
        }

        timestamps.push(now);
        true
    }
}

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
    info!(addr = %listener_addr, "IMAP server listening");

    loop {
        let (stream, peer) = listener.accept().await?;

        // Rate limit by IP
        {
            let mut limiter = rate_limiter.lock().await;
            if !limiter.check(peer.ip()) {
                warn!(peer = %peer, "rate limited, dropping connection");
                drop(stream);
                continue;
            }
        }

        info!(peer = %peer, "new IMAP connection");

        let config = config.clone();
        let tls_config = tls_config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, config, tls_config).await {
                error!(peer = %peer, error = %e, "connection error");
            }
            info!(peer = %peer, "connection closed");
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
            .map_err(|err| super::ImapError::Tls(err.to_string()))?;
        let (read, write) = tokio::io::split(tls_stream);
        let mut tls_session = ImapSession::with_starttls(read, write, config, false);
        let _ = tls_session.run().await?;
    }

    Ok(())
}

fn generate_self_signed_cert(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| super::ImapError::Tls(e.to_string()))?;

    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .map_err(|e| super::ImapError::Tls(e.to_string()))?;

    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    std::fs::write(dir.join("cert.pem"), cert_pem)
        .map_err(|e| super::ImapError::Tls(e.to_string()))?;
    std::fs::write(dir.join("key.pem"), key_pem)
        .map_err(|e| super::ImapError::Tls(e.to_string()))?;

    info!("self-signed certificate written to {}", dir.display());
    Ok(())
}
