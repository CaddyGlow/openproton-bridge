use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use super::session::{SmtpSession, SmtpSessionConfig};
use super::Result;

const MAX_CONNECTIONS_PER_IP: usize = 10;
const RATE_WINDOW_SECS: u64 = 60;

pub struct SmtpServer {
    tls_config: Option<Arc<rustls::ServerConfig>>,
}

impl Default for SmtpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpServer {
    pub fn new() -> Self {
        Self { tls_config: None }
    }

    pub fn with_tls(mut self, cert_dir: &std::path::Path) -> Result<Self> {
        let cert_path = cert_dir.join("cert.pem");
        let key_path = cert_dir.join("key.pem");

        if !cert_path.exists() || !key_path.exists() {
            info!("generating self-signed TLS certificate for SMTP");
            generate_self_signed_cert(cert_dir)?;
        }

        let cert_pem =
            std::fs::read(&cert_path).map_err(|e| super::SmtpError::Tls(e.to_string()))?;
        let key_pem = std::fs::read(&key_path).map_err(|e| super::SmtpError::Tls(e.to_string()))?;

        let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &cert_pem[..])
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| super::SmtpError::Tls(e.to_string()))?;

        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .map_err(|e| super::SmtpError::Tls(e.to_string()))?
            .ok_or_else(|| super::SmtpError::Tls("no private key found in PEM".to_string()))?;

        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| super::SmtpError::Tls(e.to_string()))?;

        self.tls_config = Some(Arc::new(tls_config));
        Ok(self)
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

pub async fn run_server(addr: &str, config: Arc<SmtpSessionConfig>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let rate_limiter = Arc::new(Mutex::new(RateLimiter::new()));
    info!(addr = %addr, "SMTP server listening");

    loop {
        let (stream, peer) = listener.accept().await?;

        // Rate limit by IP
        {
            let mut limiter = rate_limiter.lock().await;
            if !limiter.check(peer.ip()) {
                warn!(peer = %peer, "rate limited, dropping SMTP connection");
                drop(stream);
                continue;
            }
        }

        info!(peer = %peer, "new SMTP connection");

        let config = config.clone();

        tokio::spawn(async move {
            let (read, write) = tokio::io::split(stream);
            let mut session = SmtpSession::new(read, write, config);
            if let Err(e) = session.run().await {
                error!(peer = %peer, error = %e, "SMTP connection error");
            }
            info!(peer = %peer, "SMTP connection closed");
        });
    }
}

fn generate_self_signed_cert(dir: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| super::SmtpError::Tls(e.to_string()))?;

    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .map_err(|e| super::SmtpError::Tls(e.to_string()))?;

    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    std::fs::write(dir.join("cert.pem"), cert_pem)
        .map_err(|e| super::SmtpError::Tls(e.to_string()))?;
    std::fs::write(dir.join("key.pem"), key_pem)
        .map_err(|e| super::SmtpError::Tls(e.to_string()))?;

    info!("self-signed SMTP certificate written to {}", dir.display());
    Ok(())
}
