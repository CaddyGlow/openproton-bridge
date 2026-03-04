use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use crate::api::client::ProtonClient;
use crate::api::error::is_auth_error;
use crate::api::types::Address;
use crate::bridge::accounts::{AccountRuntimeError, RuntimeAccountRegistry};
use crate::bridge::auth_router::AuthRouter;
use crate::crypto::keys::{self, Keyring};

use super::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAction {
    Continue,
    StartTls,
    Close,
}

#[derive(Debug, Clone, PartialEq)]
enum State {
    Connected,
    Greeted,
    Authenticated,
    MailFrom,
    RcptTo,
    Data,
}

pub struct SmtpSessionConfig {
    pub api_base_url: String,
    pub auth_router: AuthRouter,
    pub runtime_accounts: Arc<RuntimeAccountRegistry>,
}

pub struct SmtpSession<R, W> {
    reader: BufReader<R>,
    writer: W,
    state: State,
    config: Arc<SmtpSessionConfig>,
    client: Option<ProtonClient>,
    user_keyring: Option<Keyring>,
    addr_keyrings: Option<HashMap<String, Keyring>>,
    addresses: Option<Vec<Address>>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    hostname: String,
    starttls_available: bool,
    tls_active: bool,
}

impl<R, W> SmtpSession<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    pub fn new(reader: R, writer: W, config: Arc<SmtpSessionConfig>) -> Self {
        Self::with_starttls(reader, writer, config, false, false)
    }

    pub fn with_starttls(
        reader: R,
        writer: W,
        config: Arc<SmtpSessionConfig>,
        starttls_available: bool,
        tls_active: bool,
    ) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            state: State::Connected,
            config,
            client: None,
            user_keyring: None,
            addr_keyrings: None,
            addresses: None,
            mail_from: None,
            rcpt_to: Vec::new(),
            hostname: "openproton-bridge".to_string(),
            starttls_available,
            tls_active,
        }
    }

    pub fn into_parts(self) -> (R, W) {
        (self.reader.into_inner(), self.writer)
    }

    async fn write_line(&mut self, code: u16, msg: &str) -> Result<()> {
        let line = format!("{} {}\r\n", code, msg);
        self.writer
            .write_all(line.as_bytes())
            .await
            .map_err(super::SmtpError::Io)?;
        self.writer.flush().await.map_err(super::SmtpError::Io)?;
        Ok(())
    }

    async fn write_multiline(&mut self, code: u16, lines: &[&str]) -> Result<()> {
        for (i, line) in lines.iter().enumerate() {
            let sep = if i < lines.len() - 1 { "-" } else { " " };
            let out = format!("{}{}{}\r\n", code, sep, line);
            self.writer
                .write_all(out.as_bytes())
                .await
                .map_err(super::SmtpError::Io)?;
        }
        self.writer.flush().await.map_err(super::SmtpError::Io)?;
        Ok(())
    }

    pub async fn run(&mut self) -> Result<SessionAction> {
        // Send greeting
        self.write_line(
            220,
            &format!("{} ESMTP openproton-bridge ready", self.hostname),
        )
        .await?;

        loop {
            if self.state == State::Data {
                // Read DATA content until <CRLF>.<CRLF>
                let data = self.read_data().await?;
                self.handle_data_content(&data).await?;
                continue;
            }

            let mut line = String::new();
            let n = self.reader.read_line(&mut line).await?;
            if n == 0 {
                debug!("SMTP client disconnected");
                return Ok(SessionAction::Close);
            }

            let line = line.trim_end().to_string();
            if line.is_empty() {
                continue;
            }

            debug!(line = %line, "SMTP received");

            match self.handle_command(&line).await? {
                SessionAction::Continue => {}
                SessionAction::StartTls => return Ok(SessionAction::StartTls),
                SessionAction::Close => return Ok(SessionAction::Close),
            }
        }
    }

    /// Handle a single SMTP command.
    async fn handle_command(&mut self, line: &str) -> Result<SessionAction> {
        let (verb, args) = split_command(line);
        let verb_upper = verb.to_uppercase();

        match verb_upper.as_str() {
            "EHLO" | "HELO" => self.cmd_ehlo(args).await?,
            "AUTH" => self.cmd_auth(args).await?,
            "STARTTLS" => return self.cmd_starttls().await,
            "MAIL" => self.cmd_mail_from(args).await?,
            "RCPT" => self.cmd_rcpt_to(args).await?,
            "DATA" => self.cmd_data().await?,
            "RSET" => self.cmd_rset().await?,
            "NOOP" => self.write_line(250, "OK").await?,
            "QUIT" => {
                self.write_line(221, "Bye").await?;
                return Ok(SessionAction::Close);
            }
            _ => {
                self.write_line(502, "Command not implemented").await?;
            }
        }

        Ok(SessionAction::Continue)
    }

    async fn cmd_ehlo(&mut self, args: &str) -> Result<()> {
        if args.is_empty() {
            return self.write_line(501, "EHLO requires a hostname").await;
        }

        self.state = State::Greeted;
        let mut lines = vec![self.hostname.clone()];
        if self.starttls_available && !self.tls_active {
            lines.push("STARTTLS".to_string());
        }
        lines.push("AUTH PLAIN LOGIN".to_string());
        lines.push("SIZE 26214400".to_string());
        lines.push("8BITMIME".to_string());
        lines.push("PIPELINING".to_string());
        let refs = lines.iter().map(String::as_str).collect::<Vec<_>>();
        self.write_multiline(250, &refs).await
    }

    async fn cmd_starttls(&mut self) -> Result<SessionAction> {
        if self.state != State::Greeted {
            self.write_line(503, "Bad sequence of commands").await?;
            return Ok(SessionAction::Continue);
        }
        if !self.starttls_available || self.tls_active {
            self.write_line(454, "TLS not available").await?;
            return Ok(SessionAction::Continue);
        }

        self.write_line(220, "Ready to start TLS").await?;
        Ok(SessionAction::StartTls)
    }

    async fn cmd_auth(&mut self, args: &str) -> Result<()> {
        if self.state != State::Greeted {
            return self.write_line(503, "Bad sequence of commands").await;
        }

        let mut auth_parts = args.split_whitespace();
        let Some(mechanism) = auth_parts.next() else {
            return self.write_line(501, "Syntax error in AUTH command").await;
        };

        let (username, password) = if mechanism.eq_ignore_ascii_case("PLAIN") {
            let b64_data = if let Some(initial) = auth_parts.next() {
                initial.to_string()
            } else {
                // Send continuation prompt and read the base64 data
                self.write_line(334, "").await?;
                let mut data_line = String::new();
                self.reader.read_line(&mut data_line).await?;
                data_line.trim().to_string()
            };

            let decoded = match BASE64.decode(b64_data.trim()) {
                Ok(d) => d,
                Err(_) => {
                    return self.write_line(535, "Authentication failed").await;
                }
            };

            // AUTH PLAIN format: \0username\0password
            let parts: Vec<&[u8]> = decoded.splitn(3, |&b| b == 0).collect();
            if parts.len() != 3 {
                return self.write_line(535, "Authentication failed").await;
            }

            (
                String::from_utf8_lossy(parts[1]).to_string(),
                String::from_utf8_lossy(parts[2]).to_string(),
            )
        } else if mechanism.eq_ignore_ascii_case("LOGIN") {
            let username_b64 = if let Some(initial) = auth_parts.next() {
                initial.to_string()
            } else {
                self.write_line(334, "VXNlcm5hbWU6").await?;
                let mut line = String::new();
                self.reader.read_line(&mut line).await?;
                line.trim().to_string()
            };
            let username = match BASE64.decode(username_b64.trim()) {
                Ok(decoded) => String::from_utf8_lossy(&decoded).to_string(),
                Err(_) => return self.write_line(535, "Authentication failed").await,
            };

            self.write_line(334, "UGFzc3dvcmQ6").await?;
            let mut password_line = String::new();
            self.reader.read_line(&mut password_line).await?;
            let password = match BASE64.decode(password_line.trim()) {
                Ok(decoded) => String::from_utf8_lossy(&decoded).to_string(),
                Err(_) => return self.write_line(535, "Authentication failed").await,
            };

            (username, password)
        } else {
            return self
                .write_line(504, "Only AUTH PLAIN and AUTH LOGIN are supported")
                .await;
        };

        let auth_route = match self
            .config
            .auth_router
            .resolve_login(username.as_str(), password.as_str())
        {
            Some(route) => route,
            None => return self.write_line(535, "Authentication failed").await,
        };
        let mut account_session = match self
            .config
            .runtime_accounts
            .with_valid_access_token(&auth_route.account_id)
            .await
        {
            Ok(session) => session,
            Err(AccountRuntimeError::AccountUnavailable(_)) => {
                warn!(
                    account_id = %auth_route.account_id.0,
                    "account unavailable during SMTP auth"
                );
                return self.write_line(535, "Authentication failed").await;
            }
            Err(e) => {
                warn!(
                    account_id = %auth_route.account_id.0,
                    error = %e,
                    "failed to load account session"
                );
                return self
                    .write_line(454, "Temporary authentication failure")
                    .await;
            }
        };

        // Create authenticated ProtonClient
        let mut client = match ProtonClient::authenticated_with_mode(
            account_session.api_mode.base_url(),
            account_session.api_mode,
            &account_session.uid,
            &account_session.access_token,
        ) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "failed to create ProtonClient");
                return self
                    .write_line(454, "Temporary authentication failure")
                    .await;
            }
        };

        // Unlock keys (same flow as IMAP session)
        let passphrase_b64 = match &account_session.key_passphrase {
            Some(p) => p.clone(),
            None => {
                return self
                    .write_line(454, "Temporary authentication failure")
                    .await;
            }
        };

        let mut passphrase = match BASE64.decode(&passphrase_b64) {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "invalid key passphrase encoding");
                return self
                    .write_line(454, "Temporary authentication failure")
                    .await;
            }
        };

        let user_resp = match crate::api::users::get_user(&client).await {
            Ok(r) => r,
            Err(e) if is_auth_error(&e) => {
                let refreshed = match self
                    .config
                    .runtime_accounts
                    .refresh_session_if_stale(
                        &auth_route.account_id,
                        Some(&account_session.access_token),
                    )
                    .await
                {
                    Ok(session) => session,
                    Err(refresh_err) => {
                        passphrase.zeroize();
                        warn!(
                            account_id = %auth_route.account_id.0,
                            error = %refresh_err,
                            "token refresh failed during SMTP auth"
                        );
                        return self
                            .write_line(454, "Temporary authentication failure")
                            .await;
                    }
                };
                account_session = refreshed;
                client = match ProtonClient::authenticated_with_mode(
                    account_session.api_mode.base_url(),
                    account_session.api_mode,
                    &account_session.uid,
                    &account_session.access_token,
                ) {
                    Ok(c) => c,
                    Err(err) => {
                        passphrase.zeroize();
                        warn!(error = %err, "failed to recreate ProtonClient after refresh");
                        return self
                            .write_line(454, "Temporary authentication failure")
                            .await;
                    }
                };
                match crate::api::users::get_user(&client).await {
                    Ok(r) => r,
                    Err(err) => {
                        passphrase.zeroize();
                        warn!(error = %err, "failed to fetch user info after refresh");
                        return self
                            .write_line(454, "Temporary authentication failure")
                            .await;
                    }
                }
            }
            Err(e) => {
                passphrase.zeroize();
                warn!(error = %e, "failed to fetch user info");
                return self
                    .write_line(454, "Temporary authentication failure")
                    .await;
            }
        };

        let user_keyring = match keys::unlock_user_keys(&user_resp.user.keys, &passphrase) {
            Ok(kr) => kr,
            Err(e) => {
                passphrase.zeroize();
                warn!(error = %e, "failed to unlock user keys");
                return self
                    .write_line(454, "Temporary authentication failure")
                    .await;
            }
        };

        let addr_resp = match crate::api::users::get_addresses(&client).await {
            Ok(r) => r,
            Err(e) if is_auth_error(&e) => {
                let refreshed = match self
                    .config
                    .runtime_accounts
                    .refresh_session_if_stale(
                        &auth_route.account_id,
                        Some(&account_session.access_token),
                    )
                    .await
                {
                    Ok(session) => session,
                    Err(refresh_err) => {
                        passphrase.zeroize();
                        warn!(
                            account_id = %auth_route.account_id.0,
                            error = %refresh_err,
                            "token refresh failed while fetching addresses"
                        );
                        return self
                            .write_line(454, "Temporary authentication failure")
                            .await;
                    }
                };
                account_session = refreshed;
                client = match ProtonClient::authenticated_with_mode(
                    account_session.api_mode.base_url(),
                    account_session.api_mode,
                    &account_session.uid,
                    &account_session.access_token,
                ) {
                    Ok(c) => c,
                    Err(err) => {
                        passphrase.zeroize();
                        warn!(error = %err, "failed to recreate ProtonClient after refresh");
                        return self
                            .write_line(454, "Temporary authentication failure")
                            .await;
                    }
                };
                match crate::api::users::get_addresses(&client).await {
                    Ok(r) => r,
                    Err(err) => {
                        passphrase.zeroize();
                        warn!(error = %err, "failed to fetch addresses after refresh");
                        return self
                            .write_line(454, "Temporary authentication failure")
                            .await;
                    }
                }
            }
            Err(e) => {
                passphrase.zeroize();
                warn!(error = %e, "failed to fetch addresses");
                return self
                    .write_line(454, "Temporary authentication failure")
                    .await;
            }
        };

        let mut addr_keyrings = HashMap::new();
        for addr in &addr_resp.addresses {
            if addr.status != 1 || addr.keys.is_empty() {
                continue;
            }
            match keys::unlock_address_keys(&addr.keys, &passphrase, &user_keyring) {
                Ok(kr) => {
                    addr_keyrings.insert(addr.id.clone(), kr);
                }
                Err(e) => {
                    warn!(address = %addr.email, error = %e, "could not unlock address keys");
                }
            }
        }

        passphrase.zeroize();

        if addr_keyrings.is_empty() {
            return self
                .write_line(454, "Temporary authentication failure")
                .await;
        }

        self.client = Some(client);
        self.user_keyring = Some(user_keyring);
        self.addr_keyrings = Some(addr_keyrings);
        self.addresses = Some(addr_resp.addresses);
        self.state = State::Authenticated;

        info!(email = %auth_route.primary_email, "SMTP authentication successful");
        self.write_line(235, "Authentication successful").await
    }

    async fn cmd_mail_from(&mut self, args: &str) -> Result<()> {
        if self.state != State::Authenticated {
            return self.write_line(503, "Bad sequence of commands").await;
        }

        let addr = extract_angle_addr(args);
        if addr.is_empty() {
            return self.write_line(501, "Syntax error in MAIL FROM").await;
        }

        // Validate that this is one of the user's send-enabled addresses
        let addresses = self.addresses.as_ref().unwrap();
        let addr_lower = addr.to_lowercase();
        let valid = addresses
            .iter()
            .any(|a| a.status == 1 && a.send == 1 && a.email.to_lowercase() == addr_lower);

        if !valid {
            return self.write_line(550, "Sender address not authorized").await;
        }

        self.mail_from = Some(addr);
        self.rcpt_to.clear();
        self.state = State::MailFrom;
        self.write_line(250, "OK").await
    }

    async fn cmd_rcpt_to(&mut self, args: &str) -> Result<()> {
        if self.state != State::MailFrom && self.state != State::RcptTo {
            return self.write_line(503, "Bad sequence of commands").await;
        }

        let addr = extract_angle_addr(args);
        if addr.is_empty() {
            return self.write_line(501, "Syntax error in RCPT TO").await;
        }

        self.rcpt_to.push(addr);
        self.state = State::RcptTo;
        self.write_line(250, "OK").await
    }

    async fn cmd_data(&mut self) -> Result<()> {
        if self.state != State::RcptTo {
            return self.write_line(503, "Bad sequence of commands").await;
        }

        self.state = State::Data;
        self.write_line(354, "Start mail input; end with <CRLF>.<CRLF>")
            .await
    }

    async fn read_data(&mut self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).await?;
            if n == 0 {
                break;
            }
            if line.trim_end() == "." {
                break;
            }
            // Remove dot-stuffing
            if line.starts_with("..") {
                data.extend_from_slice(&line.as_bytes()[1..]);
            } else {
                data.extend_from_slice(line.as_bytes());
            }
        }
        Ok(data)
    }

    async fn handle_data_content(&mut self, data: &[u8]) -> Result<()> {
        let client = match &self.client {
            Some(c) => c,
            None => {
                self.write_line(451, "Internal error").await?;
                self.state = State::Authenticated;
                return Ok(());
            }
        };

        let mail_from = self.mail_from.as_ref().unwrap().clone();
        let rcpt_to = self.rcpt_to.clone();
        let addresses = self.addresses.as_deref().unwrap();

        // Find the sender address and its keyring
        let sender_addr = addresses
            .iter()
            .find(|a| a.status == 1 && a.send == 1 && a.email.eq_ignore_ascii_case(&mail_from));

        let sender_keyring = match sender_addr {
            Some(addr) => match self.addr_keyrings.as_ref().and_then(|kr| kr.get(&addr.id)) {
                Some(kr) => kr,
                None => {
                    self.write_line(451, "No keyring for sender address")
                        .await?;
                    self.state = State::Authenticated;
                    return Ok(());
                }
            },
            None => {
                self.write_line(550, "Sender address not found").await?;
                self.state = State::Authenticated;
                return Ok(());
            }
        };

        match super::send::send_message(
            client,
            sender_keyring,
            addresses,
            &mail_from,
            &rcpt_to,
            data,
        )
        .await
        {
            Ok(()) => {
                self.write_line(250, "OK message sent").await?;
            }
            Err(e) => {
                warn!(error = %e, "failed to send message");
                self.write_line(451, &format!("Send failed: {}", e)).await?;
            }
        }

        // Reset transaction state
        self.mail_from = None;
        self.rcpt_to.clear();
        self.state = State::Authenticated;
        Ok(())
    }

    async fn cmd_rset(&mut self) -> Result<()> {
        self.mail_from = None;
        self.rcpt_to.clear();
        if self.state == State::MailFrom || self.state == State::RcptTo || self.state == State::Data
        {
            self.state = State::Authenticated;
        }
        self.write_line(250, "OK").await
    }
}

fn split_command(line: &str) -> (&str, &str) {
    match line.find(' ') {
        Some(pos) => (&line[..pos], line[pos + 1..].trim()),
        None => (line, ""),
    }
}

fn extract_angle_addr(args: &str) -> String {
    // Handle "FROM:<addr>" or "TO:<addr>"
    let s = if let Some(pos) = args.find(':') {
        &args[pos + 1..]
    } else {
        args
    };

    let s = s.trim();

    if let Some(start) = s.find('<') {
        if let Some(end) = s.find('>') {
            return s[start + 1..end].trim().to_string();
        }
    }

    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::accounts::AccountHealth;
    use crate::bridge::accounts::{AccountRegistry, RuntimeAccountRegistry};
    use crate::bridge::auth_router::AuthRouter;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_session() -> crate::api::types::Session {
        crate::api::types::Session {
            uid: "test-uid".to_string(),
            access_token: "test-token".to_string(),
            refresh_token: "test-refresh".to_string(),
            email: "test@proton.me".to_string(),
            display_name: "Test User".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: Some("dGVzdA==".to_string()),
            bridge_password: Some("bridge-pass-1234".to_string()),
        }
    }

    fn test_config() -> Arc<SmtpSessionConfig> {
        let session = test_session();
        let accounts = AccountRegistry::from_single_session(session.clone());
        Arc::new(SmtpSessionConfig {
            api_base_url: "https://mail-api.proton.me".to_string(),
            auth_router: AuthRouter::new(accounts),
            runtime_accounts: Arc::new(RuntimeAccountRegistry::in_memory(vec![session])),
        })
    }

    fn multi_account_config(api_base_url: &str) -> Arc<SmtpSessionConfig> {
        let account_a = crate::api::types::Session {
            uid: "uid-a".to_string(),
            access_token: "access-a".to_string(),
            refresh_token: "refresh-a".to_string(),
            email: "alice@proton.me".to_string(),
            display_name: "Alice".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: Some("dGVzdA==".to_string()),
            bridge_password: Some("pass-a".to_string()),
        };
        let account_b = crate::api::types::Session {
            uid: "uid-b".to_string(),
            access_token: "access-b".to_string(),
            refresh_token: "refresh-b".to_string(),
            email: "bob@proton.me".to_string(),
            display_name: "Bob".to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: Some("dGVzdA==".to_string()),
            bridge_password: Some("pass-b".to_string()),
        };
        let accounts = AccountRegistry::from_sessions(vec![account_a.clone(), account_b.clone()]);
        let runtime_accounts = Arc::new(RuntimeAccountRegistry::in_memory(vec![
            account_a, account_b,
        ]));
        Arc::new(SmtpSessionConfig {
            api_base_url: api_base_url.to_string(),
            auth_router: AuthRouter::new(accounts),
            runtime_accounts,
        })
    }

    async fn create_session_pair(
        config: Arc<SmtpSessionConfig>,
    ) -> (
        SmtpSession<tokio::io::DuplexStream, tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    ) {
        let (client_read, server_write) = tokio::io::duplex(8192);
        let (server_read, client_write) = tokio::io::duplex(8192);

        let session = SmtpSession::new(server_read, server_write, config);
        (session, client_read, client_write)
    }

    async fn read_response(read: &mut tokio::io::DuplexStream) -> String {
        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(read, &mut buf).await.unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    }

    #[tokio::test]
    async fn test_greeting() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session
            .write_line(220, "openproton-bridge ESMTP ready")
            .await
            .unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("220"));
        assert!(response.contains("openproton-bridge"));
    }

    #[tokio::test]
    async fn test_ehlo() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.cmd_ehlo("localhost").await.unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("250"));
        assert!(response.contains("AUTH PLAIN"));
        assert!(response.contains("8BITMIME"));
        assert!(response.contains("PIPELINING"));
    }

    #[tokio::test]
    async fn test_ehlo_requires_hostname() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.cmd_ehlo("").await.unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("501"));
    }

    #[tokio::test]
    async fn test_auth_wrong_password() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.state = State::Greeted;

        // Encode \0test@proton.me\0wrongpassword
        let auth_data = BASE64.encode(b"\0test@proton.me\0wrongpassword");
        let args = format!("PLAIN {}", auth_data);
        session.cmd_auth(&args).await.unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("535"));
    }

    #[tokio::test]
    async fn test_auth_isolation_unavailable_account_does_not_block_other_account() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/core/v4/users"))
            .and(header("x-pm-uid", "uid-b"))
            .and(header("Authorization", "Bearer access-b"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "User": {
                    "ID": "user-b",
                    "Name": "bob",
                    "DisplayName": "Bob",
                    "Email": "bob@proton.me",
                    "Keys": []
                }
            })))
            .mount(&server)
            .await;

        let config = multi_account_config(&server.uri());
        config
            .runtime_accounts
            .set_health(
                &crate::bridge::types::AccountId("uid-a".to_string()),
                AccountHealth::Unavailable,
            )
            .await
            .unwrap();

        // Unavailable account should fail immediately.
        let (mut unavailable_session, mut unavailable_read, _w1) =
            create_session_pair(config.clone()).await;
        unavailable_session.state = State::Greeted;
        let bad = BASE64.encode(b"\0alice@proton.me\0pass-a");
        unavailable_session
            .cmd_auth(&format!("PLAIN {}", bad))
            .await
            .unwrap();
        let unavailable_response = read_response(&mut unavailable_read).await;
        assert!(unavailable_response.contains("535"));

        // Healthy account should continue to per-account processing path.
        let (mut healthy_session, mut healthy_read, _w2) = create_session_pair(config).await;
        healthy_session.state = State::Greeted;
        let good = BASE64.encode(b"\0bob@proton.me\0pass-b");
        healthy_session
            .cmd_auth(&format!("PLAIN {}", good))
            .await
            .unwrap();
        let healthy_response = read_response(&mut healthy_read).await;
        assert!(healthy_response.contains("454"));
    }

    #[tokio::test]
    async fn test_auth_wrong_username() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.state = State::Greeted;

        let auth_data = BASE64.encode(b"\0wrong@proton.me\0bridge-pass-1234");
        let args = format!("PLAIN {}", auth_data);
        session.cmd_auth(&args).await.unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("535"));
    }

    #[tokio::test]
    async fn test_auth_before_ehlo() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        // State is Connected (no EHLO yet)
        let auth_data = BASE64.encode(b"\0test@proton.me\0bridge-pass-1234");
        let args = format!("PLAIN {}", auth_data);
        session.cmd_auth(&args).await.unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("503"));
    }

    #[tokio::test]
    async fn test_mail_from_before_auth() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.state = State::Greeted;
        session
            .cmd_mail_from("FROM:<test@proton.me>")
            .await
            .unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("503"));
    }

    #[tokio::test]
    async fn test_mail_from_valid_sender() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.state = State::Authenticated;
        session.addresses = Some(vec![Address {
            id: "addr-1".to_string(),
            email: "test@proton.me".to_string(),
            status: 1,
            receive: 1,
            send: 1,
            address_type: 1,
            display_name: "Test User".to_string(),
            keys: vec![],
        }]);

        session
            .cmd_mail_from("FROM:<test@proton.me>")
            .await
            .unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("250"));
        assert_eq!(session.mail_from.as_deref(), Some("test@proton.me"));
    }

    #[tokio::test]
    async fn test_mail_from_invalid_sender() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.state = State::Authenticated;
        session.addresses = Some(vec![Address {
            id: "addr-1".to_string(),
            email: "test@proton.me".to_string(),
            status: 1,
            receive: 1,
            send: 1,
            address_type: 1,
            display_name: "Test User".to_string(),
            keys: vec![],
        }]);

        session
            .cmd_mail_from("FROM:<unauthorized@other.com>")
            .await
            .unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("550"));
    }

    #[tokio::test]
    async fn test_rcpt_to() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.state = State::MailFrom;
        session.cmd_rcpt_to("TO:<bob@example.com>").await.unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("250"));
        assert_eq!(session.rcpt_to, vec!["bob@example.com"]);

        // Can add multiple recipients
        session
            .cmd_rcpt_to("TO:<charlie@example.com>")
            .await
            .unwrap();
        let response = read_response(&mut client_read).await;
        assert!(response.contains("250"));
        assert_eq!(session.rcpt_to.len(), 2);
    }

    #[tokio::test]
    async fn test_rcpt_to_before_mail_from() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.state = State::Authenticated;
        session.cmd_rcpt_to("TO:<bob@example.com>").await.unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("503"));
    }

    #[tokio::test]
    async fn test_data_before_rcpt() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.state = State::MailFrom;
        session.cmd_data().await.unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("503"));
    }

    #[tokio::test]
    async fn test_rset() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.state = State::RcptTo;
        session.mail_from = Some("test@proton.me".to_string());
        session.rcpt_to = vec!["bob@example.com".to_string()];

        session.cmd_rset().await.unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("250"));
        assert!(session.mail_from.is_none());
        assert!(session.rcpt_to.is_empty());
        assert_eq!(session.state, State::Authenticated);
    }

    #[tokio::test]
    async fn test_noop() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.handle_command("NOOP").await.unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("250"));
    }

    #[tokio::test]
    async fn test_quit() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        let action = session.handle_command("QUIT").await.unwrap();
        assert!(matches!(action, SessionAction::Close));

        let response = read_response(&mut client_read).await;
        assert!(response.contains("221"));
    }

    #[tokio::test]
    async fn test_unknown_command() {
        let config = test_config();
        let (mut session, mut client_read, _client_write) = create_session_pair(config).await;

        session.handle_command("BOGUS").await.unwrap();

        let response = read_response(&mut client_read).await;
        assert!(response.contains("502"));
    }

    #[test]
    fn test_extract_angle_addr() {
        assert_eq!(
            extract_angle_addr("FROM:<alice@proton.me>"),
            "alice@proton.me"
        );
        assert_eq!(
            extract_angle_addr("TO:<bob@example.com>"),
            "bob@example.com"
        );
        assert_eq!(
            extract_angle_addr("FROM: <alice@proton.me>"),
            "alice@proton.me"
        );
    }

    #[test]
    fn test_split_command() {
        assert_eq!(split_command("EHLO localhost"), ("EHLO", "localhost"));
        assert_eq!(split_command("QUIT"), ("QUIT", ""));
        assert_eq!(
            split_command("AUTH PLAIN dGVzdA=="),
            ("AUTH", "PLAIN dGVzdA==")
        );
    }
}
