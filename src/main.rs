#![allow(dead_code)]

use std::sync::Arc;

use anyhow::Context;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::{Parser, Subcommand};

mod api;
mod bridge;
mod crypto;
mod imap;
mod smtp;
mod vault;

#[derive(Parser)]
#[command(
    name = "openproton-bridge",
    about = "Proton Mail bridge for free accounts"
)]
struct Cli {
    /// Vault directory (default: ~/.config/openproton-bridge)
    #[arg(long, global = true)]
    vault_dir: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Log in to your Proton Mail account
    Login {
        /// Proton Mail username or email
        #[arg(short, long)]
        username: Option<String>,
    },
    /// Show account/session info
    Status,
    /// Log out one account or clear all saved sessions
    Logout {
        /// Account email to remove
        #[arg(long, conflicts_with = "all")]
        email: Option<String>,
        /// Remove all accounts
        #[arg(long)]
        all: bool,
    },
    /// Manage saved accounts
    Accounts {
        #[command(subcommand)]
        command: AccountsCommand,
    },
    /// Fetch and decrypt inbox messages
    Fetch {
        /// Maximum number of messages to fetch
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    /// Start the IMAP and SMTP servers
    Serve {
        /// IMAP port to listen on
        #[arg(long, default_value = "1143")]
        imap_port: u16,
        /// SMTP port to listen on
        #[arg(long, default_value = "1025")]
        smtp_port: u16,
        /// Address to bind to
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        /// Disable TLS (plaintext only)
        #[arg(long)]
        no_tls: bool,
        /// Event worker poll interval in seconds
        #[arg(long, default_value = "30")]
        event_poll_secs: u64,
    },
}

#[derive(Subcommand)]
enum AccountsCommand {
    /// List all saved accounts
    List,
    /// Set the default account used by fetch/serve
    Use {
        /// Account email to set as default
        email: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let dir = session_dir(cli.vault_dir.as_deref())?;

    match cli.command {
        Command::Login { username } => cmd_login(username, &dir).await,
        Command::Status => cmd_status(&dir),
        Command::Logout { email, all } => cmd_logout(email.as_deref(), all, &dir),
        Command::Accounts { command } => match command {
            AccountsCommand::List => cmd_accounts_list(&dir),
            AccountsCommand::Use { email } => cmd_accounts_use(&email, &dir),
        },
        Command::Fetch { limit } => cmd_fetch(limit, &dir).await,
        Command::Serve {
            imap_port,
            smtp_port,
            bind,
            no_tls,
            event_poll_secs,
        } => cmd_serve(imap_port, smtp_port, &bind, no_tls, event_poll_secs, &dir).await,
    }
}

async fn cmd_login(username_arg: Option<String>, dir: &std::path::Path) -> anyhow::Result<()> {
    let username = match username_arg {
        Some(u) => u,
        None => {
            eprint!("Username: ");
            let mut input = String::new();
            std::io::stdin()
                .read_line(&mut input)
                .context("failed to read username")?;
            input.trim().to_string()
        }
    };

    if username.is_empty() {
        anyhow::bail!("username cannot be empty");
    }

    let password = rpassword::prompt_password("Password: ").context("failed to read password")?;

    let mut client = api::client::ProtonClient::new()?;

    // SRP authentication
    let auth = api::auth::login(&mut client, &username, &password).await?;

    // Handle 2FA if required
    if auth.two_factor.totp_required() {
        let code = rpassword::prompt_password("2FA code: ").context("failed to read 2FA code")?;
        api::auth::submit_2fa(&client, code.trim()).await?;
    }

    // Fetch user info
    let user_resp = api::users::get_user(&client).await?;
    let user = &user_resp.user;

    // Fetch addresses
    let addr_resp = api::users::get_addresses(&client).await?;

    // Derive mailbox passphrase from salts
    let salts_resp = api::users::get_salts(&client).await?;
    let key_passphrase = if let Some(primary_key) = user.keys.iter().find(|k| k.active == 1) {
        match api::srp::salt_for_key(password.as_bytes(), &primary_key.id, &salts_resp.key_salts) {
            Ok(passphrase) => Some(BASE64.encode(&passphrase)),
            Err(e) => {
                tracing::warn!(error = %e, "could not derive key passphrase (non-fatal)");
                None
            }
        }
    } else {
        tracing::warn!("no active user key found for passphrase derivation");
        None
    };

    // Generate bridge password
    let bridge_password = generate_bridge_password();

    // Build session
    let session = api::types::Session {
        uid: auth.uid,
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
        email: user.email.clone(),
        display_name: user.display_name.clone(),
        key_passphrase,
        bridge_password: Some(bridge_password.clone()),
    };

    vault::save_session(&session, dir)?;
    vault::set_default_email(dir, &session.email)?;

    println!("Logged in as {} ({})", user.display_name, user.email);
    if !addr_resp.addresses.is_empty() {
        println!("Addresses:");
        for addr in &addr_resp.addresses {
            let status = if addr.status == 1 {
                "active"
            } else {
                "disabled"
            };
            println!("  {} ({})", addr.email, status);
        }
    }
    println!();
    println!("Bridge password: {}", bridge_password);
    println!("Use this password to connect your email client.");

    Ok(())
}

fn cmd_status(dir: &std::path::Path) -> anyhow::Result<()> {
    let sessions = vault::list_sessions(dir).context("failed to load sessions")?;
    if sessions.is_empty() {
        println!("Not logged in");
        return Ok(());
    }

    let default_email = vault::get_default_email(dir).context("failed to load default account")?;
    println!("Accounts:");
    for session in &sessions {
        let is_default = default_email
            .as_deref()
            .is_some_and(|email| email.eq_ignore_ascii_case(&session.email));
        let default_marker = if is_default { " (default)" } else { "" };
        println!(
            "  {} ({}){}",
            session.display_name, session.email, default_marker
        );
    }
    println!();

    let active = vault::load_session(dir).context("failed to load active account")?;
    println!("Active account: {}", active.email);
    if active.key_passphrase.is_some() {
        println!("Key passphrase: stored");
    } else {
        println!("Key passphrase: not stored (fetch will not work)");
    }
    if let Some(ref bp) = active.bridge_password {
        println!("Bridge password: {}", bp);
    } else {
        println!("Bridge password: not set (re-login to generate)");
    }
    Ok(())
}

fn cmd_logout(email: Option<&str>, all: bool, dir: &std::path::Path) -> anyhow::Result<()> {
    if !vault::session_exists(dir) {
        println!("Not logged in");
        return Ok(());
    }

    if all {
        vault::remove_session(dir)?;
        println!("Logged out all accounts");
    } else if let Some(email) = email {
        vault::remove_session_by_email(dir, email)?;
        println!("Removed account: {}", email);
    } else {
        vault::remove_session(dir)?;
        println!("Logged out all accounts");
    }
    Ok(())
}

fn cmd_accounts_list(dir: &std::path::Path) -> anyhow::Result<()> {
    cmd_status(dir)
}

fn cmd_accounts_use(email: &str, dir: &std::path::Path) -> anyhow::Result<()> {
    vault::set_default_email(dir, email)?;
    println!("Default account set to {}", email);
    Ok(())
}

async fn cmd_fetch(limit: usize, dir: &std::path::Path) -> anyhow::Result<()> {
    let mut session = vault::load_session(dir).context("failed to load session")?;

    // If access_token is empty (Go vault format), refresh it
    if session.access_token.is_empty() {
        session = refresh_session(session, dir).await?;
    }

    let passphrase_b64 = session
        .key_passphrase
        .as_deref()
        .context("no key passphrase in session -- please log in again")?;

    let passphrase = BASE64
        .decode(passphrase_b64)
        .context("invalid key passphrase encoding")?;

    let client = api::client::ProtonClient::authenticated(
        "https://mail-api.proton.me",
        &session.uid,
        &session.access_token,
    )?;

    // Fetch user keys and addresses
    let user_resp = api::users::get_user(&client).await?;
    let addr_resp = api::users::get_addresses(&client).await?;

    // Unlock user keys
    let user_keyring = crypto::keys::unlock_user_keys(&user_resp.user.keys, &passphrase)
        .context("failed to unlock user keys")?;

    // Build address keyrings
    let mut addr_keyrings = std::collections::HashMap::new();
    for addr in &addr_resp.addresses {
        if addr.status != 1 || addr.keys.is_empty() {
            continue;
        }
        match crypto::keys::unlock_address_keys(&addr.keys, &passphrase, &user_keyring) {
            Ok(kr) => {
                addr_keyrings.insert(addr.id.clone(), kr);
            }
            Err(e) => {
                tracing::warn!(address = %addr.email, error = %e, "could not unlock address keys");
            }
        }
    }

    if addr_keyrings.is_empty() {
        anyhow::bail!("could not unlock any address keys");
    }

    // Fetch inbox message metadata
    let filter = api::types::MessageFilter {
        label_id: Some(api::types::INBOX_LABEL.to_string()),
        desc: 1,
        ..Default::default()
    };

    let meta_resp = api::messages::get_message_metadata(&client, &filter, 0, limit as i32).await?;

    if meta_resp.messages.is_empty() {
        println!("Inbox is empty.");
        return Ok(());
    }

    println!("Inbox ({} total):\n", meta_resp.total);

    for (i, meta) in meta_resp.messages.iter().enumerate() {
        // Fetch full message
        let msg_resp = match api::messages::get_message(&client, &meta.id).await {
            Ok(r) => r,
            Err(e) => {
                println!("{}. [error fetching message {}]: {}\n", i + 1, meta.id, e);
                continue;
            }
        };

        let msg = &msg_resp.message;

        // Find address keyring
        let keyring = match addr_keyrings.get(&msg.metadata.address_id) {
            Some(kr) => kr,
            None => {
                println!(
                    "{}. {} -- from: {} <{}>\n   [no keyring for address {}]\n",
                    i + 1,
                    msg.metadata.subject,
                    msg.metadata.sender.name,
                    msg.metadata.sender.address,
                    msg.metadata.address_id,
                );
                continue;
            }
        };

        // Decrypt body
        let body_preview = match crypto::decrypt::decrypt_message_body(keyring, &msg.body) {
            Ok(plaintext) => {
                let text = String::from_utf8_lossy(&plaintext);
                let preview: String = text.chars().take(200).collect();
                preview
            }
            Err(e) => {
                format!("[decryption failed: {}]", e)
            }
        };

        let unread_marker = if msg.metadata.unread != 0 { " *" } else { "" };
        let time = chrono_format(msg.metadata.time);

        println!(
            "{}. {}{}\n   From: {} <{}>\n   Date: {}\n   Attachments: {}\n   ---\n   {}\n",
            i + 1,
            msg.metadata.subject,
            unread_marker,
            msg.metadata.sender.name,
            msg.metadata.sender.address,
            time,
            msg.metadata.num_attachments,
            body_preview,
        );
    }

    Ok(())
}

async fn cmd_serve(
    imap_port: u16,
    smtp_port: u16,
    bind: &str,
    no_tls: bool,
    event_poll_secs: u64,
    dir: &std::path::Path,
) -> anyhow::Result<()> {
    // Reject --no-tls with non-loopback bind address
    if no_tls {
        let addr: std::net::IpAddr = bind.parse().context("invalid bind address")?;
        if !addr.is_loopback() {
            anyhow::bail!(
                "refusing to run without TLS on non-loopback address {}. \
                 Use 127.0.0.1 with --no-tls, or remove --no-tls for STARTTLS.",
                bind
            );
        }
    }

    let sessions = vault::list_sessions(dir).context("failed to load sessions")?;
    if sessions.is_empty() {
        anyhow::bail!("not logged in -- run `openproton-bridge login` first");
    }

    let mut active_sessions = Vec::new();
    for mut session in sessions {
        if session.access_token.is_empty() {
            let email = session.email.clone();
            match refresh_session(session, dir).await {
                Ok(refreshed) => session = refreshed,
                Err(e) => {
                    tracing::warn!(
                        email = %email,
                        error = %e,
                        "skipping account: failed to refresh token"
                    );
                    continue;
                }
            }
        }

        if session.bridge_password.is_none() {
            let bridge_password = generate_bridge_password();
            session.bridge_password = Some(bridge_password);
            vault::save_session(&session, dir)?;
        }

        active_sessions.push(session);
    }

    if active_sessions.is_empty() {
        anyhow::bail!("no usable accounts available after token refresh");
    }

    let mut account_registry =
        bridge::accounts::AccountRegistry::from_sessions(active_sessions.clone());
    for session in &active_sessions {
        let client = match api::client::ProtonClient::authenticated(
            "https://mail-api.proton.me",
            &session.uid,
            &session.access_token,
        ) {
            Ok(client) => client,
            Err(e) => {
                tracing::warn!(
                    email = %session.email,
                    error = %e,
                    "skipping address index refresh for account"
                );
                continue;
            }
        };

        match api::users::get_addresses(&client).await {
            Ok(addresses) => {
                let account_id = bridge::types::AccountId(session.uid.clone());
                for address in addresses.addresses {
                    if address.status == 1 {
                        account_registry.add_address_email(&account_id, &address.email);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    email = %session.email,
                    error = %e,
                    "failed to refresh address index for account"
                );
            }
        }
    }
    let auth_router = bridge::auth_router::AuthRouter::new(account_registry);
    let runtime_accounts = Arc::new(bridge::accounts::RuntimeAccountRegistry::new(
        active_sessions.clone(),
        dir.to_path_buf(),
    ));
    let runtime_snapshot = runtime_accounts.snapshot().await;
    let api_base_url = "https://mail-api.proton.me".to_string();

    let store = imap::store::InMemoryStore::new();
    let event_store: Arc<dyn imap::store::MessageStore> = store.clone();

    let imap_config = imap::session::SessionConfig {
        api_base_url: api_base_url.clone(),
        auth_router: auth_router.clone(),
        runtime_accounts: runtime_accounts.clone(),
        store,
    };

    let imap_config = Arc::new(imap_config);

    let smtp_config = smtp::session::SmtpSessionConfig {
        api_base_url: api_base_url.clone(),
        auth_router: auth_router.clone(),
        runtime_accounts: runtime_accounts.clone(),
    };

    let smtp_config = Arc::new(smtp_config);

    if !no_tls {
        let cert_dir = dir.join("tls");
        let _imap_server = imap::server::ImapServer::new().with_tls(&cert_dir)?;
        let _smtp_server = smtp::server::SmtpServer::new().with_tls(&cert_dir)?;
    }

    let imap_addr = format!("{}:{}", bind, imap_port);
    let smtp_addr = format!("{}:{}", bind, smtp_port);

    println!("IMAP server configuration:");
    println!("  Server: {}", bind);
    println!("  Port: {}", imap_port);
    println!("  Security: {}", if no_tls { "None" } else { "STARTTLS" });
    println!("  Accounts:");
    for session in &active_sessions {
        let password = session
            .bridge_password
            .as_deref()
            .unwrap_or("<missing-bridge-password>");
        println!("    {} / {}", session.email, password);
    }
    println!("  Health:");
    for info in &runtime_snapshot {
        println!(
            "    {} ({}) = {:?}",
            info.email, info.account_id.0, info.health
        );
    }
    println!();
    println!("SMTP server configuration:");
    println!("  Server: {}", bind);
    println!("  Port: {}", smtp_port);
    println!("  Security: {}", if no_tls { "None" } else { "STARTTLS" });
    println!("  Accounts:");
    for session in &active_sessions {
        let password = session
            .bridge_password
            .as_deref()
            .unwrap_or("<missing-bridge-password>");
        println!("    {} / {}", session.email, password);
    }
    println!("  Health:");
    for info in &runtime_snapshot {
        println!(
            "    {} ({}) = {:?}",
            info.email, info.account_id.0, info.health
        );
    }
    println!();

    let checkpoint_store: bridge::events::SharedCheckpointStore =
        Arc::new(bridge::events::VaultCheckpointStore::new(dir.to_path_buf()));
    let event_workers = bridge::events::start_event_worker_group(
        runtime_accounts.clone(),
        runtime_snapshot.clone(),
        api_base_url,
        auth_router.clone(),
        event_store,
        checkpoint_store,
        std::time::Duration::from_secs(event_poll_secs),
    );

    let health_task = tokio::spawn(report_runtime_health_periodically(runtime_accounts.clone()));

    let serve_result: anyhow::Result<()> = tokio::select! {
        result = imap::server::run_server(&imap_addr, imap_config) => {
            result.map_err(anyhow::Error::from)
        }
        result = smtp::server::run_server(&smtp_addr, smtp_config) => {
            result.map_err(anyhow::Error::from)
        }
    };

    health_task.abort();
    let _ = health_task.await;
    event_workers.shutdown().await;

    serve_result?;

    Ok(())
}

fn generate_bridge_password() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..16)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn chrono_format(unix_timestamp: i64) -> String {
    // Simple timestamp formatting without pulling in chrono
    let secs = unix_timestamp;
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;

    // Rough date calculation (good enough for display)
    let mut year = 1970i64;
    let mut remaining_days = days_since_epoch;

    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            366
        } else {
            365
        };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_months = [
        31,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    let mut month = 1;
    for &dim in &days_in_months {
        if remaining_days < dim {
            break;
        }
        remaining_days -= dim;
        month += 1;
    }

    let day = remaining_days + 1;

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        year, month, day, hours, minutes
    )
}

/// Refresh an expired/missing access token using the stored refresh token.
/// Updates the vault with the new tokens and returns the updated session.
async fn refresh_session(
    session: api::types::Session,
    dir: &std::path::Path,
) -> anyhow::Result<api::types::Session> {
    tracing::info!("access token missing, refreshing via stored refresh token");
    let mut client = api::client::ProtonClient::new()?;
    let auth = api::auth::refresh_auth(
        &mut client,
        &session.uid,
        &session.refresh_token,
        Some(&session.access_token),
    )
    .await?;

    let refreshed = api::types::Session {
        uid: auth.uid,
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
        ..session
    };

    vault::save_session(&refreshed, dir)?;
    Ok(refreshed)
}

fn session_dir(override_dir: Option<&std::path::Path>) -> anyhow::Result<std::path::PathBuf> {
    if let Some(dir) = override_dir {
        return Ok(dir.to_path_buf());
    }
    let config_dir = dirs::config_dir()
        .context("could not determine config directory")?
        .join("openproton-bridge");
    Ok(config_dir)
}

async fn report_runtime_health_periodically(
    runtime_accounts: Arc<bridge::accounts::RuntimeAccountRegistry>,
) {
    use tokio::time::{interval, Duration, MissedTickBehavior};

    let mut ticker = interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker.tick().await;

    loop {
        ticker.tick().await;
        let snapshot = runtime_accounts.snapshot().await;
        let mut healthy = 0usize;
        let mut degraded = 0usize;
        let mut unavailable = 0usize;

        for info in &snapshot {
            match info.health {
                bridge::accounts::AccountHealth::Healthy => healthy += 1,
                bridge::accounts::AccountHealth::Degraded => degraded += 1,
                bridge::accounts::AccountHealth::Unavailable => unavailable += 1,
            }
        }

        tracing::info!(
            total_accounts = snapshot.len(),
            healthy,
            degraded,
            unavailable,
            "runtime account health snapshot"
        );

        for info in &snapshot {
            if matches!(info.health, bridge::accounts::AccountHealth::Unavailable) {
                tracing::warn!(
                    account_id = %info.account_id.0,
                    email = %info.email,
                    health = ?info.health,
                    "account unavailable while server is running"
                );
            } else {
                tracing::debug!(
                    account_id = %info.account_id.0,
                    email = %info.email,
                    health = ?info.health,
                    "account runtime health detail"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_logout_email_flag() {
        let cli =
            Cli::try_parse_from(["openproton-bridge", "logout", "--email", "alice@proton.me"])
                .unwrap();

        match cli.command {
            Command::Logout { email, all } => {
                assert_eq!(email.as_deref(), Some("alice@proton.me"));
                assert!(!all);
            }
            _ => panic!("expected logout command"),
        }
    }

    #[test]
    fn parse_logout_all_flag() {
        let cli = Cli::try_parse_from(["openproton-bridge", "logout", "--all"]).unwrap();

        match cli.command {
            Command::Logout { email, all } => {
                assert!(email.is_none());
                assert!(all);
            }
            _ => panic!("expected logout command"),
        }
    }

    #[test]
    fn parse_accounts_use_subcommand() {
        let cli =
            Cli::try_parse_from(["openproton-bridge", "accounts", "use", "bob@proton.me"]).unwrap();

        match cli.command {
            Command::Accounts { command } => match command {
                AccountsCommand::Use { email } => assert_eq!(email, "bob@proton.me"),
                _ => panic!("expected accounts use subcommand"),
            },
            _ => panic!("expected accounts command"),
        }
    }

    #[test]
    fn parse_serve_event_poll_secs_flag() {
        let cli =
            Cli::try_parse_from(["openproton-bridge", "serve", "--event-poll-secs", "10"]).unwrap();

        match cli.command {
            Command::Serve {
                event_poll_secs, ..
            } => assert_eq!(event_poll_secs, 10),
            _ => panic!("expected serve command"),
        }
    }
}
