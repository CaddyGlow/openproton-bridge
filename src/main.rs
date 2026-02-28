use anyhow::Context;
use clap::{Parser, Subcommand};

mod api;
mod bridge;
mod crypto;
mod imap;
mod smtp;

#[derive(Parser)]
#[command(
    name = "openproton-bridge",
    about = "Proton Mail bridge for free accounts"
)]
struct Cli {
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
    /// Show current session info
    Status,
    /// Log out and clear saved session
    Logout,
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

    match cli.command {
        Command::Login { username } => cmd_login(username).await,
        Command::Status => cmd_status(),
        Command::Logout => cmd_logout(),
    }
}

async fn cmd_login(username_arg: Option<String>) -> anyhow::Result<()> {
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

    // Build session
    let session = api::types::Session {
        uid: auth.uid,
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
        email: user.email.clone(),
        display_name: user.display_name.clone(),
    };

    save_session(&session)?;

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

    Ok(())
}

fn cmd_status() -> anyhow::Result<()> {
    let session = load_session()?;
    println!("Logged in as {} ({})", session.display_name, session.email);
    Ok(())
}

fn cmd_logout() -> anyhow::Result<()> {
    let path = session_path()?;
    if path.exists() {
        std::fs::remove_file(&path)?;
        println!("Logged out");
    } else {
        println!("Not logged in");
    }
    Ok(())
}

fn session_dir() -> anyhow::Result<std::path::PathBuf> {
    let config_dir = dirs::config_dir()
        .context("could not determine config directory")?
        .join("openproton-bridge");
    Ok(config_dir)
}

fn session_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(session_dir()?.join("session.json"))
}

fn save_session(session: &api::types::Session) -> anyhow::Result<()> {
    let dir = session_dir()?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("session.json");
    let json = serde_json::to_string_pretty(session)?;
    std::fs::write(&path, json)?;

    // Restrict permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

fn load_session() -> anyhow::Result<api::types::Session> {
    let path = session_path()?;
    if !path.exists() {
        anyhow::bail!("not logged in -- run `openproton-bridge login` first");
    }
    let data = std::fs::read_to_string(&path)?;
    let session: api::types::Session = serde_json::from_str(&data)?;
    Ok(session)
}
