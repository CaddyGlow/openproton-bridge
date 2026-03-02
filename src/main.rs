#![allow(dead_code)]

use std::process::Command as ProcessCommand;
use std::sync::Arc;

use anyhow::Context;
use base64::engine::general_purpose::{
    STANDARD as BASE64, STANDARD_NO_PAD as BASE64_NO_PAD, URL_SAFE as BASE64_URL,
    URL_SAFE_NO_PAD as BASE64_URL_NO_PAD,
};
use base64::Engine;
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

mod api;
mod bridge;
mod crypto;
mod frontend;
mod imap;
mod paths;
mod smtp;
mod vault;

#[derive(Parser)]
#[command(
    name = "openproton-bridge",
    about = "Proton Mail bridge for free accounts"
)]
struct Cli {
    /// Runtime settings directory override (default: Proton Bridge path)
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
    /// Generate FIDO assertion JSON using a hardware security key
    FidoAssert {
        /// FIDO authentication options JSON payload
        #[arg(long, conflicts_with = "auth_options_file")]
        auth_options_json: Option<String>,
        /// Path to a file containing FIDO authentication options JSON
        #[arg(long, conflicts_with = "auth_options_json")]
        auth_options_file: Option<std::path::PathBuf>,
        /// FIDO device path (for example /dev/hidraw0)
        #[arg(long)]
        device: Option<String>,
        /// Output file for the generated assertion JSON
        #[arg(long)]
        output: Option<std::path::PathBuf>,
        /// Security key PIN (if required)
        #[arg(long)]
        pin: Option<String>,
        /// FIDO provider path: auto, hardware, or os
        #[arg(long, default_value = "auto")]
        provider: FidoProvider,
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
    /// Start the gRPC frontend control service
    Grpc {
        /// Address to bind to (port is assigned automatically)
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
    },
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
enum FidoProvider {
    Auto,
    Hardware,
    Os,
}

#[derive(Subcommand)]
enum AccountsCommand {
    /// List all saved accounts
    List,
    /// Set the default account used by fetch/status
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
    let runtime_paths = runtime_paths(cli.vault_dir.as_deref())?;
    let dir = runtime_paths.settings_dir().to_path_buf();

    match cli.command {
        Command::Login { username } => cmd_login(username, &dir).await,
        Command::FidoAssert {
            auth_options_json,
            auth_options_file,
            device,
            output,
            pin,
            provider,
        } => cmd_fido_assert(
            auth_options_json,
            auth_options_file,
            device,
            output,
            pin,
            provider,
        ),
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
        } => {
            cmd_serve(
                imap_port,
                smtp_port,
                &bind,
                no_tls,
                event_poll_secs,
                &dir,
                &runtime_paths,
            )
            .await
        }
        Command::Grpc { bind } => cmd_grpc(&bind, &runtime_paths).await,
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

    // SRP authentication with optional human-verification retries.
    let mut hv_details: Option<api::types::HumanVerificationDetails> = None;
    let auth = loop {
        match api::auth::login(&mut client, &username, &password, hv_details.as_ref()).await {
            Ok(auth) => break auth,
            Err(err) => {
                let needs_hv = api::error::human_verification_details(&err).or_else(|| {
                    if matches!(&err, api::error::ApiError::Api { code: 12087, .. }) {
                        api::error::any_human_verification_details(&err)
                    } else {
                        None
                    }
                });

                if let Some(hv) = needs_hv {
                    let mut hv = hv;
                    if matches!(&err, api::error::ApiError::Api { code: 12087, .. }) {
                        eprintln!(
                            "CAPTCHA validation failed; please complete the challenge again."
                        );
                        eprintln!(
                            "If it still fails, capture the `pm_captcha` token from browser DevTools \
                             and paste it below."
                        );
                    } else {
                        eprintln!("Human verification required by Proton.");
                    }
                    eprintln!("Open this URL in your browser and complete the challenge:");
                    eprintln!("{}", hv.challenge_url());
                    eprint!("Press ENTER once verification is complete...");
                    let mut line = String::new();
                    std::io::stdin()
                        .read_line(&mut line)
                        .context("failed to read human verification confirmation")?;
                    eprint!(
                        "Paste CAPTCHA token from browser (optional, press ENTER to reuse URL token): "
                    );
                    line.clear();
                    std::io::stdin()
                        .read_line(&mut line)
                        .context("failed to read optional human verification token")?;
                    let token_override = line.trim();
                    if !token_override.is_empty() {
                        hv.human_verification_token = token_override.to_string();
                    }
                    hv_details = Some(hv);
                    continue;
                }

                return Err(err.into());
            }
        }
    };

    complete_cli_second_factor(&client, &auth).await?;

    // Fetch user info
    let user_resp = api::users::get_user(&client).await?;
    let user = &user_resp.user;

    // Fetch addresses
    let addr_resp = api::users::get_addresses(&client).await?;

    // Derive mailbox passphrase from salts
    let salts_resp = api::users::get_salts(&client).await?;
    let key_passphrase = {
        let mut derived = None;
        for key in user.keys.iter().filter(|k| k.active == 1) {
            match api::srp::salt_for_key(password.as_bytes(), &key.id, &salts_resp.key_salts) {
                Ok(passphrase) => {
                    derived = Some(BASE64.encode(&passphrase));
                    break;
                }
                Err(e) => {
                    tracing::debug!(key_id = %key.id, error = %e, "key passphrase derivation attempt failed");
                }
            }
        }
        if derived.is_none() {
            tracing::warn!("could not derive key passphrase from any active user key (non-fatal)");
        }
        derived
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

async fn complete_cli_second_factor(
    client: &api::client::ProtonClient,
    auth: &api::types::AuthResponse,
) -> anyhow::Result<()> {
    if !auth.two_factor.requires_second_factor() {
        return Ok(());
    }

    if auth.two_factor.totp_required() {
        let code = rpassword::prompt_password("2FA code: ").context("failed to read 2FA code")?;
        api::auth::submit_2fa(client, code.trim()).await?;
        return Ok(());
    }

    if auth.two_factor.fido_supported() {
        let auth_options = auth
            .two_factor
            .fido_authentication_options()
            .context("FIDO authentication options missing in auth response")?;
        let assertion_payload = read_cli_fido_assertion_payload(&auth_options)?;
        api::auth::submit_fido_2fa(client, &auth_options, assertion_payload.as_bytes()).await?;
        return Ok(());
    }

    anyhow::bail!("unsupported second-factor mode returned by API");
}

fn cmd_fido_assert(
    auth_options_json: Option<String>,
    auth_options_file: Option<std::path::PathBuf>,
    device: Option<String>,
    output: Option<std::path::PathBuf>,
    pin: Option<String>,
    provider: FidoProvider,
) -> anyhow::Result<()> {
    let auth_options = load_fido_authentication_options(auth_options_json, auth_options_file)?;
    let assertion = generate_fido_assertion_with_provider(
        &auth_options,
        provider,
        device.as_deref(),
        pin.as_deref(),
    )?;
    let pretty = serde_json::to_string_pretty(
        &serde_json::from_str::<Value>(&assertion).context("generated invalid assertion JSON")?,
    )
    .context("failed to format assertion JSON")?;

    if let Some(path) = output {
        std::fs::write(&path, format!("{pretty}\n"))
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!("Wrote FIDO assertion JSON to {}", path.display());
    } else {
        println!("{pretty}");
    }

    Ok(())
}

fn load_fido_authentication_options(
    auth_options_json: Option<String>,
    auth_options_file: Option<std::path::PathBuf>,
) -> anyhow::Result<Value> {
    if let Some(raw) = auth_options_json {
        return serde_json::from_str(raw.trim()).context("invalid --auth-options-json payload");
    }

    if let Some(path) = auth_options_file {
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        return serde_json::from_str(raw.trim())
            .with_context(|| format!("invalid JSON in {}", path.display()));
    }

    eprintln!("Provide FIDO authentication options JSON (from login flow).");
    eprint!("Options JSON file path (leave empty to paste JSON): ");
    let mut path_input = String::new();
    std::io::stdin()
        .read_line(&mut path_input)
        .context("failed to read options file path")?;
    let path_input = path_input.trim();
    if !path_input.is_empty() {
        let raw = std::fs::read_to_string(path_input)
            .with_context(|| format!("failed to read {path_input}"))?;
        return serde_json::from_str(raw.trim())
            .with_context(|| format!("invalid JSON in {path_input}"));
    }

    eprint!("Paste authentication options JSON (single line): ");
    let mut payload = String::new();
    std::io::stdin()
        .read_line(&mut payload)
        .context("failed to read authentication options JSON")?;
    serde_json::from_str(payload.trim()).context("invalid pasted authentication options JSON")
}

fn read_cli_fido_assertion_payload(authentication_options: &Value) -> anyhow::Result<String> {
    if let Ok(raw) = std::env::var("OPENPROTON_FIDO_ASSERTION_JSON") {
        let trimmed = raw.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    if let Ok(path) = std::env::var("OPENPROTON_FIDO_ASSERTION_FILE") {
        let payload = std::fs::read_to_string(&path).with_context(|| {
            format!("failed to read OPENPROTON_FIDO_ASSERTION_FILE from {path}")
        })?;
        let trimmed = payload.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    let pin_env = std::env::var("OPENPROTON_FIDO_PIN").ok();
    let provider = provider_from_env().unwrap_or(FidoProvider::Auto);
    let device_env = std::env::var("OPENPROTON_FIDO_DEVICE").ok();

    if let Ok(raw) = std::env::var("OPENPROTON_FIDO_OS_ASSERTION_JSON") {
        let trimmed = raw.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    if device_env
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        || matches!(provider, FidoProvider::Auto | FidoProvider::Os)
    {
        let device = device_env
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty());
        if let Ok(assertion) = generate_fido_assertion_with_provider(
            authentication_options,
            provider.clone(),
            device,
            pin_env.as_deref(),
        ) {
            return Ok(assertion);
        }
    }

    eprintln!("Security key authentication required (FIDO2).");
    eprintln!(
        "Set OPENPROTON_FIDO_PROVIDER (auto|hardware|os), OPENPROTON_FIDO_DEVICE, OPENPROTON_FIDO_ASSERTION_JSON, or OPENPROTON_FIDO_ASSERTION_FILE."
    );
    eprint!("Provider [auto/hardware/os] (default auto): ");
    let mut provider_input = String::new();
    std::io::stdin()
        .read_line(&mut provider_input)
        .context("failed to read provider")?;
    let provider = parse_provider_input(provider_input.trim()).unwrap_or(FidoProvider::Auto);

    eprint!("Security key device path for generation (empty to continue without device): ");
    let mut device = String::new();
    std::io::stdin()
        .read_line(&mut device)
        .context("failed to read FIDO device path")?;
    let device = device.trim();
    if !device.is_empty() || matches!(provider, FidoProvider::Auto | FidoProvider::Os) {
        let device = if device.is_empty() {
            None
        } else {
            Some(device)
        };
        if let Ok(assertion) = generate_fido_assertion_with_provider(
            authentication_options,
            provider,
            device,
            pin_env.as_deref(),
        ) {
            return Ok(assertion);
        }
    }

    eprint!("FIDO assertion JSON file path (leave empty to paste JSON): ");
    let mut path_input = String::new();
    std::io::stdin()
        .read_line(&mut path_input)
        .context("failed to read assertion file path")?;
    let path_input = path_input.trim();
    if !path_input.is_empty() {
        let payload = std::fs::read_to_string(path_input)
            .with_context(|| format!("failed to read FIDO assertion file {path_input}"))?;
        let trimmed = payload.trim().to_string();
        if trimmed.is_empty() {
            anyhow::bail!("FIDO assertion file is empty");
        }
        return Ok(trimmed);
    }

    eprint!("Paste FIDO assertion JSON (single line): ");
    let mut payload = String::new();
    std::io::stdin()
        .read_line(&mut payload)
        .context("failed to read FIDO assertion JSON")?;
    let payload = payload.trim().to_string();
    if payload.is_empty() {
        anyhow::bail!("FIDO assertion payload is required");
    }

    Ok(payload)
}

#[derive(Debug)]
struct FidoAssertionInput {
    rp_id: String,
    credential_id: Vec<u8>,
    client_data_json: Vec<u8>,
    client_data_hash: Vec<u8>,
}

fn provider_from_env() -> Option<FidoProvider> {
    std::env::var("OPENPROTON_FIDO_PROVIDER")
        .ok()
        .and_then(|raw| parse_provider_input(raw.trim()))
}

fn parse_provider_input(input: &str) -> Option<FidoProvider> {
    match input.to_ascii_lowercase().as_str() {
        "" => None,
        "auto" => Some(FidoProvider::Auto),
        "hardware" | "hw" | "libfido2" => Some(FidoProvider::Hardware),
        "os" | "platform" | "native" => Some(FidoProvider::Os),
        _ => None,
    }
}

fn generate_fido_assertion_with_provider(
    authentication_options: &Value,
    provider: FidoProvider,
    device: Option<&str>,
    pin: Option<&str>,
) -> anyhow::Result<String> {
    match provider {
        FidoProvider::Auto => {
            #[cfg(target_os = "windows")]
            {
                if let Ok(assertion) = generate_fido_assertion_json_os(authentication_options, pin)
                {
                    return Ok(assertion);
                }
            }
            let device = resolve_fido_device_for_hardware(device)?;
            generate_fido_assertion_json_hardware(authentication_options, &device, pin)
        }
        FidoProvider::Hardware => {
            let device = resolve_fido_device_for_hardware(device)?;
            generate_fido_assertion_json_hardware(authentication_options, &device, pin)
        }
        FidoProvider::Os => generate_fido_assertion_json_os(authentication_options, pin),
    }
}

fn resolve_fido_device_for_hardware(device: Option<&str>) -> anyhow::Result<String> {
    if let Some(device) = device.map(str::trim).filter(|value| !value.is_empty()) {
        return Ok(device.to_string());
    }

    if let Some(device) = auto_detect_fido_device() {
        eprintln!("Using detected FIDO device: {device}");
        return Ok(device);
    }

    eprint!("FIDO device path (for example /dev/hidraw0): ");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("failed to read FIDO device path")?;
    let resolved = input.trim().to_string();
    if resolved.is_empty() {
        anyhow::bail!("FIDO device path is required for hardware provider");
    }
    Ok(resolved)
}

fn auto_detect_fido_device() -> Option<String> {
    auto_detect_fido_device_os()
}

#[cfg(target_os = "linux")]
fn auto_detect_fido_device_os() -> Option<String> {
    let names = std::fs::read_dir("/dev")
        .ok()?
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    let selected = pick_first_hidraw_device_name(names)?;
    Some(format!("/dev/{selected}"))
}

#[cfg(not(target_os = "linux"))]
fn auto_detect_fido_device_os() -> Option<String> {
    None
}

fn pick_first_hidraw_device_name<I, S>(names: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut candidates = names
        .into_iter()
        .filter_map(|name| {
            let name = name.as_ref();
            if !name.starts_with("hidraw") {
                return None;
            }

            let suffix = name.trim_start_matches("hidraw");
            let idx = suffix.parse::<u32>().ok().unwrap_or(u32::MAX);
            Some((idx, name.to_string()))
        })
        .collect::<Vec<_>>();

    candidates.sort_by_key(|(idx, _)| *idx);
    candidates.into_iter().next().map(|(_, name)| name)
}

fn generate_fido_assertion_json_hardware(
    authentication_options: &Value,
    device: &str,
    pin: Option<&str>,
) -> anyhow::Result<String> {
    let input = build_fido_assertion_input(authentication_options)?;
    let command_input = format!(
        "{}\n{}\n{}\n",
        BASE64.encode(&input.client_data_hash),
        input.rp_id,
        BASE64.encode(&input.credential_id)
    );

    let temp_file = std::env::temp_dir().join(format!(
        "openproton-fido-assert-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::write(&temp_file, command_input)
        .with_context(|| format!("failed to write {}", temp_file.display()))?;

    let mut command = ProcessCommand::new("fido2-assert");
    command
        .arg("-G")
        .arg("-v")
        .arg("-i")
        .arg(&temp_file)
        .arg(device);
    if let Some(pin) = pin.filter(|pin| !pin.trim().is_empty()) {
        command.arg("-p").arg(pin.trim());
    }

    let output = command.output().context(
        "failed to execute fido2-assert; install libfido2 tools and ensure `fido2-assert` is in PATH",
    )?;
    let _ = std::fs::remove_file(&temp_file);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::bail!(
            "fido2-assert failed (exit {}): {}{}",
            output.status,
            stderr.trim(),
            if stdout.trim().is_empty() {
                String::new()
            } else {
                format!("; stdout: {}", stdout.trim())
            }
        );
    }

    let stdout =
        String::from_utf8(output.stdout).context("fido2-assert returned non-utf8 output")?;
    let lines: Vec<String> = stdout
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() < 4 {
        anyhow::bail!(
            "unexpected fido2-assert output format (expected at least 4 lines, got {})",
            lines.len()
        );
    }

    let authenticator_data = lines[2].clone();
    let signature = lines[3].clone();
    let assertion = json!({
        "rawId": BASE64.encode(&input.credential_id),
        "response": {
            "clientDataJSON": BASE64.encode(&input.client_data_json),
            "authenticatorData": authenticator_data,
            "signature": signature
        }
    });

    serde_json::to_string(&assertion).context("failed to encode assertion JSON")
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn generate_fido_assertion_json_os(
    authentication_options: &Value,
    pin: Option<&str>,
) -> anyhow::Result<String> {
    let helper = std::env::var("OPENPROTON_FIDO_OS_HELPER")
        .unwrap_or_else(|_| "openproton-fido-os-assert".to_string());
    let options_payload =
        serde_json::to_string(authentication_options).context("failed to encode auth options")?;

    let mut cmd = ProcessCommand::new(&helper);
    cmd.arg("--auth-options-json").arg(options_payload);
    if let Some(pin) = pin.filter(|pin| !pin.trim().is_empty()) {
        cmd.arg("--pin").arg(pin.trim());
    }
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let output = cmd.output().with_context(|| {
        format!(
            "failed to execute OS passkey helper `{helper}`; set OPENPROTON_FIDO_OS_HELPER to your provider bridge command"
        )
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "OS passkey helper `{helper}` failed (exit {}): {}",
            output.status,
            stderr.trim()
        );
    }

    let stdout = String::from_utf8(output.stdout).context("OS helper returned non-utf8 output")?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        anyhow::bail!("OS passkey helper returned empty assertion payload");
    }
    serde_json::from_str::<Value>(trimmed).context("OS passkey helper returned invalid JSON")?;
    Ok(trimmed.to_string())
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn generate_fido_assertion_json_os(
    _authentication_options: &Value,
    _pin: Option<&str>,
) -> anyhow::Result<String> {
    anyhow::bail!(
        "OS passkey provider is currently available only on Windows/macOS; use --provider hardware or provide OPENPROTON_FIDO_ASSERTION_JSON"
    )
}

fn build_fido_assertion_input(
    authentication_options: &Value,
) -> anyhow::Result<FidoAssertionInput> {
    let auth_options = normalize_fido_auth_options(authentication_options)?;
    let public_key = auth_options
        .get("publicKey")
        .and_then(Value::as_object)
        .context("FIDO authentication options are missing publicKey")?;
    let rp_id = public_key
        .get("rpId")
        .and_then(Value::as_str)
        .context("FIDO authentication options are missing publicKey.rpId")?
        .to_string();
    let challenge = decode_fido_bytes(
        public_key
            .get("challenge")
            .context("FIDO authentication options are missing publicKey.challenge")?,
        "publicKey.challenge",
    )?;
    let allow_credentials = public_key
        .get("allowCredentials")
        .and_then(Value::as_array)
        .context("FIDO authentication options are missing publicKey.allowCredentials")?;
    let credential_entry = allow_credentials
        .first()
        .context("FIDO authentication options contain no allowed credentials")?;
    let credential_id = decode_fido_bytes(
        credential_entry
            .get("id")
            .context("FIDO authentication options are missing allowCredentials[0].id")?,
        "allowCredentials[0].id",
    )?;

    let client_data_json = serde_json::to_vec(&json!({
        "type": "webauthn.get",
        "challenge": BASE64_URL_NO_PAD.encode(challenge),
        "origin": format!("https://{rp_id}")
    }))
    .context("failed to encode clientDataJSON")?;
    let client_data_hash = Sha256::digest(&client_data_json).to_vec();

    Ok(FidoAssertionInput {
        rp_id,
        credential_id,
        client_data_json,
        client_data_hash,
    })
}

fn normalize_fido_auth_options(value: &Value) -> anyhow::Result<Value> {
    if value.get("publicKey").is_some() {
        return Ok(value.clone());
    }

    if let Some(options) = value.get("AuthenticationOptions") {
        if options.get("publicKey").is_some() {
            return Ok(options.clone());
        }
    }

    if let Some(options) = value
        .get("FIDO2")
        .and_then(|fido| fido.get("AuthenticationOptions"))
    {
        if options.get("publicKey").is_some() {
            return Ok(options.clone());
        }
    }

    anyhow::bail!("could not locate FIDO authentication options publicKey object")
}

fn decode_fido_bytes(value: &Value, field_name: &str) -> anyhow::Result<Vec<u8>> {
    match value {
        Value::String(raw) => decode_base64_flexible(raw)
            .with_context(|| format!("invalid base64 value for {field_name}")),
        Value::Array(values) => values
            .iter()
            .map(|item| {
                let number = item
                    .as_u64()
                    .with_context(|| format!("non-integer value in byte array for {field_name}"))?;
                u8::try_from(number)
                    .with_context(|| format!("byte out of range in {field_name}: {number}"))
            })
            .collect(),
        _ => anyhow::bail!("unsupported value type for {field_name}"),
    }
}

fn decode_base64_flexible(input: &str) -> anyhow::Result<Vec<u8>> {
    BASE64
        .decode(input)
        .or_else(|_| BASE64_URL_NO_PAD.decode(input))
        .or_else(|_| BASE64_URL.decode(input))
        .or_else(|_| BASE64_NO_PAD.decode(input))
        .context("invalid base64 encoding")
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

    for addr in &addr_resp.addresses {
        if let Some(kr) = addr_keyrings.get(&addr.id) {
            let policy = sequoia_openpgp::policy::StandardPolicy::new();
            let mut ids = Vec::new();
            for unlocked in &kr.keys {
                for ka in unlocked
                    .cert
                    .keys()
                    .with_policy(&policy, None)
                    .supported()
                    .secret()
                {
                    ids.push(ka.keyid().to_string());
                }
            }
            tracing::debug!(
                address = %addr.email,
                address_id = %addr.id,
                key_ids = ?ids,
                "available unlocked key ids for address"
            );
        }
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
        tracing::debug!(
            message_id = %msg.metadata.id,
            address_id = %msg.metadata.address_id,
            subject = %msg.metadata.subject,
            "attempting message body decryption"
        );

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
        let to_display = format_email_addresses(&msg.metadata.to_list);

        println!(
            "{}. {}{}\n   From: {} <{}>\n   To: {}\n   Date: {}\n   Attachments: {}\n   ---\n   {}\n",
            i + 1,
            msg.metadata.subject,
            unread_marker,
            msg.metadata.sender.name,
            msg.metadata.sender.address,
            to_display,
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
    runtime_paths: &paths::RuntimePaths,
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
        let account_id = bridge::types::AccountId(session.uid.clone());
        let split_mode = match vault::load_split_mode_by_account_id(dir, &session.uid) {
            Ok(Some(enabled)) => enabled,
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(
                    email = %session.email,
                    error = %e,
                    "failed to load split mode setting, defaulting to combined"
                );
                false
            }
        };
        let _ = account_registry.set_split_mode(&account_id, split_mode);

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

    let store_root = effective_disk_cache_path(runtime_paths).join("imap-store");
    let store: Arc<dyn imap::store::MessageStore> =
        imap::store::PersistentStore::new(store_root)
            .context("failed to initialize persistent IMAP store")?;
    let event_store = store.clone();

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

async fn cmd_grpc(bind: &str, runtime_paths: &paths::RuntimePaths) -> anyhow::Result<()> {
    frontend::grpc::run_server(runtime_paths.clone(), bind.to_string()).await
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

fn format_email_addresses(addrs: &[api::types::EmailAddress]) -> String {
    if addrs.is_empty() {
        return "(none)".to_string();
    }

    addrs
        .iter()
        .map(|addr| {
            if addr.name.is_empty() {
                addr.address.clone()
            } else {
                format!("{} <{}>", addr.name, addr.address)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
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

fn runtime_paths(override_dir: Option<&std::path::Path>) -> anyhow::Result<paths::RuntimePaths> {
    paths::RuntimePaths::resolve(override_dir)
}

fn effective_disk_cache_path(runtime_paths: &paths::RuntimePaths) -> std::path::PathBuf {
    let default_path = runtime_paths.disk_cache_dir();
    let settings_path = runtime_paths.grpc_app_settings_path();

    let Ok(raw) = std::fs::read_to_string(&settings_path) else {
        return default_path;
    };

    let parsed: Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(
                path = %settings_path.display(),
                error = %err,
                "failed to parse app settings while resolving disk cache path; using default"
            );
            return default_path;
        }
    };

    parsed
        .get("disk_cache_path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or(default_path)
}

fn session_dir(override_dir: Option<&std::path::Path>) -> anyhow::Result<std::path::PathBuf> {
    Ok(runtime_paths(override_dir)?.settings_dir().to_path_buf())
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
    use serde_json::json;

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

    #[test]
    fn parse_fido_assert_subcommand() {
        let cli = Cli::try_parse_from([
            "openproton-bridge",
            "fido-assert",
            "--auth-options-json",
            r#"{"publicKey":{"rpId":"proton.me","challenge":[1,2,3],"allowCredentials":[{"id":[4,5,6]}]}}"#,
            "--device",
            "/dev/hidraw0",
        ])
        .unwrap();

        match cli.command {
            Command::FidoAssert {
                auth_options_json,
                auth_options_file,
                device,
                output,
                pin,
                provider,
            } => {
                assert!(auth_options_json.is_some());
                assert!(auth_options_file.is_none());
                assert_eq!(device.as_deref(), Some("/dev/hidraw0"));
                assert!(output.is_none());
                assert!(pin.is_none());
                assert_eq!(provider, FidoProvider::Auto);
            }
            _ => panic!("expected fido-assert command"),
        }
    }

    #[test]
    fn parse_fido_assert_provider_flag() {
        let cli = Cli::try_parse_from([
            "openproton-bridge",
            "fido-assert",
            "--auth-options-json",
            r#"{"publicKey":{"rpId":"proton.me","challenge":[1,2,3],"allowCredentials":[{"id":[4,5,6]}]}}"#,
            "--provider",
            "os",
        ])
        .unwrap();

        match cli.command {
            Command::FidoAssert { provider, .. } => assert_eq!(provider, FidoProvider::Os),
            _ => panic!("expected fido-assert command"),
        }
    }

    #[test]
    fn session_dir_default_uses_proton_vendor_path() {
        let dir = session_dir(None).unwrap();
        let expected_suffix = std::path::Path::new("protonmail").join("bridge-v3");
        assert!(dir.ends_with(expected_suffix));
    }

    #[test]
    fn session_dir_default_does_not_use_legacy_openproton_suffix() {
        let dir = session_dir(None).unwrap();
        assert!(!dir.ends_with(std::path::Path::new("openproton-bridge")));
    }

    #[test]
    fn effective_disk_cache_path_defaults_to_runtime_path_when_settings_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_paths = paths::RuntimePaths::resolve(Some(tmp.path())).unwrap();

        assert_eq!(
            effective_disk_cache_path(&runtime_paths),
            runtime_paths.disk_cache_dir()
        );
    }

    #[test]
    fn effective_disk_cache_path_uses_configured_path_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_paths = paths::RuntimePaths::resolve(Some(tmp.path())).unwrap();
        let configured = tmp.path().join("custom-cache");

        std::fs::create_dir_all(runtime_paths.settings_dir()).unwrap();
        std::fs::write(
            runtime_paths.grpc_app_settings_path(),
            serde_json::json!({
                "disk_cache_path": configured.display().to_string()
            })
            .to_string(),
        )
        .unwrap();

        assert_eq!(effective_disk_cache_path(&runtime_paths), configured);
    }

    #[test]
    fn build_fido_assertion_input_from_authentication_options() {
        let options = json!({
            "publicKey": {
                "rpId": "proton.me",
                "challenge": [1, 2, 3],
                "allowCredentials": [
                    {"id": [4, 5, 6]}
                ]
            }
        });
        let input = build_fido_assertion_input(&options).unwrap();
        assert_eq!(input.rp_id, "proton.me");
        assert_eq!(input.credential_id, vec![4, 5, 6]);
        assert!(!input.client_data_json.is_empty());
        assert_eq!(input.client_data_hash.len(), 32);
    }

    #[test]
    fn normalize_fido_auth_options_from_nested_shape() {
        let wrapped = json!({
            "FIDO2": {
                "AuthenticationOptions": {
                    "publicKey": {
                        "rpId": "proton.me",
                        "challenge": [1, 2, 3],
                        "allowCredentials": [{"id": [4, 5, 6]}]
                    }
                }
            }
        });
        let normalized = normalize_fido_auth_options(&wrapped).unwrap();
        assert!(normalized.get("publicKey").is_some());
    }

    #[test]
    fn pick_first_hidraw_device_name_extracts_first_numeric_device() {
        let names = vec!["tty1", "hidraw2", "hidraw10", "hidraw3"];
        let parsed = pick_first_hidraw_device_name(names);
        assert_eq!(parsed.as_deref(), Some("hidraw2"));
    }

    #[test]
    fn pick_first_hidraw_device_name_returns_none_when_absent() {
        let names = vec!["tty1", "usb0", "kbd0"];
        let parsed = pick_first_hidraw_device_name(names);
        assert!(parsed.is_none());
    }
}
