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
use tokio::io::AsyncBufReadExt;

mod api;
mod bridge;
mod crypto;
mod frontend;
mod imap;
mod paths;
mod single_instance;
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

    /// Credential store backend: auto, system, pass, file
    #[arg(long, global = true)]
    credential_store: Option<CredentialStoreBackendArg>,

    /// Credential store namespace (default: bridge-v3)
    #[arg(long, global = true)]
    credential_store_namespace: Option<String>,

    /// Credential store secret/account key (default: bridge-vault-key)
    #[arg(long, global = true)]
    credential_store_secret: Option<String>,

    /// Override system keychain service name
    #[arg(long, global = true)]
    credential_store_system_service: Option<String>,

    /// Override pass entry path
    #[arg(long, global = true)]
    credential_store_pass_entry: Option<String>,

    /// Override credential file path
    #[arg(long, global = true)]
    credential_store_file_path: Option<std::path::PathBuf>,

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
    /// Start interactive CLI shell
    Cli,
    /// Dump decrypted vault msgpack structure for debugging
    VaultDump,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
enum FidoProvider {
    Auto,
    Hardware,
    Os,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
enum CredentialStoreBackendArg {
    Auto,
    System,
    Pass,
    File,
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

const ENV_OPENPROTON_VAULT_DIR: &str = "OPENPROTON_VAULT_DIR";
const ENV_OPENPROTON_CREDENTIAL_STORE: &str = "OPENPROTON_CREDENTIAL_STORE";
const ENV_OPENPROTON_CREDENTIAL_STORE_NAMESPACE: &str = "OPENPROTON_CREDENTIAL_STORE_NAMESPACE";
const ENV_OPENPROTON_CREDENTIAL_STORE_SECRET: &str = "OPENPROTON_CREDENTIAL_STORE_SECRET";
const ENV_OPENPROTON_CREDENTIAL_STORE_SYSTEM_SERVICE: &str =
    "OPENPROTON_CREDENTIAL_STORE_SYSTEM_SERVICE";
const ENV_OPENPROTON_CREDENTIAL_STORE_PASS_ENTRY: &str = "OPENPROTON_CREDENTIAL_STORE_PASS_ENTRY";
const ENV_OPENPROTON_CREDENTIAL_STORE_FILE_PATH: &str = "OPENPROTON_CREDENTIAL_STORE_FILE_PATH";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let credential_store_overrides = resolve_credential_store_overrides(&cli)?;
    vault::set_process_credential_store_overrides(credential_store_overrides);
    let resolved_vault_dir = resolve_vault_dir(&cli);
    let runtime_paths = runtime_paths(resolved_vault_dir.as_deref())?;
    let dir = runtime_paths.settings_dir().to_path_buf();
    let _instance_lock = match &cli.command {
        Command::Serve { .. } | Command::Grpc { .. } | Command::Cli => {
            let lock = single_instance::acquire_bridge_instance_lock(&runtime_paths)?;
            tracing::info!(path = %lock.path().display(), "acquired bridge instance lock");
            Some(lock)
        }
        _ => None,
    };

    execute_command(cli.command, &dir, &runtime_paths).await
}

async fn execute_command(
    command: Command,
    dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
) -> anyhow::Result<()> {
    match command {
        Command::Cli => cmd_cli(dir, runtime_paths).await,
        other => execute_non_interactive_command(other, dir, runtime_paths).await,
    }
}

async fn execute_non_interactive_command(
    command: Command,
    dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
) -> anyhow::Result<()> {
    match command {
        Command::Login { username } => cmd_login(username, dir).await,
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
        Command::Status => cmd_status(dir),
        Command::Logout { email, all } => cmd_logout(email.as_deref(), all, dir),
        Command::Accounts { command } => match command {
            AccountsCommand::List => cmd_accounts_list(dir),
            AccountsCommand::Use { email } => cmd_accounts_use(&email, dir),
        },
        Command::Fetch { limit } => cmd_fetch(limit, dir).await,
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
                dir,
                runtime_paths,
            )
            .await
        }
        Command::Grpc { bind } => cmd_grpc(&bind, runtime_paths).await,
        Command::VaultDump => cmd_vault_dump(dir),
        Command::Cli => anyhow::bail!("cannot execute nested cli command"),
    }
}

fn resolve_vault_dir(cli: &Cli) -> Option<std::path::PathBuf> {
    cli.vault_dir
        .clone()
        .or_else(|| env_non_empty(ENV_OPENPROTON_VAULT_DIR).map(std::path::PathBuf::from))
}

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
}

fn parse_credential_store_backend(raw: &str) -> anyhow::Result<vault::CredentialStoreBackend> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(vault::CredentialStoreBackend::Auto),
        "system" => Ok(vault::CredentialStoreBackend::System),
        "pass" => Ok(vault::CredentialStoreBackend::Pass),
        "file" => Ok(vault::CredentialStoreBackend::File),
        other => anyhow::bail!(
            "invalid credential store backend `{other}`; expected one of: auto, system, pass, file"
        ),
    }
}

fn map_credential_store_backend_arg(
    backend: CredentialStoreBackendArg,
) -> vault::CredentialStoreBackend {
    match backend {
        CredentialStoreBackendArg::Auto => vault::CredentialStoreBackend::Auto,
        CredentialStoreBackendArg::System => vault::CredentialStoreBackend::System,
        CredentialStoreBackendArg::Pass => vault::CredentialStoreBackend::Pass,
        CredentialStoreBackendArg::File => vault::CredentialStoreBackend::File,
    }
}

fn resolve_credential_store_overrides(
    cli: &Cli,
) -> anyhow::Result<vault::CredentialStoreOverrides> {
    let mut overrides = vault::CredentialStoreOverrides::default();

    if let Some(raw) = env_non_empty(ENV_OPENPROTON_CREDENTIAL_STORE) {
        overrides.backend = Some(parse_credential_store_backend(&raw)?);
    }
    if let Some(raw) = env_non_empty(ENV_OPENPROTON_CREDENTIAL_STORE_NAMESPACE) {
        overrides.namespace = Some(raw);
    }
    if let Some(raw) = env_non_empty(ENV_OPENPROTON_CREDENTIAL_STORE_SECRET) {
        overrides.secret = Some(raw);
    }
    if let Some(raw) = env_non_empty(ENV_OPENPROTON_CREDENTIAL_STORE_SYSTEM_SERVICE) {
        overrides.system_service = Some(raw);
    }
    if let Some(raw) = env_non_empty(ENV_OPENPROTON_CREDENTIAL_STORE_PASS_ENTRY) {
        overrides.pass_entry = Some(raw);
    }
    if let Some(raw) = env_non_empty(ENV_OPENPROTON_CREDENTIAL_STORE_FILE_PATH) {
        overrides.file_path = Some(std::path::PathBuf::from(raw));
    }

    if let Some(backend) = cli.credential_store.clone() {
        overrides.backend = Some(map_credential_store_backend_arg(backend));
    }
    if let Some(namespace) = cli.credential_store_namespace.as_deref() {
        let namespace = namespace.trim();
        if !namespace.is_empty() {
            overrides.namespace = Some(namespace.to_string());
        }
    }
    if let Some(secret) = cli.credential_store_secret.as_deref() {
        let secret = secret.trim();
        if !secret.is_empty() {
            overrides.secret = Some(secret.to_string());
        }
    }
    if let Some(service) = cli.credential_store_system_service.as_deref() {
        let service = service.trim();
        if !service.is_empty() {
            overrides.system_service = Some(service.to_string());
        }
    }
    if let Some(pass_entry) = cli.credential_store_pass_entry.as_deref() {
        let pass_entry = pass_entry.trim();
        if !pass_entry.is_empty() {
            overrides.pass_entry = Some(pass_entry.to_string());
        }
    }
    if let Some(path) = cli.credential_store_file_path.as_ref() {
        overrides.file_path = Some(path.clone());
    }

    Ok(overrides)
}

#[derive(Clone, Debug)]
struct InteractiveServeConfig {
    imap_port: u16,
    smtp_port: u16,
    bind: String,
    no_tls: bool,
    event_poll_secs: u64,
}

impl Default for InteractiveServeConfig {
    fn default() -> Self {
        Self {
            imap_port: 1143,
            smtp_port: 1025,
            bind: "127.0.0.1".to_string(),
            no_tls: false,
            event_poll_secs: 30,
        }
    }
}

#[derive(Default, Debug)]
struct ServeCommandOverrides {
    imap_port: Option<u16>,
    smtp_port: Option<u16>,
    bind: Option<String>,
    no_tls: Option<bool>,
    event_poll_secs: Option<u64>,
}

struct InteractiveServeRuntime {
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    join_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    config: InteractiveServeConfig,
}

struct InteractiveGrpcRuntime {
    join_handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    bind: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CliStoredAppSettings {
    show_on_startup: bool,
    is_autostart_on: bool,
    is_beta_enabled: bool,
    is_all_mail_visible: bool,
    is_telemetry_disabled: bool,
    disk_cache_path: String,
    is_doh_enabled: bool,
    color_scheme_name: String,
    is_automatic_update_on: bool,
    current_keychain: String,
    main_executable: String,
    forced_launcher: String,
}

impl CliStoredAppSettings {
    fn defaults_for(runtime_paths: &paths::RuntimePaths) -> Self {
        Self {
            show_on_startup: true,
            is_autostart_on: false,
            is_beta_enabled: false,
            is_all_mail_visible: true,
            is_telemetry_disabled: false,
            disk_cache_path: runtime_paths.disk_cache_dir().display().to_string(),
            is_doh_enabled: true,
            color_scheme_name: "system".to_string(),
            is_automatic_update_on: true,
            current_keychain: vault::KEYCHAIN_BACKEND_FILE.to_string(),
            main_executable: String::new(),
            forced_launcher: String::new(),
        }
    }
}

impl InteractiveServeConfig {
    fn with_overrides(&self, overrides: ServeCommandOverrides) -> Self {
        Self {
            imap_port: overrides.imap_port.unwrap_or(self.imap_port),
            smtp_port: overrides.smtp_port.unwrap_or(self.smtp_port),
            bind: overrides.bind.unwrap_or_else(|| self.bind.clone()),
            no_tls: overrides.no_tls.unwrap_or(self.no_tls),
            event_poll_secs: overrides.event_poll_secs.unwrap_or(self.event_poll_secs),
        }
    }
}

async fn cmd_cli(dir: &std::path::Path, runtime_paths: &paths::RuntimePaths) -> anyhow::Result<()> {
    println!("Welcome to openproton-bridge interactive shell.");
    println!("Type `help` for commands, `quit` to exit.\n");

    let mut serve_config = InteractiveServeConfig::default();
    let mut runtime_state: Option<InteractiveServeRuntime> = None;
    let mut grpc_state: Option<InteractiveGrpcRuntime> = None;
    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut completion_tick = tokio::time::interval(std::time::Duration::from_millis(500));
    completion_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    completion_tick.tick().await;

    print_cli_prompt()?;

    loop {
        tokio::select! {
            _ = completion_tick.tick() => {
                if let Some(message) = maybe_collect_runtime_completion(&mut runtime_state).await {
                    println!();
                    println!("{message}");
                    print_cli_prompt()?;
                }
                if let Some(message) = maybe_collect_grpc_completion(&mut grpc_state).await {
                    println!();
                    println!("{message}");
                    print_cli_prompt()?;
                }
            }
            maybe_event = event_rx.recv() => {
                if let Some(event) = maybe_event {
                    println!();
                    println!("{event}");
                    print_cli_prompt()?;
                }
            }
            maybe_line = lines.next_line() => {
                let Some(line) = maybe_line.context("failed to read CLI input")? else {
                    println!();
                    break;
                };

                let line = line.trim();
                if line.is_empty() {
                    print_cli_prompt()?;
                    continue;
                }

                let tokens = match split_shell_words(line) {
                    Ok(tokens) => tokens,
                    Err(err) => {
                        eprintln!("Error: {err}");
                        print_cli_prompt()?;
                        continue;
                    }
                };

                if tokens.is_empty() {
                    print_cli_prompt()?;
                    continue;
                }

                let command = tokens[0].to_ascii_lowercase();
                match command.as_str() {
                    "quit" | "exit" => break,
                    "help" | "?" => {
                        print_interactive_help();
                    }
                    "manual" | "man" => {
                        println!("https://github.com/rickyslash/openproton-bridge");
                    }
                    "check-updates" => {
                        match load_app_settings_for_cli(runtime_paths).await {
                            Ok(settings) => {
                                println!(
                                    "Update check requested (headless mode): channel={}, autoupdates={}",
                                    if settings.is_beta_enabled {
                                        "early"
                                    } else {
                                        "stable"
                                    },
                                    if settings.is_automatic_update_on {
                                        "on"
                                    } else {
                                        "off"
                                    }
                                );
                            }
                            Err(err) => eprintln!("Error: {err:#}"),
                        }
                    }
                    "credits" => {
                        println!("openproton-bridge credits:");
                        println!("  - project: openproton-bridge");
                        println!("  - deps/licenses: see Cargo.toml and Cargo.lock");
                    }
                    "log-dir" | "log" | "logs" => {
                        println!("{}", runtime_paths.logs_dir().display());
                    }
                    "telemetry" => match tokens.get(1).map(|s| s.to_ascii_lowercase()) {
                        Some(action) if action == "enable" => {
                            if let Err(err) = update_app_settings(runtime_paths, |settings| {
                                settings.is_telemetry_disabled = false;
                            })
                            .await
                            {
                                eprintln!("Error: {err:#}");
                            } else {
                                println!("Telemetry collection enabled.");
                            }
                        }
                        Some(action) if action == "disable" => {
                            if let Err(err) = update_app_settings(runtime_paths, |settings| {
                                settings.is_telemetry_disabled = true;
                            })
                            .await
                            {
                                eprintln!("Error: {err:#}");
                            } else {
                                println!("Telemetry collection disabled.");
                            }
                        }
                        Some(action) if action == "status" => {
                            match load_app_settings_for_cli(runtime_paths).await {
                                Ok(settings) => println!(
                                    "Telemetry: {}",
                                    if settings.is_telemetry_disabled {
                                        "disabled"
                                    } else {
                                        "enabled"
                                    }
                                ),
                                Err(err) => eprintln!("Error: {err:#}"),
                            }
                        }
                        _ => eprintln!("Usage: telemetry <enable|disable|status>"),
                    },
                    "proxy" => match tokens.get(1).map(|s| s.to_ascii_lowercase()) {
                        Some(action) if action == "allow" => {
                            if let Err(err) = update_app_settings(runtime_paths, |settings| {
                                settings.is_doh_enabled = true;
                            })
                            .await
                            {
                                eprintln!("Error: {err:#}");
                            } else {
                                println!("Proxy fallback (DoH) enabled.");
                            }
                        }
                        Some(action) if action == "disallow" => {
                            if let Err(err) = update_app_settings(runtime_paths, |settings| {
                                settings.is_doh_enabled = false;
                            })
                            .await
                            {
                                eprintln!("Error: {err:#}");
                            } else {
                                println!("Proxy fallback (DoH) disabled.");
                            }
                        }
                        Some(action) if action == "status" => {
                            match load_app_settings_for_cli(runtime_paths).await {
                                Ok(settings) => println!(
                                    "Proxy fallback (DoH): {}",
                                    if settings.is_doh_enabled {
                                        "allowed"
                                    } else {
                                        "disallowed"
                                    }
                                ),
                                Err(err) => eprintln!("Error: {err:#}"),
                            }
                        }
                        _ => eprintln!("Usage: proxy <allow|disallow|status>"),
                    },
                    "autostart" => match tokens.get(1).map(|s| s.to_ascii_lowercase()) {
                        Some(action) if action == "enable" || action == "on" => {
                            if let Err(err) = update_app_settings(runtime_paths, |settings| {
                                settings.is_autostart_on = true;
                            })
                            .await
                            {
                                eprintln!("Error: {err:#}");
                            } else {
                                println!("Autostart enabled.");
                            }
                        }
                        Some(action) if action == "disable" || action == "off" => {
                            if let Err(err) = update_app_settings(runtime_paths, |settings| {
                                settings.is_autostart_on = false;
                            })
                            .await
                            {
                                eprintln!("Error: {err:#}");
                            } else {
                                println!("Autostart disabled.");
                            }
                        }
                        Some(action) if action == "status" => {
                            match load_app_settings_for_cli(runtime_paths).await {
                                Ok(settings) => println!(
                                    "Autostart: {}",
                                    if settings.is_autostart_on {
                                        "enabled"
                                    } else {
                                        "disabled"
                                    }
                                ),
                                Err(err) => eprintln!("Error: {err:#}"),
                            }
                        }
                        _ => eprintln!("Usage: autostart <enable|disable|status>"),
                    },
                    "all-mail-visibility" => match tokens.get(1).map(|s| s.to_ascii_lowercase()) {
                        Some(action) if action == "show" => {
                            if let Err(err) = update_app_settings(runtime_paths, |settings| {
                                settings.is_all_mail_visible = true;
                            })
                            .await
                            {
                                eprintln!("Error: {err:#}");
                            } else {
                                println!("All Mail folder visibility enabled.");
                            }
                        }
                        Some(action) if action == "hide" => {
                            if let Err(err) = update_app_settings(runtime_paths, |settings| {
                                settings.is_all_mail_visible = false;
                            })
                            .await
                            {
                                eprintln!("Error: {err:#}");
                            } else {
                                println!("All Mail folder visibility disabled.");
                            }
                        }
                        Some(action) if action == "status" => {
                            match load_app_settings_for_cli(runtime_paths).await {
                                Ok(settings) => println!(
                                    "All Mail visibility: {}",
                                    if settings.is_all_mail_visible {
                                        "shown"
                                    } else {
                                        "hidden"
                                    }
                                ),
                                Err(err) => eprintln!("Error: {err:#}"),
                            }
                        }
                        _ => eprintln!("Usage: all-mail-visibility <show|hide|status>"),
                    },
                    "updates" => {
                        let Some(scope) = tokens.get(1).map(|s| s.to_ascii_lowercase()) else {
                            eprintln!(
                                "Usage: updates <check|status|autoupdates <enable|disable|status>|channel <early|stable|status>>"
                            );
                            print_cli_prompt()?;
                            continue;
                        };

                        match scope.as_str() {
                            "check" => match load_app_settings_for_cli(runtime_paths).await {
                                Ok(settings) => {
                                    println!(
                                        "Update check requested (headless mode): channel={}, autoupdates={}",
                                        if settings.is_beta_enabled { "early" } else { "stable" },
                                        if settings.is_automatic_update_on { "on" } else { "off" }
                                    );
                                }
                                Err(err) => eprintln!("Error: {err:#}"),
                            },
                            "status" => match load_app_settings_for_cli(runtime_paths).await {
                                Ok(settings) => println!(
                                    "Updates: channel={}, autoupdates={}",
                                    if settings.is_beta_enabled { "early" } else { "stable" },
                                    if settings.is_automatic_update_on { "on" } else { "off" }
                                ),
                                Err(err) => eprintln!("Error: {err:#}"),
                            },
                            "autoupdates" => {
                                let Some(action) = tokens.get(2).map(|s| s.to_ascii_lowercase()) else {
                                    eprintln!("Usage: updates autoupdates <enable|disable|status>");
                                    print_cli_prompt()?;
                                    continue;
                                };

                                match action.as_str() {
                                    "enable" => {
                                        if let Err(err) = update_app_settings(runtime_paths, |settings| {
                                            settings.is_automatic_update_on = true;
                                        })
                                        .await
                                        {
                                            eprintln!("Error: {err:#}");
                                        } else {
                                            println!("Automatic updates enabled.");
                                        }
                                    }
                                    "disable" => {
                                        if let Err(err) = update_app_settings(runtime_paths, |settings| {
                                            settings.is_automatic_update_on = false;
                                        })
                                        .await
                                        {
                                            eprintln!("Error: {err:#}");
                                        } else {
                                            println!("Automatic updates disabled.");
                                        }
                                    }
                                    "status" => match load_app_settings_for_cli(runtime_paths).await {
                                        Ok(settings) => println!(
                                            "Automatic updates: {}",
                                            if settings.is_automatic_update_on {
                                                "enabled"
                                            } else {
                                                "disabled"
                                            }
                                        ),
                                        Err(err) => eprintln!("Error: {err:#}"),
                                    },
                                    _ => eprintln!("Usage: updates autoupdates <enable|disable|status>"),
                                }
                            }
                            "channel" => {
                                let Some(action) = tokens.get(2).map(|s| s.to_ascii_lowercase()) else {
                                    eprintln!("Usage: updates channel <early|stable|status>");
                                    print_cli_prompt()?;
                                    continue;
                                };

                                match action.as_str() {
                                    "early" => {
                                        if let Err(err) = update_app_settings(runtime_paths, |settings| {
                                            settings.is_beta_enabled = true;
                                        })
                                        .await
                                        {
                                            eprintln!("Error: {err:#}");
                                        } else {
                                            println!("Update channel set to early.");
                                        }
                                    }
                                    "stable" => {
                                        if let Err(err) = update_app_settings(runtime_paths, |settings| {
                                            settings.is_beta_enabled = false;
                                        })
                                        .await
                                        {
                                            eprintln!("Error: {err:#}");
                                        } else {
                                            println!("Update channel set to stable.");
                                        }
                                    }
                                    "status" => match load_app_settings_for_cli(runtime_paths).await {
                                        Ok(settings) => println!(
                                            "Update channel: {}",
                                            if settings.is_beta_enabled { "early" } else { "stable" }
                                        ),
                                        Err(err) => eprintln!("Error: {err:#}"),
                                    },
                                    _ => eprintln!("Usage: updates channel <early|stable|status>"),
                                }
                            }
                            _ => {
                                eprintln!(
                                    "Usage: updates <check|status|autoupdates <enable|disable|status>|channel <early|stable|status>>"
                                );
                            }
                        }
                    }
                    "list" | "ls" | "l" => {
                        if let Err(err) = execute_non_interactive_command(
                            Command::Accounts {
                                command: AccountsCommand::List,
                            },
                            dir,
                            runtime_paths,
                        )
                        .await
                        {
                            eprintln!("Error: {err:#}");
                        }
                    }
                    "info" | "i" => {
                        if let Err(err) =
                            execute_non_interactive_command(Command::Status, dir, runtime_paths).await
                        {
                            eprintln!("Error: {err:#}");
                        }
                    }
                    "use" => {
                        if tokens.len() != 2 {
                            eprintln!("Usage: use <email>");
                            print_cli_prompt()?;
                            continue;
                        }

                        if let Err(err) = execute_non_interactive_command(
                            Command::Accounts {
                                command: AccountsCommand::Use {
                                    email: tokens[1].clone(),
                                },
                            },
                            dir,
                            runtime_paths,
                        )
                        .await
                        {
                            eprintln!("Error: {err:#}");
                        }
                    }
                    "delete" | "del" | "rm" | "remove" => {
                        if tokens.len() != 2 {
                            eprintln!("Usage: delete <email>");
                            print_cli_prompt()?;
                            continue;
                        }

                        if let Err(err) = execute_non_interactive_command(
                            Command::Logout {
                                email: Some(tokens[1].clone()),
                                all: false,
                            },
                            dir,
                            runtime_paths,
                        )
                        .await
                        {
                            eprintln!("Error: {err:#}");
                        }
                    }
                    "clear" | "cl" => {
                        let clear_target = tokens.get(1).map(|value| value.to_ascii_lowercase());
                        if clear_target
                            .as_deref()
                            .is_some_and(|target| target == "accounts")
                        {
                            if let Err(err) = execute_non_interactive_command(
                                Command::Logout {
                                    email: None,
                                    all: true,
                                },
                                dir,
                                runtime_paths,
                            )
                            .await
                            {
                                eprintln!("Error: {err:#}");
                            }
                        } else if clear_target
                            .as_deref()
                            .is_some_and(|target| target == "everything")
                        {
                            if let Err(err) = run_interactive_reset(
                                dir,
                                runtime_paths,
                                &mut runtime_state,
                                &mut grpc_state,
                            )
                            .await
                            {
                                eprintln!("Error: {err:#}");
                            } else {
                                println!("Everything cleared: sessions and grpc settings removed.");
                            }
                        } else {
                            eprintln!("Usage: clear accounts | clear everything");
                        }
                    }
                    "change-location" => {
                        let Some(target) = tokens.get(1) else {
                            eprintln!("Usage: change-location <path>");
                            print_cli_prompt()?;
                            continue;
                        };
                        if let Err(err) = set_disk_cache_path_for_cli(runtime_paths, target).await {
                            eprintln!("Error: {err:#}");
                        } else {
                            println!("Disk cache location updated to {}", target);
                        }
                    }
                    "bad-event" => {
                        let Some(action) = tokens.get(1).map(|s| s.to_ascii_lowercase()) else {
                            eprintln!("Usage: bad-event <synchronize|logout <email|--all>>");
                            print_cli_prompt()?;
                            continue;
                        };

                        match action.as_str() {
                            "synchronize" => {
                                if let Err(err) = run_interactive_repair(
                                    dir,
                                    runtime_paths,
                                    &mut runtime_state,
                                    event_tx.clone(),
                                )
                                .await
                                {
                                    eprintln!("Error: {err:#}");
                                }
                            }
                            "logout" => {
                                let target = tokens.get(2).cloned();
                                if let Some(value) = target {
                                    if value == "--all" || value.eq_ignore_ascii_case("all") {
                                        if let Err(err) = execute_non_interactive_command(
                                            Command::Logout {
                                                email: None,
                                                all: true,
                                            },
                                            dir,
                                            runtime_paths,
                                        )
                                        .await
                                        {
                                            eprintln!("Error: {err:#}");
                                        }
                                    } else if let Err(err) = execute_non_interactive_command(
                                        Command::Logout {
                                            email: Some(value),
                                            all: false,
                                        },
                                        dir,
                                        runtime_paths,
                                    )
                                    .await
                                    {
                                        eprintln!("Error: {err:#}");
                                    }
                                } else {
                                    eprintln!("Usage: bad-event logout <email|--all>");
                                }
                            }
                            _ => eprintln!("Usage: bad-event <synchronize|logout <email|--all>>"),
                        }
                    }
                    "cert" => {
                        let Some(action) = tokens.get(1).map(|s| s.to_ascii_lowercase()) else {
                            eprintln!("Usage: cert <status|install|export <dir>|import <dir>>");
                            print_cli_prompt()?;
                            continue;
                        };

                        match action.as_str() {
                            "status" => {
                                let (cert_path, key_path) = cli_tls_paths(dir);
                                let installed = cert_path.exists() && key_path.exists();
                                println!(
                                    "TLS cert installed: {}",
                                    if installed { "yes" } else { "no" }
                                );
                                println!("  cert: {}", cert_path.display());
                                println!("  key: {}", key_path.display());
                            }
                            "install" => {
                                if let Err(err) = ensure_cli_tls_certificate(dir) {
                                    eprintln!("Error: {err:#}");
                                } else {
                                    println!("TLS certificate installed.");
                                }
                            }
                            "export" => {
                                let Some(target) = tokens.get(2) else {
                                    eprintln!("Usage: cert export <directory>");
                                    print_cli_prompt()?;
                                    continue;
                                };
                                if let Err(err) = export_cli_tls_certificate(dir, target) {
                                    eprintln!("Error: {err:#}");
                                } else {
                                    println!("TLS certificate exported to {}", target);
                                }
                            }
                            "import" => {
                                let Some(source) = tokens.get(2) else {
                                    eprintln!("Usage: cert import <directory>");
                                    print_cli_prompt()?;
                                    continue;
                                };
                                if let Err(err) = import_cli_tls_certificate(dir, source) {
                                    eprintln!("Error: {err:#}");
                                } else {
                                    println!("TLS certificate imported from {}", source);
                                }
                            }
                            _ => eprintln!("Usage: cert <status|install|export <dir>|import <dir>>"),
                        }
                    }
                    "repair" | "rep" => {
                        if let Err(err) = run_interactive_repair(
                            dir,
                            runtime_paths,
                            &mut runtime_state,
                            event_tx.clone(),
                        )
                        .await
                        {
                            eprintln!("Error: {err:#}");
                        }
                    }
                    "reset" => {
                        if !tokens.get(1).is_some_and(|arg| arg == "--force") {
                            eprintln!(
                                "Refusing destructive reset. Use: reset --force"
                            );
                            print_cli_prompt()?;
                            continue;
                        }

                        if let Err(err) = run_interactive_reset(
                            dir,
                            runtime_paths,
                            &mut runtime_state,
                            &mut grpc_state,
                        )
                        .await
                        {
                            eprintln!("Error: {err:#}");
                        } else {
                            println!("Reset complete: sessions and grpc settings cleared.");
                        }
                    }
                    "imap-security" | "ssl-imap" | "starttls-imap" => {
                        let mut args = vec!["imap-security".to_string()];
                        args.extend(tokens.iter().skip(1).cloned());
                        if let Err(err) = handle_interactive_change_command(&args, &mut serve_config)
                        {
                            eprintln!("Error: {err}");
                        }
                    }
                    "smtp-security" | "ssl-smtp" | "starttls-smtp" => {
                        let mut args = vec!["smtp-security".to_string()];
                        args.extend(tokens.iter().skip(1).cloned());
                        if let Err(err) = handle_interactive_change_command(&args, &mut serve_config)
                        {
                            eprintln!("Error: {err}");
                        }
                    }
                    "change" | "ch" | "switch" => {
                        if tokens
                            .get(1)
                            .is_some_and(|value| value.eq_ignore_ascii_case("mode"))
                        {
                            if tokens.len() < 4 {
                                eprintln!("Usage: change mode <email> <split|combined>");
                                print_cli_prompt()?;
                                continue;
                            }
                            if let Err(err) = set_account_mode_by_email(
                                dir,
                                &tokens[2],
                                &tokens[3],
                            ) {
                                eprintln!("Error: {err:#}");
                            }
                        } else if let Err(err) =
                            handle_interactive_change_command(&tokens[1..], &mut serve_config)
                        {
                            eprintln!("Error: {err}");
                        }
                    }
                    "serve-config" => {
                        print_interactive_serve_config(&serve_config);
                    }
                    "serve-status" => {
                        if let Some(state) = runtime_state.as_ref() {
                            println!(
                                "Serve runtime: running (bind={}, imap={}, smtp={}, tls={}, poll={}s)",
                                state.config.bind,
                                state.config.imap_port,
                                state.config.smtp_port,
                                if state.config.no_tls { "off" } else { "starttls" },
                                state.config.event_poll_secs
                            );
                        } else {
                            println!("Serve runtime: stopped");
                        }
                    }
                    "grpc-status" => {
                        if let Some(state) = grpc_state.as_ref() {
                            println!("gRPC runtime: running (bind={})", state.bind);
                        } else {
                            println!("gRPC runtime: stopped");
                        }
                    }
                    "stop" => {
                        let mut stopped_any = false;

                        if let Some(state) = runtime_state.take() {
                            println!("Stopping serve runtime...");
                            match stop_interactive_runtime(state).await {
                                Ok(()) => println!("Serve runtime stopped."),
                                Err(err) => eprintln!("Error while stopping runtime: {err:#}"),
                            }
                            stopped_any = true;
                        }

                        if let Some(state) = grpc_state.take() {
                            println!("Stopping gRPC runtime...");
                            match stop_interactive_grpc(state).await {
                                Ok(()) => println!("gRPC runtime stopped."),
                                Err(err) => eprintln!("Error while stopping gRPC runtime: {err:#}"),
                            }
                            stopped_any = true;
                        }

                        if !stopped_any {
                            println!("No background runtime is running.");
                        }
                    }
                    "serve" | "start" => {
                        if tokens
                            .get(1)
                            .is_some_and(|arg| arg == "--help" || arg == "-h")
                        {
                            print_interactive_serve_help();
                            print_cli_prompt()?;
                            continue;
                        }

                        if runtime_state.is_some() {
                            eprintln!("Serve runtime is already running. Use `stop` first.");
                            print_cli_prompt()?;
                            continue;
                        }

                        let overrides = match parse_serve_overrides(&tokens[1..]) {
                            Ok(overrides) => overrides,
                            Err(err) => {
                                eprintln!("Error: {err}");
                                print_cli_prompt()?;
                                continue;
                            }
                        };
                        let effective = serve_config.with_overrides(overrides);

                        match start_interactive_runtime(
                            effective.clone(),
                            dir,
                            runtime_paths,
                            event_tx.clone(),
                        )
                        .await
                        {
                            Ok(state) => {
                                runtime_state = Some(state);
                                println!("Serve runtime started in background.");
                            }
                            Err(err) => eprintln!("Error: {err:#}"),
                        }
                    }
                    "grpc-stop" => {
                        if let Some(state) = grpc_state.take() {
                            println!("Stopping gRPC runtime...");
                            match stop_interactive_grpc(state).await {
                                Ok(()) => println!("gRPC runtime stopped."),
                                Err(err) => eprintln!("Error while stopping gRPC runtime: {err:#}"),
                            }
                        } else {
                            println!("gRPC runtime is not running.");
                        }
                    }
                    "grpc" | "grpc-start" => {
                        if tokens
                            .get(1)
                            .is_some_and(|arg| arg == "--help" || arg == "-h")
                        {
                            print_interactive_grpc_help();
                            print_cli_prompt()?;
                            continue;
                        }

                        if grpc_state.is_some() {
                            eprintln!("gRPC runtime is already running. Use `grpc-stop` first.");
                            print_cli_prompt()?;
                            continue;
                        }

                        let bind = match parse_grpc_bind(&tokens[1..]) {
                            Ok(bind) => bind,
                            Err(err) => {
                                eprintln!("Error: {err}");
                                print_cli_prompt()?;
                                continue;
                            }
                        };

                        match start_interactive_grpc(bind.clone(), runtime_paths).await {
                            Ok(state) => {
                                grpc_state = Some(state);
                                println!("gRPC runtime started in background (bind={bind}).");
                            }
                            Err(err) => eprintln!("Error: {err:#}"),
                        }
                    }
                    _ => {
                        let rewritten = rewrite_repl_aliases(tokens);
                        let parsed = match parse_repl_clap_command(&rewritten) {
                            Ok(parsed) => parsed,
                            Err(err) => {
                                eprintln!("Error: {err:#}");
                                print_cli_prompt()?;
                                continue;
                            }
                        };

                        if matches!(parsed, Command::Cli) {
                            eprintln!("`cli` cannot be nested inside interactive mode.");
                            print_cli_prompt()?;
                            continue;
                        }

                        if let Err(err) =
                            execute_non_interactive_command(parsed, dir, runtime_paths).await
                        {
                            eprintln!("Error: {err:#}");
                        }
                    }
                }

                if let Some(message) = maybe_collect_runtime_completion(&mut runtime_state).await {
                    println!("{message}");
                }
                if let Some(message) = maybe_collect_grpc_completion(&mut grpc_state).await {
                    println!("{message}");
                }
                print_cli_prompt()?;
            }
        }
    }

    if let Some(state) = runtime_state.take() {
        println!("Stopping serve runtime...");
        let _ = stop_interactive_runtime(state).await;
    }
    if let Some(state) = grpc_state.take() {
        println!("Stopping gRPC runtime...");
        let _ = stop_interactive_grpc(state).await;
    }

    Ok(())
}

fn print_cli_prompt() -> anyhow::Result<()> {
    use std::io::Write;

    print!("openproton> ");
    std::io::stdout()
        .flush()
        .context("failed to flush stdout")?;
    Ok(())
}

fn split_shell_words(input: &str) -> anyhow::Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match quote {
            Some(active_quote) => {
                if ch == active_quote {
                    quote = None;
                    continue;
                }

                if ch == '\\' && active_quote == '"' {
                    if let Some(next) = chars.next() {
                        current.push(next);
                        continue;
                    }
                    anyhow::bail!("unterminated escape sequence");
                }

                current.push(ch);
            }
            None => match ch {
                '\'' | '"' => quote = Some(ch),
                '\\' => {
                    if let Some(next) = chars.next() {
                        current.push(next);
                    } else {
                        anyhow::bail!("unterminated escape sequence");
                    }
                }
                c if c.is_whitespace() => {
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                }
                _ => current.push(ch),
            },
        }
    }

    if quote.is_some() {
        anyhow::bail!("unterminated quoted string");
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    Ok(tokens)
}

fn parse_repl_clap_command(tokens: &[String]) -> anyhow::Result<Command> {
    let mut argv = Vec::with_capacity(tokens.len() + 1);
    argv.push("openproton-bridge".to_string());
    argv.extend(tokens.iter().cloned());

    let parsed = Cli::try_parse_from(argv).map_err(|err| anyhow::anyhow!(err.to_string()))?;
    if parsed.vault_dir.is_some()
        || parsed.credential_store.is_some()
        || parsed.credential_store_namespace.is_some()
        || parsed.credential_store_secret.is_some()
        || parsed.credential_store_system_service.is_some()
        || parsed.credential_store_pass_entry.is_some()
        || parsed.credential_store_file_path.is_some()
    {
        anyhow::bail!(
            "interactive mode does not accept global override flags; restart with the desired global flags"
        );
    }

    Ok(parsed.command)
}

fn rewrite_repl_aliases(mut tokens: Vec<String>) -> Vec<String> {
    if tokens.is_empty() {
        return tokens;
    }

    let head = tokens[0].to_ascii_lowercase();
    match head.as_str() {
        "add" | "a" | "con" | "connect" => {
            tokens[0] = "login".to_string();
        }
        "man" => {
            tokens[0] = "help".to_string();
        }
        "d" | "disconnect" => {
            tokens[0] = "logout".to_string();
        }
        _ => {}
    }

    let head = tokens[0].to_ascii_lowercase();
    if head == "login" && tokens.len() == 2 && !tokens[1].starts_with('-') {
        let username = tokens[1].clone();
        tokens = vec!["login".to_string(), "--username".to_string(), username];
    } else if head == "logout" && tokens.len() == 2 && !tokens[1].starts_with('-') {
        if tokens[1].eq_ignore_ascii_case("all") {
            tokens = vec!["logout".to_string(), "--all".to_string()];
        } else {
            let email = tokens[1].clone();
            tokens = vec!["logout".to_string(), "--email".to_string(), email];
        }
    } else if head == "fetch" && tokens.len() == 2 && !tokens[1].starts_with('-') {
        let limit = tokens[1].clone();
        tokens = vec!["fetch".to_string(), "--limit".to_string(), limit];
    }

    tokens
}

fn parse_serve_overrides(args: &[String]) -> anyhow::Result<ServeCommandOverrides> {
    let mut overrides = ServeCommandOverrides::default();
    let mut idx = 0usize;

    while idx < args.len() {
        match args[idx].as_str() {
            "--imap-port" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .context("missing value for --imap-port")?
                    .parse::<u16>()
                    .context("invalid --imap-port value")?;
                overrides.imap_port = Some(value);
            }
            "--smtp-port" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .context("missing value for --smtp-port")?
                    .parse::<u16>()
                    .context("invalid --smtp-port value")?;
                overrides.smtp_port = Some(value);
            }
            "--bind" => {
                idx += 1;
                let value = args.get(idx).context("missing value for --bind")?.trim();
                if value.is_empty() {
                    anyhow::bail!("invalid --bind value");
                }
                overrides.bind = Some(value.to_string());
            }
            "--event-poll-secs" => {
                idx += 1;
                let value = args
                    .get(idx)
                    .context("missing value for --event-poll-secs")?
                    .parse::<u64>()
                    .context("invalid --event-poll-secs value")?;
                overrides.event_poll_secs = Some(value);
            }
            "--no-tls" => {
                overrides.no_tls = Some(true);
            }
            "--tls" => {
                overrides.no_tls = Some(false);
            }
            unknown => {
                anyhow::bail!(
                    "unsupported serve option `{unknown}`. supported: --imap-port, --smtp-port, --bind, --event-poll-secs, --no-tls, --tls"
                );
            }
        }

        idx += 1;
    }

    Ok(overrides)
}

fn handle_interactive_change_command(
    args: &[String],
    serve_config: &mut InteractiveServeConfig,
) -> anyhow::Result<()> {
    if args.is_empty() {
        anyhow::bail!(
            "usage: change <imap-port|smtp-port|bind|event-poll-secs> <value> | change <imap-security|smtp-security> [starttls|none]"
        );
    }

    let field = args[0].to_ascii_lowercase();
    let value = args.get(1).map(|value| value.trim());

    match field.as_str() {
        "imap-port" => {
            let value = value.context("missing IMAP port value")?;
            serve_config.imap_port = value.parse::<u16>().context("invalid IMAP port")?;
            println!("Updated IMAP port: {}", serve_config.imap_port);
        }
        "smtp-port" => {
            let value = value.context("missing SMTP port value")?;
            serve_config.smtp_port = value.parse::<u16>().context("invalid SMTP port")?;
            println!("Updated SMTP port: {}", serve_config.smtp_port);
        }
        "bind" => {
            let value = value.context("missing bind value")?;
            if value.is_empty() {
                anyhow::bail!("bind cannot be empty");
            }
            serve_config.bind = value.to_string();
            println!("Updated bind address: {}", serve_config.bind);
        }
        "event-poll-secs" => {
            let value = value.context("missing event poll interval value")?;
            serve_config.event_poll_secs = value
                .parse::<u64>()
                .context("invalid event poll interval value")?;
            println!(
                "Updated event poll interval: {} seconds",
                serve_config.event_poll_secs
            );
        }
        "imap-security" | "smtp-security" => {
            match value.map(|value| value.to_ascii_lowercase()) {
                Some(mode) => match mode.as_str() {
                    "none" | "off" | "plain" => {
                        serve_config.no_tls = true;
                        println!("Updated security mode: None (plaintext)");
                    }
                    "starttls" | "ssl" | "tls" => {
                        serve_config.no_tls = false;
                        println!("Updated security mode: STARTTLS");
                    }
                    _ => anyhow::bail!(
                        "invalid security value `{mode}`; expected starttls or none"
                    ),
                },
                None => {
                    // Proton Bridge CLI toggles security mode when no explicit value is provided.
                    serve_config.no_tls = !serve_config.no_tls;
                    println!(
                        "Updated security mode: {}",
                        if serve_config.no_tls {
                            "None (plaintext)"
                        } else {
                            "STARTTLS"
                        }
                    );
                }
            }
        }
        _ => anyhow::bail!(
            "unknown change target `{}`; expected imap-port, smtp-port, bind, event-poll-secs, imap-security, smtp-security",
            args[0]
        ),
    }

    Ok(())
}

fn print_interactive_help() {
    println!("Available commands:");
    println!("  help                             Show this help");
    println!("  quit | exit                      Exit interactive shell");
    println!("  manual | man                     Print project manual URL");
    println!("  check-updates                    Alias for updates check");
    println!("  credits                          Print credits/dependency info");
    println!("  log-dir                          Print log directory path");
    println!("  telemetry <enable|disable|status> Manage telemetry setting");
    println!("  proxy <allow|disallow|status>    Manage DoH proxy fallback setting");
    println!("  autostart <enable|disable|status> Manage autostart setting");
    println!("  all-mail-visibility <show|hide|status> Manage All Mail visibility");
    println!("  updates ...                      Manage update channel/autoupdates");
    println!("  status                           Show account/session status");
    println!("  list | ls                        List accounts");
    println!("  info                             Alias for status");
    println!("  login [email|--username <email>] Login to Proton");
    println!("  logout [all|--all|--email <email>] Logout one account or all accounts");
    println!("  delete <email>                   Remove one account");
    println!("  use <email>                      Set default account");
    println!("  fetch [--limit <n>]              Fetch/decrypt inbox messages");
    println!("  vault-dump                       Dump decrypted vault msgpack structure");
    println!("  change-location <path>           Change encrypted message cache location");
    println!("  bad-event <synchronize|logout>   Resolve bad-event flows");
    println!("  cert <status|install|export|import> Manage TLS cert files");
    println!(
        "  repair                           Reset event checkpoints and restart serve runtime"
    );
    println!("  reset --force                    Clear sessions and grpc settings");
    println!("  imap-security                    Toggle IMAP security mode");
    println!("  smtp-security                    Toggle SMTP security mode");
    println!("  ssl-imap | starttls-imap         Alias for imap-security");
    println!("  ssl-smtp | starttls-smtp         Alias for smtp-security");
    println!("  change <field> ...               Update interactive serve defaults");
    println!("  change mode <email> <split|combined> Set account address mode");
    println!("  serve-config                     Print interactive serve defaults");
    println!("  serve-status                     Show background serve runtime status");
    println!("  serve [serve flags]              Start IMAP+SMTP server (background)");
    println!("  grpc-status                      Show background gRPC runtime status");
    println!("  grpc [grpc flags]                Start gRPC frontend service (background)");
    println!("  grpc-stop                        Stop background gRPC runtime");
    println!("  stop                             Stop all background runtimes");
    println!();
    print_interactive_serve_help();
    print_interactive_grpc_help();
}

fn cmd_vault_dump(dir: &std::path::Path) -> anyhow::Result<()> {
    let value = vault::load_vault_msgpack_value(dir)
        .context("failed to decrypt and decode vault msgpack payload")?;

    match serde_json::to_string_pretty(&value) {
        Ok(rendered) => println!("{rendered}"),
        Err(err) => {
            eprintln!("warning: failed to render JSON output ({err}); falling back to debug view");
            println!("{value:#?}");
        }
    }

    Ok(())
}

fn print_interactive_serve_help() {
    println!("Serve flags:");
    println!("  --imap-port <port>");
    println!("  --smtp-port <port>");
    println!("  --bind <ip>");
    println!("  --event-poll-secs <seconds>");
    println!("  --no-tls | --tls");
}

fn print_interactive_grpc_help() {
    println!("gRPC flags:");
    println!("  --bind <ip>");
}

fn parse_grpc_bind(args: &[String]) -> anyhow::Result<String> {
    if args.is_empty() {
        return Ok("127.0.0.1".to_string());
    }

    if args.len() == 2 && args[0] == "--bind" {
        let bind = args[1].trim();
        if bind.is_empty() {
            anyhow::bail!("invalid --bind value");
        }
        return Ok(bind.to_string());
    }

    anyhow::bail!("unsupported grpc option(s); supported: --bind <ip>")
}

async fn load_app_settings_for_cli(
    runtime_paths: &paths::RuntimePaths,
) -> anyhow::Result<CliStoredAppSettings> {
    let path = runtime_paths.grpc_app_settings_path();
    if !path.exists() {
        return Ok(CliStoredAppSettings::defaults_for(runtime_paths));
    }

    let payload = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&payload).with_context(|| format!("failed to parse {}", path.display()))
}

async fn save_app_settings_for_cli(
    runtime_paths: &paths::RuntimePaths,
    settings: &CliStoredAppSettings,
) -> anyhow::Result<()> {
    let path = runtime_paths.grpc_app_settings_path();
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create settings dir {}", parent.display()))?;
    }

    let tmp_path = path.with_file_name("grpc_app_settings.json.tmp");
    let payload = serde_json::to_vec_pretty(settings).context("failed to encode app settings")?;
    tokio::fs::write(&tmp_path, payload)
        .await
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    tokio::fs::rename(&tmp_path, &path)
        .await
        .with_context(|| format!("failed to rename settings file {}", path.display()))?;
    Ok(())
}

async fn update_app_settings<F>(
    runtime_paths: &paths::RuntimePaths,
    mutator: F,
) -> anyhow::Result<()>
where
    F: FnOnce(&mut CliStoredAppSettings),
{
    let mut settings = load_app_settings_for_cli(runtime_paths).await?;
    mutator(&mut settings);
    save_app_settings_for_cli(runtime_paths, &settings).await
}

async fn set_disk_cache_path_for_cli(
    runtime_paths: &paths::RuntimePaths,
    target: &str,
) -> anyhow::Result<()> {
    let target = target.trim();
    if target.is_empty() {
        anyhow::bail!("disk cache path cannot be empty");
    }

    let target_path = std::path::PathBuf::from(target);
    let current_path = effective_disk_cache_path(runtime_paths);

    move_disk_cache_payload_for_cli(&current_path, &target_path).await?;

    update_app_settings(runtime_paths, |settings| {
        settings.disk_cache_path = target_path.display().to_string();
    })
    .await?;

    Ok(())
}

async fn move_disk_cache_payload_for_cli(
    current: &std::path::Path,
    target: &std::path::Path,
) -> anyhow::Result<()> {
    if current == target {
        tokio::fs::create_dir_all(target)
            .await
            .with_context(|| format!("failed to create disk cache path {}", target.display()))?;
        return Ok(());
    }

    if target.starts_with(current) {
        anyhow::bail!(
            "target disk cache path {} must not be inside current path {}",
            target.display(),
            current.display()
        );
    }

    tokio::fs::create_dir_all(target)
        .await
        .with_context(|| format!("failed to create disk cache path {}", target.display()))?;

    if tokio::fs::metadata(current).await.is_err() {
        return Ok(());
    }

    copy_dir_contents_for_cli(current, target).await?;

    if let Err(err) = tokio::fs::remove_dir_all(current).await {
        tracing::warn!(
            error = %err,
            old_path = %current.display(),
            "failed to clean old disk cache path after successful move"
        );
    }

    Ok(())
}

async fn copy_dir_contents_for_cli(
    src: &std::path::Path,
    dst: &std::path::Path,
) -> anyhow::Result<()> {
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];

    while let Some((current_src, current_dst)) = stack.pop() {
        tokio::fs::create_dir_all(&current_dst)
            .await
            .with_context(|| format!("failed to create directory {}", current_dst.display()))?;

        let mut entries = tokio::fs::read_dir(&current_src)
            .await
            .with_context(|| format!("failed to read directory {}", current_src.display()))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .with_context(|| format!("failed reading entries for {}", current_src.display()))?
        {
            let src_path = entry.path();
            let dst_path = current_dst.join(entry.file_name());
            let file_type = entry
                .file_type()
                .await
                .with_context(|| format!("failed to read file type for {}", src_path.display()))?;

            if file_type.is_dir() {
                stack.push((src_path, dst_path));
                continue;
            }

            if file_type.is_file() {
                tokio::fs::copy(&src_path, &dst_path)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to copy file from {} to {}",
                            src_path.display(),
                            dst_path.display()
                        )
                    })?;
            }
        }
    }

    Ok(())
}

fn cli_tls_paths(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let tls_dir = dir.join("tls");
    (tls_dir.join("cert.pem"), tls_dir.join("key.pem"))
}

fn ensure_cli_tls_certificate(dir: &std::path::Path) -> anyhow::Result<()> {
    let cert_dir = dir.join("tls");
    let _imap = imap::server::ImapServer::new().with_tls(&cert_dir)?;
    let _smtp = smtp::server::SmtpServer::new().with_tls(&cert_dir)?;
    Ok(())
}

fn export_cli_tls_certificate(dir: &std::path::Path, target_dir: &str) -> anyhow::Result<()> {
    ensure_cli_tls_certificate(dir)?;
    let (cert_path, key_path) = cli_tls_paths(dir);
    let target = std::path::PathBuf::from(target_dir);
    std::fs::create_dir_all(&target)
        .with_context(|| format!("failed to create export dir {}", target.display()))?;
    std::fs::copy(&cert_path, target.join("cert.pem"))
        .with_context(|| format!("failed to export {}", cert_path.display()))?;
    std::fs::copy(&key_path, target.join("key.pem"))
        .with_context(|| format!("failed to export {}", key_path.display()))?;
    Ok(())
}

fn import_cli_tls_certificate(dir: &std::path::Path, source_dir: &str) -> anyhow::Result<()> {
    let source = std::path::PathBuf::from(source_dir);
    let source_cert = source.join("cert.pem");
    let source_key = source.join("key.pem");
    if !source_cert.exists() || !source_key.exists() {
        anyhow::bail!(
            "missing cert.pem/key.pem in import source directory {}",
            source.display()
        );
    }

    let (cert_path, key_path) = cli_tls_paths(dir);
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create tls dir {}", parent.display()))?;
    }
    std::fs::copy(&source_cert, &cert_path)
        .with_context(|| format!("failed to import {}", source_cert.display()))?;
    std::fs::copy(&source_key, &key_path)
        .with_context(|| format!("failed to import {}", source_key.display()))?;
    Ok(())
}

async fn run_interactive_repair(
    dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
    runtime_state: &mut Option<InteractiveServeRuntime>,
    event_tx: tokio::sync::mpsc::UnboundedSender<String>,
) -> anyhow::Result<()> {
    let sessions = vault::list_sessions(dir).context("failed to load sessions")?;
    for session in &sessions {
        let checkpoint = vault::StoredEventCheckpoint {
            last_event_id: String::new(),
            last_event_ts: None,
            sync_state: None,
        };
        vault::save_event_checkpoint_by_account_id(dir, &session.uid, &checkpoint)
            .with_context(|| format!("failed to reset event checkpoint for {}", session.email))?;
    }
    println!("Reset event checkpoints for {} account(s).", sessions.len());

    if let Some(state) = runtime_state.take() {
        let config = state.config.clone();
        stop_interactive_runtime(state).await?;
        let restarted =
            start_interactive_runtime(config, dir, runtime_paths, event_tx.clone()).await?;
        *runtime_state = Some(restarted);
        println!("Serve runtime restarted after repair.");
    } else {
        println!("Serve runtime not running. Start `serve` to apply repair now.");
    }

    Ok(())
}

async fn run_interactive_reset(
    dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
    runtime_state: &mut Option<InteractiveServeRuntime>,
    grpc_state: &mut Option<InteractiveGrpcRuntime>,
) -> anyhow::Result<()> {
    if let Some(state) = runtime_state.take() {
        stop_interactive_runtime(state).await?;
    }
    if let Some(state) = grpc_state.take() {
        stop_interactive_grpc(state).await?;
    }

    if vault::session_exists(dir) {
        vault::remove_session(dir).context("failed to clear sessions")?;
    }

    let _ = tokio::fs::remove_file(runtime_paths.grpc_mail_settings_path()).await;
    let _ = tokio::fs::remove_file(runtime_paths.grpc_app_settings_path()).await;

    Ok(())
}

fn set_account_mode_by_email(dir: &std::path::Path, email: &str, mode: &str) -> anyhow::Result<()> {
    let sessions = vault::list_sessions(dir).context("failed to load sessions")?;
    let session = sessions
        .iter()
        .find(|session| session.email.eq_ignore_ascii_case(email))
        .ok_or_else(|| anyhow::anyhow!("unknown account email: {email}"))?;

    let enabled = match mode.trim().to_ascii_lowercase().as_str() {
        "split" => true,
        "combined" => false,
        other => anyhow::bail!("invalid mode `{other}`; expected split or combined"),
    };

    vault::save_split_mode_by_account_id(dir, &session.uid, enabled)
        .with_context(|| format!("failed to update mode for {}", session.email))?;
    println!(
        "Address mode for {} set to {}.",
        session.email,
        if enabled { "split" } else { "combined" }
    );

    Ok(())
}

fn print_interactive_serve_config(config: &InteractiveServeConfig) {
    println!("Interactive serve defaults:");
    println!("  IMAP port: {}", config.imap_port);
    println!("  SMTP port: {}", config.smtp_port);
    println!("  Bind: {}", config.bind);
    println!(
        "  Security: {}",
        if config.no_tls { "None" } else { "STARTTLS" }
    );
    println!("  Event poll secs: {}", config.event_poll_secs);
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
    let context = prepare_serve_runtime(
        imap_port,
        smtp_port,
        bind,
        no_tls,
        event_poll_secs,
        dir,
        runtime_paths,
    )
    .await?;

    run_serve_runtime(context, None, None).await
}

struct ServeRuntimeContext {
    imap_addr: String,
    smtp_addr: String,
    imap_config: Arc<imap::session::SessionConfig>,
    smtp_config: Arc<smtp::session::SmtpSessionConfig>,
    runtime_accounts: Arc<bridge::accounts::RuntimeAccountRegistry>,
    runtime_snapshot: Vec<bridge::accounts::RuntimeAccountInfo>,
    api_base_url: String,
    auth_router: bridge::auth_router::AuthRouter,
    event_store: Arc<dyn imap::store::MessageStore>,
    checkpoint_store: bridge::events::SharedCheckpointStore,
    poll_interval: std::time::Duration,
}

async fn prepare_serve_runtime(
    imap_port: u16,
    smtp_port: u16,
    bind: &str,
    no_tls: bool,
    event_poll_secs: u64,
    dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
) -> anyhow::Result<ServeRuntimeContext> {
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

    let imap_config = Arc::new(imap::session::SessionConfig {
        api_base_url: api_base_url.clone(),
        auth_router: auth_router.clone(),
        runtime_accounts: runtime_accounts.clone(),
        store,
    });

    let smtp_config = Arc::new(smtp::session::SmtpSessionConfig {
        api_base_url: api_base_url.clone(),
        auth_router: auth_router.clone(),
        runtime_accounts: runtime_accounts.clone(),
    });

    if !no_tls {
        let cert_dir = dir.join("tls");
        let _imap_server = imap::server::ImapServer::new().with_tls(&cert_dir)?;
        let _smtp_server = smtp::server::SmtpServer::new().with_tls(&cert_dir)?;
    }

    print_serve_configuration(
        bind,
        imap_port,
        smtp_port,
        no_tls,
        &active_sessions,
        &runtime_snapshot,
    );

    Ok(ServeRuntimeContext {
        imap_addr: format!("{}:{}", bind, imap_port),
        smtp_addr: format!("{}:{}", bind, smtp_port),
        imap_config,
        smtp_config,
        runtime_accounts,
        runtime_snapshot,
        api_base_url,
        auth_router,
        event_store,
        checkpoint_store: Arc::new(bridge::events::VaultCheckpointStore::new(dir.to_path_buf())),
        poll_interval: std::time::Duration::from_secs(event_poll_secs),
    })
}

fn print_serve_configuration(
    bind: &str,
    imap_port: u16,
    smtp_port: u16,
    no_tls: bool,
    active_sessions: &[api::types::Session],
    runtime_snapshot: &[bridge::accounts::RuntimeAccountInfo],
) {
    println!("IMAP server configuration:");
    println!("  Server: {}", bind);
    println!("  Port: {}", imap_port);
    println!("  Security: {}", if no_tls { "None" } else { "STARTTLS" });
    println!("  Accounts:");
    for session in active_sessions {
        let password = session
            .bridge_password
            .as_deref()
            .unwrap_or("<missing-bridge-password>");
        println!("    {} / {}", session.email, password);
    }
    println!("  Health:");
    for info in runtime_snapshot {
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
    for session in active_sessions {
        let password = session
            .bridge_password
            .as_deref()
            .unwrap_or("<missing-bridge-password>");
        println!("    {} / {}", session.email, password);
    }
    println!("  Health:");
    for info in runtime_snapshot {
        println!(
            "    {} ({}) = {:?}",
            info.email, info.account_id.0, info.health
        );
    }
    println!();
}

async fn run_serve_runtime(
    context: ServeRuntimeContext,
    shutdown_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    notify_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
) -> anyhow::Result<()> {
    let ServeRuntimeContext {
        imap_addr,
        smtp_addr,
        imap_config,
        smtp_config,
        runtime_accounts,
        runtime_snapshot,
        api_base_url,
        auth_router,
        event_store,
        checkpoint_store,
        poll_interval,
    } = context;

    let account_lookup: std::collections::HashMap<String, String> = runtime_snapshot
        .iter()
        .map(|info| (info.account_id.0.clone(), info.email.clone()))
        .collect();
    let notify_for_callback = notify_tx.clone();
    let sync_progress_callback: bridge::events::SyncProgressCallback =
        Arc::new(move |event| match event {
            bridge::events::SyncProgressUpdate::Started { user_id } => {
                let label = account_lookup
                    .get(&user_id)
                    .cloned()
                    .unwrap_or_else(|| user_id.clone());
                tracing::info!(user_id = %user_id, "account sync started");
                if let Some(tx) = notify_for_callback.as_ref() {
                    let _ = tx.send(format!("[event] sync started: {label}"));
                }
            }
            bridge::events::SyncProgressUpdate::Progress {
                user_id,
                progress,
                elapsed_ms: _,
                remaining_ms: _,
            } => {
                tracing::debug!(user_id = %user_id, progress, "account sync progress");
                if let Some(tx) = notify_for_callback.as_ref() {
                    let label = account_lookup
                        .get(&user_id)
                        .cloned()
                        .unwrap_or_else(|| user_id.clone());
                    let _ = tx.send(format!(
                        "[event] sync progress: {label} ({:.1}%)",
                        progress * 100.0
                    ));
                }
            }
            bridge::events::SyncProgressUpdate::Finished { user_id } => {
                let label = account_lookup
                    .get(&user_id)
                    .cloned()
                    .unwrap_or_else(|| user_id.clone());
                tracing::info!(user_id = %user_id, "account sync finished");
                if let Some(tx) = notify_for_callback.as_ref() {
                    let _ = tx.send(format!("[event] sync finished: {label}"));
                }
            }
        });

    let event_workers = bridge::events::start_event_worker_group_with_sync_progress(
        runtime_accounts.clone(),
        runtime_snapshot.clone(),
        api_base_url,
        auth_router,
        event_store,
        checkpoint_store,
        Some(sync_progress_callback),
        poll_interval,
    );

    let health_task = tokio::spawn(report_runtime_health_periodically(
        runtime_accounts,
        notify_tx.clone(),
    ));
    let mut imap_task =
        tokio::spawn(async move { imap::server::run_server(&imap_addr, imap_config).await });
    let mut smtp_task =
        tokio::spawn(async move { smtp::server::run_server(&smtp_addr, smtp_config).await });

    let shutdown_wait = async move {
        if let Some(rx) = shutdown_rx {
            let _ = rx.await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::pin!(shutdown_wait);

    let serve_result: anyhow::Result<()> = tokio::select! {
        _ = &mut shutdown_wait => {
            Ok(())
        }
        result = &mut imap_task => {
            match result {
                Ok(inner) => inner.map_err(anyhow::Error::from),
                Err(err) => Err(anyhow::Error::new(err).context("IMAP server task failed")),
            }
        }
        result = &mut smtp_task => {
            match result {
                Ok(inner) => inner.map_err(anyhow::Error::from),
                Err(err) => Err(anyhow::Error::new(err).context("SMTP server task failed")),
            }
        }
    };

    if !imap_task.is_finished() {
        imap_task.abort();
    }
    if !smtp_task.is_finished() {
        smtp_task.abort();
    }
    let _ = imap_task.await;
    let _ = smtp_task.await;

    health_task.abort();
    let _ = health_task.await;
    event_workers.shutdown().await;

    if let Some(tx) = notify_tx.as_ref() {
        if serve_result.is_ok() {
            let _ = tx.send("[event] serve runtime stopped".to_string());
        }
    }

    serve_result
}

async fn start_interactive_runtime(
    config: InteractiveServeConfig,
    dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
    notify_tx: tokio::sync::mpsc::UnboundedSender<String>,
) -> anyhow::Result<InteractiveServeRuntime> {
    let context = prepare_serve_runtime(
        config.imap_port,
        config.smtp_port,
        &config.bind,
        config.no_tls,
        config.event_poll_secs,
        dir,
        runtime_paths,
    )
    .await?;

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let join_handle = tokio::spawn(run_serve_runtime(context, Some(stop_rx), Some(notify_tx)));
    Ok(InteractiveServeRuntime {
        stop_tx: Some(stop_tx),
        join_handle,
        config,
    })
}

async fn stop_interactive_runtime(mut state: InteractiveServeRuntime) -> anyhow::Result<()> {
    if let Some(stop_tx) = state.stop_tx.take() {
        let _ = stop_tx.send(());
    }

    match state.join_handle.await {
        Ok(result) => result,
        Err(err) => Err(anyhow::Error::new(err).context("serve runtime join failed")),
    }
}

async fn maybe_collect_runtime_completion(
    runtime_state: &mut Option<InteractiveServeRuntime>,
) -> Option<String> {
    let is_finished = runtime_state
        .as_ref()
        .is_some_and(|state| state.join_handle.is_finished());
    if !is_finished {
        return None;
    }

    let state = runtime_state.take()?;
    Some(match state.join_handle.await {
        Ok(Ok(())) => "Serve runtime exited.".to_string(),
        Ok(Err(err)) => format!("Serve runtime exited with error: {err:#}"),
        Err(err) => format!("Serve runtime task join error: {err}"),
    })
}

async fn start_interactive_grpc(
    bind: String,
    runtime_paths: &paths::RuntimePaths,
) -> anyhow::Result<InteractiveGrpcRuntime> {
    let runtime_paths = runtime_paths.clone();
    let bind_for_task = bind.clone();
    let join_handle = tokio::spawn(async move { cmd_grpc(&bind_for_task, &runtime_paths).await });
    Ok(InteractiveGrpcRuntime { join_handle, bind })
}

async fn stop_interactive_grpc(state: InteractiveGrpcRuntime) -> anyhow::Result<()> {
    if !state.join_handle.is_finished() {
        state.join_handle.abort();
    }

    match state.join_handle.await {
        Ok(result) => result,
        Err(err) if err.is_cancelled() => Ok(()),
        Err(err) => Err(anyhow::Error::new(err).context("gRPC runtime join failed")),
    }
}

async fn maybe_collect_grpc_completion(
    grpc_state: &mut Option<InteractiveGrpcRuntime>,
) -> Option<String> {
    let is_finished = grpc_state
        .as_ref()
        .is_some_and(|state| state.join_handle.is_finished());
    if !is_finished {
        return None;
    }

    let state = grpc_state.take()?;
    Some(match state.join_handle.await {
        Ok(Ok(())) => "gRPC runtime exited.".to_string(),
        Ok(Err(err)) => format!("gRPC runtime exited with error: {err:#}"),
        Err(err) => format!("gRPC runtime task join error: {err}"),
    })
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
    notify_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
) {
    use tokio::time::{interval, Duration, MissedTickBehavior};

    let mut ticker = interval(Duration::from_secs(60));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker.tick().await;
    let mut previous_health = std::collections::HashMap::new();

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

        let mut seen_account_ids = std::collections::HashSet::new();

        for info in &snapshot {
            seen_account_ids.insert(info.account_id.0.clone());
            let previous = previous_health.insert(info.account_id.0.clone(), info.health);
            if let Some(tx) = notify_tx.as_ref() {
                if previous != Some(info.health) {
                    let is_baseline_healthy = previous.is_none()
                        && matches!(info.health, bridge::accounts::AccountHealth::Healthy);
                    if !is_baseline_healthy {
                        let _ = tx.send(format!(
                            "[event] account health: {} ({}) -> {:?}",
                            info.email, info.account_id.0, info.health
                        ));
                    }
                }
            }

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

        previous_health.retain(|account_id, _| seen_account_ids.contains(account_id));
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
    fn parse_cli_subcommand() {
        let cli = Cli::try_parse_from(["openproton-bridge", "cli"]).unwrap();
        assert!(matches!(cli.command, Command::Cli));
    }

    #[test]
    fn parse_vault_dump_subcommand() {
        let cli = Cli::try_parse_from(["openproton-bridge", "vault-dump"]).unwrap();
        assert!(matches!(cli.command, Command::VaultDump));
    }

    #[test]
    fn rewrite_repl_aliases_supports_positional_login_logout_fetch_forms() {
        assert_eq!(
            rewrite_repl_aliases(vec!["login".into(), "user@proton.me".into()]),
            vec![
                "login".to_string(),
                "--username".to_string(),
                "user@proton.me".to_string()
            ]
        );
        assert_eq!(
            rewrite_repl_aliases(vec!["logout".into(), "all".into()]),
            vec!["logout".to_string(), "--all".to_string()]
        );
        assert_eq!(
            rewrite_repl_aliases(vec!["fetch".into(), "15".into()]),
            vec!["fetch".to_string(), "--limit".to_string(), "15".to_string()]
        );
    }

    #[test]
    fn split_shell_words_supports_quoted_segments() {
        let parsed =
            split_shell_words("login --username \"first last@proton.me\" --extra 'quoted value'")
                .unwrap();
        assert_eq!(
            parsed,
            vec![
                "login".to_string(),
                "--username".to_string(),
                "first last@proton.me".to_string(),
                "--extra".to_string(),
                "quoted value".to_string()
            ]
        );
    }

    #[test]
    fn parse_serve_overrides_accepts_expected_flags() {
        let parsed = parse_serve_overrides(&[
            "--imap-port".to_string(),
            "2143".to_string(),
            "--smtp-port".to_string(),
            "2025".to_string(),
            "--bind".to_string(),
            "0.0.0.0".to_string(),
            "--event-poll-secs".to_string(),
            "12".to_string(),
            "--no-tls".to_string(),
        ])
        .unwrap();

        assert_eq!(parsed.imap_port, Some(2143));
        assert_eq!(parsed.smtp_port, Some(2025));
        assert_eq!(parsed.bind.as_deref(), Some("0.0.0.0"));
        assert_eq!(parsed.event_poll_secs, Some(12));
        assert_eq!(parsed.no_tls, Some(true));
    }

    #[test]
    fn parse_grpc_bind_defaults_and_accepts_bind_flag() {
        assert_eq!(parse_grpc_bind(&[]).unwrap(), "127.0.0.1".to_string());
        assert_eq!(
            parse_grpc_bind(&["--bind".to_string(), "0.0.0.0".to_string()]).unwrap(),
            "0.0.0.0".to_string()
        );
    }

    #[test]
    fn parse_grpc_bind_rejects_unsupported_args() {
        assert!(parse_grpc_bind(&["--port".to_string(), "8080".to_string()]).is_err());
        assert!(parse_grpc_bind(&["--bind".to_string()]).is_err());
    }

    #[test]
    fn parse_global_credential_store_flags() {
        let cli = Cli::try_parse_from([
            "openproton-bridge",
            "--credential-store",
            "file",
            "--credential-store-namespace",
            "openproton-bridge",
            "--credential-store-secret",
            "openproton-vault-key",
            "--credential-store-file-path",
            "/tmp/openproton.key",
            "status",
        ])
        .unwrap();

        assert_eq!(cli.credential_store, Some(CredentialStoreBackendArg::File));
        assert_eq!(
            cli.credential_store_namespace.as_deref(),
            Some("openproton-bridge")
        );
        assert_eq!(
            cli.credential_store_secret.as_deref(),
            Some("openproton-vault-key")
        );
        assert_eq!(
            cli.credential_store_file_path.as_deref(),
            Some(std::path::Path::new("/tmp/openproton.key"))
        );
        assert!(matches!(cli.command, Command::Status));
    }

    #[test]
    fn parse_credential_store_backend_accepts_expected_values() {
        assert_eq!(
            parse_credential_store_backend("auto").unwrap(),
            vault::CredentialStoreBackend::Auto
        );
        assert_eq!(
            parse_credential_store_backend("system").unwrap(),
            vault::CredentialStoreBackend::System
        );
        assert_eq!(
            parse_credential_store_backend("pass").unwrap(),
            vault::CredentialStoreBackend::Pass
        );
        assert_eq!(
            parse_credential_store_backend("file").unwrap(),
            vault::CredentialStoreBackend::File
        );
        assert!(parse_credential_store_backend("invalid").is_err());
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
