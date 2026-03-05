#![allow(dead_code)]

use std::process::Command as ProcessCommand;
use std::sync::Once;

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
mod client_config;
mod crypto;
mod frontend;
mod imap;
mod observability;
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

    /// Command execution mode: direct (local) or grpc (frontend service)
    #[arg(long, global = true, value_enum)]
    mode: Option<ExecutionModeArg>,

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
        /// Proton API mode to use for this account (default: bridge)
        #[arg(long, value_enum)]
        api_mode: Option<ApiModeArg>,
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
    /// Start the IMAP/SMTP servers with the gRPC control service
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
    /// Generate mutt/neomutt account configuration
    MuttConfig {
        /// Account selector (email, display name, or index). Defaults to active account.
        #[arg(long)]
        account: Option<String>,
        /// Override username/from address used by mutt.
        #[arg(long)]
        address: Option<String>,
        /// Write output to a file instead of stdout.
        #[arg(long)]
        output: Option<std::path::PathBuf>,
        /// Include bridge password directly in output.
        #[arg(long, default_value_t = false)]
        include_password: bool,
    },
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

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum ApiModeArg {
    Bridge,
    Webmail,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutionModeArg {
    Direct,
    Grpc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutionMode {
    Direct,
    Grpc,
}

impl From<ApiModeArg> for api::types::ApiMode {
    fn from(value: ApiModeArg) -> Self {
        match value {
            ApiModeArg::Bridge => api::types::ApiMode::Bridge,
            ApiModeArg::Webmail => api::types::ApiMode::Webmail,
        }
    }
}

impl From<ExecutionModeArg> for ExecutionMode {
    fn from(value: ExecutionModeArg) -> Self {
        match value {
            ExecutionModeArg::Direct => ExecutionMode::Direct,
            ExecutionModeArg::Grpc => ExecutionMode::Grpc,
        }
    }
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
const ENV_OPENPROTON_EXEC_MODE: &str = "OPENPROTON_EXEC_MODE";
static PANIC_HOOK_INSTALLED: Once = Once::new();

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let credential_store_overrides = resolve_credential_store_overrides(&cli)?;
    vault::set_process_credential_store_overrides(credential_store_overrides);
    let resolved_vault_dir = resolve_vault_dir(&cli);
    let runtime_paths = runtime_paths(resolved_vault_dir.as_deref())?;
    let _tracing_file_guard = match observability::install_tracing(&runtime_paths) {
        Ok((session_log, guard)) => {
            let _ = observability::append_session_log_line(
                &session_log,
                &format!("startup_command={}", command_name(&cli.command)),
            );
            Some(guard)
        }
        Err(err) => {
            eprintln!("failed to initialize file-backed tracing: {err:#}");
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                )
                .init();
            if let Err(dirs_err) = observability::initialize_observability_dirs(&runtime_paths) {
                eprintln!("failed to initialize observability directories: {dirs_err:#}");
            }
            None
        }
    };
    install_crash_capture_hook(runtime_paths.clone());
    let dir = runtime_paths.settings_dir().to_path_buf();
    let env_execution_mode = env_non_empty(ENV_OPENPROTON_EXEC_MODE);
    let execution_mode = resolve_execution_mode(cli.mode, env_execution_mode.as_deref())?;
    let _instance_lock = match &cli.command {
        Command::Serve { .. } | Command::Grpc { .. } | Command::Cli => {
            let lock = single_instance::acquire_bridge_instance_lock(&runtime_paths)?;
            tracing::info!(path = %lock.path().display(), "acquired bridge instance lock");
            Some(lock)
        }
        _ => None,
    };

    execute_command(cli.command, execution_mode, &dir, &runtime_paths).await
}

async fn execute_command(
    command: Command,
    mode: ExecutionMode,
    dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
) -> anyhow::Result<()> {
    match command {
        Command::Cli => cmd_cli(dir, runtime_paths, mode).await,
        other => execute_non_interactive_command(other, mode, dir, runtime_paths).await,
    }
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Login { .. } => "login",
        Command::FidoAssert { .. } => "fido-assert",
        Command::Status => "status",
        Command::Logout { .. } => "logout",
        Command::Accounts { .. } => "accounts",
        Command::Fetch { .. } => "fetch",
        Command::Serve { .. } => "serve",
        Command::Grpc { .. } => "grpc",
        Command::Cli => "cli",
        Command::VaultDump => "vault-dump",
        Command::MuttConfig { .. } => "mutt-config",
    }
}

fn execution_mode_name(mode: ExecutionMode) -> &'static str {
    match mode {
        ExecutionMode::Direct => "direct",
        ExecutionMode::Grpc => "grpc",
    }
}

async fn execute_non_interactive_command(
    command: Command,
    mode: ExecutionMode,
    dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
) -> anyhow::Result<()> {
    match mode {
        ExecutionMode::Direct => {
            execute_non_interactive_command_direct(command, dir, runtime_paths).await
        }
        ExecutionMode::Grpc => execute_non_interactive_command_grpc(command, runtime_paths).await,
    }
}

async fn execute_non_interactive_command_direct(
    command: Command,
    dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
) -> anyhow::Result<()> {
    match command {
        Command::Login { username, api_mode } => {
            cmd_login(username, api_mode.map(Into::into), dir).await
        }
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
        Command::MuttConfig {
            account,
            address,
            output,
            include_password,
        } => {
            cmd_mutt_config(
                account.as_deref(),
                address.as_deref(),
                output.as_deref(),
                include_password,
                dir,
                runtime_paths,
            )
            .await
        }
        Command::Cli => anyhow::bail!("cannot execute nested cli command"),
    }
}

async fn execute_non_interactive_command_grpc(
    command: Command,
    runtime_paths: &paths::RuntimePaths,
) -> anyhow::Result<()> {
    let mut client = frontend::grpc::client::CliGrpcClient::connect(runtime_paths)
        .await
        .with_context(|| {
            format!(
                "failed to initialize grpc execution mode from {}; ensure the gRPC frontend service is running (for example `openproton-bridge grpc` or interactive `grpc`)",
                runtime_paths.grpc_server_config_path().display()
            )
        })?;
    match command {
        Command::Status => cmd_status_grpc(&mut client).await,
        Command::Logout { email, all } => cmd_logout_grpc(&mut client, email.as_deref(), all).await,
        Command::Accounts { command } => match command {
            AccountsCommand::List => cmd_accounts_list_grpc(&mut client).await,
            AccountsCommand::Use { .. } => anyhow::bail!(
                "command `accounts use` is unsupported in grpc mode; use `--mode direct`"
            ),
        },
        Command::MuttConfig {
            account,
            address,
            output,
            include_password,
        } => {
            cmd_mutt_config_grpc(
                &mut client,
                account.as_deref(),
                address.as_deref(),
                output.as_deref(),
                include_password,
            )
            .await
        }
        Command::Cli => anyhow::bail!("cannot execute nested cli command"),
        other => {
            let name = command_name(&other);
            anyhow::bail!("command `{name}` is unsupported in grpc mode; use `--mode direct`")
        }
    }
}

fn resolve_vault_dir(cli: &Cli) -> Option<std::path::PathBuf> {
    cli.vault_dir
        .clone()
        .or_else(|| env_non_empty(ENV_OPENPROTON_VAULT_DIR).map(std::path::PathBuf::from))
}

fn parse_execution_mode(raw: &str) -> anyhow::Result<ExecutionMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "direct" => Ok(ExecutionMode::Direct),
        "grpc" => Ok(ExecutionMode::Grpc),
        other => anyhow::bail!("invalid execution mode `{other}`; expected direct or grpc"),
    }
}

fn resolve_execution_mode(
    cli_mode: Option<ExecutionModeArg>,
    env_mode: Option<&str>,
) -> anyhow::Result<ExecutionMode> {
    if let Some(mode) = cli_mode {
        return Ok(mode.into());
    }
    if let Some(raw) = env_mode {
        return parse_execution_mode(raw);
    }
    Ok(ExecutionMode::Direct)
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
    supervisor: std::sync::Arc<bridge::runtime_supervisor::RuntimeSupervisor>,
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CliStoredMailSettings {
    imap_port: i32,
    smtp_port: i32,
    use_ssl_for_imap: bool,
    use_ssl_for_smtp: bool,
}

impl Default for CliStoredMailSettings {
    fn default() -> Self {
        Self {
            imap_port: 1143,
            smtp_port: 1025,
            use_ssl_for_imap: false,
            use_ssl_for_smtp: false,
        }
    }
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

async fn cmd_cli(
    dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
    startup_mode: ExecutionMode,
) -> anyhow::Result<()> {
    println!("Welcome to openproton-bridge interactive shell.");
    println!("Execution mode: {}", execution_mode_name(startup_mode));
    println!("Type `help` for commands, `quit` to exit.\n");

    let mut serve_config = load_interactive_serve_config(runtime_paths).await;
    let mut shell_mode = startup_mode;
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
                    "mode" => {
                        match tokens.get(1).map(|value| value.to_ascii_lowercase()) {
                            None => {
                                println!("Execution mode: {}", execution_mode_name(shell_mode));
                            }
                            Some(value) if value == "direct" => {
                                shell_mode = ExecutionMode::Direct;
                                println!("Execution mode set to direct.");
                            }
                            Some(value) if value == "grpc" => {
                                shell_mode = ExecutionMode::Grpc;
                                println!("Execution mode set to grpc.");
                            }
                            _ => {
                                eprintln!("Usage: mode [direct|grpc]");
                            }
                        }
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
                    "configure-apple-mail" => {
                        eprintln!(
                            "configure-apple-mail is not implemented in openproton-bridge CLI."
                        );
                    }
                    "log-dir" | "log" | "logs" => {
                        println!("{}", runtime_paths.logs_dir().display());
                    }
                    "debug" => match tokens.get(1).map(|s| s.to_ascii_lowercase()) {
                        Some(action) if action == "mailbox-state" => {
                            println!("{}", render_mailbox_state_diagnostics(dir, runtime_paths));
                        }
                        Some(action) if action == "support-bundle" => {
                            let diagnostics = render_mailbox_state_diagnostics(dir, runtime_paths);
                            match observability::generate_support_log_bundle(
                                runtime_paths,
                                &diagnostics,
                            ) {
                                Ok(bundle) => println!("{}", bundle.display()),
                                Err(err) => eprintln!("Error: {err:#}"),
                            }
                        }
                        _ => eprintln!("Usage: debug <mailbox-state|support-bundle>"),
                    },
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
                            shell_mode,
                            dir,
                            runtime_paths,
                        )
                        .await
                        {
                            eprintln!("Error: {err:#}");
                        }
                    }
                    "info" | "i" => {
                        if let Some(selector) = tokens.get(1) {
                            let result = match shell_mode {
                                ExecutionMode::Direct => {
                                    cmd_account_info(selector, dir, runtime_paths).await
                                }
                                ExecutionMode::Grpc => {
                                    let mut client = match frontend::grpc::client::CliGrpcClient::connect(
                                        runtime_paths,
                                    )
                                    .await
                                    {
                                        Ok(client) => client,
                                        Err(err) => {
                                            eprintln!("Error: {err:#}");
                                            print_cli_prompt()?;
                                            continue;
                                        }
                                    };
                                    cmd_account_info_grpc(&mut client, selector).await
                                }
                            };
                            if let Err(err) = result {
                                eprintln!("Error: {err:#}");
                            }
                        } else if let Err(err) =
                            execute_non_interactive_command(
                                Command::Status,
                                shell_mode,
                                dir,
                                runtime_paths,
                            )
                            .await
                        {
                            eprintln!("Error: {err:#}");
                        }
                    }
                    "use" => {
                        if tokens.len() != 2 {
                            eprintln!("Usage: use <email|index>");
                            print_cli_prompt()?;
                            continue;
                        }
                        let target = match resolve_account_selector_session(dir, &tokens[1]) {
                            Ok(session) => session.email,
                            Err(err) => {
                                eprintln!("Error: {err:#}");
                                print_cli_prompt()?;
                                continue;
                            }
                        };

                        if let Err(err) = execute_non_interactive_command(
                            Command::Accounts {
                                command: AccountsCommand::Use {
                                    email: target,
                                },
                            },
                            shell_mode,
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
                            eprintln!("Usage: delete <email|index>");
                            print_cli_prompt()?;
                            continue;
                        }
                        let target = match resolve_account_selector_session(dir, &tokens[1]) {
                            Ok(session) => session.email,
                            Err(err) => {
                                eprintln!("Error: {err:#}");
                                print_cli_prompt()?;
                                continue;
                            }
                        };

                        if let Err(err) = execute_non_interactive_command(
                            Command::Logout {
                                email: Some(target),
                                all: false,
                            },
                            shell_mode,
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
                                shell_mode,
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
                            eprintln!("Usage: bad-event <synchronize|logout [email|index|--all]>");
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
                                            shell_mode,
                                            dir,
                                            runtime_paths,
                                        )
                                        .await
                                        {
                                            eprintln!("Error: {err:#}");
                                        }
                                    } else {
                                        let selected =
                                            match resolve_account_selector_session(dir, &value) {
                                                Ok(session) => session.email,
                                                Err(err) => {
                                                    eprintln!("Error: {err:#}");
                                                    print_cli_prompt()?;
                                                    continue;
                                                }
                                            };
                                        if let Err(err) = execute_non_interactive_command(
                                            Command::Logout {
                                                email: Some(selected),
                                                all: false,
                                            },
                                            shell_mode,
                                            dir,
                                            runtime_paths,
                                        )
                                        .await
                                        {
                                            eprintln!("Error: {err:#}");
                                        }
                                    }
                                } else {
                                    match vault::load_session(dir) {
                                        Ok(active) => {
                                            if let Err(err) = execute_non_interactive_command(
                                                Command::Logout {
                                                    email: Some(active.email),
                                                    all: false,
                                                },
                                                shell_mode,
                                                dir,
                                                runtime_paths,
                                            )
                                            .await
                                            {
                                                eprintln!("Error: {err:#}");
                                            }
                                        }
                                        Err(err) => eprintln!("Error: {err:#}"),
                                    }
                                }
                            }
                            _ => eprintln!(
                                "Usage: bad-event <synchronize|logout [email|index|--all]>"
                            ),
                        }
                    }
                    "cert" => {
                        let Some(action) = tokens.get(1).map(|s| s.to_ascii_lowercase()) else {
                            eprintln!(
                                "Usage: cert <status|install|uninstall|export <dir>|import <dir>>"
                            );
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
                            "uninstall" => {
                                if let Err(err) = uninstall_cli_tls_certificate(dir) {
                                    eprintln!("Error: {err:#}");
                                } else {
                                    println!("TLS certificate removed from local runtime paths.");
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
                            _ => eprintln!(
                                "Usage: cert <status|install|uninstall|export <dir>|import <dir>>"
                            ),
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
                        if tokens.get(1).is_none_or(|arg| arg != "--force") {
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
                        if let Err(err) = handle_interactive_change_command(&args, &mut serve_config) {
                            eprintln!("Error: {err}");
                        } else if let Err(err) =
                            persist_mail_ports_from_serve_config(runtime_paths, &serve_config).await
                        {
                            eprintln!("Error: {err:#}");
                        }
                    }
                    "smtp-security" | "ssl-smtp" | "starttls-smtp" => {
                        let mut args = vec!["smtp-security".to_string()];
                        args.extend(tokens.iter().skip(1).cloned());
                        if let Err(err) = handle_interactive_change_command(&args, &mut serve_config) {
                            eprintln!("Error: {err}");
                        } else if let Err(err) =
                            persist_mail_ports_from_serve_config(runtime_paths, &serve_config).await
                        {
                            eprintln!("Error: {err:#}");
                        }
                    }
                    "change" | "ch" | "switch" => {
                        if tokens
                            .get(1)
                            .is_some_and(|value| value.eq_ignore_ascii_case("mode"))
                        {
                            if tokens.len() < 4 {
                                eprintln!("Usage: change mode <email|index> <split|combined>");
                                print_cli_prompt()?;
                                continue;
                            }
                            if let Err(err) = set_account_mode_by_selector(dir, &tokens[2], &tokens[3]) {
                                eprintln!("Error: {err:#}");
                            }
                        } else if tokens
                            .get(1)
                            .is_some_and(|value| value.eq_ignore_ascii_case("change-location"))
                        {
                            let Some(target) = tokens.get(2) else {
                                eprintln!("Usage: change change-location <path>");
                                print_cli_prompt()?;
                                continue;
                            };
                            if let Err(err) = set_disk_cache_path_for_cli(runtime_paths, target).await
                            {
                                eprintln!("Error: {err:#}");
                            } else {
                                println!("Disk cache location updated to {}", target);
                            }
                        } else if let Err(err) =
                            handle_interactive_change_command(&tokens[1..], &mut serve_config)
                        {
                            eprintln!("Error: {err}");
                        } else if let Err(err) =
                            persist_mail_ports_from_serve_config(runtime_paths, &serve_config).await
                        {
                            eprintln!("Error: {err:#}");
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
                        if grpc_state.is_some() {
                            eprintln!(
                                "Cannot start serve runtime while gRPC runtime is running. Use `grpc-stop` first."
                            );
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

                        let grpc_options = if let Some(runtime) = runtime_state.as_ref() {
                            frontend::grpc::GrpcServerOptions {
                                runtime_supervisor: Some(runtime.supervisor.clone()),
                                start_mail_runtime_on_startup: false,
                                stop_mail_runtime_on_shutdown: false,
                            }
                        } else {
                            frontend::grpc::GrpcServerOptions::default()
                        };

                        match start_interactive_grpc(bind.clone(), runtime_paths, grpc_options).await {
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
                            execute_non_interactive_command(parsed, shell_mode, dir, runtime_paths)
                                .await
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
        || parsed.mode.is_some()
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
        "configure-mutt" => {
            tokens[0] = "mutt-config".to_string();
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
    println!("  mode [direct|grpc]               Show or switch command execution mode");
    println!("  manual | man                     Print project manual URL");
    println!("  check-updates                    Alias for updates check");
    println!("  credits                          Print credits/dependency info");
    println!("  configure-apple-mail             Placeholder (not yet implemented)");
    println!("  configure-mutt [flags]           Generate mutt/neomutt config snippet");
    println!("  log-dir                          Print log directory path");
    println!("  debug mailbox-state              Print deterministic mailbox diagnostics");
    println!("  debug support-bundle             Build a support diagnostics bundle path");
    println!("  telemetry <enable|disable|status> Manage telemetry setting");
    println!("  proxy <allow|disallow|status>    Manage DoH proxy fallback setting");
    println!("  autostart <enable|disable|status> Manage autostart setting");
    println!("  all-mail-visibility <show|hide|status> Manage All Mail visibility");
    println!("  updates ...                      Manage update channel/autoupdates");
    println!("  status                           Show account/session status");
    println!("  list | ls                        List accounts");
    println!("  info [email|index]               Show account/session info");
    println!("  login [email|--username <email>] [--api-mode bridge|webmail] Login to Proton");
    println!("  logout [all|--all|--email <email>] Logout one account or all accounts");
    println!("  delete <email|index>             Remove one account");
    println!("  use <email|index>                Set default account");
    println!("  fetch [--limit <n>]              Fetch/decrypt inbox messages");
    println!("  vault-dump                       Dump decrypted vault msgpack structure");
    println!("  change-location <path>           Change encrypted message cache location");
    println!("  bad-event <synchronize|logout>   Resolve bad-event flows (logout defaults to active account)");
    println!("  cert <status|install|uninstall|export|import> Manage TLS cert files");
    println!(
        "  repair                           Reset event checkpoints and restart serve runtime"
    );
    println!("  reset --force                    Clear sessions and grpc settings");
    println!("  imap-security                    Toggle IMAP security mode");
    println!("  smtp-security                    Toggle SMTP security mode");
    println!("  ssl-imap | starttls-imap         Alias for imap-security");
    println!("  ssl-smtp | starttls-smtp         Alias for smtp-security");
    println!("  change <field> ...               Update interactive serve defaults");
    println!("  change mode <email|index> <split|combined> Set account address mode");
    println!("  serve-config                     Print interactive serve defaults");
    println!("  serve-status                     Show background serve runtime status");
    println!("  serve [serve flags]              Start IMAP+SMTP server (background)");
    println!("  grpc-status                      Show background gRPC runtime status");
    println!("  grpc [grpc flags]                Start gRPC frontend service (background)");
    println!("  grpc-stop                        Stop background gRPC runtime");
    println!(
        "  note                             serve/grpc/grpc-stop are always local runtime controls"
    );
    println!("  stop                             Stop all background runtimes");
    println!("  mutt-config [flags]              Generate mutt/neomutt config snippet");
    println!();
    print_interactive_serve_help();
    print_interactive_grpc_help();
}

fn crash_reports_dir(runtime_paths: &paths::RuntimePaths) -> std::path::PathBuf {
    runtime_paths.crash_reports_dir()
}

fn write_crash_report_artifact(
    runtime_paths: &paths::RuntimePaths,
    details: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let crash_dir = crash_reports_dir(runtime_paths);
    std::fs::create_dir_all(&crash_dir)
        .with_context(|| format!("failed to create crash reports dir {}", crash_dir.display()))?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let path = crash_dir.join(format!("panic-{}-{}.log", std::process::id(), timestamp));
    std::fs::write(&path, details)
        .with_context(|| format!("failed to write crash report {}", path.display()))?;
    Ok(path)
}

fn install_crash_capture_hook(runtime_paths: paths::RuntimePaths) {
    PANIC_HOOK_INSTALLED.call_once(move || {
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            let location = panic_info
                .location()
                .map(|loc| format!("{}:{}", loc.file(), loc.line()))
                .unwrap_or_else(|| "<unknown>".to_string());
            let payload = panic_info
                .payload()
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic_info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic payload unavailable".to_string());
            let report = format!("panic_location={location}\npanic_payload={payload}\n");
            if let Err(err) = write_crash_report_artifact(&runtime_paths, &report) {
                eprintln!("failed to persist crash report: {err:#}");
            }
            previous_hook(panic_info);
        }));
    });
}

fn render_mailbox_state_diagnostics(
    dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
) -> String {
    let mut lines = Vec::new();
    lines.push("mailbox-state diagnostics".to_string());
    lines.push(format!(
        "settings_dir={}",
        runtime_paths.settings_dir().display()
    ));
    lines.push(format!("data_dir={}", runtime_paths.data_dir().display()));
    lines.push(format!("cache_dir={}", runtime_paths.cache_dir().display()));
    lines.push(format!("logs_dir={}", runtime_paths.logs_dir().display()));
    lines.push(format!(
        "crash_reports_dir={}",
        crash_reports_dir(runtime_paths).display()
    ));
    lines.push(format!(
        "support_bundles_dir={}",
        runtime_paths.support_bundles_dir().display()
    ));
    lines.push(format!(
        "disk_cache_dir={}",
        effective_disk_cache_path(runtime_paths).display()
    ));

    let mut sessions = vault::list_sessions(dir).unwrap_or_default();
    sessions.sort_by(|left, right| left.uid.cmp(&right.uid));
    lines.push(format!("accounts={}", sessions.len()));
    for session in sessions {
        lines.push(format!(
            "account uid={} email={} api_mode={}",
            session.uid,
            session.email,
            session.api_mode.as_str()
        ));
    }

    lines.join("\n")
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

async fn load_interactive_serve_config(
    runtime_paths: &paths::RuntimePaths,
) -> InteractiveServeConfig {
    let mut config = InteractiveServeConfig::default();
    match load_mail_settings_for_cli(runtime_paths).await {
        Ok(settings) => {
            if let Ok(imap_port) = u16::try_from(settings.imap_port) {
                if imap_port > 0 {
                    config.imap_port = imap_port;
                }
            }
            if let Ok(smtp_port) = u16::try_from(settings.smtp_port) {
                if smtp_port > 0 {
                    config.smtp_port = smtp_port;
                }
            }
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "failed to load mail settings for interactive defaults; using built-ins"
            );
        }
    }
    config
}

async fn load_mail_settings_for_cli(
    runtime_paths: &paths::RuntimePaths,
) -> anyhow::Result<CliStoredMailSettings> {
    let path = runtime_paths.grpc_mail_settings_path();
    if !path.exists() {
        return Ok(CliStoredMailSettings::default());
    }

    let payload = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&payload).with_context(|| format!("failed to parse {}", path.display()))
}

async fn save_mail_settings_for_cli(
    runtime_paths: &paths::RuntimePaths,
    settings: &CliStoredMailSettings,
) -> anyhow::Result<()> {
    let path = runtime_paths.grpc_mail_settings_path();
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create settings dir {}", parent.display()))?;
    }

    let tmp_path = path.with_file_name("grpc_mail_settings.json.tmp");
    let payload = serde_json::to_vec_pretty(settings).context("failed to encode mail settings")?;
    tokio::fs::write(&tmp_path, payload)
        .await
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    tokio::fs::rename(&tmp_path, &path)
        .await
        .with_context(|| format!("failed to rename settings file {}", path.display()))?;
    Ok(())
}

async fn update_mail_settings<F>(
    runtime_paths: &paths::RuntimePaths,
    mutator: F,
) -> anyhow::Result<()>
where
    F: FnOnce(&mut CliStoredMailSettings),
{
    let mut settings = load_mail_settings_for_cli(runtime_paths).await?;
    mutator(&mut settings);
    save_mail_settings_for_cli(runtime_paths, &settings).await
}

async fn persist_mail_ports_from_serve_config(
    runtime_paths: &paths::RuntimePaths,
    serve_config: &InteractiveServeConfig,
) -> anyhow::Result<()> {
    update_mail_settings(runtime_paths, |settings| {
        settings.imap_port = i32::from(serve_config.imap_port);
        settings.smtp_port = i32::from(serve_config.smtp_port);
    })
    .await
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
    let current_path = resolve_live_gluon_cache_root_for_cli(runtime_paths)
        .unwrap_or_else(|| effective_disk_cache_path(runtime_paths));

    move_disk_cache_payload_for_cli(&current_path, &target_path).await?;

    update_app_settings(runtime_paths, |settings| {
        settings.disk_cache_path = target_path.display().to_string();
    })
    .await?;

    match vault::save_gluon_dir(
        runtime_paths.settings_dir(),
        &target_path.display().to_string(),
    ) {
        Ok(()) | Err(vault::VaultError::NotLoggedIn) => {}
        Err(err) => {
            anyhow::bail!("failed to persist gluon cache root after disk cache move: {err}");
        }
    }

    Ok(())
}

fn resolve_live_gluon_cache_root_for_cli(
    runtime_paths: &paths::RuntimePaths,
) -> Option<std::path::PathBuf> {
    let sessions = match vault::list_sessions(runtime_paths.settings_dir()) {
        Ok(sessions) => sessions,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "failed to load sessions while resolving live gluon cache root"
            );
            return None;
        }
    };
    if sessions.is_empty() {
        return None;
    }

    let account_ids = sessions
        .iter()
        .map(|session| session.uid.clone())
        .collect::<Vec<_>>();
    let bootstrap =
        match vault::load_gluon_store_bootstrap(runtime_paths.settings_dir(), &account_ids) {
            Ok(bootstrap) => bootstrap,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to load gluon bootstrap while resolving live cache root"
                );
                return None;
            }
        };

    Some(
        runtime_paths
            .gluon_paths(Some(bootstrap.gluon_dir.as_str()))
            .root()
            .to_path_buf(),
    )
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

fn uninstall_cli_tls_certificate(dir: &std::path::Path) -> anyhow::Result<()> {
    let (cert_path, key_path) = cli_tls_paths(dir);

    if cert_path.exists() {
        std::fs::remove_file(&cert_path)
            .with_context(|| format!("failed to remove {}", cert_path.display()))?;
    }
    if key_path.exists() {
        std::fs::remove_file(&key_path)
            .with_context(|| format!("failed to remove {}", key_path.display()))?;
    }

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

fn resolve_account_selector_session(
    dir: &std::path::Path,
    selector: &str,
) -> anyhow::Result<api::types::Session> {
    let sessions = vault::list_sessions(dir).context("failed to load sessions")?;
    if sessions.is_empty() {
        anyhow::bail!("no accounts are configured");
    }

    if let Ok(index) = selector.trim().parse::<usize>() {
        if let Some(session) = sessions.get(index) {
            return Ok(session.clone());
        }
        anyhow::bail!(
            "account index {index} is out of range (max {})",
            sessions.len().saturating_sub(1)
        );
    }

    sessions
        .iter()
        .find(|session| {
            session.email.eq_ignore_ascii_case(selector)
                || session.display_name.eq_ignore_ascii_case(selector)
        })
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("unknown account selector: {selector}"))
}

fn set_account_mode_by_selector(
    dir: &std::path::Path,
    selector: &str,
    mode: &str,
) -> anyhow::Result<()> {
    let session = resolve_account_selector_session(dir, selector)?;

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

async fn cmd_login(
    username_arg: Option<String>,
    api_mode: Option<api::types::ApiMode>,
    dir: &std::path::Path,
) -> anyhow::Result<()> {
    let requested_api_mode = api_mode.unwrap_or(api::types::ApiMode::Bridge);
    let mut effective_api_mode = requested_api_mode;
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

    tracing::info!(
        pkg = "bridge/login",
        username = %username,
        api_mode = requested_api_mode.as_str(),
        "login requested"
    );

    let password = rpassword::prompt_password("Password: ").context("failed to read password")?;

    let mut client = api::client::ProtonClient::with_api_mode(effective_api_mode)?;
    let mut tried_mode_fallback = false;

    // SRP authentication with optional human-verification retries.
    let mut hv_details: Option<api::types::HumanVerificationDetails> = None;
    let auth = loop {
        match api::auth::login(&mut client, &username, &password, hv_details.as_ref()).await {
            Ok(auth) => break auth,
            Err(err) => {
                if !tried_mode_fallback
                    && matches!(&err, api::error::ApiError::Api { code: 10004, .. })
                {
                    let fallback_mode = effective_api_mode.alternate();
                    tracing::warn!(
                        pkg = "bridge/login",
                        username = %username,
                        from_api_mode = effective_api_mode.as_str(),
                        to_api_mode = fallback_mode.as_str(),
                        "login mode fallback requested after API gating"
                    );
                    eprintln!(
                        "Login mode {} is gated for this account; retrying with {}.",
                        effective_api_mode.as_str(),
                        fallback_mode.as_str()
                    );
                    client = api::client::ProtonClient::with_api_mode(fallback_mode)?;
                    effective_api_mode = fallback_mode;
                    tried_mode_fallback = true;
                    continue;
                }

                let needs_hv = api::error::human_verification_details(&err).or_else(|| {
                    if matches!(&err, api::error::ApiError::Api { code: 12087, .. }) {
                        api::error::any_human_verification_details(&err)
                    } else {
                        None
                    }
                });

                if let Some(hv) = needs_hv {
                    let mut hv = hv;
                    tracing::info!(
                        pkg = "bridge/login",
                        username = %username,
                        methods = ?hv.human_verification_methods,
                        "human verification required for login"
                    );
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

                tracing::warn!(
                    pkg = "bridge/login",
                    username = %username,
                    error = %err,
                    "login failed"
                );
                return Err(err.into());
            }
        }
    };

    if let Err(err) = complete_cli_second_factor(&client, &auth).await {
        tracing::warn!(
            pkg = "bridge/login",
            username = %username,
            user_id = %auth.uid,
            error = %err,
            "second-factor login step failed"
        );
        return Err(err);
    }

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

    // Reuse existing bridge password for cross-bridge compatibility.
    let bridge_password = vault::load_session_by_account_id(dir, &auth.uid)
        .ok()
        .and_then(|stored| stored.bridge_password)
        .or_else(|| {
            vault::load_session_by_email(dir, &user.email)
                .ok()
                .and_then(|stored| stored.bridge_password)
        })
        .unwrap_or_else(generate_bridge_password);

    // Build session
    let session = api::types::Session {
        uid: auth.uid,
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
        email: user.email.clone(),
        display_name: user.display_name.clone(),
        api_mode: effective_api_mode,
        key_passphrase,
        bridge_password: Some(bridge_password.clone()),
    };

    vault::save_session_with_user_id(&session, Some(user.id.as_str()), dir)?;
    vault::set_default_email(dir, &session.email)?;
    tracing::info!(
        pkg = "bridge/login",
        user_id = %session.uid,
        email = %session.email,
        api_mode = session.api_mode.as_str(),
        "login succeeded"
    );

    println!(
        "Logged in as {} ({}) using API mode {}",
        user.display_name,
        user.email,
        effective_api_mode.as_str()
    );
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
        tracing::info!(
            pkg = "bridge/login",
            user_id = %auth.uid,
            "Requesting TOTP"
        );
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
            "  {} ({}){} [{}]",
            session.display_name,
            session.email,
            default_marker,
            session.api_mode.as_str()
        );
    }
    println!();

    let active = vault::load_session(dir).context("failed to load active account")?;
    println!("Active account: {}", active.email);
    println!("API mode: {}", active.api_mode.as_str());
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

async fn cmd_account_info(
    selector: &str,
    dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
) -> anyhow::Result<()> {
    let session = resolve_account_selector_session(dir, selector)?;
    let mail_settings = load_mail_settings_for_cli(runtime_paths).await?;
    let split_mode = vault::load_split_mode_by_account_id(dir, &session.uid)
        .context("failed to load account mode")?
        .unwrap_or(false);

    println!("Account: {} ({})", session.display_name, session.email);
    println!("API mode: {}", session.api_mode.as_str());
    println!(
        "Address mode: {}",
        if split_mode { "split" } else { "combined" }
    );
    println!();
    println!(
        "IMAP Settings\nAddress:   127.0.0.1\nIMAP port: {}\nUsername:  {}\nPassword:  {}\nSecurity:  STARTTLS",
        mail_settings.imap_port,
        session.email,
        session
            .bridge_password
            .as_deref()
            .unwrap_or("<not set; re-login to generate>")
    );
    println!();
    println!(
        "SMTP Settings\nAddress:   127.0.0.1\nSMTP port: {}\nUsername:  {}\nPassword:  {}\nSecurity:  STARTTLS",
        mail_settings.smtp_port,
        session.email,
        session
            .bridge_password
            .as_deref()
            .unwrap_or("<not set; re-login to generate>")
    );

    Ok(())
}

async fn cmd_account_info_grpc(
    client: &mut frontend::grpc::client::CliGrpcClient,
    selector: &str,
) -> anyhow::Result<()> {
    let users = client.get_user_list().await?;
    let user = resolve_grpc_account_selector_user(&users, selector)?;
    let mail_settings = client.mail_server_settings().await?;

    let password = if user.password.is_empty() {
        "<not set; re-login to generate>".to_string()
    } else {
        std::str::from_utf8(&user.password)
            .map(str::to_string)
            .unwrap_or_else(|_| "<non-utf8-password>".to_string())
    };

    println!("Account: {} ({})", user.display_name, user.username);
    println!("API mode: unknown (grpc mode)");
    println!(
        "Address mode: {}",
        if user.split_mode { "split" } else { "combined" }
    );
    println!();
    println!(
        "IMAP Settings\nAddress:   127.0.0.1\nIMAP port: {}\nUsername:  {}\nPassword:  {}\nSecurity:  {}",
        mail_settings.imap_port,
        user.username,
        password,
        if mail_settings.use_ssl_for_imap {
            "SSL"
        } else {
            "STARTTLS"
        }
    );
    println!();
    println!(
        "SMTP Settings\nAddress:   127.0.0.1\nSMTP port: {}\nUsername:  {}\nPassword:  {}\nSecurity:  {}",
        mail_settings.smtp_port,
        user.username,
        password,
        if mail_settings.use_ssl_for_smtp {
            "SSL"
        } else {
            "STARTTLS"
        }
    );

    Ok(())
}

fn resolve_grpc_account_selector_user(
    users: &[frontend::grpc::pb::User],
    selector: &str,
) -> anyhow::Result<frontend::grpc::pb::User> {
    if users.is_empty() {
        anyhow::bail!("no accounts are configured");
    }

    let selector = selector.trim();
    if selector.is_empty() {
        anyhow::bail!("empty account selector");
    }

    if let Ok(index) = selector.parse::<usize>() {
        return users
            .get(index)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("account index {index} is out of range"));
    }

    users
        .iter()
        .find(|user| {
            user.id == selector
                || user.username.eq_ignore_ascii_case(selector)
                || user.display_name.eq_ignore_ascii_case(selector)
        })
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("unknown account selector: {selector}"))
}

async fn cmd_mutt_config(
    account_selector: Option<&str>,
    address_override: Option<&str>,
    output: Option<&std::path::Path>,
    include_password: bool,
    dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
) -> anyhow::Result<()> {
    let session = if let Some(selector) = account_selector {
        resolve_account_selector_session(dir, selector)?
    } else {
        vault::load_session(dir)
            .map_err(anyhow::Error::new)
            .context("no active account found; pass --account or login first")?
    };
    let mail_settings = load_mail_settings_for_cli(runtime_paths).await?;

    let account_address = address_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(session.email.as_str())
        .to_string();
    let bridge_password = session
        .bridge_password
        .clone()
        .filter(|value| !value.trim().is_empty());
    if include_password && bridge_password.is_none() {
        anyhow::bail!(
            "bridge password is missing for {}; re-login to regenerate it or omit --include-password",
            session.email
        );
    }

    let imap_port = u16::try_from(mail_settings.imap_port)
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "invalid IMAP port in mail settings: {}",
                mail_settings.imap_port
            )
        })?;
    let smtp_port = u16::try_from(mail_settings.smtp_port)
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "invalid SMTP port in mail settings: {}",
                mail_settings.smtp_port
            )
        })?;

    let rendered = client_config::render_mutt_config(
        &client_config::MuttConfigTemplate {
            account_address,
            display_name: session.display_name,
            hostname: "127.0.0.1".to_string(),
            imap_port,
            smtp_port,
            use_ssl_for_imap: mail_settings.use_ssl_for_imap,
            use_ssl_for_smtp: mail_settings.use_ssl_for_smtp,
            bridge_password,
        },
        include_password,
    );

    if let Some(path) = output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
        }
        std::fs::write(path, rendered.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        }
        println!("Wrote mutt config to {}", path.display());
    } else {
        print!("{rendered}");
    }

    Ok(())
}

async fn cmd_status_grpc(client: &mut frontend::grpc::client::CliGrpcClient) -> anyhow::Result<()> {
    let mut users = client.get_user_list().await?;
    users.sort_by_cached_key(|user| user.username.to_ascii_lowercase());
    if users.is_empty() {
        println!("Not logged in");
        return Ok(());
    }

    println!("Accounts:");
    for user in &users {
        let display_name = if user.display_name.trim().is_empty() {
            user.username.as_str()
        } else {
            user.display_name.as_str()
        };
        println!("  {} ({}) [grpc]", display_name, user.username);
    }
    println!();

    let active = &users[0];
    println!("Active account: {}", active.username);
    println!("API mode: unknown (grpc mode)");
    println!("Key passphrase: unavailable in grpc mode");
    if active.password.is_empty() {
        println!("Bridge password: not set");
    } else if let Ok(password) = std::str::from_utf8(&active.password) {
        println!("Bridge password: {password}");
    } else {
        println!("Bridge password: <non-utf8>");
    }
    Ok(())
}

async fn cmd_accounts_list_grpc(
    client: &mut frontend::grpc::client::CliGrpcClient,
) -> anyhow::Result<()> {
    let mut users = client.get_user_list().await?;
    users.sort_by_cached_key(|user| user.username.to_ascii_lowercase());
    if users.is_empty() {
        println!("Not logged in");
        return Ok(());
    }

    println!(
        "{:<3} {:<30} {:<12} {:<12} {:<8}",
        "#", "account", "status", "address mode", "api mode"
    );
    for (idx, user) in users.iter().enumerate() {
        println!(
            "{:<3} {:<30} {:<12} {:<12} {:<8}",
            idx,
            user.username,
            grpc_user_state_label(user.state),
            if user.split_mode { "split" } else { "combined" },
            "unknown"
        );
    }
    println!();
    Ok(())
}

async fn cmd_logout_grpc(
    client: &mut frontend::grpc::client::CliGrpcClient,
    email: Option<&str>,
    all: bool,
) -> anyhow::Result<()> {
    let users = client.get_user_list().await?;
    if users.is_empty() {
        println!("Not logged in");
        return Ok(());
    }

    let should_logout_all = all || email.is_none();
    if should_logout_all {
        for user in users {
            client.logout_user(user.id.as_str()).await?;
        }
        println!("Logged out all accounts");
        return Ok(());
    }

    let target_email = email.unwrap_or_default();
    let target_user = users
        .into_iter()
        .find(|user| user.username.eq_ignore_ascii_case(target_email))
        .ok_or_else(|| anyhow::anyhow!("account `{target_email}` not found"))?;
    client.logout_user(target_user.id.as_str()).await?;
    println!("Removed account: {}", target_user.username);
    Ok(())
}

fn grpc_user_state_label(state: i32) -> &'static str {
    match frontend::grpc::pb::UserState::try_from(state) {
        Ok(frontend::grpc::pb::UserState::Connected) => "connected",
        Ok(frontend::grpc::pb::UserState::Locked) => "locked",
        Ok(frontend::grpc::pb::UserState::SignedOut) => "signed-out",
        Err(_) => "unknown",
    }
}

async fn cmd_mutt_config_grpc(
    client: &mut frontend::grpc::client::CliGrpcClient,
    account_selector: Option<&str>,
    address_override: Option<&str>,
    output: Option<&std::path::Path>,
    include_password: bool,
) -> anyhow::Result<()> {
    let rendered = client
        .render_mutt_config(account_selector, address_override, include_password)
        .await?;

    if let Some(path) = output {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
        }
        std::fs::write(path, rendered.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to set permissions on {}", path.display()))?;
        }
        println!("Wrote mutt config to {}", path.display());
    } else {
        print!("{rendered}");
    }

    Ok(())
}

fn cmd_logout(email: Option<&str>, all: bool, dir: &std::path::Path) -> anyhow::Result<()> {
    if !vault::session_exists(dir) {
        tracing::info!(
            pkg = "bridge/login",
            scope = "none",
            "logout requested without active session"
        );
        println!("Not logged in");
        return Ok(());
    }

    if all {
        tracing::info!(pkg = "bridge/login", scope = "all", "logout requested");
        vault::remove_session(dir)?;
        tracing::info!(pkg = "bridge/login", scope = "all", "logout completed");
        println!("Logged out all accounts");
    } else if let Some(email) = email {
        tracing::info!(pkg = "bridge/login", scope = "single", email = %email, "logout requested");
        vault::remove_session_by_email(dir, email)?;
        tracing::info!(pkg = "bridge/login", scope = "single", email = %email, "logout completed");
        println!("Removed account: {}", email);
    } else {
        tracing::info!(pkg = "bridge/login", scope = "all", "logout requested");
        vault::remove_session(dir)?;
        tracing::info!(pkg = "bridge/login", scope = "all", "logout completed");
        println!("Logged out all accounts");
    }
    Ok(())
}

fn cmd_accounts_list(dir: &std::path::Path) -> anyhow::Result<()> {
    let sessions = vault::list_sessions(dir).context("failed to load sessions")?;
    if sessions.is_empty() {
        println!("Not logged in");
        return Ok(());
    }

    println!(
        "{:<3} {:<30} {:<12} {:<12} {:<8}",
        "#", "account", "status", "address mode", "api mode"
    );
    for (idx, session) in sessions.iter().enumerate() {
        let split_mode = vault::load_split_mode_by_account_id(dir, &session.uid)
            .context("failed to load account mode")?
            .unwrap_or(false);
        println!(
            "{:<3} {:<30} {:<12} {:<12} {:<8}",
            idx,
            session.email,
            "connected",
            if split_mode { "split" } else { "combined" },
            session.api_mode.as_str()
        );
    }
    println!();
    Ok(())
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

    let client = api::client::ProtonClient::authenticated_with_mode(
        session.api_mode.base_url(),
        session.api_mode,
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
    _dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
) -> anyhow::Result<()> {
    let runtime_config = bridge::mail_runtime::MailRuntimeConfig {
        bind_host: bind.to_string(),
        imap_port,
        smtp_port,
        disable_tls: no_tls,
        use_ssl_for_imap: !no_tls,
        use_ssl_for_smtp: !no_tls,
        event_poll_interval: std::time::Duration::from_secs(event_poll_secs),
    };
    let supervisor = std::sync::Arc::new(bridge::runtime_supervisor::RuntimeSupervisor::new(
        runtime_paths.clone(),
    ));
    let snapshot = supervisor
        .start_with_snapshot(
            runtime_config,
            bridge::mail_runtime::MailRuntimeTransition::Startup,
            None,
        )
        .await?;
    print_serve_configuration(
        bind,
        imap_port,
        smtp_port,
        no_tls,
        &snapshot.active_sessions,
        &snapshot.runtime_snapshot,
    );
    frontend::grpc::run_server_with_options(
        runtime_paths.clone(),
        bind.to_string(),
        frontend::grpc::GrpcServerOptions {
            runtime_supervisor: Some(supervisor),
            start_mail_runtime_on_startup: false,
            stop_mail_runtime_on_shutdown: true,
        },
    )
    .await
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

async fn start_interactive_runtime(
    config: InteractiveServeConfig,
    _dir: &std::path::Path,
    runtime_paths: &paths::RuntimePaths,
    notify_tx: tokio::sync::mpsc::UnboundedSender<String>,
) -> anyhow::Result<InteractiveServeRuntime> {
    let runtime_config = bridge::mail_runtime::MailRuntimeConfig {
        bind_host: config.bind.clone(),
        imap_port: config.imap_port,
        smtp_port: config.smtp_port,
        disable_tls: config.no_tls,
        use_ssl_for_imap: !config.no_tls,
        use_ssl_for_smtp: !config.no_tls,
        event_poll_interval: std::time::Duration::from_secs(config.event_poll_secs),
    };
    let supervisor = std::sync::Arc::new(bridge::runtime_supervisor::RuntimeSupervisor::new(
        runtime_paths.clone(),
    ));
    let snapshot = supervisor
        .start_with_snapshot(
            runtime_config,
            bridge::mail_runtime::MailRuntimeTransition::Startup,
            Some(notify_tx),
        )
        .await?;
    print_serve_configuration(
        &config.bind,
        config.imap_port,
        config.smtp_port,
        config.no_tls,
        &snapshot.active_sessions,
        &snapshot.runtime_snapshot,
    );

    Ok(InteractiveServeRuntime { supervisor, config })
}

async fn stop_interactive_runtime(state: InteractiveServeRuntime) -> anyhow::Result<()> {
    state.supervisor.stop("interactive_stop").await
}

async fn maybe_collect_runtime_completion(
    runtime_state: &mut Option<InteractiveServeRuntime>,
) -> Option<String> {
    let state = runtime_state.as_ref()?;
    if state.supervisor.is_running().await {
        return None;
    }

    let state = runtime_state.take()?;
    Some(match state.supervisor.wait_for_termination().await {
        Ok(()) => "Serve runtime exited.".to_string(),
        Err(err) => format!("Serve runtime exited with error: {err:#}"),
    })
}

async fn start_interactive_grpc(
    bind: String,
    runtime_paths: &paths::RuntimePaths,
    options: frontend::grpc::GrpcServerOptions,
) -> anyhow::Result<InteractiveGrpcRuntime> {
    let runtime_paths = runtime_paths.clone();
    let bind_for_task = bind.clone();
    let join_handle = tokio::spawn(async move {
        frontend::grpc::run_server_with_options(runtime_paths, bind_for_task, options).await
    });
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
    use rand::RngCore;
    let mut token = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut token);
    BASE64_URL_NO_PAD.encode(token)
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
    tracing::info!(
        pkg = "bridge/token",
        user_id = %session.uid,
        email = %session.email,
        "access token missing, refreshing via stored refresh token"
    );
    let mut client = api::client::ProtonClient::with_api_mode(session.api_mode)?;
    let auth = api::auth::refresh_auth(&mut client, &session.uid, &session.refresh_token, None)
        .await
        .map_err(|err| {
            tracing::warn!(
                pkg = "bridge/token",
                user_id = %session.uid,
                email = %session.email,
                error = %err,
                "stored refresh token exchange failed"
            );
            err
        })?;
    tracing::info!(
        pkg = "bridge/token",
        user_id = %auth.uid,
        "stored refresh token exchange completed"
    );

    let mut refreshed = api::types::Session {
        uid: auth.uid,
        access_token: auth.access_token,
        refresh_token: auth.refresh_token,
        ..session
    };

    let mut canonical_user_id = None;
    match api::users::get_user(&client).await {
        Ok(user_resp) => {
            canonical_user_id = Some(user_resp.user.id.clone());
            if !user_resp.user.email.trim().is_empty() {
                refreshed.email = user_resp.user.email.clone();
            }
            if !user_resp.user.display_name.trim().is_empty() {
                refreshed.display_name = user_resp.user.display_name.clone();
            }
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "failed to refresh canonical user context after token refresh"
            );
        }
    }

    vault::save_session_with_user_id(&refreshed, canonical_user_id.as_deref(), dir)?;
    tracing::info!(
        pkg = "bridge/token",
        user_id = %refreshed.uid,
        email = %refreshed.email,
        "session token refresh persisted"
    );
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
    fn parse_global_mode_flag() {
        let cli = Cli::try_parse_from(["openproton-bridge", "--mode", "grpc", "status"]).unwrap();
        assert_eq!(cli.mode, Some(ExecutionModeArg::Grpc));
        assert!(matches!(cli.command, Command::Status));
    }

    #[test]
    fn parse_execution_mode_accepts_expected_values() {
        assert_eq!(
            parse_execution_mode("direct").unwrap(),
            ExecutionMode::Direct
        );
        assert_eq!(parse_execution_mode("grpc").unwrap(), ExecutionMode::Grpc);
        assert!(parse_execution_mode("invalid").is_err());
    }

    #[test]
    fn resolve_execution_mode_prioritizes_cli_over_env() {
        assert_eq!(
            resolve_execution_mode(Some(ExecutionModeArg::Direct), Some("grpc")).unwrap(),
            ExecutionMode::Direct
        );
        assert_eq!(
            resolve_execution_mode(None, Some("grpc")).unwrap(),
            ExecutionMode::Grpc
        );
        assert_eq!(
            resolve_execution_mode(None, None).unwrap(),
            ExecutionMode::Direct
        );
    }

    #[test]
    fn parse_vault_dump_subcommand() {
        let cli = Cli::try_parse_from(["openproton-bridge", "vault-dump"]).unwrap();
        assert!(matches!(cli.command, Command::VaultDump));
    }

    #[test]
    fn parse_mutt_config_subcommand() {
        let cli = Cli::try_parse_from([
            "openproton-bridge",
            "mutt-config",
            "--account",
            "alice@proton.me",
            "--address",
            "alias@proton.me",
            "--output",
            "/tmp/muttrc",
            "--include-password",
        ])
        .unwrap();

        match cli.command {
            Command::MuttConfig {
                account,
                address,
                output,
                include_password,
            } => {
                assert_eq!(account.as_deref(), Some("alice@proton.me"));
                assert_eq!(address.as_deref(), Some("alias@proton.me"));
                assert_eq!(output.as_deref(), Some(std::path::Path::new("/tmp/muttrc")));
                assert!(include_password);
            }
            _ => panic!("expected mutt-config command"),
        }
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
        assert_eq!(
            rewrite_repl_aliases(vec![
                "configure-mutt".into(),
                "--account".into(),
                "0".into()
            ]),
            vec![
                "mutt-config".to_string(),
                "--account".to_string(),
                "0".to_string()
            ]
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
    fn render_mailbox_state_diagnostics_is_deterministic() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_paths = paths::RuntimePaths::resolve(Some(tmp.path())).unwrap();
        let dir = runtime_paths.settings_dir();

        let session_b = api::types::Session {
            uid: "uid-b".to_string(),
            access_token: String::new(),
            refresh_token: "refresh-b".to_string(),
            email: "b@proton.me".to_string(),
            display_name: "B".to_string(),
            api_mode: api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: None,
        };
        let session_a = api::types::Session {
            uid: "uid-a".to_string(),
            access_token: String::new(),
            refresh_token: "refresh-a".to_string(),
            email: "a@proton.me".to_string(),
            display_name: "A".to_string(),
            api_mode: api::types::ApiMode::Webmail,
            key_passphrase: None,
            bridge_password: None,
        };
        vault::save_session(&session_b, dir).unwrap();
        vault::save_session(&session_a, dir).unwrap();

        let report = render_mailbox_state_diagnostics(dir, &runtime_paths);
        assert!(report.contains("mailbox-state diagnostics"));
        assert!(report.contains("accounts=2"));
        let pos_a = report.find("account uid=uid-a").unwrap();
        let pos_b = report.find("account uid=uid-b").unwrap();
        assert!(pos_a < pos_b, "accounts should be sorted by uid");
        assert!(report.contains("crash_reports_dir="));
        assert!(report.contains("support_bundles_dir="));
    }

    #[test]
    fn write_crash_report_artifact_persists_file() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_paths = paths::RuntimePaths::resolve(Some(tmp.path())).unwrap();
        let path = write_crash_report_artifact(&runtime_paths, "panic_payload=test").unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(path).unwrap();
        assert!(content.contains("panic_payload=test"));
    }

    #[tokio::test]
    async fn cmd_mutt_config_writes_template_file_without_inline_password_by_default() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_paths = paths::RuntimePaths::resolve(Some(tmp.path())).unwrap();
        let dir = runtime_paths.settings_dir();
        let session = api::types::Session {
            uid: "uid-mutt-1".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            email: "alice@proton.me".to_string(),
            display_name: "Alice".to_string(),
            api_mode: api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: Some("bridge-pass".to_string()),
        };
        vault::save_session(&session, dir).unwrap();

        let output_path = tmp.path().join("muttrc");
        cmd_mutt_config(
            Some("alice@proton.me"),
            Some("alias@proton.me"),
            Some(output_path.as_path()),
            false,
            dir,
            &runtime_paths,
        )
        .await
        .unwrap();

        let rendered = std::fs::read_to_string(&output_path).unwrap();
        assert!(rendered.contains("set from = \"alias@proton.me\""));
        assert!(rendered.contains("set imap_user = \"alias@proton.me\""));
        assert!(rendered.contains("set folder = \"imap://127.0.0.1:1143/\""));
        assert!(rendered.contains("set smtp_url = \"smtp://alias%40proton.me@127.0.0.1:1025/\""));
        assert!(rendered.contains("# set imap_pass = \"<bridge-password>\""));
        assert!(!rendered.contains("set imap_pass = \"bridge-pass\""));
    }

    #[tokio::test]
    async fn cmd_mutt_config_rejects_include_password_when_bridge_password_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_paths = paths::RuntimePaths::resolve(Some(tmp.path())).unwrap();
        let dir = runtime_paths.settings_dir();
        let session = api::types::Session {
            uid: "uid-mutt-2".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            email: "alice@proton.me".to_string(),
            display_name: "Alice".to_string(),
            api_mode: api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: None,
        };
        vault::save_session(&session, dir).unwrap();

        let err = cmd_mutt_config(
            Some("alice@proton.me"),
            None,
            None,
            true,
            dir,
            &runtime_paths,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("bridge password is missing"));
    }

    #[tokio::test]
    async fn set_disk_cache_path_for_cli_moves_live_gluon_store_and_updates_bootstrap_path() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime_paths = paths::RuntimePaths::resolve(Some(tmp.path())).unwrap();

        let session = api::types::Session {
            uid: "uid-cli-cache-switch".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            email: "cli-cache-switch@example.com".to_string(),
            display_name: "CLI Cache Switch".to_string(),
            api_mode: api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: None,
        };
        vault::save_session(&session, runtime_paths.settings_dir()).unwrap();
        vault::set_gluon_key_by_account_id(
            runtime_paths.settings_dir(),
            &session.uid,
            vec![7u8; 32],
        )
        .unwrap();

        let source_gluon_root = runtime_paths
            .gluon_paths(Some("gluon"))
            .root()
            .to_path_buf();
        let source_blob = source_gluon_root
            .join("backend")
            .join("store")
            .join("live-user")
            .join("00000001.msg");
        tokio::fs::create_dir_all(source_blob.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&source_blob, b"gluon-cli-live")
            .await
            .unwrap();

        let target_gluon_root = tmp.path().join("gluon-cli-moved");
        set_disk_cache_path_for_cli(&runtime_paths, target_gluon_root.to_str().unwrap())
            .await
            .unwrap();

        let moved_blob = target_gluon_root
            .join("backend")
            .join("store")
            .join("live-user")
            .join("00000001.msg");
        assert_eq!(
            tokio::fs::read(&moved_blob).await.unwrap(),
            b"gluon-cli-live"
        );
        assert!(!source_gluon_root.exists());

        let bootstrap = vault::load_gluon_store_bootstrap(
            runtime_paths.settings_dir(),
            std::slice::from_ref(&session.uid),
        )
        .unwrap();
        assert_eq!(
            runtime_paths.gluon_paths(Some(&bootstrap.gluon_dir)).root(),
            target_gluon_root
        );
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
