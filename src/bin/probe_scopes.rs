use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base32::Alphabet;
use clap::{ArgAction, Parser, ValueEnum};
use hmac::{Hmac, Mac};
use openproton_bridge::{api, cli_human_verification};
use reqwest::Url;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const DEFAULT_CLIENT_IDS: &[&str] = &[
    "web-account",
    "web-account-lite",
    "web-mail",
    "web-contacts",
    "web-calendar",
    "web-drive",
    "web-pass",
    "web-vpn-settings",
    "web-admin",
    "web-verify",
    "web-wallet",
    "web-docs",
    "web-docs-editor",
    "web-sheets",
    "web-sheets-editor",
    "web-lumo",
    "web-authenticator",
    "web-meet",
    "windows-mail",
    "macos-mail",
    "linux-mail",
    "windows-pass",
    "macos-pass",
    "linux-pass",
    "windows-authenticator",
    "macos-authenticator",
    "linux-authenticator",
    "windows-meet",
    "macos-meet",
    "linux-meet",
    "browser-pass",
    "browser-vpn",
    "android-mail",
    "android-calendar",
    "ios-mail",
    "ios-calendar",
    "windows-drive",
    "ios-drive",
    "ios-drive-fileprovider",
    "macos-drive",
    "macos-drive-fileprovider",
    "linux-bridge",
    "macos-bridge",
    "windows-bridge",
];

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ApiModeArg {
    Webmail,
    Bridge,
}

impl From<ApiModeArg> for api::types::ApiMode {
    fn from(value: ApiModeArg) -> Self {
        match value {
            ApiModeArg::Webmail => api::types::ApiMode::Webmail,
            ApiModeArg::Bridge => api::types::ApiMode::Bridge,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone)]
struct TotpConfig {
    secret: String,
    digits: u32,
    period: u64,
    algorithm: TotpAlgorithm,
}

#[derive(Debug, Parser)]
#[command(
    name = "probe-scopes",
    about = "Probe Proton scope grants across app identities"
)]
struct Args {
    #[arg(long)]
    username: String,
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    totp_secret: Option<String>,
    #[arg(long)]
    totp_code: Option<String>,
    #[arg(long, value_enum, default_value = "webmail")]
    api_mode: ApiModeArg,
    #[arg(long, default_value = "9.9.9")]
    version: String,
    #[arg(long, action = ArgAction::Append)]
    client_id: Vec<String>,
    #[arg(long, action = ArgAction::Append)]
    client_version: Vec<String>,
    #[arg(long, default_value_t = 20)]
    max_attempts: usize,
    #[arg(long, default_value_t = 420)]
    attempt_timeout: u64,
    #[arg(long)]
    json_out: Option<std::path::PathBuf>,
    #[arg(long)]
    scopes: Option<String>,
    #[arg(long, action = ArgAction::Append)]
    scope: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AttemptResult {
    client_version: String,
    status: String,
    granted_scopes: Option<String>,
    missing_requested_scopes: Option<String>,
    human_verification_required: bool,
    human_verification_url: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProbeReport {
    username: String,
    api_mode: String,
    attempt_count: usize,
    results: Vec<AttemptResult>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.username.trim().is_empty() {
        anyhow::bail!("--username cannot be empty");
    }
    let password = match args.password.as_deref() {
        Some(password) => password.to_string(),
        None => rpassword::prompt_password("Password: ").context("failed to read password")?,
    };
    if password.trim().is_empty() {
        anyhow::bail!("empty password is not allowed");
    }

    let totp_config = parse_totp_config(args.totp_secret.as_deref())?;
    let requested_scopes = collect_requested_scopes(args.scopes.clone(), args.scope.clone());
    let client_versions = build_client_versions(&args)?;
    let api_mode: api::types::ApiMode = args.api_mode.into();

    println!(
        "Probing {} client identities in {} mode",
        client_versions.len(),
        api_mode.as_str()
    );
    let mut results = Vec::with_capacity(client_versions.len());

    for (index, client_version) in client_versions.iter().enumerate() {
        println!(
            "[{}/{}] {}",
            index + 1,
            client_versions.len(),
            client_version
        );

        let outcome = tokio::time::timeout(
            Duration::from_secs(args.attempt_timeout),
            run_single_attempt(
                api_mode,
                &args.username,
                &password,
                totp_config.as_ref(),
                args.totp_code.as_deref(),
                &requested_scopes,
                client_version,
            ),
        )
        .await;

        let result = match outcome {
            Ok(result) => result?,
            Err(_) => AttemptResult {
                client_version: client_version.clone(),
                status: "TIMEOUT".to_string(),
                granted_scopes: None,
                missing_requested_scopes: None,
                human_verification_required: false,
                human_verification_url: None,
                error: Some(format!("attempt timed out after {}s", args.attempt_timeout)),
            },
        };

        println!(
            "  -> {}, scopes: {}",
            result.status,
            result
                .granted_scopes
                .as_deref()
                .or(result.error.as_deref())
                .unwrap_or("unknown")
        );
        results.push(result);
    }

    let report = ProbeReport {
        username: args.username.clone(),
        api_mode: api_mode.as_str().to_string(),
        attempt_count: results.len(),
        results,
    };

    println!("\nSummary:");
    for row in &report.results {
        let scopes = row.granted_scopes.as_deref().unwrap_or("-");
        let hv = row
            .human_verification_url
            .as_ref()
            .map(|url| format!(" hv={url}"))
            .unwrap_or_default();
        println!(
            "- {:11} {:40} scopes={}{}",
            row.status, row.client_version, scopes, hv
        );
    }

    if let Some(json_out) = args.json_out {
        if let Some(parent) = json_out.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let payload = serde_json::to_string_pretty(&report)?;
        std::fs::write(&json_out, payload)
            .with_context(|| format!("failed to write {}", json_out.display()))?;
        println!("\nJSON report: {}", json_out.display());
    }

    Ok(())
}

fn collect_requested_scopes(scopes: Option<String>, scope: Vec<String>) -> Vec<String> {
    let mut requested = Vec::new();
    if let Some(grouped) = scopes {
        requested.extend(
            grouped
                .split_whitespace()
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(str::to_string),
        );
    }
    for entry in scope {
        requested.extend(
            entry
                .split_whitespace()
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(str::to_string),
        );
    }
    api::auth::normalize_scope_list(Some(&requested))
}

fn build_client_versions(args: &Args) -> Result<Vec<String>> {
    let mut versions = Vec::new();
    let mut seen = HashSet::new();

    let client_ids: Vec<String> = if args.client_id.is_empty() {
        DEFAULT_CLIENT_IDS
            .iter()
            .map(|value| value.to_string())
            .collect()
    } else {
        args.client_id.clone()
    };

    for client_id in client_ids {
        let value = format!("{client_id}@{}", args.version);
        if seen.insert(value.clone()) {
            versions.push(value);
        }
    }

    for full in &args.client_version {
        let value = full.trim();
        if value.is_empty() {
            continue;
        }
        if seen.insert(value.to_string()) {
            versions.push(value.to_string());
        }
    }

    if args.max_attempts > 0 && versions.len() > args.max_attempts {
        versions.truncate(args.max_attempts);
    }
    if versions.is_empty() {
        anyhow::bail!("no client versions to probe");
    }
    Ok(versions)
}

fn apply_client_version_env(api_mode: api::types::ApiMode, client_version: &str) -> Result<()> {
    match api_mode {
        api::types::ApiMode::Webmail => {
            std::env::remove_var("OPENPROTON_PM_APP_VERSION");
            std::env::set_var("OPENPROTON_PM_WEBMAIL_APP_VERSION", client_version);
        }
        api::types::ApiMode::Bridge => {
            std::env::remove_var("OPENPROTON_PM_WEBMAIL_APP_VERSION");
            std::env::set_var("OPENPROTON_PM_APP_VERSION", client_version);
        }
    }
    Ok(())
}

async fn run_single_attempt(
    api_mode: api::types::ApiMode,
    username: &str,
    password: &str,
    totp_config: Option<&TotpConfig>,
    totp_code_override: Option<&str>,
    requested_scopes: &[String],
    client_version: &str,
) -> Result<AttemptResult> {
    apply_client_version_env(api_mode, client_version)?;
    let mut client = api::client::ProtonClient::with_api_mode(api_mode)?;
    let mut hv_details: Option<api::types::HumanVerificationDetails> = None;

    let auth = loop {
        match api::auth::login(
            &mut client,
            username,
            password,
            hv_details.as_ref(),
            if requested_scopes.is_empty() {
                None
            } else {
                Some(requested_scopes)
            },
        )
        .await
        {
            Ok(auth) => break auth,
            Err(err) => {
                let needs_hv = api::error::human_verification_details(&err).or_else(|| {
                    if matches!(&err, api::error::ApiError::Api { code: 12087, .. }) {
                        api::error::any_human_verification_details(&err)
                    } else {
                        None
                    }
                });

                if let Some(mut hv) = needs_hv {
                    let hv_url = hv.challenge_url();
                    let token = match cli_human_verification::prompt_for_token(&hv).await {
                        Ok(token) => token,
                        Err(prompt_err) => {
                            return Ok(AttemptResult {
                                client_version: client_version.to_string(),
                                status: "HV_REQUIRED".to_string(),
                                granted_scopes: None,
                                missing_requested_scopes: None,
                                human_verification_required: true,
                                human_verification_url: Some(hv_url),
                                error: Some(prompt_err.to_string()),
                            });
                        }
                    };
                    if let Some(token_override) = token {
                        hv.human_verification_token = token_override;
                    }
                    if !hv.is_usable() {
                        return Ok(AttemptResult {
                            client_version: client_version.to_string(),
                            status: "HV_REQUIRED".to_string(),
                            granted_scopes: None,
                            missing_requested_scopes: None,
                            human_verification_required: true,
                            human_verification_url: Some(hv_url),
                            error: Some("human verification token missing".to_string()),
                        });
                    }
                    hv_details = Some(hv);
                    continue;
                }

                return Ok(AttemptResult {
                    client_version: client_version.to_string(),
                    status: "FAIL".to_string(),
                    granted_scopes: None,
                    missing_requested_scopes: None,
                    human_verification_required: false,
                    human_verification_url: None,
                    error: Some(err.to_string()),
                });
            }
        }
    };

    let second_factor_scopes =
        match complete_second_factor(&client, &auth, totp_config, totp_code_override).await {
            Ok(scopes) => scopes,
            Err(err) => {
                return Ok(AttemptResult {
                    client_version: client_version.to_string(),
                    status: "FAIL".to_string(),
                    granted_scopes: None,
                    missing_requested_scopes: None,
                    human_verification_required: false,
                    human_verification_url: None,
                    error: Some(format!("second-factor step failed: {err}")),
                });
            }
        };
    let mut granted_scopes = if second_factor_scopes.is_empty() {
        api::auth::normalize_scope_string(auth.scope.as_deref())
    } else {
        second_factor_scopes
    };
    if granted_scopes.is_empty() {
        if let Ok(scopes) = api::auth::get_granted_scopes(&client).await {
            granted_scopes = scopes;
        }
    }

    let missing_requested = if requested_scopes.is_empty() {
        Vec::new()
    } else {
        requested_scopes
            .iter()
            .filter(|scope| !api::auth::has_scope(&granted_scopes, scope))
            .cloned()
            .collect()
    };

    Ok(AttemptResult {
        client_version: client_version.to_string(),
        status: "OK".to_string(),
        granted_scopes: api::auth::scope_list_to_string(&granted_scopes),
        missing_requested_scopes: api::auth::scope_list_to_string(&missing_requested),
        human_verification_required: false,
        human_verification_url: None,
        error: None,
    })
}

async fn complete_second_factor(
    client: &api::client::ProtonClient,
    auth: &api::types::AuthResponse,
    totp_config: Option<&TotpConfig>,
    totp_code_override: Option<&str>,
) -> Result<Vec<String>> {
    if !auth.two_factor.requires_second_factor() {
        return Ok(Vec::new());
    }
    if auth.two_factor.totp_required() {
        let code = match totp_code_override {
            Some(code) => code.to_string(),
            None => match totp_config {
                Some(config) => generate_totp_code(config)?,
                None => {
                    rpassword::prompt_password("2FA code: ").context("failed to read 2FA code")?
                }
            },
        };
        let result = api::auth::submit_2fa(client, code.trim()).await?;
        return Ok(api::auth::normalize_scope_list(Some(&result.scopes)));
    }
    anyhow::bail!("unsupported second-factor mode returned by API");
}

fn parse_totp_config(raw: Option<&str>) -> Result<Option<TotpConfig>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if !value.starts_with("otpauth://") {
        return Ok(Some(TotpConfig {
            secret: value.to_string(),
            digits: 6,
            period: 30,
            algorithm: TotpAlgorithm::Sha1,
        }));
    }

    let url = Url::parse(value).context("invalid otpauth URI")?;
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let secret = query
        .get("secret")
        .map(String::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if secret.is_empty() {
        anyhow::bail!("otpauth URI missing `secret`");
    }

    let digits = query
        .get("digits")
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(6);
    let period = query
        .get("period")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(30);
    let algorithm = query
        .get("algorithm")
        .map(|value| value.trim().to_ascii_uppercase())
        .unwrap_or_else(|| "SHA1".to_string());
    let algorithm = match algorithm.as_str() {
        "SHA1" => TotpAlgorithm::Sha1,
        "SHA256" => TotpAlgorithm::Sha256,
        "SHA512" => TotpAlgorithm::Sha512,
        other => anyhow::bail!("unsupported TOTP algorithm: {other}"),
    };

    Ok(Some(TotpConfig {
        secret,
        digits,
        period,
        algorithm,
    }))
}

fn generate_totp_code(config: &TotpConfig) -> Result<String> {
    let cleaned_secret: String = config
        .secret
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    let key = base32::decode(Alphabet::Rfc4648 { padding: false }, &cleaned_secret)
        .or_else(|| base32::decode(Alphabet::Rfc4648 { padding: true }, &cleaned_secret))
        .context("invalid base32 TOTP secret")?;

    let unix_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before unix epoch")?
        .as_secs();
    let counter = unix_now / config.period.max(1);
    let counter_bytes = counter.to_be_bytes();
    let digest = match config.algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac =
                HmacSha1::new_from_slice(&key).context("failed to initialize SHA1 HMAC")?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac =
                HmacSha256::new_from_slice(&key).context("failed to initialize SHA256 HMAC")?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut mac =
                HmacSha512::new_from_slice(&key).context("failed to initialize SHA512 HMAC")?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };

    if digest.len() < 20 {
        anyhow::bail!("unexpected short HMAC digest");
    }
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    if offset + 4 > digest.len() {
        anyhow::bail!("invalid TOTP dynamic truncation offset");
    }
    let code = ((u32::from(digest[offset]) & 0x7f) << 24)
        | ((u32::from(digest[offset + 1]) & 0xff) << 16)
        | ((u32::from(digest[offset + 2]) & 0xff) << 8)
        | (u32::from(digest[offset + 3]) & 0xff);
    let modulo = 10u32.saturating_pow(config.digits.max(1));
    Ok(format!(
        "{:0width$}",
        code % modulo,
        width = config.digits as usize
    ))
}
