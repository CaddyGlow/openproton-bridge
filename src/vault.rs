use std::collections::HashMap;
use std::path::Path;

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::api::types::Session;

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const VAULT_FILE: &str = "vault.enc";
const KEY_FILE: &str = "vault.key";
const DEFAULT_EMAIL_FILE: &str = "default_email";
const VAULT_VERSION: i32 = 2;

// Keychain constants matching the Go bridge
const KEYCHAIN_SERVICE: &str = "protonmail/bridge-v3/users";
const KEYCHAIN_SECRET: &str = "bridge-vault-key";

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encryption error")]
    Encrypt,
    #[error("decryption error")]
    Decrypt,
    #[error("msgpack encode error: {0}")]
    MsgpackEncode(#[from] rmp_serde::encode::Error),
    #[error("msgpack decode error: {0}")]
    MsgpackDecode(#[from] rmp_serde::decode::Error),
    #[error("invalid vault key length")]
    InvalidKeyLength,
    #[error("not logged in -- run `openproton-bridge login` first")]
    NotLoggedIn,
    #[error("account not found for email: {0}")]
    AccountNotFound(String),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEventCheckpoint {
    pub last_event_id: String,
    pub last_event_ts: Option<i64>,
    pub sync_state: Option<String>,
}

// ---------------------------------------------------------------------------
// MsgpackTimestamp: Custom serde for msgpack extension type -1 (timestamp)
//
// Go's vmihailenco/msgpack encodes time.Time as msgpack ext type -1.
// The format uses 4, 8, or 12 bytes depending on the value.
// Go's zero time.Time{} (0001-01-01 00:00:00 UTC) = (-62135596800, 0).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MsgpackTimestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

impl MsgpackTimestamp {
    /// Go's time.Time{} zero value.
    pub fn zero() -> Self {
        Self {
            seconds: -62135596800,
            nanoseconds: 0,
        }
    }
}

impl Default for MsgpackTimestamp {
    fn default() -> Self {
        Self::zero()
    }
}

impl Serialize for MsgpackTimestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        // Encode as msgpack ext type -1 (timestamp).
        // Use the 12-byte format (type 12): 4 bytes nanoseconds + 8 bytes seconds.
        // This is the most general format and handles negative seconds.
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&self.nanoseconds.to_be_bytes());
        buf[4..12].copy_from_slice(&self.seconds.to_be_bytes());
        serializer.serialize_newtype_struct(
            rmp_serde::MSGPACK_EXT_STRUCT_NAME,
            &(-1i8, serde_bytes::ByteBuf::from(buf.to_vec())),
        )
    }
}

impl<'de> Deserialize<'de> for MsgpackTimestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        // rmp_serde represents ext types as NewtypeStruct("_ExtStruct", (i8, &[u8])).
        // We must use deserialize_newtype_struct with a visitor to handle this.
        struct TimestampVisitor;

        impl<'de> serde::de::Visitor<'de> for TimestampVisitor {
            type Value = MsgpackTimestamp;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("msgpack ext type -1 (timestamp)")
            }

            fn visit_newtype_struct<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> std::result::Result<Self::Value, D::Error> {
                let (type_id, data): (i8, serde_bytes::ByteBuf) =
                    Deserialize::deserialize(deserializer)?;
                if type_id != -1 {
                    return Err(serde::de::Error::custom(format!(
                        "expected msgpack ext type -1, got {}",
                        type_id
                    )));
                }
                parse_timestamp_bytes(data.as_ref())
            }
        }

        deserializer
            .deserialize_newtype_struct(rmp_serde::MSGPACK_EXT_STRUCT_NAME, TimestampVisitor)
    }
}

fn parse_timestamp_bytes<E: serde::de::Error>(
    bytes: &[u8],
) -> std::result::Result<MsgpackTimestamp, E> {
    match bytes.len() {
        4 => {
            let secs = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
            Ok(MsgpackTimestamp {
                seconds: secs as i64,
                nanoseconds: 0,
            })
        }
        8 => {
            let val = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
            let ns = (val >> 34) as u32;
            let secs = (val & 0x3_FFFF_FFFF) as i64;
            Ok(MsgpackTimestamp {
                seconds: secs,
                nanoseconds: ns,
            })
        }
        12 => {
            let ns = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
            let secs = i64::from_be_bytes(bytes[4..12].try_into().unwrap());
            Ok(MsgpackTimestamp {
                seconds: secs,
                nanoseconds: ns,
            })
        }
        other => Err(serde::de::Error::custom(format!(
            "invalid timestamp ext length: {}",
            other
        ))),
    }
}

// ---------------------------------------------------------------------------
// Go-compatible vault structs
// ---------------------------------------------------------------------------

/// Outer file envelope: msgpack { Version: i32, Data: bytes }
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VaultFile {
    version: i32,
    #[serde(with = "serde_bytes")]
    data: Vec<u8>,
}

/// Inner decrypted data matching Go's vault.Data.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VaultData {
    settings: Settings,
    users: Vec<UserData>,
    #[serde(with = "serde_bytes")]
    cookies: Vec<u8>,
    certs: VaultCerts,
    migrated: bool,
    /// UUID as 16 raw bytes (google/uuid.UUID uses BinaryMarshaler -> 16 bytes).
    #[serde(with = "serde_bytes")]
    feature_flag_sticky_key: Vec<u8>,
}

impl Default for VaultData {
    fn default() -> Self {
        Self {
            settings: Settings::default(),
            users: Vec::new(),
            cookies: Vec::new(),
            certs: VaultCerts::default(),
            migrated: false,
            feature_flag_sticky_key: vec![0u8; 16],
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UserData {
    #[serde(rename = "UserID")]
    user_id: String,
    username: String,
    primary_email: String,

    #[serde(with = "serde_bytes")]
    gluon_key: Vec<u8>,
    #[serde(rename = "GluonIDs")]
    gluon_ids: HashMap<String, String>,
    #[serde(with = "serde_bytes")]
    bridge_pass: Vec<u8>,
    address_mode: i32,

    #[serde(rename = "AuthUID")]
    auth_uid: String,
    auth_ref: String,
    #[serde(with = "serde_bytes")]
    key_pass: Vec<u8>,

    sync_status: SyncStatus,
    #[serde(rename = "EventID")]
    event_id: String,
    #[serde(rename = "LastEventTS", default)]
    last_event_ts: Option<i64>,
    #[serde(rename = "SyncState", default)]
    sync_state: Option<String>,

    #[serde(rename = "UIDValidity")]
    uid_validity: HashMap<String, u32>,

    should_resync: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SyncStatus {
    has_labels: bool,
    has_messages: bool,
    #[serde(rename = "LastMessageID")]
    last_message_id: String,
    #[serde(rename = "FailedMessageIDs")]
    failed_message_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Settings {
    gluon_dir: String,

    #[serde(rename = "IMAPPort")]
    imap_port: i32,
    #[serde(rename = "SMTPPort")]
    smtp_port: i32,
    #[serde(rename = "IMAPSSL")]
    imap_ssl: bool,
    #[serde(rename = "SMTPSSL")]
    smtp_ssl: bool,

    update_channel: String,
    update_rollout: f64,

    color_scheme: String,
    proxy_allowed: bool,
    show_all_mail: bool,
    autostart: bool,
    auto_update: bool,
    telemetry_disabled: bool,

    last_version: String,
    first_start: bool,

    max_sync_memory: u64,

    last_user_agent: String,
    last_heartbeat_sent: MsgpackTimestamp,

    password_archive: PasswordArchive,

    sync_workers: i32,
    sync_att_pool: i32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            gluon_dir: String::new(),
            imap_port: 1143,
            smtp_port: 1025,
            imap_ssl: false,
            smtp_ssl: false,
            update_channel: "stable".to_string(),
            update_rollout: 0.0,
            color_scheme: String::new(),
            proxy_allowed: false,
            show_all_mail: true,
            autostart: true,
            auto_update: true,
            telemetry_disabled: false,
            last_version: "0.0.0".to_string(),
            first_start: true,
            max_sync_memory: 2 * 1024 * 1024 * 1024,
            last_user_agent: String::new(),
            last_heartbeat_sent: MsgpackTimestamp::zero(),
            password_archive: PasswordArchive::default(),
            sync_workers: 16,
            sync_att_pool: 16,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PasswordArchive {
    archive: HashMap<String, serde_bytes::ByteBuf>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VaultCerts {
    bridge: VaultCert,
    custom_cert_path: String,
    custom_key_path: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VaultCert {
    #[serde(with = "serde_bytes")]
    cert: Vec<u8>,
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

/// Derive AES-256 key from the raw vault key using SHA-256 (matches Go bridge).
fn derive_aes_key(raw: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    Sha256::digest(raw).into()
}

fn encrypt(plaintext: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    let aes_key = derive_aes_key(key);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| VaultError::Encrypt)?;
    // Go format: nonce || ciphertext (gcm.Seal prepends nonce)
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt(data: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN {
        return Err(VaultError::Decrypt);
    }
    let aes_key = derive_aes_key(key);
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::Decrypt)
}

/// Load the vault encryption key. Checks vault.key file first (local, deterministic),
/// then OS keychain (for Go bridge interop). If neither exists, generates a new key
/// and stores it in both keychain (if available) and file.
fn get_or_create_vault_key(dir: &Path) -> Result<[u8; KEY_LEN]> {
    // 1. Try vault.key file (preferred: local, deterministic, no race conditions)
    let key_path = dir.join(KEY_FILE);
    if key_path.exists() {
        let data = std::fs::read(&key_path)?;
        if data.len() != KEY_LEN {
            return Err(VaultError::InvalidKeyLength);
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&data);
        return Ok(key);
    }

    // 2. Try OS keychain (for Go bridge interop -- it stores key in keychain)
    match try_keychain_get() {
        Ok(Some(key)) => return Ok(key),
        Ok(None) => {}
        Err(e) => tracing::debug!(error = %e, "keychain read failed"),
    }

    // 3. Generate new key, store in file and try keychain
    let mut key = [0u8; KEY_LEN];
    use rand::RngCore;
    OsRng.fill_bytes(&mut key);

    std::fs::create_dir_all(dir)?;
    std::fs::write(&key_path, key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Also store in keychain for Go bridge interop (best-effort)
    let _ = try_keychain_set(&key);

    Ok(key)
}

/// Try to read the vault key from the OS keychain.
/// Returns Ok(Some(key)) if found, Ok(None) if not found, Err on failure.
fn try_keychain_get() -> std::result::Result<Option<[u8; KEY_LEN]>, keyring::Error> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_SECRET)?;
    match entry.get_password() {
        Ok(encoded) => {
            let decoded = BASE64
                .decode(&encoded)
                .map_err(|e| keyring::Error::Invalid(e.to_string(), encoded.clone()))?;
            if decoded.len() != KEY_LEN {
                return Err(keyring::Error::Invalid(
                    "wrong key length".to_string(),
                    encoded,
                ));
            }
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(&decoded);
            Ok(Some(key))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Try to store the vault key in the OS keychain (base64-encoded, like Go bridge).
fn try_keychain_set(key: &[u8; KEY_LEN]) -> std::result::Result<(), keyring::Error> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_SECRET)?;
    let encoded = BASE64.encode(key);
    entry.set_password(&encoded)
}

// ---------------------------------------------------------------------------
// Session <-> UserData conversion
// ---------------------------------------------------------------------------

fn session_to_userdata(session: &Session) -> UserData {
    // key_passphrase: our Session stores base64, Go stores raw bytes
    let key_pass = session
        .key_passphrase
        .as_deref()
        .and_then(|b64| BASE64.decode(b64).ok())
        .unwrap_or_default();

    // bridge_password: our Session stores as string, Go stores as raw bytes
    let bridge_pass = session
        .bridge_password
        .as_deref()
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_default();

    // Generate a random 32-byte gluon key
    let mut gluon_key = vec![0u8; 32];
    use rand::RngCore;
    OsRng.fill_bytes(&mut gluon_key);

    UserData {
        user_id: String::new(),
        username: session.display_name.clone(),
        primary_email: session.email.clone(),
        gluon_key,
        gluon_ids: HashMap::new(),
        bridge_pass,
        address_mode: 0, // CombinedMode
        auth_uid: session.uid.clone(),
        auth_ref: session.refresh_token.clone(),
        key_pass,
        sync_status: SyncStatus::default(),
        event_id: String::new(),
        last_event_ts: None,
        sync_state: None,
        uid_validity: HashMap::new(),
        should_resync: false,
    }
}

fn userdata_to_session(ud: &UserData) -> Session {
    // key_passphrase: Go stores raw bytes, we store base64
    let key_passphrase = if ud.key_pass.is_empty() {
        None
    } else {
        Some(BASE64.encode(&ud.key_pass))
    };

    // bridge_password: Go stores raw bytes, we store as string
    let bridge_password = if ud.bridge_pass.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&ud.bridge_pass).to_string())
    };

    Session {
        uid: ud.auth_uid.clone(),
        // Go vault does not store access_token; must be obtained via refresh
        access_token: String::new(),
        refresh_token: ud.auth_ref.clone(),
        email: ud.primary_email.clone(),
        display_name: ud.username.clone(),
        key_passphrase,
        bridge_password,
    }
}

// ---------------------------------------------------------------------------
// Marshal / unmarshal helpers
// ---------------------------------------------------------------------------

fn marshal_vault(data: &VaultData, key: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    let inner = rmp_serde::to_vec_named(data)?;
    let encrypted = encrypt(&inner, key)?;
    let file = VaultFile {
        version: VAULT_VERSION,
        data: encrypted,
    };
    Ok(rmp_serde::to_vec_named(&file)?)
}

fn unmarshal_vault(raw: &[u8], key: &[u8; KEY_LEN]) -> Result<VaultData> {
    let file: VaultFile = rmp_serde::from_slice(raw)?;
    let decrypted = decrypt(&file.data, key)?;
    let data: VaultData = rmp_serde::from_slice(&decrypted)?;
    Ok(data)
}

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn load_vault_data(dir: &Path) -> Result<Option<VaultData>> {
    let vault_path = dir.join(VAULT_FILE);
    if !vault_path.exists() {
        return Ok(None);
    }

    let raw = std::fs::read(&vault_path)?;
    let mut key = get_or_create_vault_key(dir)?;
    let data = unmarshal_vault(&raw, &key);
    key.zeroize();
    let data = data?;
    Ok(Some(data))
}

fn save_vault_data(dir: &Path, data: &VaultData) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let mut key = get_or_create_vault_key(dir)?;
    let encoded = marshal_vault(data, &key);
    key.zeroize();
    let encoded = encoded?;

    let vault_path = dir.join(VAULT_FILE);
    std::fs::write(&vault_path, &encoded)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&vault_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

fn write_default_email(dir: &Path, email: &str) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(DEFAULT_EMAIL_FILE);
    std::fs::write(&path, email.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn save_session(session: &Session, dir: &Path) -> Result<()> {
    let mut data = load_vault_data(dir)?.unwrap_or_default();
    let session_email = normalize_email(&session.email);

    // Find existing user by email, or append new
    let ud = session_to_userdata(session);
    if let Some(existing) = data
        .users
        .iter_mut()
        .find(|u| normalize_email(&u.primary_email) == session_email)
    {
        existing.primary_email = session.email.clone();
        existing.auth_uid = ud.auth_uid;
        existing.auth_ref = ud.auth_ref;
        existing.key_pass = ud.key_pass;
        existing.bridge_pass = ud.bridge_pass;
        existing.username = ud.username;
    } else {
        data.users.push(ud);
    }

    save_vault_data(dir, &data)?;
    if get_default_email(dir)?.is_none() {
        write_default_email(dir, &session.email)?;
    }
    Ok(())
}

pub fn load_session(dir: &Path) -> Result<Session> {
    if let Some(default_email) = get_default_email(dir)? {
        if let Ok(session) = load_session_by_email(dir, &default_email) {
            return Ok(session);
        }
    }

    let sessions = list_sessions(dir)?;
    sessions.into_iter().next().ok_or(VaultError::NotLoggedIn)
}

/// Load session for a specific email address.
pub fn load_session_by_email(dir: &Path, email: &str) -> Result<Session> {
    let data = load_vault_data(dir)?.ok_or(VaultError::NotLoggedIn)?;
    let email = normalize_email(email);

    let ud = data
        .users
        .iter()
        .find(|u| normalize_email(&u.primary_email) == email)
        .ok_or_else(|| VaultError::AccountNotFound(email.clone()))?;
    Ok(userdata_to_session(ud))
}

/// List all stored sessions.
pub fn list_sessions(dir: &Path) -> Result<Vec<Session>> {
    let Some(data) = load_vault_data(dir)? else {
        return Ok(Vec::new());
    };

    Ok(data.users.iter().map(userdata_to_session).collect())
}

/// Get the configured default account email (if any).
pub fn get_default_email(dir: &Path) -> Result<Option<String>> {
    let path = dir.join(DEFAULT_EMAIL_FILE);
    if !path.exists() {
        return Ok(None);
    }

    let email = std::fs::read_to_string(path)?;
    let email = email.trim();
    if email.is_empty() {
        return Ok(None);
    }

    Ok(Some(email.to_string()))
}

/// Set the default account email. The email must already exist in the vault.
pub fn set_default_email(dir: &Path, email: &str) -> Result<()> {
    let email = normalize_email(email);
    let data = load_vault_data(dir)?.ok_or(VaultError::NotLoggedIn)?;
    let user = data
        .users
        .iter()
        .find(|u| normalize_email(&u.primary_email) == email)
        .ok_or_else(|| VaultError::AccountNotFound(email.clone()))?;
    write_default_email(dir, &user.primary_email)
}

pub fn session_exists(dir: &Path) -> bool {
    dir.join(VAULT_FILE).exists()
}

/// Remove a specific account session by email.
pub fn remove_session_by_email(dir: &Path, email: &str) -> Result<()> {
    let mut data = load_vault_data(dir)?.ok_or(VaultError::NotLoggedIn)?;
    let email = normalize_email(email);
    let original_len = data.users.len();
    data.users
        .retain(|u| normalize_email(&u.primary_email) != email);

    if data.users.len() == original_len {
        return Err(VaultError::AccountNotFound(email));
    }

    if data.users.is_empty() {
        return remove_session(dir);
    }

    save_vault_data(dir, &data)?;

    let default_email = get_default_email(dir)?;
    let still_valid_default = default_email.is_some_and(|default_email| {
        data.users
            .iter()
            .any(|u| normalize_email(&u.primary_email) == normalize_email(&default_email))
    });
    if !still_valid_default {
        write_default_email(dir, &data.users[0].primary_email)?;
    }

    Ok(())
}

pub fn remove_session(dir: &Path) -> Result<()> {
    let vault = dir.join(VAULT_FILE);
    let key_file = dir.join(KEY_FILE);
    let default_email_file = dir.join(DEFAULT_EMAIL_FILE);
    if vault.exists() {
        std::fs::remove_file(&vault)?;
    }
    if key_file.exists() {
        std::fs::remove_file(&key_file)?;
    }
    if default_email_file.exists() {
        std::fs::remove_file(&default_email_file)?;
    }
    // Also try to remove keychain entry (best-effort)
    if let Ok(entry) = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_SECRET) {
        let _ = entry.delete_credential();
    }
    Ok(())
}

pub fn load_event_checkpoint_by_account_id(
    dir: &Path,
    account_id: &str,
) -> Result<Option<StoredEventCheckpoint>> {
    let Some(data) = load_vault_data(dir)? else {
        return Ok(None);
    };

    let Some(user) = data.users.iter().find(|u| u.auth_uid == account_id) else {
        return Ok(None);
    };

    if user.event_id.is_empty() && user.last_event_ts.is_none() && user.sync_state.is_none() {
        return Ok(None);
    }

    Ok(Some(StoredEventCheckpoint {
        last_event_id: user.event_id.clone(),
        last_event_ts: user.last_event_ts,
        sync_state: user.sync_state.clone(),
    }))
}

pub fn save_event_checkpoint_by_account_id(
    dir: &Path,
    account_id: &str,
    checkpoint: &StoredEventCheckpoint,
) -> Result<()> {
    let mut data = load_vault_data(dir)?.ok_or(VaultError::NotLoggedIn)?;
    let Some(user) = data.users.iter_mut().find(|u| u.auth_uid == account_id) else {
        return Err(VaultError::AccountNotFound(account_id.to_string()));
    };

    user.event_id = checkpoint.last_event_id.clone();
    user.last_event_ts = checkpoint.last_event_ts;
    user.sync_state = checkpoint.sync_state.clone();

    save_vault_data(dir, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; KEY_LEN];
        let plaintext = b"hello, vault!";
        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = [0x42u8; KEY_LEN];
        let key2 = [0x43u8; KEY_LEN];
        let plaintext = b"secret data";
        let encrypted = encrypt(plaintext, &key1).unwrap();
        let result = decrypt(&encrypted, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_truncated() {
        let key = [0x42u8; KEY_LEN];
        let result = decrypt(&[0u8; 5], &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered() {
        let key = [0x42u8; KEY_LEN];
        let plaintext = b"tamper test";
        let mut encrypted = encrypt(plaintext, &key).unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        let result = decrypt(&encrypted, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_each_encryption_unique() {
        let key = [0x42u8; KEY_LEN];
        let plaintext = b"same data";
        let enc1 = encrypt(plaintext, &key).unwrap();
        let enc2 = encrypt(plaintext, &key).unwrap();
        assert_ne!(enc1, enc2);
        assert_eq!(decrypt(&enc1, &key).unwrap(), plaintext);
        assert_eq!(decrypt(&enc2, &key).unwrap(), plaintext);
    }

    #[test]
    fn test_key_derivation_sha256() {
        let raw = [0x42u8; KEY_LEN];
        let derived = derive_aes_key(&raw);
        let expected: [u8; 32] = Sha256::digest([0x42u8; 32]).into();
        assert_eq!(derived, expected);
        // Derived key should differ from the raw key
        assert_ne!(derived, raw);
    }

    #[test]
    fn test_vault_key_creation_file_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let key1 = get_or_create_vault_key(tmp.path()).unwrap();
        let key2 = get_or_create_vault_key(tmp.path()).unwrap();
        assert_eq!(key1, key2);
        assert_ne!(key1, [0u8; KEY_LEN]);
    }

    #[test]
    fn test_msgpack_timestamp_zero_roundtrip() {
        let ts = MsgpackTimestamp::zero();
        let encoded = rmp_serde::to_vec_named(&ts).unwrap();
        let decoded: MsgpackTimestamp = rmp_serde::from_slice(&encoded).unwrap();
        assert_eq!(decoded, ts);
        assert_eq!(decoded.seconds, -62135596800);
        assert_eq!(decoded.nanoseconds, 0);
    }

    #[test]
    fn test_msgpack_timestamp_normal_roundtrip() {
        let ts = MsgpackTimestamp {
            seconds: 1700000000,
            nanoseconds: 123456789,
        };
        let encoded = rmp_serde::to_vec_named(&ts).unwrap();
        let decoded: MsgpackTimestamp = rmp_serde::from_slice(&encoded).unwrap();
        assert_eq!(decoded, ts);
    }

    #[test]
    fn test_vault_data_roundtrip() {
        let key = [0x42u8; KEY_LEN];
        let mut data = VaultData::default();
        data.users.push(UserData {
            user_id: "user-1".to_string(),
            username: "Test User".to_string(),
            primary_email: "test@proton.me".to_string(),
            gluon_key: vec![0u8; 32],
            gluon_ids: HashMap::new(),
            bridge_pass: b"bridgepass12345a".to_vec(),
            address_mode: 0,
            auth_uid: "uid-123".to_string(),
            auth_ref: "refresh-456".to_string(),
            key_pass: b"rawkeypass".to_vec(),
            sync_status: SyncStatus::default(),
            event_id: String::new(),
            last_event_ts: None,
            sync_state: None,
            uid_validity: HashMap::new(),
            should_resync: false,
        });

        let encoded = marshal_vault(&data, &key).unwrap();
        let decoded = unmarshal_vault(&encoded, &key).unwrap();

        assert_eq!(decoded.users.len(), 1);
        assert_eq!(decoded.users[0].primary_email, "test@proton.me");
        assert_eq!(decoded.users[0].auth_uid, "uid-123");
        assert_eq!(decoded.users[0].auth_ref, "refresh-456");
        assert_eq!(decoded.users[0].bridge_pass, b"bridgepass12345a");
        assert_eq!(decoded.users[0].key_pass, b"rawkeypass");
        assert_eq!(decoded.settings.imap_port, 1143);
        assert_eq!(
            decoded.settings.last_heartbeat_sent,
            MsgpackTimestamp::zero()
        );
    }

    #[test]
    fn test_save_load_session() {
        let tmp = tempfile::tempdir().unwrap();
        let session = Session {
            uid: "uid-123".to_string(),
            access_token: "access-456".to_string(),
            refresh_token: "refresh-789".to_string(),
            email: "test@proton.me".to_string(),
            display_name: "Test".to_string(),
            key_passphrase: Some("cGFzcw==".to_string()),
            bridge_password: Some("bridgepass12345a".to_string()),
        };

        save_session(&session, tmp.path()).unwrap();
        let loaded = load_session(tmp.path()).unwrap();

        assert_eq!(loaded.uid, session.uid);
        // access_token is NOT stored in Go format -- it will be empty on load
        assert_eq!(loaded.access_token, "");
        assert_eq!(loaded.refresh_token, session.refresh_token);
        assert_eq!(loaded.email, session.email);
        assert_eq!(loaded.display_name, session.display_name);
        assert_eq!(loaded.key_passphrase, session.key_passphrase);
        assert_eq!(loaded.bridge_password, session.bridge_password);
    }

    #[test]
    fn test_list_sessions_and_load_by_email() {
        let tmp = tempfile::tempdir().unwrap();
        let session_a = Session {
            uid: "uid-a".to_string(),
            access_token: "access-a".to_string(),
            refresh_token: "refresh-a".to_string(),
            email: "alice@proton.me".to_string(),
            display_name: "Alice".to_string(),
            key_passphrase: None,
            bridge_password: Some("bridge-a".to_string()),
        };
        let session_b = Session {
            uid: "uid-b".to_string(),
            access_token: "access-b".to_string(),
            refresh_token: "refresh-b".to_string(),
            email: "bob@proton.me".to_string(),
            display_name: "Bob".to_string(),
            key_passphrase: None,
            bridge_password: Some("bridge-b".to_string()),
        };

        save_session(&session_a, tmp.path()).unwrap();
        save_session(&session_b, tmp.path()).unwrap();

        let sessions = list_sessions(tmp.path()).unwrap();
        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().any(|s| s.email == "alice@proton.me"));
        assert!(sessions.iter().any(|s| s.email == "bob@proton.me"));

        let loaded_b = load_session_by_email(tmp.path(), "BOB@PROTON.ME").unwrap();
        assert_eq!(loaded_b.uid, "uid-b");
        assert_eq!(loaded_b.email, "bob@proton.me");
    }

    #[test]
    fn test_remove_session_by_email_keeps_other_accounts() {
        let tmp = tempfile::tempdir().unwrap();
        let session_a = Session {
            uid: "uid-a".to_string(),
            access_token: String::new(),
            refresh_token: "refresh-a".to_string(),
            email: "alice@proton.me".to_string(),
            display_name: "Alice".to_string(),
            key_passphrase: None,
            bridge_password: Some("bridge-a".to_string()),
        };
        let session_b = Session {
            uid: "uid-b".to_string(),
            access_token: String::new(),
            refresh_token: "refresh-b".to_string(),
            email: "bob@proton.me".to_string(),
            display_name: "Bob".to_string(),
            key_passphrase: None,
            bridge_password: Some("bridge-b".to_string()),
        };
        save_session(&session_a, tmp.path()).unwrap();
        save_session(&session_b, tmp.path()).unwrap();

        remove_session_by_email(tmp.path(), "alice@proton.me").unwrap();
        let sessions = list_sessions(tmp.path()).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].email, "bob@proton.me");
        assert!(load_session_by_email(tmp.path(), "alice@proton.me").is_err());
        assert!(session_exists(tmp.path()));
    }

    #[test]
    fn test_default_email_roundtrip_and_load_session() {
        let tmp = tempfile::tempdir().unwrap();
        let session_a = Session {
            uid: "uid-a".to_string(),
            access_token: String::new(),
            refresh_token: "refresh-a".to_string(),
            email: "alice@proton.me".to_string(),
            display_name: "Alice".to_string(),
            key_passphrase: None,
            bridge_password: Some("bridge-a".to_string()),
        };
        let session_b = Session {
            uid: "uid-b".to_string(),
            access_token: String::new(),
            refresh_token: "refresh-b".to_string(),
            email: "bob@proton.me".to_string(),
            display_name: "Bob".to_string(),
            key_passphrase: None,
            bridge_password: Some("bridge-b".to_string()),
        };
        save_session(&session_a, tmp.path()).unwrap();
        save_session(&session_b, tmp.path()).unwrap();

        set_default_email(tmp.path(), "bob@proton.me").unwrap();
        assert_eq!(
            get_default_email(tmp.path()).unwrap(),
            Some("bob@proton.me".to_string())
        );

        let loaded = load_session(tmp.path()).unwrap();
        assert_eq!(loaded.email, "bob@proton.me");
    }

    #[test]
    fn test_event_checkpoint_roundtrip_by_account_id() {
        let tmp = tempfile::tempdir().unwrap();
        let session = Session {
            uid: "uid-checkpoint".to_string(),
            access_token: String::new(),
            refresh_token: "refresh-checkpoint".to_string(),
            email: "checkpoint@proton.me".to_string(),
            display_name: "Checkpoint".to_string(),
            key_passphrase: None,
            bridge_password: Some("bridge".to_string()),
        };
        save_session(&session, tmp.path()).unwrap();

        let checkpoint = StoredEventCheckpoint {
            last_event_id: "event-123".to_string(),
            last_event_ts: Some(123),
            sync_state: Some("ok".to_string()),
        };
        save_event_checkpoint_by_account_id(tmp.path(), &session.uid, &checkpoint).unwrap();

        let loaded = load_event_checkpoint_by_account_id(tmp.path(), &session.uid)
            .unwrap()
            .unwrap();
        assert_eq!(loaded, checkpoint);
    }

    #[test]
    fn test_event_checkpoint_missing_account_returns_error() {
        let tmp = tempfile::tempdir().unwrap();
        let session = Session {
            uid: "uid-a".to_string(),
            access_token: String::new(),
            refresh_token: "refresh-a".to_string(),
            email: "a@proton.me".to_string(),
            display_name: "A".to_string(),
            key_passphrase: None,
            bridge_password: None,
        };
        save_session(&session, tmp.path()).unwrap();

        let checkpoint = StoredEventCheckpoint {
            last_event_id: "event-1".to_string(),
            last_event_ts: None,
            sync_state: None,
        };
        let err = save_event_checkpoint_by_account_id(tmp.path(), "uid-missing", &checkpoint)
            .unwrap_err();
        assert!(matches!(err, VaultError::AccountNotFound(_)));
    }

    #[test]
    fn test_load_session_backward_compatible_without_default_file() {
        let tmp = tempfile::tempdir().unwrap();
        let session = Session {
            uid: "uid-legacy".to_string(),
            access_token: String::new(),
            refresh_token: "refresh-legacy".to_string(),
            email: "legacy@proton.me".to_string(),
            display_name: "Legacy".to_string(),
            key_passphrase: None,
            bridge_password: None,
        };
        save_session(&session, tmp.path()).unwrap();
        std::fs::remove_file(tmp.path().join(DEFAULT_EMAIL_FILE)).unwrap();

        let loaded = load_session(tmp.path()).unwrap();
        assert_eq!(loaded.email, "legacy@proton.me");
    }

    #[test]
    fn test_session_userdata_conversion() {
        let session = Session {
            uid: "uid-abc".to_string(),
            access_token: "token-ignored".to_string(),
            refresh_token: "refresh-xyz".to_string(),
            email: "user@proton.me".to_string(),
            display_name: "User Name".to_string(),
            key_passphrase: Some(BASE64.encode(b"raw-passphrase")),
            bridge_password: Some("mybridge123".to_string()),
        };

        let ud = session_to_userdata(&session);
        assert_eq!(ud.auth_uid, "uid-abc");
        assert_eq!(ud.auth_ref, "refresh-xyz");
        assert_eq!(ud.primary_email, "user@proton.me");
        assert_eq!(ud.username, "User Name");
        assert_eq!(ud.key_pass, b"raw-passphrase");
        assert_eq!(ud.bridge_pass, b"mybridge123");

        let back = userdata_to_session(&ud);
        assert_eq!(back.uid, "uid-abc");
        assert_eq!(back.access_token, ""); // not stored
        assert_eq!(back.refresh_token, "refresh-xyz");
        assert_eq!(back.email, "user@proton.me");
        assert_eq!(back.display_name, "User Name");
        assert_eq!(
            back.key_passphrase.as_deref(),
            Some(BASE64.encode(b"raw-passphrase").as_str())
        );
        assert_eq!(back.bridge_password.as_deref(), Some("mybridge123"));
    }

    #[test]
    fn test_not_logged_in() {
        let tmp = tempfile::tempdir().unwrap();
        let result = load_session(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_session() {
        let tmp = tempfile::tempdir().unwrap();
        let session = Session {
            uid: "uid".to_string(),
            access_token: "tok".to_string(),
            refresh_token: "ref".to_string(),
            email: "a@b.c".to_string(),
            display_name: "T".to_string(),
            key_passphrase: None,
            bridge_password: None,
        };
        save_session(&session, tmp.path()).unwrap();
        assert!(session_exists(tmp.path()));
        remove_session(tmp.path()).unwrap();
        assert!(!session_exists(tmp.path()));
    }

    #[test]
    fn test_msgpack_field_names_match_go() {
        // Verify that our struct serialization uses PascalCase field names
        // matching the Go bridge's vmihailenco/msgpack default encoding.
        let data = VaultFile {
            version: 2,
            data: vec![1, 2, 3],
        };
        let encoded = rmp_serde::to_vec_named(&data).unwrap();
        // The encoded bytes should contain "Version" and "Data" as string keys
        let as_str = String::from_utf8_lossy(&encoded);
        assert!(as_str.contains("Version"));
        assert!(as_str.contains("Data"));
    }

    #[test]
    fn test_vault_data_field_names() {
        let data = VaultData::default();
        let encoded = rmp_serde::to_vec_named(&data).unwrap();
        let as_str = String::from_utf8_lossy(&encoded);
        assert!(as_str.contains("Settings"));
        assert!(as_str.contains("Users"));
        assert!(as_str.contains("Cookies"));
        assert!(as_str.contains("Certs"));
        assert!(as_str.contains("Migrated"));
        assert!(as_str.contains("FeatureFlagStickyKey"));
    }

    #[test]
    fn test_userdata_field_names() {
        let ud = UserData {
            user_id: String::new(),
            username: String::new(),
            primary_email: String::new(),
            gluon_key: vec![],
            gluon_ids: HashMap::new(),
            bridge_pass: vec![],
            address_mode: 0,
            auth_uid: String::new(),
            auth_ref: String::new(),
            key_pass: vec![],
            sync_status: SyncStatus::default(),
            event_id: String::new(),
            last_event_ts: None,
            sync_state: None,
            uid_validity: HashMap::new(),
            should_resync: false,
        };
        let encoded = rmp_serde::to_vec_named(&ud).unwrap();
        let as_str = String::from_utf8_lossy(&encoded);
        assert!(as_str.contains("UserID"));
        assert!(as_str.contains("Username"));
        assert!(as_str.contains("PrimaryEmail"));
        assert!(as_str.contains("GluonIDs"));
        assert!(as_str.contains("BridgePass"));
        assert!(as_str.contains("AuthUID"));
        assert!(as_str.contains("AuthRef"));
        assert!(as_str.contains("KeyPass"));
        assert!(as_str.contains("EventID"));
        assert!(as_str.contains("LastEventTS"));
        assert!(as_str.contains("SyncState"));
        assert!(as_str.contains("UIDValidity"));
        assert!(as_str.contains("ShouldResync"));
    }
}
