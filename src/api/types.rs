use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

// System label constants
pub const INBOX_LABEL: &str = "0";
pub const ALL_DRAFTS_LABEL: &str = "1";
pub const ALL_SENT_LABEL: &str = "2";
pub const TRASH_LABEL: &str = "3";
pub const SPAM_LABEL: &str = "4";
pub const ALL_MAIL_LABEL: &str = "5";
pub const ARCHIVE_LABEL: &str = "6";
pub const SENT_LABEL: &str = "7";
pub const DRAFTS_LABEL: &str = "8";
pub const STARRED_LABEL: &str = "10";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ApiMode {
    #[default]
    Bridge,
    Webmail,
}

impl ApiMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::Webmail => "webmail",
        }
    }

    pub fn from_str_name(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "bridge" => Some(Self::Bridge),
            "webmail" => Some(Self::Webmail),
            _ => None,
        }
    }

    pub fn base_url(self) -> &'static str {
        match self {
            Self::Bridge => "https://mail-api.proton.me",
            Self::Webmail => "https://mail.proton.me/api",
        }
    }

    pub fn alternate(self) -> Self {
        match self {
            Self::Bridge => Self::Webmail,
            Self::Webmail => Self::Bridge,
        }
    }
}

/// API response from POST /auth/v4/info
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthInfoResponse {
    pub version: i32,
    pub modulus: String,
    pub server_ephemeral: String,
    pub salt: String,
    #[serde(rename = "SRPSession")]
    pub srp_session: String,
    #[serde(rename = "2FA", default)]
    pub two_factor: Option<TwoFactorInfo>,
}

/// API response from POST /auth/v4
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthResponse {
    #[serde(rename = "UserID", default)]
    pub user_id: Option<String>,
    #[serde(rename = "UID")]
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub server_proof: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub password_mode: i32,
    #[serde(rename = "2FA")]
    pub two_factor: TwoFactorInfo,
}

impl AuthResponse {
    pub fn requires_two_passwords(&self) -> bool {
        self.password_mode == 2
    }
}

/// Human verification metadata returned by Proton in error `Code: 9001`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct HumanVerificationDetails {
    #[serde(default)]
    pub human_verification_methods: Vec<String>,
    #[serde(default)]
    pub human_verification_token: String,
}

impl HumanVerificationDetails {
    pub fn normalized_methods(&self) -> Vec<String> {
        let mut normalized = Vec::new();
        let mut seen = HashSet::new();
        for method in &self.human_verification_methods {
            let canonical = method.trim().to_ascii_lowercase();
            if canonical.is_empty() {
                continue;
            }
            if seen.insert(canonical.clone()) {
                normalized.push(canonical);
            }
        }
        if normalized.is_empty() {
            normalized.push("captcha".to_string());
        }
        normalized
    }

    pub fn methods_header_value(&self) -> String {
        self.normalized_methods().join(",")
    }

    pub fn is_usable(&self) -> bool {
        !self.human_verification_token.trim().is_empty()
    }

    pub fn challenge_url(&self) -> String {
        format!(
            "https://verify.proton.me/?methods={}&token={}",
            self.methods_header_value(),
            self.human_verification_token
        )
    }
}

/// API response from POST /auth/v4/refresh
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RefreshResponse {
    #[serde(rename = "UID", default)]
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub server_proof: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(rename = "2FA", default)]
    pub two_factor: Option<TwoFactorInfo>,
    #[serde(default)]
    pub password_mode: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TwoFactorInfo {
    pub enabled: i32,
    #[serde(rename = "FIDO2", default)]
    pub fido2: Option<Fido2Info>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Fido2Info {
    pub authentication_options: Value,
    #[serde(default)]
    pub registered_keys: Vec<RegisteredKey>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RegisteredKey {
    #[serde(default)]
    pub attestation_format: String,
    #[serde(rename = "CredentialID", default)]
    pub credential_id: Vec<i32>,
    #[serde(default)]
    pub name: String,
}

impl TwoFactorInfo {
    pub fn requires_second_factor(&self) -> bool {
        self.enabled != 0
    }

    pub fn totp_required(&self) -> bool {
        self.enabled & TWO_FACTOR_STATUS_HAS_TOTP != 0
    }

    pub fn fido_supported(&self) -> bool {
        self.enabled & TWO_FACTOR_STATUS_HAS_FIDO2 != 0
    }

    pub fn fido_authentication_options(&self) -> Option<Value> {
        self.fido2
            .as_ref()
            .map(|f| f.authentication_options.clone())
    }
}

const TWO_FACTOR_STATUS_HAS_TOTP: i32 = 1;
const TWO_FACTOR_STATUS_HAS_FIDO2: i32 = 2;

/// API response from POST /auth/v4/2fa
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TwoFactorResponse {
    pub scopes: Vec<String>,
}

/// API response from GET /core/v4/users
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserResponse {
    pub user: User,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct User {
    #[serde(rename = "ID")]
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub email: String,
    pub keys: Vec<UserKey>,
    #[serde(default)]
    pub used_space: i64,
    #[serde(default)]
    pub max_space: i64,
    #[serde(default)]
    pub max_upload: i64,
    #[serde(default)]
    pub credit: i64,
    #[serde(default)]
    pub currency: String,
    #[serde(default)]
    pub product_used_space: ProductUsedSpace,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserKey {
    #[serde(rename = "ID")]
    pub id: String,
    pub private_key: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub primary: Option<i32>,
    #[serde(default)]
    pub flags: Option<i32>,
    pub active: i32,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ProductUsedSpace {
    #[serde(default)]
    pub calendar: i64,
    #[serde(default)]
    pub contact: i64,
    #[serde(default)]
    pub drive: i64,
    #[serde(default)]
    pub mail: i64,
    #[serde(default)]
    pub pass: i64,
}

/// API response from GET /core/v4/addresses
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AddressesResponse {
    pub addresses: Vec<Address>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Address {
    #[serde(rename = "ID")]
    pub id: String,
    pub email: String,
    pub status: i32,
    pub receive: i32,
    pub send: i32,
    #[serde(rename = "Type")]
    pub address_type: i32,
    #[serde(default)]
    pub order: i32,
    pub display_name: String,
    pub keys: Vec<AddressKey>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AddressKey {
    #[serde(rename = "ID")]
    pub id: String,
    pub private_key: String,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub primary: Option<i32>,
    #[serde(default)]
    pub flags: Option<i32>,
    pub active: i32,
}

/// API response from GET /core/v4/keys/salts
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SaltsResponse {
    pub key_salts: Vec<KeySalt>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct KeySalt {
    #[serde(rename = "ID")]
    pub id: String,
    pub key_salt: Option<String>,
}

/// Persisted session data for the bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub email: String,
    pub display_name: String,
    #[serde(default)]
    pub api_mode: ApiMode,
    /// Base64-encoded derived key passphrase (31 bytes from mailbox_password).
    #[serde(default)]
    pub key_passphrase: Option<String>,
    /// Bridge password for IMAP/SMTP authentication.
    #[serde(default)]
    pub bridge_password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EmailAddress {
    pub name: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MessageMetadata {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "AddressID")]
    pub address_id: String,
    #[serde(rename = "LabelIDs")]
    pub label_ids: Vec<String>,
    #[serde(rename = "ExternalID", default)]
    pub external_id: Option<String>,
    pub subject: String,
    pub sender: EmailAddress,
    pub to_list: Vec<EmailAddress>,
    #[serde(rename = "CCList")]
    pub cc_list: Vec<EmailAddress>,
    #[serde(rename = "BCCList")]
    pub bcc_list: Vec<EmailAddress>,
    #[serde(default)]
    pub reply_tos: Vec<EmailAddress>,
    #[serde(default)]
    pub flags: i64,
    pub time: i64,
    pub size: i64,
    pub unread: i32,
    #[serde(default)]
    pub is_replied: i32,
    #[serde(default)]
    pub is_replied_all: i32,
    #[serde(default)]
    pub is_forwarded: i32,
    pub num_attachments: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MessageResponse {
    pub message: Message,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MessagesMetadataResponse {
    pub messages: Vec<MessageMetadata>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Message {
    #[serde(flatten)]
    pub metadata: MessageMetadata,
    pub header: String,
    #[serde(default)]
    pub parsed_headers: Option<Value>,
    pub body: String,
    #[serde(rename = "MIMEType")]
    pub mime_type: String,
    pub attachments: Vec<Attachment>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Attachment {
    #[serde(rename = "ID")]
    pub id: String,
    pub name: String,
    pub size: i64,
    #[serde(rename = "MIMEType")]
    pub mime_type: String,
    #[serde(default)]
    pub disposition: Option<String>,
    #[serde(default)]
    pub headers: Option<Value>,
    pub key_packets: String,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MessageFilter {
    #[serde(rename = "ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "AddressID", skip_serializing_if = "Option::is_none")]
    pub address_id: Option<String>,
    #[serde(rename = "ExternalID", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(rename = "LabelID", skip_serializing_if = "Option::is_none")]
    pub label_id: Option<String>,
    #[serde(rename = "EndID", skip_serializing_if = "Option::is_none")]
    pub end_id: Option<String>,
    pub desc: i32,
}

// Encryption scheme constants (bitmask)
pub const INTERNAL_SCHEME: i32 = 1;
pub const ENCRYPTED_OUTSIDE_SCHEME: i32 = 2;
pub const CLEAR_SCHEME: i32 = 4;
pub const PGP_INLINE_SCHEME: i32 = 8;
pub const PGP_MIME_SCHEME: i32 = 16;
pub const CLEAR_MIME_SCHEME: i32 = 32;

// Signature type constants
pub const NO_SIGNATURE: i32 = 0;
pub const DETACHED_SIGNATURE: i32 = 1;
pub const ATTACHED_SIGNATURE: i32 = 2;

// Message flag constants (bitmask subset used by mailbox projection).
pub const MESSAGE_FLAG_REPLIED: i64 = 1 << 5;
pub const MESSAGE_FLAG_REPLIED_ALL: i64 = 1 << 6;
pub const MESSAGE_FLAG_FORWARDED: i64 = 1 << 7;

// Recipient type constants
pub const RECIPIENT_INTERNAL: i32 = 1;
pub const RECIPIENT_EXTERNAL: i32 = 2;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EventsResponse {
    #[serde(rename = "EventID", default)]
    pub event_id: String,
    #[serde(default)]
    pub more: i32,
    #[serde(default)]
    pub refresh: i32,
    #[serde(
        default,
        alias = "Event",
        deserialize_with = "deserialize_events_payload"
    )]
    pub events: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct TypedEventPayload {
    #[serde(default)]
    pub user: Option<Value>,
    #[serde(default)]
    pub user_settings: Option<Value>,
    #[serde(default)]
    pub mail_settings: Option<Value>,
    #[serde(default, deserialize_with = "deserialize_optional_typed_event_items")]
    pub messages: Option<Vec<TypedEventItem>>,
    #[serde(default)]
    pub message: Option<TypedEventItem>,
    #[serde(default, deserialize_with = "deserialize_optional_typed_event_items")]
    pub labels: Option<Vec<TypedEventItem>>,
    #[serde(default)]
    pub label: Option<TypedEventItem>,
    #[serde(default, deserialize_with = "deserialize_optional_typed_event_items")]
    pub addresses: Option<Vec<TypedEventItem>>,
    #[serde(default)]
    pub address: Option<TypedEventItem>,
    #[serde(default, deserialize_with = "deserialize_optional_typed_event_items")]
    pub calendars: Option<Vec<TypedEventItem>>,
    #[serde(default, deserialize_with = "deserialize_optional_typed_event_items")]
    pub calendar_members: Option<Vec<TypedEventItem>>,
    #[serde(default, deserialize_with = "deserialize_optional_typed_event_items")]
    pub contacts: Option<Vec<TypedEventItem>>,
    #[serde(default, deserialize_with = "deserialize_optional_typed_event_items")]
    pub contact_emails: Option<Vec<TypedEventItem>>,
    #[serde(default)]
    pub notifications: Option<Value>,
    #[serde(default)]
    pub used_space: Option<i64>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl TypedEventPayload {
    pub fn has_recognized_event_fields(&self) -> bool {
        self.messages.is_some()
            || self.message.is_some()
            || self.labels.is_some()
            || self.label.is_some()
            || self.addresses.is_some()
            || self.address.is_some()
            || self.calendars.is_some()
            || self.calendar_members.is_some()
            || self.contacts.is_some()
            || self.contact_emails.is_some()
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct TypedEventItem {
    #[serde(rename = "ID", default)]
    pub id: String,
    #[serde(default)]
    pub action: Option<Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl TypedEventItem {
    pub fn action_code(&self) -> Option<i64> {
        parse_action_code(self.action.as_ref())
    }

    pub fn is_create(&self) -> bool {
        self.action_code() == Some(1)
    }

    pub fn is_update(&self) -> bool {
        matches!(self.action_code(), Some(2 | 3))
    }

    pub fn is_delete(&self) -> bool {
        self.action_code() == Some(0)
    }
}

fn deserialize_events_payload<'de, D>(deserializer: D) -> std::result::Result<Vec<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    let events = match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(events)) => events,
        Some(single_event) => vec![single_event],
    };
    Ok(events)
}

fn deserialize_optional_typed_event_items<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Vec<TypedEventItem>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };

    let items = match value {
        Value::Array(entries) => entries
            .into_iter()
            .filter_map(|entry| typed_event_item_from_value(entry, None))
            .collect(),
        Value::Object(entries) => entries
            .into_iter()
            .filter_map(|(fallback_id, entry)| {
                typed_event_item_from_value(entry, Some(fallback_id))
            })
            .collect(),
        single => typed_event_item_from_value(single, None)
            .into_iter()
            .collect(),
    };

    Ok(Some(items))
}

fn typed_event_item_from_value(
    value: Value,
    fallback_id: Option<String>,
) -> Option<TypedEventItem> {
    match value {
        Value::Object(fields) => {
            let id = fields
                .get("ID")
                .and_then(|value| value.as_str())
                .map(str::to_string)
                .or_else(|| infer_nested_event_id(&fields))
                .or(fallback_id)?;
            let action = fields.get("Action").cloned();
            Some(TypedEventItem {
                id,
                action,
                extra: fields.into_iter().collect(),
            })
        }
        Value::Null => fallback_id.map(|id| TypedEventItem {
            id,
            action: Some(Value::from(0)),
            extra: HashMap::new(),
        }),
        Value::String(value) => {
            if let Some(id) = fallback_id {
                Some(TypedEventItem {
                    id,
                    action: Some(Value::String(value)),
                    extra: HashMap::new(),
                })
            } else {
                Some(TypedEventItem {
                    id: value,
                    action: None,
                    extra: HashMap::new(),
                })
            }
        }
        primitive => fallback_id.map(|id| TypedEventItem {
            id,
            action: Some(primitive),
            extra: HashMap::new(),
        }),
    }
}

fn parse_action_code(action: Option<&Value>) -> Option<i64> {
    let action = action?;
    match action {
        Value::Number(value) => value.as_i64(),
        Value::String(value) => value.parse::<i64>().ok(),
        _ => None,
    }
}

fn infer_nested_event_id(fields: &serde_json::Map<String, Value>) -> Option<String> {
    for value in fields.values() {
        if let Some(id) = extract_nested_id(value) {
            return Some(id);
        }
    }
    None
}

fn extract_nested_id(value: &Value) -> Option<String> {
    match value {
        Value::Object(obj) => {
            if let Some(id) = obj.get("ID").and_then(|v| v.as_str()) {
                return Some(id.to_string());
            }
            for nested in obj.values() {
                if let Some(id) = extract_nested_id(nested) {
                    return Some(id);
                }
            }
            None
        }
        Value::Array(values) => values.iter().find_map(extract_nested_id),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct DraftTemplate {
    pub subject: String,
    pub sender: EmailAddress,
    pub to_list: Vec<EmailAddress>,
    #[serde(rename = "CCList")]
    pub cc_list: Vec<EmailAddress>,
    #[serde(rename = "BCCList")]
    pub bcc_list: Vec<EmailAddress>,
    pub body: String,
    #[serde(rename = "MIMEType")]
    pub mime_type: String,
    pub unread: i32,
    #[serde(rename = "ExternalID", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateDraftReq {
    pub message: DraftTemplate,
    #[serde(
        rename = "AttachmentKeyPackets",
        skip_serializing_if = "Option::is_none"
    )]
    pub attachment_key_packets: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub action: i32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SendDraftReq {
    pub packages: Vec<MessagePackage>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MessagePackage {
    pub addresses: std::collections::HashMap<String, MessageRecipient>,
    #[serde(rename = "MIMEType")]
    pub mime_type: String,
    #[serde(rename = "Type")]
    pub package_type: i32,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_key: Option<SessionKeyInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment_keys: Option<std::collections::HashMap<String, SessionKeyInfo>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MessageRecipient {
    #[serde(rename = "Type")]
    pub recipient_type: i32,
    pub signature: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_key_packet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment_key_packets: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SessionKeyInfo {
    pub key: String,
    pub algorithm: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PublicKeysResponse {
    pub keys: Vec<PublicKeyInfo>,
    pub recipient_type: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PublicKeyInfo {
    pub flags: i32,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SendDraftResponse {
    pub sent: Message,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AttachmentResponse {
    pub attachment: Attachment,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_info_response_deserialize() {
        let json = serde_json::json!({
            "Code": 1000,
            "Version": 4,
            "Modulus": "-----BEGIN PGP SIGNED MESSAGE-----\ntest\n-----END PGP SIGNATURE-----",
            "ServerEphemeral": "AAAA",
            "Salt": "BBBB",
            "SRPSession": "session-id-123",
            "2FA": {
                "Enabled": 1,
                "TOTP": 1
            }
        });

        let info: AuthInfoResponse = serde_json::from_value(json).unwrap();
        assert_eq!(info.version, 4);
        assert_eq!(info.srp_session, "session-id-123");
        assert_eq!(info.salt, "BBBB");
        assert!(info.two_factor.is_some());
    }

    #[test]
    fn test_auth_response_deserialize() {
        let json = serde_json::json!({
            "Code": 1000,
            "UID": "uid-abc",
            "UserID": "user-abc",
            "AccessToken": "token-xyz",
            "RefreshToken": "refresh-123",
            "TokenType": "Bearer",
            "ServerProof": "proof-b64",
            "Scope": "mail self",
            "2FA": {
                "Enabled": 0,
                "TOTP": 0,
                "FIDO2": null
            },
            "Scopes": ["mail", "calendar"]
        });

        let auth: AuthResponse = serde_json::from_value(json).unwrap();
        assert_eq!(auth.uid, "uid-abc");
        assert_eq!(auth.user_id.as_deref(), Some("user-abc"));
        assert_eq!(auth.access_token, "token-xyz");
        assert_eq!(auth.refresh_token, "refresh-123");
        assert_eq!(auth.scope.as_deref(), Some("mail self"));
        assert!(!auth.two_factor.totp_required());
        assert_eq!(auth.password_mode, 0);
        assert!(!auth.requires_two_passwords());
    }

    #[test]
    fn test_auth_response_two_password_mode() {
        let json = serde_json::json!({
            "Code": 1000,
            "UID": "uid-abc",
            "AccessToken": "token-xyz",
            "RefreshToken": "refresh-123",
            "TokenType": "Bearer",
            "ServerProof": "proof-b64",
            "PasswordMode": 2,
            "2FA": {
                "Enabled": 0,
                "TOTP": 0,
                "FIDO2": null
            },
            "Scopes": ["mail", "calendar"]
        });

        let auth: AuthResponse = serde_json::from_value(json).unwrap();
        assert_eq!(auth.password_mode, 2);
        assert!(auth.requires_two_passwords());
    }

    #[test]
    fn test_refresh_response_deserialize_without_server_proof() {
        let json = serde_json::json!({
            "Code": 1000,
            "UID": "uid-abc",
            "AccessToken": "token-xyz",
            "RefreshToken": "refresh-123",
            "TokenType": "Bearer"
        });

        let auth: RefreshResponse = serde_json::from_value(json).unwrap();
        assert_eq!(auth.uid, "uid-abc");
        assert_eq!(auth.access_token, "token-xyz");
        assert_eq!(auth.refresh_token, "refresh-123");
        assert!(auth.server_proof.is_none());
        assert!(auth.scope.is_none());
        assert!(auth.two_factor.is_none());
        assert!(auth.password_mode.is_none());
    }

    #[test]
    fn test_refresh_response_deserialize_with_extended_fields() {
        let json = serde_json::json!({
            "Code": 1000,
            "UID": "uid-abc",
            "AccessToken": "token-xyz",
            "RefreshToken": "refresh-123",
            "ServerProof": "proof-b64",
            "Scope": "mail self",
            "2FA": {
                "Enabled": 2,
                "TOTP": 0,
                "FIDO2": {
                    "AuthenticationOptions": {},
                    "RegisteredKeys": []
                }
            },
            "PasswordMode": 2
        });

        let auth: RefreshResponse = serde_json::from_value(json).unwrap();
        assert_eq!(auth.server_proof.as_deref(), Some("proof-b64"));
        assert_eq!(auth.scope.as_deref(), Some("mail self"));
        assert_eq!(auth.password_mode, Some(2));
        assert!(auth.two_factor.is_some());
    }

    #[test]
    fn test_two_factor_info_totp_required() {
        let info = TwoFactorInfo {
            enabled: 1,
            fido2: None,
        };
        assert!(info.totp_required());
        assert!(info.requires_second_factor());
        assert!(!info.fido_supported());

        let info = TwoFactorInfo {
            enabled: 0,
            fido2: None,
        };
        assert!(!info.totp_required());
        assert!(!info.requires_second_factor());

        let info = TwoFactorInfo {
            enabled: 2,
            fido2: None,
        };
        assert!(!info.totp_required());

        let info = TwoFactorInfo {
            enabled: 3,
            fido2: None,
        };
        assert!(info.totp_required());
    }

    #[test]
    fn test_two_factor_info_fido_supported() {
        let info = TwoFactorInfo {
            enabled: 2,
            fido2: Some(Fido2Info {
                authentication_options: serde_json::json!({
                    "publicKey": { "challenge": [1, 2, 3] }
                }),
                registered_keys: vec![],
            }),
        };
        assert!(info.requires_second_factor());
        assert!(info.fido_supported());
        assert!(info.fido_authentication_options().is_some());
    }

    #[test]
    fn test_fido2_registered_keys_deserialize() {
        let json = serde_json::json!({
            "AuthenticationOptions": {},
            "RegisteredKeys": [{
                "AttestationFormat": "packed",
                "CredentialID": [1, 2, 3],
                "Name": "Laptop key"
            }]
        });

        let info: Fido2Info = serde_json::from_value(json).unwrap();
        assert_eq!(info.registered_keys.len(), 1);
        assert_eq!(info.registered_keys[0].attestation_format, "packed");
        assert_eq!(info.registered_keys[0].credential_id, vec![1, 2, 3]);
        assert_eq!(info.registered_keys[0].name, "Laptop key");
    }

    #[test]
    fn test_two_factor_response_deserialize() {
        let json = serde_json::json!({
            "Code": 1000,
            "Scopes": ["mail", "self"]
        });

        let resp: TwoFactorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.scopes, vec!["mail", "self"]);
    }

    #[test]
    fn test_human_verification_details_deserialize_and_format_url() {
        let json = serde_json::json!({
            "HumanVerificationMethods": ["captcha", "ownership-email"],
            "HumanVerificationToken": "token-123"
        });
        let hv: HumanVerificationDetails = serde_json::from_value(json).unwrap();
        assert!(hv.is_usable());
        assert_eq!(
            hv.challenge_url(),
            "https://verify.proton.me/?methods=captcha,ownership-email&token=token-123"
        );
    }

    #[test]
    fn test_human_verification_details_fallbacks_to_captcha_method() {
        let json = serde_json::json!({
            "HumanVerificationMethods": ["", "   "],
            "HumanVerificationToken": "token-123"
        });
        let hv: HumanVerificationDetails = serde_json::from_value(json).unwrap();
        assert!(hv.is_usable());
        assert_eq!(hv.normalized_methods(), vec!["captcha".to_string()]);
        assert_eq!(hv.methods_header_value(), "captcha");
        assert_eq!(
            hv.challenge_url(),
            "https://verify.proton.me/?methods=captcha&token=token-123"
        );
    }

    #[test]
    fn test_human_verification_details_normalizes_methods() {
        let json = serde_json::json!({
            "HumanVerificationMethods": [" CAPTCHA ", "ownership-email", "captcha"],
            "HumanVerificationToken": "token-123"
        });
        let hv: HumanVerificationDetails = serde_json::from_value(json).unwrap();
        assert_eq!(
            hv.normalized_methods(),
            vec!["captcha".to_string(), "ownership-email".to_string()]
        );
        assert_eq!(hv.methods_header_value(), "captcha,ownership-email");
    }

    #[test]
    fn test_user_response_deserialize() {
        let json = serde_json::json!({
            "Code": 1000,
            "User": {
                "ID": "user-id-1",
                "Name": "testuser",
                "DisplayName": "Test User",
                "Email": "test@proton.me",
                "Keys": [{
                    "ID": "key-1",
                    "PrivateKey": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nfake\n-----END PGP PRIVATE KEY BLOCK-----",
                    "Token": "tok",
                    "Signature": "sig",
                    "Primary": 1,
                    "Flags": 3,
                    "Active": 1
                }]
            }
        });

        let resp: UserResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.user.id, "user-id-1");
        assert_eq!(resp.user.name, "testuser");
        assert_eq!(resp.user.email, "test@proton.me");
        assert_eq!(resp.user.keys.len(), 1);
        assert_eq!(resp.user.keys[0].active, 1);
        assert_eq!(resp.user.keys[0].token.as_deref(), Some("tok"));
        assert_eq!(resp.user.keys[0].signature.as_deref(), Some("sig"));
        assert_eq!(resp.user.keys[0].primary, Some(1));
        assert_eq!(resp.user.keys[0].flags, Some(3));
    }

    #[test]
    fn test_addresses_response_deserialize() {
        let json = serde_json::json!({
            "Code": 1000,
            "Addresses": [{
                "ID": "addr-1",
                "Email": "test@proton.me",
                "Status": 1,
                "Receive": 1,
                "Send": 1,
                "Type": 1,
                "Order": 2,
                "DisplayName": "Test User",
                "Keys": [{
                    "ID": "akey-1",
                    "PrivateKey": "armored-key-data",
                    "Token": null,
                    "Signature": null,
                    "Primary": 1,
                    "Flags": 2,
                    "Active": 1
                }]
            }]
        });

        let resp: AddressesResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.addresses.len(), 1);
        assert_eq!(resp.addresses[0].email, "test@proton.me");
        assert_eq!(resp.addresses[0].order, 2);
        assert_eq!(resp.addresses[0].keys.len(), 1);
        assert_eq!(resp.addresses[0].keys[0].primary, Some(1));
        assert_eq!(resp.addresses[0].keys[0].flags, Some(2));
    }

    #[test]
    fn test_salts_response_deserialize() {
        let json = serde_json::json!({
            "Code": 1000,
            "KeySalts": [
                { "ID": "key-1", "KeySalt": "base64salt" },
                { "ID": "key-2", "KeySalt": null }
            ]
        });

        let resp: SaltsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.key_salts.len(), 2);
        assert_eq!(resp.key_salts[0].key_salt.as_deref(), Some("base64salt"));
        assert!(resp.key_salts[1].key_salt.is_none());
    }

    #[test]
    fn test_session_round_trip() {
        let session = Session {
            uid: "uid-123".to_string(),
            access_token: "access-456".to_string(),
            refresh_token: "refresh-789".to_string(),
            email: "test@proton.me".to_string(),
            display_name: "Test User".to_string(),
            api_mode: ApiMode::Bridge,
            key_passphrase: Some("cGFzc3BocmFzZQ==".to_string()),
            bridge_password: Some("abcd1234efgh5678".to_string()),
        };

        let json = serde_json::to_string(&session).unwrap();
        let restored: Session = serde_json::from_str(&json).unwrap();

        assert_eq!(session.uid, restored.uid);
        assert_eq!(session.access_token, restored.access_token);
        assert_eq!(session.refresh_token, restored.refresh_token);
        assert_eq!(session.email, restored.email);
        assert_eq!(session.display_name, restored.display_name);
        assert_eq!(session.api_mode, restored.api_mode);
        assert_eq!(session.key_passphrase, restored.key_passphrase);
        assert_eq!(session.bridge_password, restored.bridge_password);
    }

    #[test]
    fn test_session_backward_compat_no_key_passphrase() {
        let json = serde_json::json!({
            "uid": "uid-1",
            "access_token": "tok",
            "refresh_token": "ref",
            "email": "test@proton.me",
            "display_name": "Test"
        });

        let session: Session = serde_json::from_value(json).unwrap();
        assert!(session.key_passphrase.is_none());
        assert!(session.bridge_password.is_none());
    }

    #[test]
    fn test_email_address_deserialize() {
        let json = serde_json::json!({
            "Name": "Alice",
            "Address": "alice@proton.me"
        });

        let addr: EmailAddress = serde_json::from_value(json).unwrap();
        assert_eq!(addr.name, "Alice");
        assert_eq!(addr.address, "alice@proton.me");
    }

    #[test]
    fn test_message_metadata_deserialize() {
        let json = serde_json::json!({
            "ID": "msg-1",
            "AddressID": "addr-1",
            "LabelIDs": ["0", "5"],
            "ExternalID": "ext-1",
            "Subject": "Test Subject",
            "Sender": { "Name": "Alice", "Address": "alice@proton.me" },
            "ToList": [{ "Name": "Bob", "Address": "bob@proton.me" }],
            "CCList": [],
            "BCCList": [],
            "ReplyTos": [{ "Name": "Reply", "Address": "reply@proton.me" }],
            "Flags": 96,
            "Time": 1700000000,
            "Size": 4096,
            "Unread": 1,
            "IsReplied": 1,
            "IsRepliedAll": 0,
            "IsForwarded": 1,
            "NumAttachments": 0
        });

        let meta: MessageMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(meta.id, "msg-1");
        assert_eq!(meta.address_id, "addr-1");
        assert_eq!(meta.label_ids, vec!["0", "5"]);
        assert_eq!(meta.external_id.as_deref(), Some("ext-1"));
        assert_eq!(meta.subject, "Test Subject");
        assert_eq!(meta.sender.address, "alice@proton.me");
        assert_eq!(meta.to_list.len(), 1);
        assert_eq!(meta.reply_tos.len(), 1);
        assert_eq!(meta.flags, 96);
        assert_eq!(meta.time, 1700000000);
        assert_eq!(meta.unread, 1);
        assert_eq!(meta.is_replied, 1);
        assert_eq!(meta.is_forwarded, 1);
    }

    #[test]
    fn test_message_deserialize() {
        let json = serde_json::json!({
            "ID": "msg-1",
            "AddressID": "addr-1",
            "LabelIDs": ["0"],
            "Subject": "Hello",
            "Sender": { "Name": "Alice", "Address": "alice@proton.me" },
            "ToList": [{ "Name": "Bob", "Address": "bob@proton.me" }],
            "CCList": [],
            "BCCList": [],
            "Time": 1700000000,
            "Size": 1024,
            "Unread": 0,
            "NumAttachments": 1,
            "Header": "From: alice@proton.me\r\nTo: bob@proton.me\r\n",
            "ParsedHeaders": {
                "From": "alice@proton.me",
                "To": ["bob@proton.me"]
            },
            "Body": "-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----",
            "MIMEType": "text/html",
            "Attachments": [{
                "ID": "att-1",
                "Name": "file.pdf",
                "Size": 2048,
                "MIMEType": "application/pdf",
                "Disposition": "attachment",
                "Headers": {"Content-ID": "cid-1"},
                "KeyPackets": "base64keypackets",
                "Signature": "sig-1"
            }]
        });

        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.metadata.id, "msg-1");
        assert_eq!(msg.metadata.subject, "Hello");
        assert_eq!(
            msg.body,
            "-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----"
        );
        assert!(msg.parsed_headers.is_some());
        assert_eq!(msg.mime_type, "text/html");
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].name, "file.pdf");
        assert_eq!(msg.attachments[0].key_packets, "base64keypackets");
        assert_eq!(
            msg.attachments[0].disposition.as_deref(),
            Some("attachment")
        );
        assert_eq!(msg.attachments[0].signature.as_deref(), Some("sig-1"));
    }

    #[test]
    fn test_attachment_deserialize() {
        let json = serde_json::json!({
            "ID": "att-1",
            "Name": "document.txt",
            "Size": 512,
            "MIMEType": "text/plain",
            "Disposition": "inline",
            "Headers": {"Content-ID": "cid-inline"},
            "KeyPackets": "AAAA",
            "Signature": "sig"
        });

        let att: Attachment = serde_json::from_value(json).unwrap();
        assert_eq!(att.id, "att-1");
        assert_eq!(att.name, "document.txt");
        assert_eq!(att.size, 512);
        assert_eq!(att.mime_type, "text/plain");
        assert_eq!(att.disposition.as_deref(), Some("inline"));
        assert_eq!(att.signature.as_deref(), Some("sig"));
        assert!(att.headers.is_some());
    }

    #[test]
    fn test_message_filter_serialize() {
        let filter = MessageFilter {
            id: Some(vec!["msg-1".to_string(), "msg-2".to_string()]),
            subject: Some("test".to_string()),
            address_id: Some("addr-1".to_string()),
            external_id: Some("ext-1".to_string()),
            label_id: Some("0".to_string()),
            end_id: None,
            desc: 1,
        };

        let json = serde_json::to_value(&filter).unwrap();
        assert_eq!(json["ID"], serde_json::json!(["msg-1", "msg-2"]));
        assert_eq!(json["Subject"], "test");
        assert_eq!(json["AddressID"], "addr-1");
        assert_eq!(json["ExternalID"], "ext-1");
        assert_eq!(json["LabelID"], "0");
        assert_eq!(json["Desc"], 1);
        assert!(json.get("EndID").is_none());
    }

    #[test]
    fn test_email_address_serialize() {
        let addr = EmailAddress {
            name: "Alice".to_string(),
            address: "alice@proton.me".to_string(),
        };
        let json = serde_json::to_value(&addr).unwrap();
        assert_eq!(json["Name"], "Alice");
        assert_eq!(json["Address"], "alice@proton.me");
    }

    #[test]
    fn test_draft_template_serialize() {
        let draft = DraftTemplate {
            subject: "Test".to_string(),
            sender: EmailAddress {
                name: "Alice".to_string(),
                address: "alice@proton.me".to_string(),
            },
            to_list: vec![EmailAddress {
                name: "Bob".to_string(),
                address: "bob@proton.me".to_string(),
            }],
            cc_list: vec![],
            bcc_list: vec![],
            body: "encrypted body".to_string(),
            mime_type: "text/plain".to_string(),
            unread: 0,
            external_id: Some("ext-draft".to_string()),
        };
        let json = serde_json::to_value(&draft).unwrap();
        assert_eq!(json["Subject"], "Test");
        assert_eq!(json["Sender"]["Name"], "Alice");
        assert_eq!(json["ToList"][0]["Address"], "bob@proton.me");
        assert_eq!(json["MIMEType"], "text/plain");
        assert_eq!(json["ExternalID"], "ext-draft");
    }

    #[test]
    fn test_create_draft_req_serialize() {
        let req = CreateDraftReq {
            message: DraftTemplate {
                subject: "Hello".to_string(),
                sender: EmailAddress {
                    name: "Me".to_string(),
                    address: "me@proton.me".to_string(),
                },
                to_list: vec![],
                cc_list: vec![],
                bcc_list: vec![],
                body: "body".to_string(),
                mime_type: "text/html".to_string(),
                unread: 0,
                external_id: None,
            },
            attachment_key_packets: Some(vec!["packet-a".to_string(), "packet-b".to_string()]),
            parent_id: None,
            action: 0,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["Message"]["Subject"], "Hello");
        assert_eq!(
            json["AttachmentKeyPackets"],
            serde_json::json!(["packet-a", "packet-b"])
        );
        assert_eq!(json["Action"], 0);
        assert!(json.get("ParentID").is_none());
    }

    #[test]
    fn test_message_package_serialize() {
        let mut addresses = std::collections::HashMap::new();
        addresses.insert(
            "bob@proton.me".to_string(),
            MessageRecipient {
                recipient_type: INTERNAL_SCHEME,
                signature: DETACHED_SIGNATURE,
                body_key_packet: Some("base64packet".to_string()),
                attachment_key_packets: None,
            },
        );

        let pkg = MessagePackage {
            addresses,
            mime_type: "text/plain".to_string(),
            package_type: INTERNAL_SCHEME,
            body: "base64body".to_string(),
            body_key: None,
            attachment_keys: None,
        };

        let json = serde_json::to_value(&pkg).unwrap();
        assert_eq!(json["MIMEType"], "text/plain");
        assert_eq!(json["Type"], 1);
        assert_eq!(json["Body"], "base64body");
        let bob = &json["Addresses"]["bob@proton.me"];
        assert_eq!(bob["Type"], 1);
        assert_eq!(bob["Signature"], 1);
        assert_eq!(bob["BodyKeyPacket"], "base64packet");
    }

    #[test]
    fn test_session_key_info_round_trip() {
        let key_info = SessionKeyInfo {
            key: "base64key".to_string(),
            algorithm: "aes256".to_string(),
        };
        let json = serde_json::to_string(&key_info).unwrap();
        let restored: SessionKeyInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.key, "base64key");
        assert_eq!(restored.algorithm, "aes256");
    }

    #[test]
    fn test_public_keys_response_deserialize() {
        let json = serde_json::json!({
            "Code": 1000,
            "Keys": [{
                "Flags": 3,
                "PublicKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----"
            }],
            "RecipientType": 1
        });
        let resp: PublicKeysResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.keys.len(), 1);
        assert_eq!(resp.keys[0].flags, 3);
        assert_eq!(resp.recipient_type, RECIPIENT_INTERNAL);
    }

    #[test]
    fn test_send_draft_response_deserialize() {
        let json = serde_json::json!({
            "Code": 1000,
            "Sent": {
                "ID": "sent-1",
                "AddressID": "addr-1",
                "LabelIDs": ["2"],
                "Subject": "Sent msg",
                "Sender": { "Name": "Alice", "Address": "alice@proton.me" },
                "ToList": [{ "Name": "Bob", "Address": "bob@proton.me" }],
                "CCList": [],
                "BCCList": [],
                "Time": 1700000000,
                "Size": 512,
                "Unread": 0,
                "NumAttachments": 0,
                "Header": "",
                "Body": "encrypted",
                "MIMEType": "text/plain",
                "Attachments": []
            }
        });
        let resp: SendDraftResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.sent.metadata.id, "sent-1");
        assert_eq!(resp.sent.metadata.subject, "Sent msg");
    }

    #[test]
    fn test_attachment_response_deserialize() {
        let json = serde_json::json!({
            "Code": 1000,
            "Attachment": {
                "ID": "att-1",
                "Name": "file.txt",
                "Size": 100,
                "MIMEType": "text/plain",
                "KeyPackets": "base64kp"
            }
        });
        let resp: AttachmentResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.attachment.id, "att-1");
        assert_eq!(resp.attachment.name, "file.txt");
    }

    #[test]
    fn test_send_draft_req_serialize() {
        let req = SendDraftReq {
            packages: vec![MessagePackage {
                addresses: std::collections::HashMap::new(),
                mime_type: "text/plain".to_string(),
                package_type: CLEAR_SCHEME,
                body: "body64".to_string(),
                body_key: Some(SessionKeyInfo {
                    key: "sk".to_string(),
                    algorithm: "aes256".to_string(),
                }),
                attachment_keys: None,
            }],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["Packages"][0]["Type"], 4);
        assert_eq!(json["Packages"][0]["BodyKey"]["Key"], "sk");
    }

    #[test]
    fn test_typed_event_payload_deserializes_map_and_array_shapes() {
        let payload = serde_json::json!({
            "Messages": {
                "msg-delete": null,
                "msg-update": {"Action": 2}
            },
            "Labels": [
                {"ID": "label-1", "Action": 3}
            ],
            "Addresses": ["addr-1"],
            "UsedSpace": 1234
        });

        let typed: TypedEventPayload = serde_json::from_value(payload).unwrap();
        assert!(typed.has_recognized_event_fields());
        assert_eq!(typed.messages.as_ref().map(|v| v.len()), Some(2));
        assert_eq!(typed.labels.as_ref().map(|v| v.len()), Some(1));
        assert_eq!(typed.addresses.as_ref().map(|v| v.len()), Some(1));
        assert_eq!(typed.used_space, Some(1234));
    }

    #[test]
    fn test_typed_event_payload_deserializes_contact_and_calendar_items_with_nested_ids() {
        let payload = serde_json::json!({
            "Contacts": [
                { "Action": 1, "Contact": { "ID": "contact-1" } },
                { "Action": 0, "Contact": { "ID": "contact-2" } }
            ],
            "ContactEmails": [
                { "Action": 2, "ContactEmail": { "ID": "contact-email-1" } }
            ],
            "Calendars": [
                { "Action": 2, "Calendar": { "ID": "calendar-1" } }
            ],
            "CalendarMembers": [
                { "Action": 0, "Member": { "ID": "member-1" } }
            ]
        });

        let typed: TypedEventPayload = serde_json::from_value(payload).unwrap();
        assert!(typed.has_recognized_event_fields());

        let contacts = typed.contacts.unwrap();
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].id, "contact-1");
        assert!(contacts[0].is_create());
        assert_eq!(contacts[1].id, "contact-2");
        assert!(contacts[1].is_delete());

        let contact_emails = typed.contact_emails.unwrap();
        assert_eq!(contact_emails[0].id, "contact-email-1");
        assert!(contact_emails[0].is_update());

        let calendars = typed.calendars.unwrap();
        assert_eq!(calendars[0].id, "calendar-1");
        assert!(calendars[0].is_update());

        let calendar_members = typed.calendar_members.unwrap();
        assert_eq!(calendar_members[0].id, "member-1");
        assert!(calendar_members[0].is_delete());
    }

    #[test]
    fn test_events_response_accepts_single_event_object_payload() {
        let response = serde_json::json!({
            "Code": 1000,
            "EventID": "event-1",
            "Event": {"Messages": [{"ID": "msg-1", "Action": 1}]}
        });

        let parsed: EventsResponse = serde_json::from_value(response).unwrap();
        assert_eq!(parsed.event_id, "event-1");
        assert_eq!(parsed.events.len(), 1);
    }
}
