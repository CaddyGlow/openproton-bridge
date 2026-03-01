use serde::{Deserialize, Serialize};
use serde_json::Value;

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
}

/// API response from POST /auth/v4
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AuthResponse {
    #[serde(rename = "UID")]
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub server_proof: String,
    #[serde(rename = "2FA")]
    pub two_factor: TwoFactorInfo,
    pub scopes: Vec<String>,
}

/// API response from POST /auth/v4/refresh
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RefreshResponse {
    #[serde(rename = "UID", default)]
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TwoFactorInfo {
    pub enabled: i32,
    #[serde(rename = "TOTP")]
    pub totp: i32,
    #[serde(rename = "FIDO2", default)]
    pub fido2: Option<Fido2Info>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Fido2Info {
    pub authentication_options: Value,
}

impl TwoFactorInfo {
    pub fn requires_second_factor(&self) -> bool {
        self.enabled != 0
    }

    pub fn totp_required(&self) -> bool {
        self.enabled != 0 && self.totp != 0
    }

    pub fn fido_supported(&self) -> bool {
        self.enabled == 2 || self.enabled == 3
    }

    pub fn fido_authentication_options(&self) -> Option<Value> {
        self.fido2
            .as_ref()
            .map(|f| f.authentication_options.clone())
    }
}

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
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserKey {
    #[serde(rename = "ID")]
    pub id: String,
    pub private_key: String,
    pub active: i32,
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
    pub display_name: String,
    pub keys: Vec<AddressKey>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AddressKey {
    #[serde(rename = "ID")]
    pub id: String,
    pub private_key: String,
    pub token: Option<String>,
    pub signature: Option<String>,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MessageMetadata {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "AddressID")]
    pub address_id: String,
    #[serde(rename = "LabelIDs")]
    pub label_ids: Vec<String>,
    pub subject: String,
    pub sender: EmailAddress,
    pub to_list: Vec<EmailAddress>,
    #[serde(rename = "CCList")]
    pub cc_list: Vec<EmailAddress>,
    #[serde(rename = "BCCList")]
    pub bcc_list: Vec<EmailAddress>,
    pub time: i64,
    pub size: i64,
    pub unread: i32,
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
    pub key_packets: String,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MessageFilter {
    #[serde(rename = "LabelID", skip_serializing_if = "Option::is_none")]
    pub label_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_id: Option<String>,
    pub desc: i32,
}

// Encryption scheme constants (bitmask)
pub const INTERNAL_SCHEME: i32 = 1;
pub const CLEAR_SCHEME: i32 = 4;
pub const PGP_INLINE_SCHEME: i32 = 8;
pub const PGP_MIME_SCHEME: i32 = 16;
pub const CLEAR_MIME_SCHEME: i32 = 32;

// Signature type constants
pub const NO_SIGNATURE: i32 = 0;
pub const DETACHED_SIGNATURE: i32 = 1;

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
    #[serde(default)]
    pub events: Vec<Value>,
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
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateDraftReq {
    pub message: DraftTemplate,
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
            "SRPSession": "session-id-123"
        });

        let info: AuthInfoResponse = serde_json::from_value(json).unwrap();
        assert_eq!(info.version, 4);
        assert_eq!(info.srp_session, "session-id-123");
        assert_eq!(info.salt, "BBBB");
    }

    #[test]
    fn test_auth_response_deserialize() {
        let json = serde_json::json!({
            "Code": 1000,
            "UID": "uid-abc",
            "AccessToken": "token-xyz",
            "RefreshToken": "refresh-123",
            "TokenType": "Bearer",
            "ServerProof": "proof-b64",
            "2FA": {
                "Enabled": 0,
                "TOTP": 0,
                "FIDO2": null
            },
            "Scopes": ["mail", "calendar"]
        });

        let auth: AuthResponse = serde_json::from_value(json).unwrap();
        assert_eq!(auth.uid, "uid-abc");
        assert_eq!(auth.access_token, "token-xyz");
        assert_eq!(auth.refresh_token, "refresh-123");
        assert_eq!(auth.scopes, vec!["mail", "calendar"]);
        assert!(!auth.two_factor.totp_required());
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
    }

    #[test]
    fn test_two_factor_info_totp_required() {
        let info = TwoFactorInfo {
            enabled: 1,
            totp: 1,
            fido2: None,
        };
        assert!(info.totp_required());
        assert!(info.requires_second_factor());
        assert!(!info.fido_supported());

        let info = TwoFactorInfo {
            enabled: 0,
            totp: 1,
            fido2: None,
        };
        assert!(!info.totp_required());
        assert!(!info.requires_second_factor());

        let info = TwoFactorInfo {
            enabled: 1,
            totp: 0,
            fido2: None,
        };
        assert!(!info.totp_required());
    }

    #[test]
    fn test_two_factor_info_fido_supported() {
        let info = TwoFactorInfo {
            enabled: 2,
            totp: 0,
            fido2: Some(Fido2Info {
                authentication_options: serde_json::json!({
                    "publicKey": { "challenge": [1, 2, 3] }
                }),
            }),
        };
        assert!(info.requires_second_factor());
        assert!(info.fido_supported());
        assert!(info.fido_authentication_options().is_some());
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
                "DisplayName": "Test User",
                "Keys": [{
                    "ID": "akey-1",
                    "PrivateKey": "armored-key-data",
                    "Token": null,
                    "Signature": null,
                    "Active": 1
                }]
            }]
        });

        let resp: AddressesResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.addresses.len(), 1);
        assert_eq!(resp.addresses[0].email, "test@proton.me");
        assert_eq!(resp.addresses[0].keys.len(), 1);
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
            "Subject": "Test Subject",
            "Sender": { "Name": "Alice", "Address": "alice@proton.me" },
            "ToList": [{ "Name": "Bob", "Address": "bob@proton.me" }],
            "CCList": [],
            "BCCList": [],
            "Time": 1700000000,
            "Size": 4096,
            "Unread": 1,
            "NumAttachments": 0
        });

        let meta: MessageMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(meta.id, "msg-1");
        assert_eq!(meta.address_id, "addr-1");
        assert_eq!(meta.label_ids, vec!["0", "5"]);
        assert_eq!(meta.subject, "Test Subject");
        assert_eq!(meta.sender.address, "alice@proton.me");
        assert_eq!(meta.to_list.len(), 1);
        assert_eq!(meta.time, 1700000000);
        assert_eq!(meta.unread, 1);
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
            "Body": "-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----",
            "MIMEType": "text/html",
            "Attachments": [{
                "ID": "att-1",
                "Name": "file.pdf",
                "Size": 2048,
                "MIMEType": "application/pdf",
                "KeyPackets": "base64keypackets"
            }]
        });

        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.metadata.id, "msg-1");
        assert_eq!(msg.metadata.subject, "Hello");
        assert_eq!(
            msg.body,
            "-----BEGIN PGP MESSAGE-----\nfake\n-----END PGP MESSAGE-----"
        );
        assert_eq!(msg.mime_type, "text/html");
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].name, "file.pdf");
        assert_eq!(msg.attachments[0].key_packets, "base64keypackets");
    }

    #[test]
    fn test_attachment_deserialize() {
        let json = serde_json::json!({
            "ID": "att-1",
            "Name": "document.txt",
            "Size": 512,
            "MIMEType": "text/plain",
            "KeyPackets": "AAAA"
        });

        let att: Attachment = serde_json::from_value(json).unwrap();
        assert_eq!(att.id, "att-1");
        assert_eq!(att.name, "document.txt");
        assert_eq!(att.size, 512);
        assert_eq!(att.mime_type, "text/plain");
    }

    #[test]
    fn test_message_filter_serialize() {
        let filter = MessageFilter {
            label_id: Some("0".to_string()),
            end_id: None,
            desc: 1,
        };

        let json = serde_json::to_value(&filter).unwrap();
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
        };
        let json = serde_json::to_value(&draft).unwrap();
        assert_eq!(json["Subject"], "Test");
        assert_eq!(json["Sender"]["Name"], "Alice");
        assert_eq!(json["ToList"][0]["Address"], "bob@proton.me");
        assert_eq!(json["MIMEType"], "text/plain");
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
            },
            parent_id: None,
            action: 0,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["Message"]["Subject"], "Hello");
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
}
