use serde::{Deserialize, Serialize};

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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TwoFactorInfo {
    pub enabled: i32,
    #[serde(rename = "TOTP")]
    pub totp: i32,
}

impl TwoFactorInfo {
    pub fn totp_required(&self) -> bool {
        self.enabled != 0 && self.totp != 0
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
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub uid: String,
    pub access_token: String,
    pub refresh_token: String,
    pub email: String,
    pub display_name: String,
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
                "TOTP": 0
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
    fn test_two_factor_info_totp_required() {
        let info = TwoFactorInfo {
            enabled: 1,
            totp: 1,
        };
        assert!(info.totp_required());

        let info = TwoFactorInfo {
            enabled: 0,
            totp: 1,
        };
        assert!(!info.totp_required());

        let info = TwoFactorInfo {
            enabled: 1,
            totp: 0,
        };
        assert!(!info.totp_required());
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
        };

        let json = serde_json::to_string(&session).unwrap();
        let restored: Session = serde_json::from_str(&json).unwrap();

        assert_eq!(session.uid, restored.uid);
        assert_eq!(session.access_token, restored.access_token);
        assert_eq!(session.refresh_token, restored.refresh_token);
        assert_eq!(session.email, restored.email);
        assert_eq!(session.display_name, restored.display_name);
    }
}
