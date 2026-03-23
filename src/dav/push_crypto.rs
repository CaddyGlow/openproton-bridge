use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use base64::Engine;
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use sha2::Sha256;

use super::error::DavError;

pub struct VapidKeyPair {
    signing_key: SigningKey,
    pub public_key_bytes: Vec<u8>,
    pub public_key_base64url: String,
}

impl VapidKeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = VerifyingKey::from(&signing_key);
        let point = verifying_key.to_encoded_point(false);
        let public_key_bytes = point.as_bytes().to_vec();
        let public_key_base64url = BASE64URL.encode(&public_key_bytes);
        Self {
            signing_key,
            public_key_bytes,
            public_key_base64url,
        }
    }

    pub fn sign_vapid_jwt(&self, audience: &str) -> Result<String, DavError> {
        use p256::ecdsa::signature::Signer;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let header = BASE64URL.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let payload = format!(
            r#"{{"aud":"{}","exp":{},"sub":"mailto:bridge@localhost"}}"#,
            audience,
            now + 86400,
        );
        let payload_b64 = BASE64URL.encode(payload.as_bytes());
        let signing_input = format!("{header}.{payload_b64}");

        let signature: p256::ecdsa::Signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = BASE64URL.encode(signature.to_bytes());

        Ok(format!(
            "vapid t={signing_input}.{sig_b64}, k={}",
            self.public_key_base64url
        ))
    }
}

/// Encrypt a push message payload per RFC 8291 (aes128gcm content encoding).
pub fn encrypt_push_payload(
    plaintext: &[u8],
    client_public_key: &[u8],
    auth_secret: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), DavError> {
    // Decode client's P-256 public key
    let client_pk = PublicKey::from_sec1_bytes(client_public_key)
        .map_err(|e| DavError::Backend(format!("invalid client public key: {e}")))?;

    // Generate ephemeral server key pair
    let server_secret = EphemeralSecret::random(&mut rand::thread_rng());
    let server_pk = p256::PublicKey::from(&server_secret);
    let server_point = server_pk.to_encoded_point(false);
    let server_pub_bytes = server_point.as_bytes().to_vec();

    // ECDH shared secret
    let shared_secret = server_secret.diffie_hellman(&client_pk);

    // RFC 8291 Section 3.4: Key derivation
    // IKM = HKDF-Extract(auth_secret, shared_secret)
    let hkdf_auth = Hkdf::<Sha256>::new(Some(auth_secret), shared_secret.raw_secret_bytes());

    // info for IKM: "WebPush: info\0" || client_pub || server_pub
    let mut ikm_info = Vec::with_capacity(128);
    ikm_info.extend_from_slice(b"WebPush: info\0");
    ikm_info.extend_from_slice(client_public_key);
    ikm_info.extend_from_slice(&server_pub_bytes);

    let mut ikm = [0u8; 32];
    hkdf_auth
        .expand(&ikm_info, &mut ikm)
        .map_err(|e| DavError::Backend(format!("HKDF expand for IKM failed: {e}")))?;

    // Generate random 16-byte salt
    let mut salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);

    // Derive content encryption key and nonce from IKM + salt
    let hkdf_cek = Hkdf::<Sha256>::new(Some(&salt), &ikm);

    let mut cek = [0u8; 16];
    hkdf_cek
        .expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .map_err(|e| DavError::Backend(format!("HKDF expand for CEK failed: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    hkdf_cek
        .expand(b"Content-Encoding: nonce\0", &mut nonce_bytes)
        .map_err(|e| DavError::Backend(format!("HKDF expand for nonce failed: {e}")))?;

    // aes128gcm record: pad with delimiter byte 0x02 then encrypt
    let mut padded = Vec::with_capacity(plaintext.len() + 1);
    padded.extend_from_slice(plaintext);
    padded.push(0x02); // padding delimiter

    let cipher = Aes128Gcm::new_from_slice(&cek)
        .map_err(|e| DavError::Backend(format!("AES-GCM key init failed: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, padded.as_ref())
        .map_err(|e| DavError::Backend(format!("AES-GCM encrypt failed: {e}")))?;

    // aes128gcm header: salt(16) || rs(4) || idlen(1) || keyid(65) || ciphertext
    let rs: u32 = 4096;
    let keyid_len = server_pub_bytes.len() as u8;

    let mut body = Vec::new();
    body.extend_from_slice(&salt);
    body.extend_from_slice(&rs.to_be_bytes());
    body.push(keyid_len);
    body.extend_from_slice(&server_pub_bytes);
    body.extend_from_slice(&ciphertext);

    Ok((body, server_pub_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vapid_key_pair_generates_valid_keys() {
        let kp = VapidKeyPair::generate();
        assert_eq!(kp.public_key_bytes.len(), 65); // uncompressed P-256
        assert_eq!(kp.public_key_bytes[0], 0x04);
        assert!(!kp.public_key_base64url.is_empty());
    }

    #[test]
    fn vapid_jwt_has_expected_structure() {
        let kp = VapidKeyPair::generate();
        let auth = kp.sign_vapid_jwt("https://push.example.com").unwrap();
        assert!(auth.starts_with("vapid t="));
        assert!(auth.contains(", k="));
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        // Generate client key pair
        let client_secret = EphemeralSecret::random(&mut rand::thread_rng());
        let client_pk = p256::PublicKey::from(&client_secret);
        let client_point = client_pk.to_encoded_point(false);
        let client_pub_bytes = client_point.as_bytes();

        let mut auth_secret = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut auth_secret);

        let plaintext = b"<push-message>test</push-message>";
        let (body, _server_pub) =
            encrypt_push_payload(plaintext, client_pub_bytes, &auth_secret).unwrap();

        // Verify body structure: salt(16) + rs(4) + idlen(1) + keyid(65) + ciphertext
        assert!(body.len() > 86);
        let salt = &body[0..16];
        let rs = u32::from_be_bytes(body[16..20].try_into().unwrap());
        assert_eq!(rs, 4096);
        let idlen = body[20] as usize;
        assert_eq!(idlen, 65);
        let server_pub = &body[21..21 + idlen];
        let ciphertext = &body[21 + idlen..];

        // Decrypt: replicate the server's key derivation using client's private key
        let server_pk = PublicKey::from_sec1_bytes(server_pub).unwrap();
        let shared = client_secret.diffie_hellman(&server_pk);

        let hkdf_auth = Hkdf::<Sha256>::new(Some(&auth_secret), shared.raw_secret_bytes());
        let mut ikm_info = Vec::new();
        ikm_info.extend_from_slice(b"WebPush: info\0");
        ikm_info.extend_from_slice(client_pub_bytes);
        ikm_info.extend_from_slice(server_pub);
        let mut ikm = [0u8; 32];
        hkdf_auth.expand(&ikm_info, &mut ikm).unwrap();

        let hkdf_cek = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let mut cek = [0u8; 16];
        hkdf_cek
            .expand(b"Content-Encoding: aes128gcm\0", &mut cek)
            .unwrap();
        let mut nonce = [0u8; 12];
        hkdf_cek
            .expand(b"Content-Encoding: nonce\0", &mut nonce)
            .unwrap();

        let cipher = Aes128Gcm::new_from_slice(&cek).unwrap();
        let decrypted = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .unwrap();

        // Remove padding delimiter
        assert_eq!(decrypted.last(), Some(&0x02));
        let recovered = &decrypted[..decrypted.len() - 1];
        assert_eq!(recovered, plaintext);
    }
}
