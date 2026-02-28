/// SRP-6a implementation for Proton authentication.
///
/// Reference: github.com/ProtonMail/go-srp
///
/// Key differences from textbook SRP-6a:
/// - All integers serialized as LITTLE-ENDIAN on the wire
/// - Hash function is `expandHash` (4x SHA-512 = 256 bytes), not SHA-256
/// - Password hashing uses standard bcrypt ($2y$10$) + expandHash, not bcrypt-pbkdf
/// - Multiplier k = expandHash(pad_le(g) || pad_le(N))  (generator first)
/// - Exponent = (u * x + a) mod (N - 1)
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha512};

use super::error::{ApiError, Result};

const GENERATOR: u32 = 2;
const BIT_LENGTH: usize = 2048;
const BYTE_LEN: usize = BIT_LENGTH / 8; // 256

// -- expandHash: the core hash function used throughout Proton SRP --

/// Proton's expandHash: SHA-512(data || 0) || SHA-512(data || 1) || SHA-512(data || 2) || SHA-512(data || 3)
/// Returns 256 bytes (2048 bits).
pub fn expand_hash(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(256);
    for i in 0u8..4 {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.update([i]);
        result.extend_from_slice(&hasher.finalize());
    }
    result
}

// -- Password hashing --

/// Hash password using Proton's method (SRP version 3/4).
///
/// Steps:
/// 1. Decode API salt from base64 (typically 10 bytes)
/// 2. Append b"proton" to get 16 bytes
/// 3. Encode with bcrypt base64 to get 22-char salt string
/// 4. Run standard bcrypt ($2y$10$) on raw password bytes with that salt
/// 5. Concatenate full bcrypt output string bytes with modulus LE bytes
/// 6. Return expandHash of the concatenation (256 bytes)
pub fn hash_password(password: &str, salt_b64: &str, modulus_le: &[u8]) -> Result<Vec<u8>> {
    let salt_raw = BASE64
        .decode(salt_b64)
        .map_err(|e| ApiError::Srp(format!("invalid salt base64: {}", e)))?;

    // Build bcrypt salt: api_salt_bytes + b"proton"
    let mut combined_salt = salt_raw;
    combined_salt.extend_from_slice(b"proton");

    let salt_16 = bcrypt_salt_16(&combined_salt)?;

    // Run standard bcrypt with cost 10, $2y$ version
    let hash_parts = bcrypt::hash_with_salt(password.as_bytes(), 10, salt_16)
        .map_err(|e| ApiError::Srp(format!("bcrypt failed: {}", e)))?;
    let hash_string = hash_parts.format_for_version(bcrypt::Version::TwoY);

    // expandHash(bcrypt_output_string_bytes || modulus_le_256_bytes)
    let modulus_padded = pad_le(modulus_le, BYTE_LEN);
    let mut to_hash = hash_string.into_bytes();
    to_hash.extend_from_slice(&modulus_padded);

    Ok(expand_hash(&to_hash))
}

/// Convert combined salt bytes to the 16-byte array bcrypt expects.
fn bcrypt_salt_16(combined: &[u8]) -> Result<[u8; 16]> {
    use base64::alphabet::BCRYPT;
    use base64::engine::{GeneralPurpose, GeneralPurposeConfig};

    let bcrypt_b64 = GeneralPurpose::new(
        &BCRYPT,
        GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );

    let encoded = bcrypt_b64.encode(combined);

    let salt_str = if encoded.len() >= 22 {
        &encoded[..22]
    } else {
        return Err(ApiError::Srp(format!(
            "bcrypt salt encoding too short: {} chars from {} bytes",
            encoded.len(),
            combined.len()
        )));
    };

    // Decode those 22 chars back to raw bytes (16 bytes + 2 padding bits)
    let mut padded_str = salt_str.to_string();
    while padded_str.len() % 4 != 0 {
        padded_str.push('.'); // '.' = value 0 in bcrypt base64 alphabet
    }

    let decoded = bcrypt_b64
        .decode(&padded_str)
        .map_err(|e| ApiError::Srp(format!("bcrypt salt decode failed: {}", e)))?;

    let mut salt = [0u8; 16];
    let copy_len = decoded.len().min(16);
    salt[..copy_len].copy_from_slice(&decoded[..copy_len]);
    Ok(salt)
}

// -- Modulus decoding --

/// Decode the modulus from a PGP-signed base64 message.
/// Returns (BigUint for math, raw LE bytes for password hashing).
pub fn decode_modulus(modulus_signed: &str) -> Result<(BigUint, Vec<u8>)> {
    let lines: Vec<&str> = modulus_signed.lines().collect();
    let mut payload = String::new();
    let mut in_body = false;

    for line in &lines {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
            continue;
        }
        if trimmed.starts_with("Hash:") {
            continue;
        }
        if trimmed.starts_with("-----BEGIN PGP SIGNATURE-----") {
            break;
        }
        if trimmed.is_empty() {
            in_body = true;
            continue;
        }
        if in_body {
            payload.push_str(trimmed);
        }
    }

    if payload.is_empty() {
        return Err(ApiError::Srp("empty modulus payload".to_string()));
    }

    let modulus_le_bytes = BASE64
        .decode(&payload)
        .map_err(|e| ApiError::Srp(format!("modulus base64 decode failed: {}", e)))?;

    let modulus = BigUint::from_bytes_le(&modulus_le_bytes);
    Ok((modulus, modulus_le_bytes))
}

// -- SRP proof computation --

/// Compute SRP-6a client proof.
///
/// Returns (client_ephemeral_b64, client_proof_b64, expected_server_proof_bytes).
pub fn compute_srp_proof(
    hashed_password: &[u8],
    server_ephemeral_b64: &str,
    modulus: &BigUint,
) -> Result<(String, String, Vec<u8>)> {
    let n = modulus;
    let g = BigUint::from(GENERATOR);
    let n_minus_one = n - BigUint::one();

    // Decode server ephemeral B (LE bytes from API)
    let b_le_bytes = BASE64
        .decode(server_ephemeral_b64)
        .map_err(|e| ApiError::Srp(format!("server ephemeral decode: {}", e)))?;
    let big_b = BigUint::from_bytes_le(&b_le_bytes);

    if big_b.is_zero() || (&big_b % n).is_zero() {
        return Err(ApiError::Srp("invalid server ephemeral".to_string()));
    }

    // Generate client ephemeral: a in (BIT_LENGTH*2, N-1), A = g^a mod N
    let (big_a, a_secret) = generate_client_ephemeral(&g, n, &n_minus_one)?;

    // Serialize A and B as LE bytes padded to BYTE_LEN
    let a_le = to_le_padded(&big_a);
    let b_le = pad_le(&b_le_bytes, BYTE_LEN);

    // u = expandHash(A_le || B_le), interpreted as LE integer
    let u = {
        let mut buf = Vec::with_capacity(BYTE_LEN * 2);
        buf.extend_from_slice(&a_le);
        buf.extend_from_slice(&b_le);
        BigUint::from_bytes_le(&expand_hash(&buf))
    };

    if u.is_zero() {
        return Err(ApiError::Srp("SRP parameter u is zero".to_string()));
    }

    // x = hashed password interpreted as LE integer
    let x = BigUint::from_bytes_le(hashed_password);

    // k = expandHash(pad_le(g) || pad_le(N)), interpreted as LE integer, mod N
    let k = {
        let g_le = to_le_padded(&g);
        let n_le = to_le_padded(n);
        let mut buf = Vec::with_capacity(BYTE_LEN * 2);
        buf.extend_from_slice(&g_le);
        buf.extend_from_slice(&n_le);
        BigUint::from_bytes_le(&expand_hash(&buf)) % n
    };

    // S = (B - k * g^x mod N) ^ ((u * x + a) mod (N-1)) mod N
    let gx_mod_n = g.modpow(&x, n);
    let kgx = (&k * &gx_mod_n) % n;

    let base = if big_b >= kgx {
        (&big_b - &kgx) % n
    } else {
        (n - &kgx + &big_b) % n
    };

    let exp = ((&u * &x) + &a_secret) % &n_minus_one;
    let big_s = base.modpow(&exp, n);
    let s_le = to_le_padded(&big_s);

    // Client proof M1 = expandHash(A_le || B_le || S_le)
    let client_proof = {
        let mut buf = Vec::with_capacity(BYTE_LEN * 3);
        buf.extend_from_slice(&a_le);
        buf.extend_from_slice(&b_le);
        buf.extend_from_slice(&s_le);
        expand_hash(&buf)
    };

    // Expected server proof M2 = expandHash(A_le || M1 || S_le)
    let server_proof = {
        let mut buf = Vec::with_capacity(BYTE_LEN + 256 + BYTE_LEN);
        buf.extend_from_slice(&a_le);
        buf.extend_from_slice(&client_proof);
        buf.extend_from_slice(&s_le);
        expand_hash(&buf)
    };

    let a_b64 = BASE64.encode(&a_le);
    let proof_b64 = BASE64.encode(&client_proof);

    Ok((a_b64, proof_b64, server_proof))
}

/// Verify the server proof matches our expected value.
pub fn verify_server_proof(expected: &[u8], server_proof_b64: &str) -> Result<()> {
    let server_proof = BASE64
        .decode(server_proof_b64)
        .map_err(|e| ApiError::Srp(format!("server proof decode: {}", e)))?;

    if expected != server_proof.as_slice() {
        return Err(ApiError::Srp(
            "server proof verification failed".to_string(),
        ));
    }
    Ok(())
}

// -- Mailbox password derivation --

/// Derive the mailbox password from raw password bytes and a 16-byte salt.
///
/// This is the Proton "MailboxPassword" KDF:
/// 1. Encode salt (16 bytes) using bcrypt's dot-slash base64 alphabet (22 chars).
/// 2. Run bcrypt ($2y$10$) on password with that salt.
/// 3. Return the last 31 bytes of the 60-char bcrypt output string.
///
/// Reference: go-srp hash.go MailboxPassword
pub fn mailbox_password(password: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    if salt.len() != 16 {
        return Err(ApiError::Srp(format!(
            "mailbox password salt must be 16 bytes, got {}",
            salt.len()
        )));
    }

    let mut salt_16 = [0u8; 16];
    salt_16.copy_from_slice(salt);

    let hash_parts = bcrypt::hash_with_salt(password, 10, salt_16)
        .map_err(|e| ApiError::Srp(format!("bcrypt failed: {}", e)))?;
    let hash_string = hash_parts.format_for_version(bcrypt::Version::TwoY);

    let bytes = hash_string.into_bytes();
    Ok(bytes[bytes.len() - 31..].to_vec())
}

/// Look up the salt for a given key ID and derive the mailbox passphrase.
///
/// Reference: go-proton-api/salt_types.go SaltForKey
pub fn salt_for_key(
    password: &[u8],
    key_id: &str,
    salts: &[super::types::KeySalt],
) -> Result<Vec<u8>> {
    let salt_entry = salts
        .iter()
        .find(|s| s.id == key_id)
        .ok_or_else(|| ApiError::Srp(format!("no salt found for key {}", key_id)))?;

    let salt_b64 = salt_entry
        .key_salt
        .as_deref()
        .ok_or_else(|| ApiError::Srp(format!("null salt for key {}", key_id)))?;

    let decoded = BASE64
        .decode(salt_b64)
        .map_err(|e| ApiError::Srp(format!("salt base64 decode failed: {}", e)))?;

    mailbox_password(password, &decoded)
}

// -- Helper functions --

fn generate_client_ephemeral(
    g: &BigUint,
    n: &BigUint,
    n_minus_one: &BigUint,
) -> Result<(BigUint, BigUint)> {
    use num_bigint::RandBigInt;
    let mut rng = rand::thread_rng();
    let lower_bound = BigUint::from(BIT_LENGTH * 2);

    for _ in 0..64 {
        let a_secret = rng.gen_biguint_below(n_minus_one);

        if a_secret <= lower_bound {
            continue;
        }

        let big_a = g.modpow(&a_secret, n);
        if big_a.is_zero() {
            continue;
        }

        return Ok((big_a, a_secret));
    }

    Err(ApiError::Srp(
        "failed to generate valid client ephemeral".to_string(),
    ))
}

/// Convert a BigUint to BYTE_LEN little-endian bytes, zero-padded on the right (high end).
fn to_le_padded(n: &BigUint) -> Vec<u8> {
    let mut le = n.to_bytes_le();
    le.resize(BYTE_LEN, 0);
    le
}

/// Pad raw LE bytes to the given length with zeros on the right (high end).
fn pad_le(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut padded = bytes.to_vec();
    padded.resize(len, 0);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_hash_length() {
        let result = expand_hash(b"test data");
        assert_eq!(result.len(), 256);
    }

    #[test]
    fn test_expand_hash_deterministic() {
        let a = expand_hash(b"hello");
        let b = expand_hash(b"hello");
        assert_eq!(a, b);

        let c = expand_hash(b"world");
        assert_ne!(a, c);
    }

    #[test]
    fn test_expand_hash_known_vector() {
        // Verify first 8 bytes of expandHash("test") match SHA-512("test" || 0x00) prefix
        let result = expand_hash(b"test");
        let mut hasher = Sha512::new();
        hasher.update(b"test");
        hasher.update([0u8]);
        let first_block = hasher.finalize();
        assert_eq!(&result[..64], first_block.as_slice());
    }

    #[test]
    fn test_to_le_padded() {
        let n = BigUint::from(0x0102u32);
        let le = to_le_padded(&n);
        assert_eq!(le.len(), BYTE_LEN);
        assert_eq!(le[0], 0x02);
        assert_eq!(le[1], 0x01);
        assert_eq!(le[2], 0x00);
    }

    #[test]
    fn test_pad_le_extends_with_zeros() {
        let bytes = vec![0x01, 0x02];
        let padded = pad_le(&bytes, 5);
        assert_eq!(padded, vec![0x01, 0x02, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_pad_le_already_long_enough() {
        let bytes = vec![0x01, 0x02, 0x03];
        let padded = pad_le(&bytes, 3);
        assert_eq!(padded, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_modulus_decode_le() {
        let signed = "-----BEGIN PGP SIGNED MESSAGE-----\n\
            Hash: SHA256\n\
            \n\
            wA==\n\
            -----BEGIN PGP SIGNATURE-----\n\
            fake\n\
            -----END PGP SIGNATURE-----";

        let (modulus, le_bytes) = decode_modulus(signed).unwrap();
        assert_eq!(modulus, BigUint::from(192u32));
        assert_eq!(le_bytes, vec![0xC0]);
    }

    #[test]
    fn test_modulus_decode_empty_payload_error() {
        let signed = "-----BEGIN PGP SIGNED MESSAGE-----\n\
            Hash: SHA256\n\
            \n\
            -----BEGIN PGP SIGNATURE-----\n\
            fake\n\
            -----END PGP SIGNATURE-----";

        let err = decode_modulus(signed).unwrap_err();
        assert!(err.to_string().contains("empty modulus"));
    }

    #[test]
    fn test_modulus_decode_multiline_payload() {
        // Two lines of base64 that together decode to some bytes
        let modulus_bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let b64 = BASE64.encode(&modulus_bytes);

        let signed = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\n\
             Hash: SHA256\n\
             \n\
             {}\n\
             -----BEGIN PGP SIGNATURE-----\n\
             fake\n\
             -----END PGP SIGNATURE-----",
            b64
        );

        let (modulus, le_bytes) = decode_modulus(&signed).unwrap();
        assert_eq!(le_bytes, modulus_bytes);
        assert_eq!(modulus, BigUint::from_bytes_le(&modulus_bytes));
    }

    #[test]
    fn test_hash_password_produces_256_bytes() {
        // Use a minimal modulus for testing
        let salt_b64 = BASE64.encode(b"0123456789"); // 10-byte salt
        let modulus_le = vec![0xFF; 256];

        let result = hash_password("testpassword", &salt_b64, &modulus_le).unwrap();
        assert_eq!(result.len(), 256);
    }

    #[test]
    fn test_hash_password_deterministic() {
        let salt_b64 = BASE64.encode(b"0123456789");
        let modulus_le = vec![0xFF; 256];

        let a = hash_password("testpassword", &salt_b64, &modulus_le).unwrap();
        let b = hash_password("testpassword", &salt_b64, &modulus_le).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_hash_password_different_passwords_differ() {
        let salt_b64 = BASE64.encode(b"0123456789");
        let modulus_le = vec![0xFF; 256];

        let a = hash_password("password1", &salt_b64, &modulus_le).unwrap();
        let b = hash_password("password2", &salt_b64, &modulus_le).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_hash_password_different_salts_differ() {
        let salt_a = BASE64.encode(b"0123456789");
        let salt_b = BASE64.encode(b"9876543210");
        let modulus_le = vec![0xFF; 256];

        let a = hash_password("testpassword", &salt_a, &modulus_le).unwrap();
        let b = hash_password("testpassword", &salt_b, &modulus_le).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_verify_server_proof_success() {
        let proof = vec![1, 2, 3, 4];
        let proof_b64 = BASE64.encode(&proof);
        verify_server_proof(&proof, &proof_b64).unwrap();
    }

    #[test]
    fn test_verify_server_proof_mismatch() {
        let expected = vec![1, 2, 3, 4];
        let wrong = BASE64.encode([5, 6, 7, 8]);
        let err = verify_server_proof(&expected, &wrong).unwrap_err();
        assert!(err.to_string().contains("server proof verification failed"));
    }

    #[test]
    fn test_verify_server_proof_invalid_base64() {
        let expected = vec![1, 2, 3, 4];
        let err = verify_server_proof(&expected, "not!valid!base64!!!").unwrap_err();
        assert!(err.to_string().contains("server proof decode"));
    }

    #[test]
    fn test_bcrypt_salt_16_standard_case() {
        // 10-byte API salt + 6-byte "proton" = 16 bytes total
        let mut combined = b"0123456789".to_vec();
        combined.extend_from_slice(b"proton");
        assert_eq!(combined.len(), 16);

        let salt = bcrypt_salt_16(&combined).unwrap();
        assert_eq!(salt.len(), 16);
    }

    #[test]
    fn test_bcrypt_salt_16_short_input_fails() {
        // Very short input that produces fewer than 22 bcrypt base64 chars
        let combined = b"ab".to_vec();
        let err = bcrypt_salt_16(&combined).unwrap_err();
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn test_mailbox_password_returns_31_bytes() {
        let salt = [0u8; 16];
        let result = mailbox_password(b"testpassword", &salt).unwrap();
        assert_eq!(result.len(), 31);
    }

    #[test]
    fn test_mailbox_password_deterministic() {
        let salt = [1u8; 16];
        let a = mailbox_password(b"password", &salt).unwrap();
        let b = mailbox_password(b"password", &salt).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_mailbox_password_different_passwords_differ() {
        let salt = [2u8; 16];
        let a = mailbox_password(b"password1", &salt).unwrap();
        let b = mailbox_password(b"password2", &salt).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_mailbox_password_different_salts_differ() {
        let salt_a = [3u8; 16];
        let salt_b = [4u8; 16];
        let a = mailbox_password(b"password", &salt_a).unwrap();
        let b = mailbox_password(b"password", &salt_b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_mailbox_password_wrong_salt_length() {
        let short_salt = [0u8; 8];
        let err = mailbox_password(b"password", &short_salt).unwrap_err();
        assert!(err.to_string().contains("16 bytes"));
    }

    #[test]
    fn test_salt_for_key_found() {
        use crate::api::types::KeySalt;

        let salt_raw = [5u8; 16];
        let salt_b64 = BASE64.encode(salt_raw);

        let salts = vec![
            KeySalt {
                id: "key-1".to_string(),
                key_salt: Some(salt_b64),
            },
            KeySalt {
                id: "key-2".to_string(),
                key_salt: Some(BASE64.encode([6u8; 16])),
            },
        ];

        let result = salt_for_key(b"password", "key-1", &salts).unwrap();
        let expected = mailbox_password(b"password", &salt_raw).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_salt_for_key_not_found() {
        use crate::api::types::KeySalt;

        let salts = vec![KeySalt {
            id: "key-1".to_string(),
            key_salt: Some(BASE64.encode([0u8; 16])),
        }];

        let err = salt_for_key(b"password", "key-999", &salts).unwrap_err();
        assert!(err.to_string().contains("no salt found"));
    }

    #[test]
    fn test_salt_for_key_null_salt() {
        use crate::api::types::KeySalt;

        let salts = vec![KeySalt {
            id: "key-1".to_string(),
            key_salt: None,
        }];

        let err = salt_for_key(b"password", "key-1", &salts).unwrap_err();
        assert!(err.to_string().contains("null salt"));
    }
}
