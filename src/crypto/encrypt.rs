use std::io::Write;

use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{LiteralWriter, Message, Signer};
use openpgp::serialize::Serialize;
use openpgp::Cert;
use sequoia_openpgp as openpgp;

use super::keys::Keyring;
use super::{CryptoError, Result};

/// Session key data extracted from an encrypted message.
pub struct SessionKeyData {
    pub key: Vec<u8>,
    pub algorithm: String,
}

/// Encrypt body with keyring (signed), split into key packets and data packets,
/// extract session key. Mirrors Go `encSplit()`.
///
/// Returns (session_key_data, data_packets).
pub fn enc_split(keyring: &Keyring, body: &str) -> Result<(SessionKeyData, Vec<u8>)> {
    // Encrypt and sign the body
    let encrypted = keyring.encrypt_and_sign(body.as_bytes())?;

    // Split into PKESK (key packets) and SEIPD (data packets)
    let pile = openpgp::PacketPile::from_bytes(&encrypted)
        .map_err(|e| CryptoError::EncryptionFailed(format!("parse packets: {}", e)))?;
    let packets: Vec<_> = pile.into_children().collect();

    let mut key_packets = Vec::new();
    let mut data_packets = Vec::new();
    let mut seen_encrypted = false;

    for pkt in &packets {
        let mut buf = Vec::new();
        pkt.serialize(&mut buf)
            .map_err(|e| CryptoError::EncryptionFailed(format!("serialize packet: {}", e)))?;
        if !seen_encrypted {
            match pkt {
                openpgp::Packet::PKESK(_) => {
                    key_packets.extend_from_slice(&buf);
                }
                _ => {
                    seen_encrypted = true;
                    data_packets.extend_from_slice(&buf);
                }
            }
        } else {
            data_packets.extend_from_slice(&buf);
        }
    }

    // Decrypt session key from key packets + data packets using keyring
    // (same approach as the DecryptionHelper -- we extract the session key)
    let session_key = extract_session_key(keyring, &key_packets, &data_packets)?;

    Ok((session_key, data_packets))
}

/// Encrypt a session key to a recipient's public key certificate.
/// Returns the binary PKESK packet(s).
pub fn encrypt_session_key(recipient_cert: &Cert, session_key: &SessionKeyData) -> Result<Vec<u8>> {
    let policy = StandardPolicy::new();
    let algo = parse_algorithm(&session_key.algorithm)?;

    let sk = openpgp::crypto::SessionKey::from(session_key.key.as_slice());

    // Find encryption-capable subkey
    let recipient = recipient_cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .for_transport_encryption()
        .for_storage_encryption()
        .next()
        .ok_or_else(|| {
            CryptoError::EncryptionFailed("no encryption subkey in recipient cert".to_string())
        })?;

    let pkesk = openpgp::packet::pkesk::PKESK3::for_recipient(algo, &sk, recipient.key())
        .map_err(|e| CryptoError::EncryptionFailed(format!("PKESK3: {}", e)))?;

    let mut buf = Vec::new();
    openpgp::Packet::from(pkesk)
        .serialize(&mut buf)
        .map_err(|e| CryptoError::EncryptionFailed(format!("serialize PKESK: {}", e)))?;

    Ok(buf)
}

/// Create a detached signature over data using the keyring's signing key.
pub fn sign_detached(keyring: &Keyring, data: &[u8]) -> Result<Vec<u8>> {
    let key = keyring.first_key()?;
    let policy = StandardPolicy::new();

    let signing_ka = key
        .cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .secret()
        .for_signing()
        .next()
        .ok_or_else(|| CryptoError::SigningFailed("no signing key".to_string()))?;

    let signing_secret = signing_ka
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|e| CryptoError::SigningFailed(format!("parts_into_secret: {}", e)))?;
    let signing_decrypted = signing_secret
        .decrypt_secret(&key.password)
        .map_err(|e| CryptoError::SigningFailed(format!("decrypt signing key: {}", e)))?;
    let keypair = signing_decrypted
        .into_keypair()
        .map_err(|e| CryptoError::SigningFailed(format!("keypair: {}", e)))?;

    let mut sig_bytes = Vec::new();
    let message = Message::new(&mut sig_bytes);
    let mut signer = Signer::new(message, keypair)
        .detached()
        .build()
        .map_err(|e| CryptoError::SigningFailed(format!("signer: {}", e)))?;
    signer
        .write_all(data)
        .map_err(|e| CryptoError::SigningFailed(format!("write: {}", e)))?;
    signer
        .finalize()
        .map_err(|e| CryptoError::SigningFailed(format!("finalize: {}", e)))?;

    Ok(sig_bytes)
}

/// Encrypt an attachment, returning (key_packets, data_packets).
pub fn encrypt_attachment(keyring: &Keyring, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = keyring.first_key()?;
    let policy = StandardPolicy::new();
    let recipients = key
        .cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .for_transport_encryption()
        .for_storage_encryption();

    let mut ciphertext = Vec::new();
    let message = Message::new(&mut ciphertext);
    let encryptor = openpgp::serialize::stream::Encryptor2::for_recipients(message, recipients)
        .build()
        .map_err(|e| CryptoError::EncryptionFailed(format!("encryptor: {}", e)))?;
    let mut writer = LiteralWriter::new(encryptor)
        .build()
        .map_err(|e| CryptoError::EncryptionFailed(format!("literal: {}", e)))?;
    writer
        .write_all(data)
        .map_err(|e| CryptoError::EncryptionFailed(format!("write: {}", e)))?;
    writer
        .finalize()
        .map_err(|e| CryptoError::EncryptionFailed(format!("finalize: {}", e)))?;

    // Split into key packets and data packets
    let pile = openpgp::PacketPile::from_bytes(&ciphertext)
        .map_err(|e| CryptoError::EncryptionFailed(format!("parse packets: {}", e)))?;
    let packets: Vec<_> = pile.into_children().collect();

    let mut key_packets = Vec::new();
    let mut data_packets = Vec::new();
    let mut seen_encrypted = false;

    for pkt in &packets {
        let mut buf = Vec::new();
        pkt.serialize(&mut buf)
            .map_err(|e| CryptoError::EncryptionFailed(format!("serialize: {}", e)))?;
        if !seen_encrypted {
            match pkt {
                openpgp::Packet::PKESK(_) => {
                    key_packets.extend_from_slice(&buf);
                }
                _ => {
                    seen_encrypted = true;
                    data_packets.extend_from_slice(&buf);
                }
            }
        } else {
            data_packets.extend_from_slice(&buf);
        }
    }

    Ok((key_packets, data_packets))
}

/// Extract the session key from attachment key packets using the keyring.
/// This is used during sending to get the attachment session key for the send package.
pub fn extract_attachment_session_key(
    keyring: &Keyring,
    key_packets: &[u8],
) -> super::Result<SessionKeyData> {
    // We only have key packets, no data packets. Parse just the PKESKs.
    let pile = openpgp::PacketPile::from_bytes(key_packets)
        .map_err(|e| CryptoError::SessionKeyError(format!("parse key packets: {}", e)))?;

    let policy = StandardPolicy::new();

    for pkt in pile.children() {
        if let openpgp::Packet::PKESK(pkesk) = pkt {
            for unlocked_key in &keyring.keys {
                for ka in unlocked_key
                    .cert
                    .keys()
                    .with_policy(&policy, None)
                    .supported()
                    .secret()
                    .for_transport_encryption()
                    .for_storage_encryption()
                {
                    let secret = match ka.key().clone().parts_into_secret() {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let decrypted = match secret.decrypt_secret(&unlocked_key.password) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };
                    let mut keypair = match decrypted.into_keypair() {
                        Ok(kp) => kp,
                        Err(_) => continue,
                    };

                    if let Some((algo, sk)) = pkesk.decrypt(&mut keypair, None) {
                        let algo_str = match algo {
                            openpgp::types::SymmetricAlgorithm::AES128 => "aes128",
                            openpgp::types::SymmetricAlgorithm::AES192 => "aes192",
                            openpgp::types::SymmetricAlgorithm::AES256 => "aes256",
                            other => {
                                return Err(CryptoError::SessionKeyError(format!(
                                    "unsupported algorithm: {:?}",
                                    other
                                )));
                            }
                        };

                        return Ok(SessionKeyData {
                            key: sk.to_vec(),
                            algorithm: algo_str.to_string(),
                        });
                    }
                }
            }
        }
    }

    Err(CryptoError::SessionKeyError(
        "could not decrypt attachment session key".to_string(),
    ))
}

/// Extract the session key by decrypting the PKESK packets with the keyring.
fn extract_session_key(
    keyring: &Keyring,
    key_packets: &[u8],
    data_packets: &[u8],
) -> Result<SessionKeyData> {
    // Reassemble the full PGP message
    let mut full_message = key_packets.to_vec();
    full_message.extend_from_slice(data_packets);

    // Parse PKESK packets to extract the session key
    let pile = openpgp::PacketPile::from_bytes(&full_message)
        .map_err(|e| CryptoError::SessionKeyError(format!("parse: {}", e)))?;

    let policy = StandardPolicy::new();

    for pkt in pile.children() {
        if let openpgp::Packet::PKESK(pkesk) = pkt {
            for unlocked_key in &keyring.keys {
                for ka in unlocked_key
                    .cert
                    .keys()
                    .with_policy(&policy, None)
                    .supported()
                    .secret()
                    .for_transport_encryption()
                    .for_storage_encryption()
                {
                    let secret = match ka.key().clone().parts_into_secret() {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let decrypted = match secret.decrypt_secret(&unlocked_key.password) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };
                    let mut keypair = match decrypted.into_keypair() {
                        Ok(kp) => kp,
                        Err(_) => continue,
                    };

                    if let Some((algo, sk)) = pkesk.decrypt(&mut keypair, None) {
                        let algo_str = match algo {
                            openpgp::types::SymmetricAlgorithm::AES128 => "aes128",
                            openpgp::types::SymmetricAlgorithm::AES192 => "aes192",
                            openpgp::types::SymmetricAlgorithm::AES256 => "aes256",
                            other => {
                                return Err(CryptoError::SessionKeyError(format!(
                                    "unsupported algorithm: {:?}",
                                    other
                                )));
                            }
                        };

                        return Ok(SessionKeyData {
                            key: sk.to_vec(),
                            algorithm: algo_str.to_string(),
                        });
                    }
                }
            }
        }
    }

    Err(CryptoError::SessionKeyError(
        "could not decrypt session key".to_string(),
    ))
}

fn parse_algorithm(algo: &str) -> Result<openpgp::types::SymmetricAlgorithm> {
    match algo {
        "aes128" => Ok(openpgp::types::SymmetricAlgorithm::AES128),
        "aes192" => Ok(openpgp::types::SymmetricAlgorithm::AES192),
        "aes256" => Ok(openpgp::types::SymmetricAlgorithm::AES256),
        other => Err(CryptoError::SessionKeyError(format!(
            "unsupported algorithm: {}",
            other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use openpgp::cert::CertBuilder;
    use openpgp::crypto::Password;
    use openpgp::parse::stream::{MessageStructure, VerificationHelper};

    use crate::crypto::keys::UnlockedKey;

    fn make_test_keyring() -> (openpgp::Cert, Keyring) {
        let password = "test-pass";
        let (cert, _) = CertBuilder::general_purpose(None, Some("test@test.com"))
            .set_password(Some(Password::from(password)))
            .generate()
            .unwrap();

        let keyring = Keyring::new(vec![UnlockedKey::new(cert.clone(), password)]);
        (cert, keyring)
    }

    #[test]
    fn test_encrypt_armored_roundtrip() {
        let (_, keyring) = make_test_keyring();
        let plaintext = b"hello, encrypted world!";

        let armored = keyring.encrypt_armored(plaintext).unwrap();
        assert!(armored.contains("BEGIN PGP MESSAGE"));

        let decrypted = keyring.decrypt_armored(&armored).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_and_sign_roundtrip() {
        let (_, keyring) = make_test_keyring();
        let plaintext = b"signed and encrypted";

        let ciphertext = keyring.encrypt_and_sign(plaintext).unwrap();
        let decrypted = keyring.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_enc_split_roundtrip() {
        let (cert, keyring) = make_test_keyring();
        let body = "This is the message body for enc_split test.";

        let (session_key, data_packets) = enc_split(&keyring, body).unwrap();

        // Verify session key was extracted
        assert!(!session_key.key.is_empty());
        assert!(!session_key.algorithm.is_empty());
        assert!(!data_packets.is_empty());

        // Re-encrypt the session key to our own cert and verify we can decrypt
        let key_packets = encrypt_session_key(&cert, &session_key).unwrap();

        // Concatenate key_packets + data_packets to form a valid PGP message
        let mut full_msg = key_packets;
        full_msg.extend_from_slice(&data_packets);

        // Decrypt using the same keyring
        let decrypted = keyring.decrypt(&full_msg).unwrap();
        assert_eq!(String::from_utf8_lossy(&decrypted), body);
    }

    #[test]
    fn test_encrypt_session_key_roundtrip() {
        let (cert, _keyring) = make_test_keyring();

        // Create a known session key
        let session_key = SessionKeyData {
            key: vec![0x42; 32],
            algorithm: "aes256".to_string(),
        };

        // Encrypt the session key to our cert
        let key_packets = encrypt_session_key(&cert, &session_key).unwrap();
        assert!(!key_packets.is_empty());

        // Verify the PKESK can be parsed
        let pile = openpgp::PacketPile::from_bytes(&key_packets).unwrap();
        let has_pkesk = pile
            .children()
            .any(|p| matches!(p, openpgp::Packet::PKESK(_)));
        assert!(has_pkesk);
    }

    #[test]
    fn test_sign_detached_verify() {
        let (cert, keyring) = make_test_keyring();
        let data = b"data to sign";

        let sig_bytes = sign_detached(&keyring, data).unwrap();
        assert!(!sig_bytes.is_empty());

        // Verify the detached signature
        let policy = StandardPolicy::new();

        struct CertHelper(Cert);
        impl VerificationHelper for CertHelper {
            fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
                Ok(vec![self.0.clone()])
            }
            fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
                for layer in structure {
                    if let openpgp::parse::stream::MessageLayer::SignatureGroup { ref results } =
                        layer
                    {
                        if results.iter().any(|r| r.is_err()) {
                            return Err(anyhow::anyhow!("signature verification failed"));
                        }
                    }
                }
                Ok(())
            }
        }

        let helper = CertHelper(cert);
        let mut verifier = openpgp::parse::stream::DetachedVerifierBuilder::from_bytes(&sig_bytes)
            .unwrap()
            .with_policy(&policy, None, helper)
            .unwrap();
        verifier.verify_bytes(data).unwrap();
    }

    #[test]
    fn test_encrypt_attachment_roundtrip() {
        let (_, keyring) = make_test_keyring();
        let data = b"attachment file content here for encrypt test";

        let (key_packets, data_packets) = encrypt_attachment(&keyring, data).unwrap();
        assert!(!key_packets.is_empty());
        assert!(!data_packets.is_empty());

        // Decrypt by reassembling
        let mut full_message = key_packets;
        full_message.extend_from_slice(&data_packets);

        let decrypted = keyring.decrypt(&full_message).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypt_attachment_split_matches_decrypt_attachment() {
        let (_, keyring) = make_test_keyring();
        let data = b"attachment for base64 test";

        let (key_packets, data_packets) = encrypt_attachment(&keyring, data).unwrap();

        // Use the existing decrypt_attachment function with base64 key packets
        let key_packets_b64 = BASE64.encode(&key_packets);
        let decrypted =
            crate::crypto::decrypt::decrypt_attachment(&keyring, &key_packets_b64, &data_packets)
                .unwrap();
        assert_eq!(decrypted, data);
    }
}
