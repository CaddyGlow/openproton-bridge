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

/// Encrypt an RFC822 message for Proton import.
///
/// Encrypts the entire literal as a PGP/MIME multipart/encrypted message.
/// This mirrors the Go bridge's `encryptFull` fallback path in `EncryptRFC822`.
///
/// The output is a valid RFC822 message with:
/// - Original headers (From, To, Subject, Date, Cc, Message-Id)
/// - Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"
/// - Part 1: PGP version identification
/// - Part 2: The armored PGP-encrypted original message
pub fn encrypt_rfc822(keyring: &Keyring, literal: &[u8]) -> Result<Vec<u8>> {
    // Encrypt the entire literal
    let encrypted = keyring.encrypt_and_sign(literal)?;

    // Armor the encrypted message
    let mut armored = Vec::new();
    let mut armor_writer = openpgp::armor::Writer::new(&mut armored, openpgp::armor::Kind::Message)
        .map_err(|e| CryptoError::EncryptionFailed(format!("armor writer: {}", e)))?;
    armor_writer
        .write_all(&encrypted)
        .map_err(|e| CryptoError::EncryptionFailed(format!("armor write: {}", e)))?;
    armor_writer
        .finalize()
        .map_err(|e| CryptoError::EncryptionFailed(format!("armor finalize: {}", e)))?;
    let armored_str = String::from_utf8(armored)
        .map_err(|e| CryptoError::EncryptionFailed(format!("armor utf8: {}", e)))?;

    // Parse headers from the original message, handling folded (continuation) lines.
    // Folded headers start with whitespace and continue the previous header line.
    let literal_str = String::from_utf8_lossy(literal);
    let header_end = literal_str
        .find("\r\n\r\n")
        .or_else(|| literal_str.find("\n\n"))
        .unwrap_or(literal_str.len());
    let header_section = &literal_str[..header_end];

    let mut parsed_headers: Vec<(String, String)> = Vec::new();
    for line in header_section.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of previous header
            if let Some(last) = parsed_headers.last_mut() {
                last.1.push_str("\r\n");
                last.1.push_str(line);
            }
        } else if let Some(colon) = line.find(':') {
            let name = line[..colon].to_string();
            let value = line[colon + 1..].trim_start().to_string();
            parsed_headers.push((name, value));
        }
    }

    let boundary = uuid::Uuid::new_v4().to_string().replace('-', "");

    let mut output = Vec::new();

    // Write preserved headers (with their folded continuations)
    let preserve = [
        "From",
        "To",
        "Cc",
        "Subject",
        "Date",
        "Message-Id",
        "Received",
    ];
    for (name, value) in &parsed_headers {
        if preserve.iter().any(|h| h.eq_ignore_ascii_case(name)) {
            write!(output, "{}: {}\r\n", name, value)
                .map_err(|e| CryptoError::EncryptionFailed(format!("write header: {}", e)))?;
        }
    }

    // Write MIME headers
    write!(
        output,
        "MIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\"\r\n\r\n"
    )
    .map_err(|e| CryptoError::EncryptionFailed(format!("write headers: {}", e)))?;

    // Part 1: PGP version identification
    write!(
        output,
        "--{boundary}\r\nContent-Description: PGP/MIME version identification\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n"
    )
    .map_err(|e| CryptoError::EncryptionFailed(format!("write part 1: {}", e)))?;

    // Part 2: Encrypted message
    write!(
        output,
        "--{boundary}\r\nContent-Description: OpenPGP encrypted message\r\nContent-Disposition: inline; filename=encrypted.asc\r\nContent-Type: application/octet-stream; name=encrypted.asc\r\n\r\n{armored_str}\r\n"
    )
    .map_err(|e| CryptoError::EncryptionFailed(format!("write part 2: {}", e)))?;

    // Close multipart
    write!(output, "--{boundary}--\r\n")
        .map_err(|e| CryptoError::EncryptionFailed(format!("write boundary: {}", e)))?;

    Ok(output)
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

    #[test]
    fn test_encrypt_rfc822_produces_pgp_mime() {
        let (_, keyring) = make_test_keyring();
        let literal = b"From: alice@proton.me\r\nTo: bob@example.com\r\nSubject: Test\r\nDate: Mon, 10 Mar 2025 12:00:00 +0000\r\n\r\nHello, world!";

        let encrypted = encrypt_rfc822(&keyring, literal).unwrap();
        let encrypted_str = String::from_utf8_lossy(&encrypted);

        // Should preserve original headers
        assert!(
            encrypted_str.contains("From: alice@proton.me"),
            "missing From header"
        );
        assert!(
            encrypted_str.contains("Subject: Test"),
            "missing Subject header"
        );

        // Should have PGP/MIME structure
        assert!(
            encrypted_str.contains("multipart/encrypted"),
            "missing multipart/encrypted"
        );
        assert!(
            encrypted_str.contains("application/pgp-encrypted"),
            "missing pgp-encrypted part"
        );
        assert!(
            encrypted_str.contains("BEGIN PGP MESSAGE"),
            "missing PGP message"
        );
        assert!(
            encrypted_str.contains("END PGP MESSAGE"),
            "missing PGP message end"
        );
    }

    #[test]
    fn test_encrypt_rfc822_roundtrip() {
        let (_, keyring) = make_test_keyring();
        let literal = b"From: alice@proton.me\r\nSubject: Roundtrip\r\n\r\nBody text";

        let encrypted = encrypt_rfc822(&keyring, literal).unwrap();
        let encrypted_str = String::from_utf8_lossy(&encrypted);

        // Extract the armored PGP block and decrypt it
        let begin = encrypted_str.find("-----BEGIN PGP MESSAGE-----").unwrap();
        let end = encrypted_str.find("-----END PGP MESSAGE-----").unwrap()
            + "-----END PGP MESSAGE-----".len();
        let armored = &encrypted_str[begin..end];

        let decrypted = keyring.decrypt_armored(armored).unwrap();
        assert_eq!(decrypted, literal);
    }

    #[test]
    fn test_encrypt_rfc822_preserves_folded_headers() {
        let (_, keyring) = make_test_keyring();
        let literal = b"From: alice@proton.me\r\nSubject: This is a very long\r\n subject that spans multiple lines\r\nTo: bob@example.com\r\n\r\nBody";

        let encrypted = encrypt_rfc822(&keyring, literal).unwrap();
        let encrypted_str = String::from_utf8_lossy(&encrypted);

        // The full folded subject should be preserved
        assert!(
            encrypted_str
                .contains("Subject: This is a very long\r\n subject that spans multiple lines"),
            "folded Subject header not preserved: {encrypted_str}"
        );
    }

    #[test]
    fn test_encrypt_rfc822_uses_uuid_boundary() {
        let (_, keyring) = make_test_keyring();
        let literal = b"From: alice@proton.me\r\n\r\nBody";

        let encrypted = encrypt_rfc822(&keyring, literal).unwrap();
        let encrypted_str = String::from_utf8_lossy(&encrypted);

        // boundary should be a 32-char hex string (uuid v4 without dashes)
        let boundary_start = encrypted_str.find("boundary=\"").unwrap() + 10;
        let boundary_end = encrypted_str[boundary_start..].find('"').unwrap() + boundary_start;
        let boundary = &encrypted_str[boundary_start..boundary_end];
        assert_eq!(boundary.len(), 32, "boundary={boundary}");
        assert!(
            boundary.chars().all(|c| c.is_ascii_hexdigit()),
            "boundary should be hex: {boundary}"
        );
    }
}
