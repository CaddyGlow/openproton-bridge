use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use super::keys::Keyring;
use super::Result;

/// Decrypt a PGP-armored message body using the address keyring.
///
/// Reference: go-proton-api/message_types.go Message.Decrypt
pub fn decrypt_message_body(keyring: &Keyring, armored_body: &str) -> Result<Vec<u8>> {
    keyring.decrypt_armored(armored_body)
}

/// Decrypt an attachment given its base64-encoded key packets and raw encrypted data.
///
/// Proton stores attachments as two parts:
/// - key_packets: base64-encoded PGP key packets (encrypted session key)
/// - encrypted_data: raw encrypted data packets
///
/// Concatenating them forms a complete PGP message that can be decrypted.
///
/// Reference: proton-bridge/pkg/message/decrypt.go DecryptMessage (attachment section)
pub fn decrypt_attachment(
    keyring: &Keyring,
    key_packets_b64: &str,
    encrypted_data: &[u8],
) -> Result<Vec<u8>> {
    let key_packets = BASE64.decode(key_packets_b64)?;

    let mut full_message = key_packets;
    full_message.extend_from_slice(encrypted_data);

    keyring.decrypt(&full_message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::cert::CertBuilder;
    use openpgp::crypto::Password;
    use openpgp::parse::Parse;
    use openpgp::policy::StandardPolicy;
    use openpgp::serialize::stream::{Encryptor2, LiteralWriter, Message};
    use sequoia_openpgp as openpgp;
    use std::io::Write;

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

    fn encrypt_armored(cert: &openpgp::Cert, plaintext: &[u8]) -> String {
        let policy = StandardPolicy::new();
        let recipients = cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .for_transport_encryption()
            .for_storage_encryption();

        let mut ciphertext = Vec::new();
        let message = Message::new(&mut ciphertext);
        let armorer = openpgp::serialize::stream::Armorer::new(message)
            .kind(openpgp::armor::Kind::Message)
            .build()
            .unwrap();
        let encryptor = Encryptor2::for_recipients(armorer, recipients)
            .build()
            .unwrap();
        let mut writer = LiteralWriter::new(encryptor).build().unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finalize().unwrap();

        String::from_utf8(ciphertext).unwrap()
    }

    fn encrypt_binary(cert: &openpgp::Cert, plaintext: &[u8]) -> Vec<u8> {
        let policy = StandardPolicy::new();
        let recipients = cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .for_transport_encryption()
            .for_storage_encryption();

        let mut ciphertext = Vec::new();
        let message = Message::new(&mut ciphertext);
        let encryptor = Encryptor2::for_recipients(message, recipients)
            .build()
            .unwrap();
        let mut writer = LiteralWriter::new(encryptor).build().unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finalize().unwrap();

        ciphertext
    }

    #[test]
    fn test_decrypt_message_body() {
        let (cert, keyring) = make_test_keyring();
        let plaintext = b"Subject: Hello\r\n\r\nThis is the email body.";
        let armored = encrypt_armored(&cert, plaintext);

        let decrypted = decrypt_message_body(&keyring, &armored).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_message_body_wrong_key() {
        let (cert, _) = make_test_keyring();
        let (_, wrong_keyring) = make_test_keyring();

        let plaintext = b"secret content";
        let armored = encrypt_armored(&cert, plaintext);

        let result = decrypt_message_body(&wrong_keyring, &armored);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_attachment() {
        let (cert, keyring) = make_test_keyring();
        let plaintext = b"attachment file content here";

        let full_pgp = encrypt_binary(&cert, plaintext);

        // Split into key packets (PKESK) and data packets (SEIPD)
        let ppr = openpgp::PacketPile::from_bytes(&full_pgp).unwrap();
        let packets: Vec<_> = ppr.into_children().collect();

        let mut key_packets = Vec::new();
        let mut data_packets = Vec::new();
        let mut seen_encrypted = false;

        for pkt in &packets {
            let mut buf = Vec::new();
            openpgp::serialize::Serialize::serialize(pkt, &mut buf).unwrap();
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

        let key_packets_b64 = BASE64.encode(&key_packets);
        let decrypted = decrypt_attachment(&keyring, &key_packets_b64, &data_packets).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_attachment_corrupted_data() {
        let (_, keyring) = make_test_keyring();
        let result = decrypt_attachment(&keyring, &BASE64.encode(b"garbage"), b"more garbage");
        assert!(result.is_err());
    }
}
