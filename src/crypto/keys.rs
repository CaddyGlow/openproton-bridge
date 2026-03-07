use std::io::{Read, Write};

use openpgp::crypto::{Password, SessionKey};
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor2, LiteralWriter, Message, Signer};
use openpgp::types::SymmetricAlgorithm;
use openpgp::Cert;
use sequoia_openpgp as openpgp;
use zeroize::Zeroize;

use crate::api::types::{AddressKey, UserKey};

use super::{CryptoError, Result};

/// An unlocked PGP key: the cert plus the password needed to access secret key material.
pub struct UnlockedKey {
    pub cert: Cert,
    pub(crate) password: Password,
}

impl UnlockedKey {
    pub fn new(cert: Cert, password: impl Into<Password>) -> Self {
        Self {
            cert,
            password: password.into(),
        }
    }
}

/// A collection of unlocked keys that can decrypt messages.
pub struct Keyring {
    pub(crate) keys: Vec<UnlockedKey>,
}

impl Keyring {
    pub fn new(keys: Vec<UnlockedKey>) -> Self {
        Self { keys }
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Get a reference to the first unlocked key.
    pub fn first_key(&self) -> Result<&UnlockedKey> {
        self.keys.first().ok_or(CryptoError::NoActiveKey)
    }

    /// Encrypt plaintext to the first key, return armored PGP message.
    pub fn encrypt_armored(&self, plaintext: &[u8]) -> Result<String> {
        let key = self.first_key()?;
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
        let armorer = openpgp::serialize::stream::Armorer::new(message)
            .kind(openpgp::armor::Kind::Message)
            .build()
            .map_err(|e| CryptoError::EncryptionFailed(format!("armorer: {}", e)))?;
        let encryptor = Encryptor2::for_recipients(armorer, recipients)
            .build()
            .map_err(|e| CryptoError::EncryptionFailed(format!("encryptor: {}", e)))?;
        let mut writer = LiteralWriter::new(encryptor)
            .build()
            .map_err(|e| CryptoError::EncryptionFailed(format!("literal: {}", e)))?;
        writer
            .write_all(plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(format!("write: {}", e)))?;
        writer
            .finalize()
            .map_err(|e| CryptoError::EncryptionFailed(format!("finalize: {}", e)))?;

        String::from_utf8(ciphertext)
            .map_err(|e| CryptoError::EncryptionFailed(format!("utf8: {}", e)))
    }

    /// Encrypt and sign plaintext to the first key, return binary PGP message.
    pub fn encrypt_and_sign(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = self.first_key()?;
        let policy = StandardPolicy::new();
        let recipients = key
            .cert
            .keys()
            .with_policy(&policy, None)
            .supported()
            .for_transport_encryption()
            .for_storage_encryption();

        // Get a signing-capable key
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

        let mut ciphertext = Vec::new();
        let message = Message::new(&mut ciphertext);
        let encryptor = Encryptor2::for_recipients(message, recipients)
            .build()
            .map_err(|e| CryptoError::EncryptionFailed(format!("encryptor: {}", e)))?;
        let signer = Signer::new(encryptor, keypair)
            .build()
            .map_err(|e| CryptoError::SigningFailed(format!("signer: {}", e)))?;
        let mut writer = LiteralWriter::new(signer)
            .build()
            .map_err(|e| CryptoError::EncryptionFailed(format!("literal: {}", e)))?;
        writer
            .write_all(plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(format!("write: {}", e)))?;
        writer
            .finalize()
            .map_err(|e| CryptoError::EncryptionFailed(format!("finalize: {}", e)))?;

        Ok(ciphertext)
    }

    /// Decrypt an armored PGP message.
    pub fn decrypt_armored(&self, armored: &str) -> Result<Vec<u8>> {
        // Sequoia's PacketParser handles armor transparently.
        self.decrypt(armored.as_bytes())
    }

    /// Decrypt a PGP message (binary or armored).
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let policy = StandardPolicy::new();
        let helper = KeyringHelper { keyring: self };

        let decryptor = DecryptorBuilder::from_bytes(ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed(format!("parse: {}", e)))?
            .with_policy(&policy, None, helper)
            .map_err(|e| CryptoError::DecryptionFailed(format!("decrypt: {}", e)))?;

        let mut plaintext = Vec::new();
        let mut reader = decryptor;
        reader
            .read_to_end(&mut plaintext)
            .map_err(|e| CryptoError::DecryptionFailed(format!("read: {}", e)))?;

        Ok(plaintext)
    }

    /// Decrypt from a reader (for streaming, e.g. attachments).
    pub fn decrypt_reader(&self, reader: impl Read + Send + Sync) -> Result<Vec<u8>> {
        let policy = StandardPolicy::new();
        let helper = KeyringHelper { keyring: self };

        let decryptor = DecryptorBuilder::from_reader(reader)
            .map_err(|e| CryptoError::DecryptionFailed(format!("parse: {}", e)))?
            .with_policy(&policy, None, helper)
            .map_err(|e| CryptoError::DecryptionFailed(format!("decrypt: {}", e)))?;

        let mut plaintext = Vec::new();
        let mut r = decryptor;
        r.read_to_end(&mut plaintext)
            .map_err(|e| CryptoError::DecryptionFailed(format!("read: {}", e)))?;

        Ok(plaintext)
    }
}

/// Unlock user keys with the derived mailbox passphrase.
///
/// For each active UserKey, parse the armored private key and decrypt it
/// with the passphrase. Returns a Keyring of successfully unlocked keys.
///
/// Reference: go-proton-api/keyring.go Keys.Unlock
pub fn unlock_user_keys(user_keys: &[UserKey], passphrase: &[u8]) -> Result<Keyring> {
    let mut passphrase_copy = passphrase.to_vec();
    let password = Password::from(passphrase_copy.clone());
    passphrase_copy.zeroize();
    let mut unlocked = Vec::new();

    for key in user_keys.iter().filter(|k| k.active == 1) {
        match unlock_armored_key(&key.private_key, &password) {
            Ok(cert) => unlocked.push(UnlockedKey {
                cert,
                password: password.clone(),
            }),
            Err(e) => {
                tracing::warn!(key_id = %key.id, error = %e, "cannot unlock user key");
            }
        }
    }

    if unlocked.is_empty() {
        return Err(CryptoError::NoActiveKey);
    }

    Ok(Keyring::new(unlocked))
}

/// Unlock address keys using the mailbox passphrase and optionally the user keyring
/// for token-based key migration.
///
/// For each active AddressKey:
/// - If token + signature are present: decrypt token with user keyring to get passphrase
/// - Otherwise: use the mailbox passphrase directly
///
/// Reference: go-proton-api/keyring.go Key.Unlock
pub fn unlock_address_keys(
    addr_keys: &[AddressKey],
    passphrase: &[u8],
    user_keyring: &Keyring,
) -> Result<Keyring> {
    let mut passphrase_copy = passphrase.to_vec();
    let direct_password = Password::from(passphrase_copy.clone());
    passphrase_copy.zeroize();
    let mut unlocked = Vec::new();

    for key in addr_keys.iter().filter(|k| k.active == 1) {
        let has_token_material = key
            .token
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
            && key
                .signature
                .as_deref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false);

        let (cert, pw) = if has_token_material {
            // Token-based: decrypt the token with user keys to get the real passphrase
            let token_armored = key.token.as_deref().unwrap();
            match user_keyring.decrypt_armored(token_armored) {
                Ok(token_passphrase) => {
                    let token_password = Password::from(token_passphrase);
                    match unlock_armored_key(&key.private_key, &token_password) {
                        Ok(cert) => (cert, token_password),
                        Err(e) => {
                            tracing::warn!(key_id = %key.id, error = %e, "cannot unlock address key");
                            continue;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(key_id = %key.id, error = %e, "cannot decrypt address key token");
                    continue;
                }
            }
        } else {
            match unlock_armored_key(&key.private_key, &direct_password) {
                Ok(cert) => (cert, direct_password.clone()),
                Err(e) => {
                    tracing::warn!(key_id = %key.id, error = %e, "cannot unlock address key");
                    continue;
                }
            }
        };

        unlocked.push(UnlockedKey { cert, password: pw });
    }

    if unlocked.is_empty() {
        return Err(CryptoError::NoActiveKey);
    }

    Ok(Keyring::new(unlocked))
}

/// Unlock arbitrary armored private keys using the provided passphrase.
///
/// This is used for non-mailbox key material, such as Proton Calendar keys
/// that are returned from the Calendar API bootstrap endpoints.
pub fn unlock_private_keys<'a, I>(armored_keys: I, passphrase: &[u8]) -> Result<Keyring>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut passphrase_copy = passphrase.to_vec();
    let password = Password::from(passphrase_copy.clone());
    passphrase_copy.zeroize();

    let mut unlocked = Vec::new();
    for armored in armored_keys {
        match unlock_armored_key(armored, &password) {
            Ok(cert) => unlocked.push(UnlockedKey {
                cert,
                password: password.clone(),
            }),
            Err(e) => {
                tracing::warn!(error = %e, "cannot unlock private key");
            }
        }
    }

    if unlocked.is_empty() {
        return Err(CryptoError::NoActiveKey);
    }

    Ok(Keyring::new(unlocked))
}

/// Parse an armored PGP private key and verify it can be decrypted with the given password.
fn unlock_armored_key(armored: &str, password: &Password) -> Result<Cert> {
    let cert = Cert::from_bytes(armored.as_bytes())
        .map_err(|e| CryptoError::UnlockFailed(format!("parse key: {}", e)))?;

    let policy = StandardPolicy::new();
    let mut found_decryptable = false;

    for ka in cert.keys().with_policy(&policy, None).supported().secret() {
        let secret = ka
            .key()
            .clone()
            .parts_into_secret()
            .map_err(|e| CryptoError::UnlockFailed(format!("parts_into_secret: {}", e)))?;

        match secret.decrypt_secret(password) {
            Ok(_) => {
                found_decryptable = true;
                break;
            }
            Err(_) => continue,
        }
    }

    if !found_decryptable {
        return Err(CryptoError::UnlockFailed(
            "no key decryptable with given passphrase".to_string(),
        ));
    }

    Ok(cert)
}

/// Helper struct implementing DecryptionHelper for sequoia's Decryptor.
struct KeyringHelper<'a> {
    keyring: &'a Keyring,
}

impl VerificationHelper for KeyringHelper<'_> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self.keyring.keys.iter().map(|k| k.cert.clone()).collect())
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for KeyringHelper<'_> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        let policy = StandardPolicy::new();
        let mut attempts = 0usize;
        let mut failures = 0usize;

        for pkesk in pkesks {
            tracing::trace!(
                keys_available = self.keyring.keys.len(),
                "starting pkesk decryption attempt"
            );
            for unlocked_key in &self.keyring.keys {
                for ka in unlocked_key
                    .cert
                    .keys()
                    .with_policy(&policy, None)
                    .supported()
                    .secret()
                {
                    attempts += 1;
                    tracing::trace!(keyid = %ka.keyid(), "trying secret key for message decryption");
                    let secret = match ka.key().clone().parts_into_secret() {
                        Ok(secret) => secret,
                        Err(e) => {
                            failures += 1;
                            tracing::trace!(keyid = %ka.keyid(), error = %e, "parts_into_secret failed");
                            continue;
                        }
                    };

                    // Decrypt the secret key material with our stored password.
                    let decrypted = match secret.decrypt_secret(&unlocked_key.password) {
                        Ok(d) => d,
                        Err(e) => {
                            failures += 1;
                            tracing::trace!(keyid = %ka.keyid(), error = %e, "decrypt_secret failed");
                            continue;
                        }
                    };

                    let mut keypair = match decrypted.into_keypair() {
                        Ok(keypair) => keypair,
                        Err(e) => {
                            failures += 1;
                            tracing::trace!(keyid = %ka.keyid(), error = %e, "into_keypair failed");
                            continue;
                        }
                    };

                    if let Some((algo, sk)) = pkesk.decrypt(&mut keypair, sym_algo) {
                        tracing::trace!(keyid = %ka.keyid(), sym_algo = ?algo, "pkesk decrypted, testing session key");
                        if decrypt(algo, &sk) {
                            tracing::debug!(
                                keyid = %ka.keyid(),
                                attempts,
                                failures,
                                "message decryption succeeded"
                            );
                            return Ok(Some(ka.fingerprint()));
                        }
                        failures += 1;
                        tracing::trace!(keyid = %ka.keyid(), "session key rejected");
                    }
                }
            }
        }

        tracing::debug!(
            attempts,
            failures,
            "message decryption failed for all available keys"
        );

        Err(anyhow::anyhow!("no key could decrypt the message"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::cert::CertBuilder;
    use openpgp::policy::StandardPolicy;
    use openpgp::serialize::stream::{Encryptor2, LiteralWriter, Message};
    use openpgp::serialize::Serialize;
    use std::io::Write;

    fn generate_test_cert(password: &str) -> (Cert, String) {
        let (cert, _) = CertBuilder::general_purpose(None, Some("test@test.com"))
            .set_password(Some(Password::from(password)))
            .generate()
            .unwrap();

        let mut armored_buf = Vec::new();
        let mut armor_writer =
            openpgp::armor::Writer::new(&mut armored_buf, openpgp::armor::Kind::SecretKey).unwrap();
        cert.as_tsk().serialize(&mut armor_writer).unwrap();
        armor_writer.finalize().unwrap();

        let armored = String::from_utf8(armored_buf).unwrap();
        (cert, armored)
    }

    fn encrypt_to_cert(cert: &Cert, plaintext: &[u8]) -> Vec<u8> {
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

    fn make_keyring(cert: &Cert, password: &str) -> Keyring {
        Keyring::new(vec![UnlockedKey {
            cert: cert.clone(),
            password: Password::from(password),
        }])
    }

    #[test]
    fn test_unlock_armored_key_correct_password() {
        let password = "test-passphrase";
        let (_, armored) = generate_test_cert(password);
        let result = unlock_armored_key(&armored, &Password::from(password));
        assert!(result.is_ok());
    }

    #[test]
    fn test_unlock_armored_key_wrong_password() {
        let (_, armored) = generate_test_cert("correct");
        let result = unlock_armored_key(&armored, &Password::from("wrong"));
        assert!(result.is_err());
    }

    #[test]
    fn test_keyring_decrypt() {
        let password = "test-passphrase";
        let (cert, _) = generate_test_cert(password);

        let plaintext = b"hello, encrypted world!";
        let ciphertext = encrypt_to_cert(&cert, plaintext);

        let keyring = make_keyring(&cert, password);
        let decrypted = keyring.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_keyring_decrypt_wrong_key() {
        let (cert1, _) = generate_test_cert("pass1");
        let (cert2, _) = generate_test_cert("pass2");

        let plaintext = b"secret message";
        let ciphertext = encrypt_to_cert(&cert1, plaintext);

        let keyring = make_keyring(&cert2, "pass2");
        let result = keyring.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_keyring_decrypt_multiple_keys() {
        let (cert1, _) = generate_test_cert("pass1");
        let (cert2, _) = generate_test_cert("pass2");

        let plaintext = b"message for cert2";
        let ciphertext = encrypt_to_cert(&cert2, plaintext);

        let keyring = Keyring::new(vec![
            UnlockedKey {
                cert: cert1,
                password: Password::from("pass1"),
            },
            UnlockedKey {
                cert: cert2,
                password: Password::from("pass2"),
            },
        ]);

        let decrypted = keyring.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_unlock_user_keys_success() {
        let password = "mailbox-pass";
        let (_, armored) = generate_test_cert(password);

        let user_keys = vec![UserKey {
            id: "key-1".to_string(),
            private_key: armored,
            token: None,
            signature: None,
            primary: None,
            flags: None,
            active: 1,
        }];

        let keyring = unlock_user_keys(&user_keys, password.as_bytes()).unwrap();
        assert!(!keyring.is_empty());
    }

    #[test]
    fn test_unlock_user_keys_skips_inactive() {
        let password = "mailbox-pass";
        let (_, armored) = generate_test_cert(password);

        let user_keys = vec![UserKey {
            id: "key-1".to_string(),
            private_key: armored,
            token: None,
            signature: None,
            primary: None,
            flags: None,
            active: 0,
        }];

        let result = unlock_user_keys(&user_keys, password.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_unlock_and_decrypt_roundtrip() {
        let password = "roundtrip-pass";
        let (cert, armored) = generate_test_cert(password);

        let plaintext = b"roundtrip test message";
        let ciphertext = encrypt_to_cert(&cert, plaintext);

        let user_keys = vec![UserKey {
            id: "key-1".to_string(),
            private_key: armored,
            token: None,
            signature: None,
            primary: None,
            flags: None,
            active: 1,
        }];

        let keyring = unlock_user_keys(&user_keys, password.as_bytes()).unwrap();
        let decrypted = keyring.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
