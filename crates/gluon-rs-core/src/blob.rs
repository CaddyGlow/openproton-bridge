use std::io::{Read, Write};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use lz4_flex::frame::{FrameDecoder, FrameEncoder};
use sha2::{Digest, Sha256};

use crate::{
    error::{GluonCoreError, Result},
    key::GluonKey,
};

const BLOCK_SIZE: usize = 64 * 4096;
const NONCE_SIZE: usize = 12;
const ENCRYPTION_OVERHEAD: usize = 16;
const STORE_VERSION: u32 = 1;
const STORE_HEADER_ID: &[u8] = b"GLUON-CACHE";

pub fn encode_blob(key: &GluonKey, data: &[u8]) -> Result<Vec<u8>> {
    let cipher = new_cipher(key)?;
    let generated_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&generated_nonce);
    let compressed = compress(data)?;

    let mut out = make_header_bytes();
    out.extend_from_slice(&nonce);

    for (chunk_index, chunk) in compressed.chunks(BLOCK_SIZE).enumerate() {
        let nonce = nonce_for_chunk(&nonce, chunk_index);
        out.extend_from_slice(&cipher.encrypt(Nonce::from_slice(&nonce), chunk)?);
    }

    Ok(out)
}

pub fn decode_blob(key: &GluonKey, data: &[u8]) -> Result<Vec<u8>> {
    let header = make_header_bytes();
    let cipher = new_cipher(key)?;
    let nonce = parse_nonce(data, &header)?;
    let encrypted = &data[header.len() + NONCE_SIZE..];

    decompress(&decrypt_blocks(&cipher, &nonce, encrypted)?)
}

pub fn is_gluon_store_blob(data: &[u8]) -> bool {
    data.starts_with(&make_header_bytes())
}

fn new_cipher(key: &GluonKey) -> Result<Aes256Gcm> {
    let hashed = Sha256::digest(key.as_bytes());
    Aes256Gcm::new_from_slice(&hashed).map_err(|_| GluonCoreError::Crypto)
}

fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = FrameEncoder::new(Vec::new());
    encoder.write_all(data)?;
    encoder
        .finish()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err).into())
}

fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = FrameDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

fn make_header_bytes() -> Vec<u8> {
    let mut header = STORE_HEADER_ID.to_vec();
    header.extend_from_slice(&STORE_VERSION.to_le_bytes());
    header
}

fn parse_nonce(data: &[u8], header: &[u8]) -> Result<[u8; NONCE_SIZE]> {
    if !data.starts_with(header) {
        return Err(GluonCoreError::InvalidBlob {
            reason: "missing gluon store header".to_string(),
        });
    }

    let minimum_len = header.len() + NONCE_SIZE;
    if data.len() < minimum_len {
        return Err(GluonCoreError::InvalidBlob {
            reason: format!(
                "blob shorter than header+nonce (have {}, need at least {})",
                data.len(),
                minimum_len
            ),
        });
    }

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&data[header.len()..minimum_len]);
    Ok(nonce)
}

fn nonce_for_chunk(base_nonce: &[u8; NONCE_SIZE], chunk_index: usize) -> [u8; NONCE_SIZE] {
    let mut nonce = *base_nonce;
    let mut counter = u32::from_be_bytes(nonce[NONCE_SIZE - 4..].try_into().expect("nonce tail"));
    counter = counter.wrapping_add(u32::try_from(chunk_index).unwrap_or(u32::MAX));
    nonce[NONCE_SIZE - 4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn decrypt_blocks(
    cipher: &Aes256Gcm,
    nonce: &[u8; NONCE_SIZE],
    encrypted: &[u8],
) -> Result<Vec<u8>> {
    let encrypted_block_size = BLOCK_SIZE + ENCRYPTION_OVERHEAD;
    let mut decrypted = Vec::new();

    for (chunk_index, chunk) in encrypted.chunks(encrypted_block_size).enumerate() {
        if chunk.len() < ENCRYPTION_OVERHEAD {
            return Err(GluonCoreError::InvalidBlob {
                reason: format!(
                    "encrypted chunk {} shorter than authentication tag",
                    chunk_index
                ),
            });
        }

        let chunk_nonce = nonce_for_chunk(nonce, chunk_index);
        decrypted.extend_from_slice(&cipher.decrypt(Nonce::from_slice(&chunk_nonce), chunk)?);
    }

    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use crate::{key::GluonKey, GluonCoreError};

    use super::{decode_blob, encode_blob, is_gluon_store_blob, make_header_bytes, NONCE_SIZE};

    #[test]
    fn round_trips_gluon_store_blob() {
        let key = GluonKey::try_from_slice(&[7u8; 32]).expect("key");
        let payload = vec![42u8; 300_000];

        let encoded = encode_blob(&key, &payload).expect("encode");
        assert!(is_gluon_store_blob(&encoded));
        assert_eq!(decode_blob(&key, &encoded).expect("decode"), payload);
    }

    #[test]
    fn rejects_truncated_blob_without_panicking() {
        let key = GluonKey::try_from_slice(&[7u8; 32]).expect("key");
        let mut encoded = encode_blob(&key, b"hello").expect("encode");
        encoded.truncate(make_header_bytes().len() + NONCE_SIZE - 1);

        let err = decode_blob(&key, &encoded).unwrap_err();
        assert!(matches!(err, GluonCoreError::InvalidBlob { .. }));
    }
}
