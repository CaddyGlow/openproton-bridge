use std::io::{Read, Write};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use lz4_flex::frame::{FrameDecoder, FrameEncoder};
use sha2::{Digest, Sha256};

use crate::{error::Result, key::GluonKey};

const BLOCK_SIZE: usize = 64 * 4096;
const STORE_VERSION: u32 = 1;
const STORE_HEADER_ID: &[u8] = b"GLUON-CACHE";

pub fn encode_blob(key: &GluonKey, data: &[u8]) -> Result<Vec<u8>> {
    let cipher = new_cipher(key)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let compressed = compress(data)?;

    let mut out = make_header_bytes();
    out.extend_from_slice(&nonce);

    for chunk in compressed.chunks(BLOCK_SIZE) {
        out.extend_from_slice(&cipher.encrypt(&nonce, chunk)?);
    }

    Ok(out)
}

pub fn decode_blob(key: &GluonKey, data: &[u8]) -> Result<Vec<u8>> {
    let header = make_header_bytes();
    let nonce_size = 12usize;
    let overhead = 16usize;
    let cipher = new_cipher(key)?;

    let nonce = Nonce::from_slice(&data[header.len()..header.len() + nonce_size]);
    let encrypted = &data[header.len() + nonce_size..];
    let encrypted_block_size = BLOCK_SIZE + overhead;

    let mut decrypted = Vec::new();
    for chunk in encrypted.chunks(encrypted_block_size) {
        decrypted.extend_from_slice(&cipher.decrypt(nonce, chunk)?);
    }

    decompress(&decrypted)
}

pub fn is_gluon_store_blob(data: &[u8]) -> bool {
    data.starts_with(&make_header_bytes())
}

fn new_cipher(key: &GluonKey) -> Result<Aes256Gcm> {
    let hashed = Sha256::digest(key.as_bytes());
    Aes256Gcm::new_from_slice(&hashed).map_err(|_| crate::GluonError::Crypto)
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

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, process::Command};

    use tempfile::tempdir;

    use crate::key::GluonKey;

    use super::{decode_blob, encode_blob, is_gluon_store_blob};

    #[test]
    fn round_trips_gluon_store_blob() {
        let key = GluonKey::try_from_slice(&[7u8; 32]).expect("key");
        let payload = vec![42u8; 300_000];

        let encoded = encode_blob(&key, &payload).expect("encode");
        assert!(is_gluon_store_blob(&encoded));
        assert_eq!(decode_blob(&key, &encoded).expect("decode"), payload);
    }

    #[test]
    fn interoperates_with_upstream_go_store_when_enabled() {
        if std::env::var_os("GLUON_RS_INTEROP_TEST").is_none() {
            return;
        }

        let gluon_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../gluon")
            .canonicalize()
            .expect("canonicalize sibling gluon checkout");
        assert!(gluon_root.join("go.mod").exists(), "sibling ../gluon checkout missing");

        let key = [11u8; 32];
        let key_hex = to_hex(&key);
        let message_id = "66666666-6666-6666-6666-666666666666";
        let payload = b"hello from rust";

        let rust_store = tempdir().expect("rust store");
        let key_obj = GluonKey::try_from_slice(&key).expect("key");
        let encoded = encode_blob(&key_obj, payload).expect("encode");
        fs::write(rust_store.path().join(message_id), encoded).expect("write rust blob");

        let go_project = tempdir().expect("go project");
        let go_cache = tempdir().expect("go cache");
        let go_modcache = tempdir().expect("go modcache");
        let go_path = tempdir().expect("go path");
        fs::write(
            go_project.path().join("go.mod"),
            format!(
                "module gluonrsinterop\n\ngo 1.24\n\nrequire github.com/ProtonMail/gluon v0.0.0\nreplace github.com/ProtonMail/gluon => {}\n",
                gluon_root.display()
            ),
        )
        .expect("write go.mod");
        fs::write(
            go_project.path().join("main.go"),
            r#"
package main

import (
    "bytes"
    "encoding/hex"
    "fmt"
    "os"

    "github.com/ProtonMail/gluon/imap"
    "github.com/ProtonMail/gluon/store"
)

func main() {
    if len(os.Args) < 5 {
        panic("usage: <mode> <storeDir> <keyHex> <id> [payload]")
    }
    mode := os.Args[1]
    storeDir := os.Args[2]
    key, err := hex.DecodeString(os.Args[3])
    if err != nil {
        panic(err)
    }
    msgID, err := imap.InternalMessageIDFromString(os.Args[4])
    if err != nil {
        panic(err)
    }

    s, err := store.NewOnDiskStore(storeDir, key)
    if err != nil {
        panic(err)
    }
    defer s.Close()

    switch mode {
    case "read":
        b, err := s.Get(msgID)
        if err != nil {
            panic(err)
        }
        os.Stdout.Write(b)
    case "write":
        payload := []byte(os.Args[5])
        if err := s.Set(msgID, bytes.NewReader(payload)); err != nil {
            panic(err)
        }
        fmt.Print("ok")
    default:
        panic("unknown mode")
    }
}
"#,
        )
        .expect("write main.go");

        let tidy = Command::new("go")
            .arg("mod")
            .arg("tidy")
            .env("GO111MODULE", "on")
            .env("GOCACHE", go_cache.path())
            .env("GOMODCACHE", go_modcache.path())
            .env("GOPATH", go_path.path())
            .current_dir(go_project.path())
            .output()
            .expect("go mod tidy");
        assert!(
            tidy.status.success(),
            "go mod tidy failed: {}",
            String::from_utf8_lossy(&tidy.stderr)
        );

        let read = Command::new("go")
            .arg("run")
            .arg(".")
            .arg("read")
            .arg(rust_store.path())
            .arg(&key_hex)
            .arg(message_id)
            .env("GO111MODULE", "on")
            .env("GOCACHE", go_cache.path())
            .env("GOMODCACHE", go_modcache.path())
            .env("GOPATH", go_path.path())
            .current_dir(go_project.path())
            .output()
            .expect("go read");
        assert!(
            read.status.success(),
            "go read failed: {}",
            String::from_utf8_lossy(&read.stderr)
        );
        assert_eq!(read.stdout, payload);

        let go_store = tempdir().expect("go store");
        let write = Command::new("go")
            .arg("run")
            .arg(".")
            .arg("write")
            .arg(go_store.path())
            .arg(&key_hex)
            .arg(message_id)
            .arg("hello from go")
            .env("GO111MODULE", "on")
            .env("GOCACHE", go_cache.path())
            .env("GOMODCACHE", go_modcache.path())
            .env("GOPATH", go_path.path())
            .current_dir(go_project.path())
            .output()
            .expect("go write");
        assert!(
            write.status.success(),
            "go write failed: {}",
            String::from_utf8_lossy(&write.stderr)
        );

        let encoded = fs::read(go_store.path().join(message_id)).expect("read go blob");
        assert!(is_gluon_store_blob(&encoded));
        assert_eq!(
            decode_blob(&key_obj, &encoded).expect("decode go blob"),
            b"hello from go"
        );
    }

    fn to_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}
