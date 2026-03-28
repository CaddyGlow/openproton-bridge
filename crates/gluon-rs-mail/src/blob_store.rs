use crate::error::Result;

/// Encrypted blob storage for message bodies, keyed by message ID.
pub trait BlobStore: Send + Sync {
    /// Read and decrypt a blob by message ID.
    fn get(&self, message_id: &str) -> Result<Vec<u8>>;
    /// Encrypt and write a blob for the given message ID.
    fn set(&self, message_id: &str, data: &[u8]) -> Result<()>;
    /// Delete the blob for the given message ID (no-op if absent).
    fn delete(&self, message_id: &str) -> Result<()>;
    /// Check whether a blob exists for the given message ID.
    fn exists(&self, message_id: &str) -> Result<bool>;
}

/// File-backed blob store that encrypts each blob with a GluonKey.
pub struct FilesystemBlobStore {
    store_dir: std::path::PathBuf,
    key: gluon_rs_core::GluonKey,
}

impl FilesystemBlobStore {
    /// Create a new store rooted at `store_dir`, encrypting with `key`.
    pub fn new(store_dir: std::path::PathBuf, key: gluon_rs_core::GluonKey) -> Self {
        Self { store_dir, key }
    }

    fn blob_path(&self, message_id: &str) -> std::path::PathBuf {
        self.store_dir.join(message_id)
    }
}

impl BlobStore for FilesystemBlobStore {
    fn get(&self, message_id: &str) -> Result<Vec<u8>> {
        let path = self.blob_path(message_id);
        let encoded = std::fs::read(&path).map_err(gluon_rs_core::GluonCoreError::from)?;
        Ok(gluon_rs_core::decode_blob(&self.key, &encoded)?)
    }

    fn set(&self, message_id: &str, data: &[u8]) -> Result<()> {
        std::fs::create_dir_all(&self.store_dir).map_err(gluon_rs_core::GluonCoreError::from)?;
        let path = self.blob_path(message_id);
        let encoded = gluon_rs_core::encode_blob(&self.key, data)?;
        std::fs::write(&path, encoded).map_err(gluon_rs_core::GluonCoreError::from)?;
        Ok(())
    }

    fn delete(&self, message_id: &str) -> Result<()> {
        let path = self.blob_path(message_id);
        if path.exists() {
            std::fs::remove_file(&path).map_err(gluon_rs_core::GluonCoreError::from)?;
        }
        Ok(())
    }

    fn exists(&self, message_id: &str) -> Result<bool> {
        Ok(self.blob_path(message_id).exists())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key = gluon_rs_core::GluonKey::try_from_slice(&[7u8; 32]).unwrap();
        let store = FilesystemBlobStore::new(dir.path().to_path_buf(), key);

        store.set("msg1", b"hello world").unwrap();
        assert!(store.exists("msg1").unwrap());
        assert_eq!(store.get("msg1").unwrap(), b"hello world");

        store.delete("msg1").unwrap();
        assert!(!store.exists("msg1").unwrap());
    }

    #[test]
    fn test_blob_store_missing() {
        let dir = tempfile::tempdir().unwrap();
        let key = gluon_rs_core::GluonKey::try_from_slice(&[7u8; 32]).unwrap();
        let store = FilesystemBlobStore::new(dir.path().to_path_buf(), key);
        assert!(!store.exists("nonexistent").unwrap());
    }

    #[test]
    fn test_blob_store_delete_missing_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let key = gluon_rs_core::GluonKey::try_from_slice(&[7u8; 32]).unwrap();
        let store = FilesystemBlobStore::new(dir.path().to_path_buf(), key);
        store.delete("nonexistent").unwrap();
    }
}
