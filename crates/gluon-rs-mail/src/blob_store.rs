use crate::error::Result;

pub trait BlobStore: Send + Sync {
    fn get(&self, message_id: &str) -> Result<Vec<u8>>;
    fn set(&self, message_id: &str, data: &[u8]) -> Result<()>;
    fn delete(&self, message_id: &str) -> Result<()>;
    fn exists(&self, message_id: &str) -> Result<bool>;
}

pub struct FilesystemBlobStore {
    store_dir: std::path::PathBuf,
    key: gluon_rs_core::GluonKey,
}

impl FilesystemBlobStore {
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
