use std::fmt;

use zeroize::Zeroize;

use crate::error::{GluonCoreError, Result};

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct GluonKey([u8; 32]);

impl GluonKey {
    pub const LEN: usize = 32;

    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::LEN {
            return Err(GluonCoreError::InvalidKeyLength {
                length: bytes.len(),
            });
        }

        let mut key = [0u8; Self::LEN];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for GluonKey {
    type Error = GluonCoreError;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        Self::try_from_slice(&value)
    }
}

impl fmt::Debug for GluonKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GluonKey([REDACTED; 32])")
    }
}

#[cfg(test)]
mod tests {
    use super::GluonKey;

    #[test]
    fn rejects_wrong_length() {
        assert!(GluonKey::try_from_slice(&[7u8; 31]).is_err());
        assert!(GluonKey::try_from_slice(&[7u8; 33]).is_err());
    }
}
