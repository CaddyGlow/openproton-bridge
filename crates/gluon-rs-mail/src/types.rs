use std::collections::HashSet;

use gluon_rs_core::{AccountBootstrap, CacheLayout, GluonCoreError};

use crate::{error::Result, target::CompatibilityTarget};

#[derive(Debug, Clone)]
pub struct StoreBootstrap {
    pub layout: CacheLayout,
    pub target: CompatibilityTarget,
    pub accounts: Vec<AccountBootstrap>,
}

impl StoreBootstrap {
    pub fn new(
        layout: CacheLayout,
        target: CompatibilityTarget,
        accounts: Vec<AccountBootstrap>,
    ) -> Self {
        Self {
            layout,
            target,
            accounts,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let mut account_ids = HashSet::new();
        let mut storage_user_ids = HashSet::new();

        for account in &self.accounts {
            if !account_ids.insert(account.account_id.clone()) {
                return Err(GluonCoreError::DuplicateAccountId {
                    account_id: account.account_id.clone(),
                }
                .into());
            }
            if !storage_user_ids.insert(account.storage_user_id.clone()) {
                return Err(GluonCoreError::DuplicateStorageUserId {
                    storage_user_id: account.storage_user_id.clone(),
                }
                .into());
            }
            self.layout.account_paths(account.storage_user_id.clone())?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use gluon_rs_core::{CacheLayout, GluonKey};

    use crate::target::CompatibilityTarget;

    use super::{AccountBootstrap, StoreBootstrap};

    #[test]
    fn rejects_duplicate_storage_users() {
        let key = GluonKey::try_from_slice(&[9u8; 32]).expect("key");
        let bootstrap = StoreBootstrap::new(
            CacheLayout::new("/tmp/gluon"),
            CompatibilityTarget::default(),
            vec![
                AccountBootstrap::new("account-a", "user-1", key.clone()),
                AccountBootstrap::new("account-b", "user-1", key),
            ],
        );

        assert!(bootstrap.validate().is_err());
    }
}
