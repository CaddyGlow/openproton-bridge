use std::collections::HashSet;

use crate::{
    error::{GluonError, Result},
    key::GluonKey,
    layout::CacheLayout,
    target::CompatibilityTarget,
};

#[derive(Debug, Clone)]
pub struct AccountBootstrap {
    pub account_id: String,
    pub storage_user_id: String,
    pub key: GluonKey,
}

impl AccountBootstrap {
    pub fn new(
        account_id: impl Into<String>,
        storage_user_id: impl Into<String>,
        key: GluonKey,
    ) -> Self {
        Self {
            account_id: account_id.into(),
            storage_user_id: storage_user_id.into(),
            key,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoreBootstrap {
    pub layout: CacheLayout,
    pub target: CompatibilityTarget,
    pub accounts: Vec<AccountBootstrap>,
}

impl StoreBootstrap {
    pub fn new(layout: CacheLayout, target: CompatibilityTarget, accounts: Vec<AccountBootstrap>) -> Self {
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
                return Err(GluonError::DuplicateAccountId {
                    account_id: account.account_id.clone(),
                });
            }
            if !storage_user_ids.insert(account.storage_user_id.clone()) {
                return Err(GluonError::DuplicateStorageUserId {
                    storage_user_id: account.storage_user_id.clone(),
                });
            }
            self.layout.account_paths(account.storage_user_id.clone())?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{key::GluonKey, layout::CacheLayout, target::CompatibilityTarget};

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
