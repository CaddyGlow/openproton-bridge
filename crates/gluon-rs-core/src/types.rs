use std::collections::HashSet;

use crate::{
    error::{GluonCoreError, Result},
    key::GluonKey,
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

pub fn validate_account_bootstraps(accounts: &[AccountBootstrap]) -> Result<()> {
    let mut account_ids = HashSet::new();
    let mut storage_user_ids = HashSet::new();

    for account in accounts {
        if !account_ids.insert(account.account_id.clone()) {
            return Err(GluonCoreError::DuplicateAccountId {
                account_id: account.account_id.clone(),
            });
        }
        if !storage_user_ids.insert(account.storage_user_id.clone()) {
            return Err(GluonCoreError::DuplicateStorageUserId {
                storage_user_id: account.storage_user_id.clone(),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_account_bootstraps, AccountBootstrap};
    use crate::key::GluonKey;

    #[test]
    fn rejects_duplicate_storage_users() {
        let key = GluonKey::try_from_slice(&[9u8; 32]).expect("key");
        let accounts = vec![
            AccountBootstrap::new("account-a", "user-1", key.clone()),
            AccountBootstrap::new("account-b", "user-1", key),
        ];

        assert!(validate_account_bootstraps(&accounts).is_err());
    }
}
