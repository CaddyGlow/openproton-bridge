use std::sync::{Arc, RwLock};

use super::accounts::AccountRegistry;
use super::types::AccountId;

#[derive(Debug, Clone)]
pub struct AuthRoute {
    pub account_id: AccountId,
    pub primary_email: String,
}

#[derive(Debug, Clone)]
pub struct AuthRouter {
    registry: Arc<RwLock<AccountRegistry>>,
}

impl AuthRouter {
    pub fn new(registry: AccountRegistry) -> Self {
        Self {
            registry: Arc::new(RwLock::new(registry)),
        }
    }

    pub fn resolve_login(&self, login_email: &str, password: &str) -> Option<AuthRoute> {
        let registry = self.registry.read().ok()?;
        let account = registry.resolve_by_email(login_email)?;
        let stored_password = account.session.bridge_password.as_deref()?;

        if !constant_time_eq(stored_password.as_bytes(), password.as_bytes()) {
            return None;
        }

        Some(AuthRoute {
            account_id: account.account_id.clone(),
            primary_email: account.primary_email.clone(),
        })
    }

    pub fn set_account_addresses(&self, account_id: &AccountId, emails: Vec<String>) -> bool {
        let Ok(mut registry) = self.registry.write() else {
            return false;
        };
        registry.set_address_emails(account_id, emails)
    }

    pub fn add_account_address(&self, account_id: &AccountId, email: &str) -> bool {
        let Ok(mut registry) = self.registry.write() else {
            return false;
        };
        if registry.get_by_account_id(account_id).is_none() {
            return false;
        }
        registry.add_address_email(account_id, email);
        true
    }

    pub fn set_account_split_mode(&self, account_id: &AccountId, split_mode: bool) -> bool {
        let Ok(mut registry) = self.registry.write() else {
            return false;
        };
        registry.set_split_mode(account_id, split_mode)
    }

    pub fn account_count(&self) -> usize {
        self.registry
            .read()
            .map(|registry| registry.account_count())
            .unwrap_or_default()
    }
}

impl Default for AuthRouter {
    fn default() -> Self {
        Self {
            registry: Arc::new(RwLock::new(AccountRegistry::default())),
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use crate::api::types::Session;

    use super::*;

    fn session(uid: &str, email: &str, bridge_password: &str) -> Session {
        Session {
            uid: uid.to_string(),
            access_token: String::new(),
            refresh_token: String::new(),
            email: email.to_string(),
            display_name: uid.to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: Some(bridge_password.to_string()),
        }
    }

    #[test]
    fn resolves_valid_login() {
        let registry =
            AccountRegistry::from_single_session(session("uid-1", "alice@proton.me", "secret"));
        let router = AuthRouter::new(registry);

        let route = router.resolve_login("alice@proton.me", "secret").unwrap();
        assert_eq!(route.account_id, AccountId("uid-1".to_string()));
        assert_eq!(route.primary_email, "alice@proton.me");
    }

    #[test]
    fn rejects_wrong_password() {
        let registry =
            AccountRegistry::from_single_session(session("uid-1", "alice@proton.me", "secret"));
        let router = AuthRouter::new(registry);

        assert!(router.resolve_login("alice@proton.me", "wrong").is_none());
    }

    #[test]
    fn updates_account_addresses() {
        let registry =
            AccountRegistry::from_single_session(session("uid-1", "alice@proton.me", "secret"));
        let router = AuthRouter::new(registry);
        let updated = router.set_account_addresses(
            &AccountId("uid-1".to_string()),
            vec!["alias@proton.me".to_string()],
        );
        assert!(updated);

        assert!(router.resolve_login("alias@proton.me", "secret").is_none());
        assert!(router.set_account_split_mode(&AccountId("uid-1".to_string()), true));

        let route = router.resolve_login("alias@proton.me", "secret").unwrap();
        assert_eq!(route.account_id, AccountId("uid-1".to_string()));

        assert!(router.resolve_login("alice@proton.me", "secret").is_some());
        assert_eq!(router.account_count(), 1);
    }
}
