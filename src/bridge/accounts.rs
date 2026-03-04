use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tracing::{debug, warn};

use crate::api::auth;
use crate::api::client::ProtonClient;
use crate::api::error::{is_auth_error, is_invalid_refresh_token_error, ApiError};
use crate::api::types::Session;

use super::types::{AccountId, AccountResolver};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountHealth {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone)]
pub struct AccountState {
    pub account_id: AccountId,
    pub primary_email: String,
    pub address_emails: Vec<String>,
    pub split_mode: bool,
    pub session: Session,
    pub health: AccountHealth,
}

#[derive(Debug, Clone, Default)]
pub struct AccountRegistry {
    accounts: HashMap<AccountId, AccountState>,
    email_index: HashMap<String, AccountId>,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountRuntimeError {
    #[error("account not found: {0}")]
    AccountNotFound(String),
    #[error("account unavailable: {0}")]
    AccountUnavailable(String),
    #[error("api error: {0}")]
    Api(#[from] ApiError),
    #[error("vault error: {0}")]
    Vault(#[from] crate::vault::VaultError),
}

#[derive(Debug)]
pub struct RuntimeAccountRegistry {
    sessions: RwLock<HashMap<AccountId, Session>>,
    health: RwLock<HashMap<AccountId, AccountHealth>>,
    refresh_locks: Mutex<HashMap<AccountId, Arc<AsyncMutex<()>>>>,
    vault_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct RuntimeAccountInfo {
    pub account_id: AccountId,
    pub email: String,
    pub api_mode: crate::api::types::ApiMode,
    pub health: AccountHealth,
}

impl AccountRegistry {
    pub fn from_single_session(session: Session) -> Self {
        Self::from_sessions(vec![session])
    }

    pub fn from_sessions(sessions: Vec<Session>) -> Self {
        let mut registry = Self::default();
        for session in sessions {
            if !is_session_runtime_usable(&session) {
                warn!(
                    email = %session.email,
                    uid = %session.uid,
                    has_refresh_token = !session.refresh_token.trim().is_empty(),
                    "skipping invalid account session while building account registry"
                );
                continue;
            }
            registry.upsert_session(session);
        }
        registry
    }

    pub fn upsert_session(&mut self, session: Session) {
        let account_id = AccountId(session.uid.clone());
        if let Some(existing) = self.accounts.get(&account_id) {
            for email in &existing.address_emails {
                self.email_index.remove(&normalize_email(email));
            }
        }
        let state = AccountState {
            account_id: account_id.clone(),
            primary_email: session.email.clone(),
            address_emails: vec![session.email.clone()],
            split_mode: false,
            session: session.clone(),
            health: AccountHealth::Healthy,
        };

        self.email_index
            .insert(normalize_email(&session.email), account_id.clone());
        self.accounts.insert(account_id, state);
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    pub fn all_accounts(&self) -> impl Iterator<Item = &AccountState> {
        self.accounts.values()
    }

    pub fn get_by_account_id(&self, account_id: &AccountId) -> Option<&AccountState> {
        self.accounts.get(account_id)
    }

    pub fn resolve_by_email(&self, email: &str) -> Option<&AccountState> {
        let account_id = self.email_index.get(&normalize_email(email))?;
        self.accounts.get(account_id)
    }

    pub fn add_address_email(&mut self, account_id: &AccountId, email: &str) {
        let normalized = normalize_email(email);
        if normalized.is_empty() {
            return;
        }

        let Some(state) = self.accounts.get_mut(account_id) else {
            return;
        };

        if !state
            .address_emails
            .iter()
            .any(|existing| normalize_email(existing) == normalized)
        {
            state.address_emails.push(email.to_string());
        }

        if state.split_mode || normalize_email(&state.primary_email) == normalized {
            self.email_index.insert(normalized, account_id.clone());
        }
    }

    pub fn set_address_emails(&mut self, account_id: &AccountId, emails: Vec<String>) -> bool {
        let Some(state) = self.accounts.get_mut(account_id) else {
            return false;
        };

        for email in &state.address_emails {
            self.email_index.remove(&normalize_email(email));
        }

        let mut dedup = Vec::new();
        let mut push_email = |email: String| {
            let normalized = normalize_email(&email);
            if normalized.is_empty() {
                return;
            }
            if dedup
                .iter()
                .any(|existing: &String| normalize_email(existing) == normalized)
            {
                return;
            }
            dedup.push(email);
        };

        push_email(state.primary_email.clone());
        for email in emails {
            push_email(email);
        }

        state.address_emails = dedup;
        self.email_index
            .insert(normalize_email(&state.primary_email), account_id.clone());
        if state.split_mode {
            for email in &state.address_emails {
                self.email_index
                    .insert(normalize_email(email), account_id.clone());
            }
        }
        true
    }

    pub fn set_split_mode(&mut self, account_id: &AccountId, split_mode: bool) -> bool {
        let Some(state) = self.accounts.get_mut(account_id) else {
            return false;
        };
        state.split_mode = split_mode;

        for email in &state.address_emails {
            self.email_index.remove(&normalize_email(email));
        }
        self.email_index
            .insert(normalize_email(&state.primary_email), account_id.clone());
        if split_mode {
            for email in &state.address_emails {
                self.email_index
                    .insert(normalize_email(email), account_id.clone());
            }
        }
        true
    }
}

impl AccountResolver for AccountRegistry {
    fn resolve_account_id(&self, email: &str) -> Option<AccountId> {
        self.email_index.get(&normalize_email(email)).cloned()
    }
}

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn is_session_runtime_usable(session: &Session) -> bool {
    !session.uid.trim().is_empty() && !session.refresh_token.trim().is_empty()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RefreshAttemptContext {
    uid: String,
    refresh_token: String,
    access_token: Option<String>,
}

impl RefreshAttemptContext {
    fn from_session(session: &Session, include_access_token: bool) -> Self {
        let access_token = if include_access_token && !session.access_token.trim().is_empty() {
            Some(session.access_token.clone())
        } else {
            None
        };
        Self {
            uid: session.uid.clone(),
            refresh_token: session.refresh_token.clone(),
            access_token,
        }
    }
}

fn register_refresh_attempt(
    attempts: &mut HashSet<RefreshAttemptContext>,
    session: &Session,
    include_access_token: bool,
) -> bool {
    attempts.insert(RefreshAttemptContext::from_session(
        session,
        include_access_token,
    ))
}

fn has_refresh_context_changed(previous: &Session, candidate: &Session) -> bool {
    previous.uid != candidate.uid
        || previous.refresh_token != candidate.refresh_token
        || previous.access_token != candidate.access_token
}

fn select_reconciled_vault_session(
    account_id: &AccountId,
    existing: &Session,
    sessions: Vec<Session>,
) -> Option<Session> {
    let account_id_key = account_id.0.trim();
    if !account_id_key.is_empty() {
        let mut uid_matches = sessions
            .iter()
            .filter(|session| session.uid.trim() == account_id_key);
        if let Some(uid_match) = uid_matches.next() {
            if uid_matches.next().is_some() {
                return None;
            }
            if is_session_runtime_usable(uid_match) {
                return Some(uid_match.clone());
            }
            return None;
        }
    }

    let target_email = normalize_email(&existing.email);
    if target_email.is_empty() {
        return None;
    }

    let mut email_matches = sessions.into_iter().filter(|session| {
        is_session_runtime_usable(session) && normalize_email(&session.email) == target_email
    });
    let first = email_matches.next()?;
    if email_matches.next().is_some() {
        return None;
    }
    Some(first)
}

impl RuntimeAccountRegistry {
    pub fn new(sessions: Vec<Session>, vault_dir: PathBuf) -> Self {
        Self::with_optional_vault_dir(sessions, Some(vault_dir))
    }

    pub fn in_memory(sessions: Vec<Session>) -> Self {
        Self::with_optional_vault_dir(sessions, None)
    }

    fn with_optional_vault_dir(sessions: Vec<Session>, vault_dir: Option<PathBuf>) -> Self {
        let mut map = HashMap::new();
        let mut health = HashMap::new();
        for session in sessions {
            if !is_session_runtime_usable(&session) {
                warn!(
                    email = %session.email,
                    uid = %session.uid,
                    has_refresh_token = !session.refresh_token.trim().is_empty(),
                    "skipping invalid account session while building runtime registry"
                );
                continue;
            }
            let account_id = AccountId(session.uid.clone());
            map.insert(account_id.clone(), session);
            health.insert(account_id, AccountHealth::Healthy);
        }
        Self {
            sessions: RwLock::new(map),
            health: RwLock::new(health),
            refresh_locks: Mutex::new(HashMap::new()),
            vault_dir,
        }
    }

    fn refresh_lock_for(&self, account_id: &AccountId) -> Arc<AsyncMutex<()>> {
        let mut locks = self.refresh_locks.lock().expect("refresh lock poisoned");
        locks
            .entry(account_id.clone())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    fn load_latest_session_from_vault(
        &self,
        account_id: &AccountId,
        existing: &Session,
    ) -> Option<Session> {
        let Some(vault_dir) = &self.vault_dir else {
            return None;
        };

        let sessions = match crate::vault::list_sessions(vault_dir) {
            Ok(sessions) => sessions,
            Err(err) => {
                warn!(
                    account_id = %account_id.0,
                    error = %err,
                    "failed to reload sessions from vault after refresh-token failure"
                );
                return None;
            }
        };

        let selected = select_reconciled_vault_session(account_id, existing, sessions);
        if selected.is_none() {
            debug!(
                account_id = %account_id.0,
                email = %existing.email,
                "no deterministic vault session candidate found after refresh-token failure"
            );
        }
        selected
    }

    pub async fn get_session(&self, account_id: &AccountId) -> Option<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(account_id).cloned()
    }

    pub async fn get_health(&self, account_id: &AccountId) -> Option<AccountHealth> {
        let health = self.health.read().await;
        health.get(account_id).copied()
    }

    pub async fn set_health(
        &self,
        account_id: &AccountId,
        account_health: AccountHealth,
    ) -> Result<(), AccountRuntimeError> {
        let mut health = self.health.write().await;
        let Some(previous) = health.get(account_id).copied() else {
            return Err(AccountRuntimeError::AccountNotFound(account_id.0.clone()));
        };
        health.insert(account_id.clone(), account_health);
        if previous != account_health {
            warn!(
                account_id = %account_id.0,
                previous = ?previous,
                current = ?account_health,
                "account health changed"
            );
        }
        Ok(())
    }

    pub async fn snapshot(&self) -> Vec<RuntimeAccountInfo> {
        let sessions = self.sessions.read().await;
        let health = self.health.read().await;
        let mut out = Vec::new();
        for (account_id, session) in sessions.iter() {
            out.push(RuntimeAccountInfo {
                account_id: account_id.clone(),
                email: session.email.clone(),
                api_mode: session.api_mode,
                health: health
                    .get(account_id)
                    .copied()
                    .unwrap_or(AccountHealth::Degraded),
            });
        }
        out
    }

    pub async fn with_valid_access_token(
        &self,
        account_id: &AccountId,
    ) -> Result<Session, AccountRuntimeError> {
        if matches!(
            self.get_health(account_id).await,
            Some(AccountHealth::Unavailable)
        ) {
            return Err(AccountRuntimeError::AccountUnavailable(
                account_id.0.clone(),
            ));
        }
        let session = self
            .get_session(account_id)
            .await
            .ok_or_else(|| AccountRuntimeError::AccountNotFound(account_id.0.clone()))?;
        if !session.access_token.is_empty() {
            return Ok(session);
        }
        self.refresh_session_if_stale(account_id, Some("")).await
    }

    pub async fn refresh_session(
        &self,
        account_id: &AccountId,
    ) -> Result<Session, AccountRuntimeError> {
        self.refresh_session_if_stale(account_id, None).await
    }

    pub async fn refresh_session_if_stale(
        &self,
        account_id: &AccountId,
        stale_access_token: Option<&str>,
    ) -> Result<Session, AccountRuntimeError> {
        let lock = self.refresh_lock_for(account_id);
        let _guard = lock.lock().await;

        let existing = self
            .get_session(account_id)
            .await
            .ok_or_else(|| AccountRuntimeError::AccountNotFound(account_id.0.clone()))?;
        if matches!(
            self.get_health(account_id).await,
            Some(AccountHealth::Unavailable)
        ) {
            return Err(AccountRuntimeError::AccountUnavailable(
                account_id.0.clone(),
            ));
        }

        if let Some(stale) = stale_access_token {
            let stale_matches = if stale.is_empty() {
                existing.access_token.is_empty()
            } else {
                existing.access_token == stale
            };
            if !stale_matches {
                return Ok(existing);
            }
        }

        let mut session_for_refresh = existing;
        let mut refresh_attempts = HashSet::new();

        let mut refresh_result =
            refresh_with_optional_access_token(&session_for_refresh, true).await;
        let _ = register_refresh_attempt(&mut refresh_attempts, &session_for_refresh, true);

        if let Err(err) = &refresh_result {
            if is_invalid_refresh_token_error(err) {
                if let Some(reloaded) =
                    self.load_latest_session_from_vault(account_id, &session_for_refresh)
                {
                    let changed_refresh_context =
                        has_refresh_context_changed(&session_for_refresh, &reloaded);

                    if changed_refresh_context
                        && register_refresh_attempt(&mut refresh_attempts, &reloaded, true)
                    {
                        debug!(
                            account_id = %account_id.0,
                            old_uid = %session_for_refresh.uid,
                            new_uid = %reloaded.uid,
                            "retrying refresh with latest vault session after invalid refresh token"
                        );
                        session_for_refresh = reloaded;
                        refresh_result =
                            refresh_with_optional_access_token(&session_for_refresh, true).await;
                    }
                }
            }
        }

        if let Err(err) = &refresh_result {
            if is_auth_error(err)
                && !session_for_refresh.access_token.is_empty()
                && register_refresh_attempt(&mut refresh_attempts, &session_for_refresh, false)
            {
                debug!(
                    account_id = %account_id.0,
                    "retrying refresh without access token after auth refresh failure"
                );
                refresh_result =
                    refresh_with_optional_access_token(&session_for_refresh, false).await;
            }
        }

        let refreshed = match refresh_result {
            Ok(auth) => auth,
            Err(err) => {
                let next_health = if is_auth_error(&err) {
                    AccountHealth::Unavailable
                } else {
                    AccountHealth::Degraded
                };
                debug!(
                    account_id = %account_id.0,
                    is_auth_error = is_auth_error(&err),
                    "refresh failed; updating account health"
                );
                let _ = self.set_health(account_id, next_health).await;
                return Err(err.into());
            }
        };

        let mut updated = Session {
            uid: refreshed.uid,
            access_token: refreshed.access_token,
            refresh_token: refreshed.refresh_token,
            ..session_for_refresh
        };

        let canonical_user_id = match fetch_canonical_user_context(&updated).await {
            Some((user_id, email, display_name)) => {
                if !email.trim().is_empty() {
                    updated.email = email;
                }
                if !display_name.trim().is_empty() {
                    updated.display_name = display_name;
                }
                Some(user_id)
            }
            None => None,
        };

        if let Some(vault_dir) = &self.vault_dir {
            crate::vault::save_session_with_user_id(
                &updated,
                canonical_user_id.as_deref(),
                vault_dir,
            )?;
        }

        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(account_id.clone(), updated.clone());
        }
        let _ = self.set_health(account_id, AccountHealth::Healthy).await;
        Ok(updated)
    }
}

async fn refresh_with_optional_access_token(
    session: &Session,
    include_access_token: bool,
) -> Result<crate::api::types::RefreshResponse, ApiError> {
    let mut client = ProtonClient::with_api_mode(session.api_mode)?;
    let access = if include_access_token {
        Some(session.access_token.as_str())
    } else {
        None
    };
    auth::refresh_auth(&mut client, &session.uid, &session.refresh_token, access).await
}

async fn fetch_canonical_user_context(session: &Session) -> Option<(String, String, String)> {
    if session.uid.trim().is_empty() || session.access_token.trim().is_empty() {
        return None;
    }

    let client = ProtonClient::authenticated_with_mode(
        session.api_mode.base_url(),
        session.api_mode,
        &session.uid,
        &session.access_token,
    )
    .ok()?;

    match crate::api::users::get_user(&client).await {
        Ok(user_resp) => Some((
            user_resp.user.id,
            user_resp.user.email,
            user_resp.user.display_name,
        )),
        Err(err) => {
            debug!(
                user_id = %session.uid,
                error = %err,
                "failed to fetch canonical user context after refresh"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn session(uid: &str, email: &str) -> Session {
        Session {
            uid: uid.to_string(),
            access_token: String::new(),
            refresh_token: format!("refresh-{uid}"),
            email: email.to_string(),
            display_name: uid.to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: None,
            bridge_password: Some("bridge-password".to_string()),
        }
    }

    #[test]
    fn resolves_accounts_case_insensitively() {
        let registry = AccountRegistry::from_sessions(vec![
            session("uid-1", "alice@proton.me"),
            session("uid-2", "bob@proton.me"),
        ]);

        let account = registry.resolve_by_email("ALICE@PROTON.ME").unwrap();
        assert_eq!(account.account_id, AccountId("uid-1".to_string()));
    }

    #[test]
    fn upsert_replaces_existing_account_state() {
        let mut registry =
            AccountRegistry::from_single_session(session("uid-1", "alice@proton.me"));
        let mut updated = session("uid-1", "alice@proton.me");
        updated.display_name = "Alice Updated".to_string();
        registry.upsert_session(updated);

        let account = registry.resolve_by_email("alice@proton.me").unwrap();
        assert_eq!(account.session.display_name, "Alice Updated");
        assert_eq!(registry.account_count(), 1);
    }

    #[test]
    fn upsert_replaces_primary_email_index() {
        let mut registry =
            AccountRegistry::from_single_session(session("uid-1", "alice@proton.me"));
        let updated = session("uid-1", "new@proton.me");
        registry.upsert_session(updated);

        assert!(registry.resolve_by_email("alice@proton.me").is_none());
        assert!(registry.resolve_by_email("new@proton.me").is_some());
    }

    #[test]
    fn resolves_alias_addresses_when_split_mode_enabled() {
        let mut registry =
            AccountRegistry::from_single_session(session("uid-1", "alice@proton.me"));
        let account_id = AccountId("uid-1".to_string());
        assert!(registry.set_split_mode(&account_id, true));
        registry.add_address_email(&AccountId("uid-1".to_string()), "alias@proton.me");

        let account = registry.resolve_by_email("ALIAS@PROTON.ME").unwrap();
        assert_eq!(account.account_id, AccountId("uid-1".to_string()));
        assert!(account
            .address_emails
            .iter()
            .any(|e| e == "alias@proton.me"));
    }

    #[test]
    fn set_address_emails_replaces_aliases_and_keeps_primary() {
        let mut registry =
            AccountRegistry::from_single_session(session("uid-1", "alice@proton.me"));
        let account_id = AccountId("uid-1".to_string());
        assert!(registry.set_split_mode(&account_id, true));
        registry.add_address_email(&account_id, "old@proton.me");
        assert!(registry.resolve_by_email("old@proton.me").is_some());

        let updated = registry.set_address_emails(
            &account_id,
            vec!["new@proton.me".to_string(), "new@proton.me".to_string()],
        );
        assert!(updated);
        assert!(registry.resolve_by_email("old@proton.me").is_none());
        assert!(registry.resolve_by_email("new@proton.me").is_some());
        assert!(registry.resolve_by_email("alice@proton.me").is_some());
    }

    #[test]
    fn split_mode_disabled_hides_alias_logins() {
        let mut registry =
            AccountRegistry::from_single_session(session("uid-1", "alice@proton.me"));
        let account_id = AccountId("uid-1".to_string());
        registry.add_address_email(&account_id, "alias@proton.me");
        assert!(registry.resolve_by_email("alias@proton.me").is_none());

        assert!(registry.set_split_mode(&account_id, true));
        assert!(registry.resolve_by_email("alias@proton.me").is_some());

        assert!(registry.set_split_mode(&account_id, false));
        assert!(registry.resolve_by_email("alias@proton.me").is_none());
        assert!(registry.resolve_by_email("alice@proton.me").is_some());
    }

    #[tokio::test]
    async fn runtime_registry_returns_valid_session_without_refresh() {
        let mut session = session("uid-1", "alice@proton.me");
        session.access_token = "access-token".to_string();
        let runtime = RuntimeAccountRegistry::in_memory(vec![session]);
        let account_id = AccountId("uid-1".to_string());
        let loaded = runtime.with_valid_access_token(&account_id).await.unwrap();
        assert_eq!(loaded.uid, "uid-1");
    }

    #[tokio::test]
    async fn runtime_registry_not_found() {
        let runtime = RuntimeAccountRegistry::in_memory(vec![]);
        let err = runtime
            .with_valid_access_token(&AccountId("missing".to_string()))
            .await
            .unwrap_err();
        assert!(matches!(err, AccountRuntimeError::AccountNotFound(_)));
    }

    #[tokio::test]
    async fn runtime_registry_defaults_to_healthy() {
        let runtime = RuntimeAccountRegistry::in_memory(vec![session("uid-1", "alice@proton.me")]);
        let health = runtime
            .get_health(&AccountId("uid-1".to_string()))
            .await
            .unwrap();
        assert_eq!(health, AccountHealth::Healthy);
    }

    #[tokio::test]
    async fn runtime_registry_unavailable_blocks_access() {
        let mut sess = session("uid-1", "alice@proton.me");
        sess.access_token = "token".to_string();
        let runtime = RuntimeAccountRegistry::in_memory(vec![sess]);
        let account_id = AccountId("uid-1".to_string());
        runtime
            .set_health(&account_id, AccountHealth::Unavailable)
            .await
            .unwrap();

        let err = runtime
            .with_valid_access_token(&account_id)
            .await
            .unwrap_err();
        assert!(matches!(err, AccountRuntimeError::AccountUnavailable(_)));
    }

    #[tokio::test]
    async fn runtime_registry_unavailable_is_isolated_per_account() {
        let mut sess_a = session("uid-1", "alice@proton.me");
        sess_a.access_token = "token-a".to_string();
        let mut sess_b = session("uid-2", "bob@proton.me");
        sess_b.access_token = "token-b".to_string();
        let runtime = RuntimeAccountRegistry::in_memory(vec![sess_a, sess_b]);

        runtime
            .set_health(&AccountId("uid-1".to_string()), AccountHealth::Unavailable)
            .await
            .unwrap();

        let err = runtime
            .with_valid_access_token(&AccountId("uid-1".to_string()))
            .await
            .unwrap_err();
        assert!(matches!(err, AccountRuntimeError::AccountUnavailable(_)));

        let ok = runtime
            .with_valid_access_token(&AccountId("uid-2".to_string()))
            .await
            .unwrap();
        assert_eq!(ok.email, "bob@proton.me");
    }

    #[test]
    fn reconciled_vault_session_prefers_account_id_match() {
        let account_id = AccountId("uid-target".to_string());
        let existing = session("uid-target", "alice@proton.me");

        let mut uid_match = session("uid-target", "old-alias@proton.me");
        uid_match.refresh_token = "refresh-updated".to_string();
        let email_only_match = session("uid-other", "alice@proton.me");

        let selected = select_reconciled_vault_session(
            &account_id,
            &existing,
            vec![email_only_match, uid_match.clone()],
        )
        .expect("should select canonical uid match");

        assert_eq!(selected.uid, uid_match.uid);
        assert_eq!(selected.refresh_token, "refresh-updated");
    }

    #[test]
    fn reconciled_vault_session_rejects_ambiguous_email_fallback() {
        let account_id = AccountId("uid-missing".to_string());
        let existing = session("uid-current", "shared@proton.me");

        let candidate_a = session("uid-a", "shared@proton.me");
        let candidate_b = session("uid-b", "shared@proton.me");

        let selected =
            select_reconciled_vault_session(&account_id, &existing, vec![candidate_a, candidate_b]);
        assert!(selected.is_none());
    }

    #[test]
    fn refresh_attempt_registration_deduplicates_same_context() {
        let mut attempts = HashSet::new();
        let mut sess = session("uid-1", "alice@proton.me");
        sess.access_token = "access".to_string();

        assert!(register_refresh_attempt(&mut attempts, &sess, true));
        assert!(
            !register_refresh_attempt(&mut attempts, &sess, true),
            "same refresh context should only be attempted once"
        );
        assert!(
            register_refresh_attempt(&mut attempts, &sess, false),
            "fallback attempt without access token should still be allowed once"
        );
        assert!(
            !register_refresh_attempt(&mut attempts, &sess, false),
            "duplicate fallback context should be suppressed"
        );
    }
}
