use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::{watch, RwLock};
use tracing::{debug, warn};

use crate::api::auth;
use crate::api::client::ProtonClient;
use crate::api::error::{is_auth_error, is_invalid_refresh_token_error, ApiError};
use crate::api::types::{Address, Session, UserKey};
use crate::imap::mailbox::ResolvedMailbox;

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
    auth_material: RwLock<HashMap<AccountId, Arc<RuntimeAuthMaterial>>>,
    runtime_generations: RwLock<HashMap<AccountId, u64>>,
    generation_watchers: Mutex<HashMap<AccountId, watch::Sender<u64>>>,
    user_labels: std::sync::RwLock<HashMap<AccountId, Vec<ResolvedMailbox>>>,
    vault_dir: Option<PathBuf>,
}

#[derive(Debug)]
pub struct RuntimeAuthMaterial {
    pub user_keys: Vec<UserKey>,
    pub addresses: Vec<Address>,
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
        let mut runtime_generations = HashMap::new();
        let mut generation_watchers = HashMap::new();
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
            health.insert(account_id.clone(), AccountHealth::Healthy);
            runtime_generations.insert(account_id.clone(), 0);
            let (generation_tx, _generation_rx) = watch::channel(0);
            generation_watchers.insert(account_id, generation_tx);
        }
        Self {
            sessions: RwLock::new(map),
            health: RwLock::new(health),
            auth_material: RwLock::new(HashMap::new()),
            runtime_generations: RwLock::new(runtime_generations),
            generation_watchers: Mutex::new(generation_watchers),
            user_labels: std::sync::RwLock::new(HashMap::new()),
            vault_dir,
        }
    }

    fn generation_sender_for(&self, account_id: &AccountId) -> Option<watch::Sender<u64>> {
        let watchers = self
            .generation_watchers
            .lock()
            .expect("generation watcher lock poisoned");
        watchers.get(account_id).cloned()
    }

    pub async fn get_session(&self, account_id: &AccountId) -> Option<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(account_id).cloned()
    }

    pub async fn active_sessions(&self) -> Vec<Session> {
        let sessions = self.sessions.read().await;
        let mut active = sessions.values().cloned().collect::<Vec<_>>();
        active.sort_by(|left, right| left.uid.cmp(&right.uid));
        active
    }

    pub async fn has_sessions(&self) -> bool {
        let sessions = self.sessions.read().await;
        !sessions.is_empty()
    }

    pub async fn upsert_session(&self, session: Session) -> Result<(), AccountRuntimeError> {
        if !is_session_runtime_usable(&session) {
            warn!(
                email = %session.email,
                uid = %session.uid,
                has_refresh_token = !session.refresh_token.trim().is_empty(),
                "skipping invalid account session while updating runtime registry"
            );
            return Ok(());
        }

        let account_id = AccountId(session.uid.clone());
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(account_id.clone(), session);
        }
        {
            let mut health = self.health.write().await;
            health.insert(account_id.clone(), AccountHealth::Healthy);
        }
        {
            let mut generations = self.runtime_generations.write().await;
            generations.entry(account_id.clone()).or_insert(0);
        }
        {
            let mut watchers = self
                .generation_watchers
                .lock()
                .expect("generation watcher lock poisoned");
            watchers.entry(account_id).or_insert_with(|| {
                let (generation_tx, _generation_rx) = watch::channel(0);
                generation_tx
            });
        }
        Ok(())
    }

    pub async fn load_or_seed_session(
        &self,
        session: Session,
    ) -> Result<Session, AccountRuntimeError> {
        if !is_session_runtime_usable(&session) {
            warn!(
                email = %session.email,
                uid = %session.uid,
                has_refresh_token = !session.refresh_token.trim().is_empty(),
                "skipping invalid account session while seeding runtime registry"
            );
            return Ok(session);
        }

        let account_id = AccountId(session.uid.clone());
        let mut inserted = false;
        let current = {
            let mut sessions = self.sessions.write().await;
            match sessions.get(&account_id).cloned() {
                Some(existing) => existing,
                None => {
                    inserted = true;
                    sessions.insert(account_id.clone(), session.clone());
                    session
                }
            }
        };

        if inserted {
            {
                let mut health = self.health.write().await;
                health
                    .entry(account_id.clone())
                    .or_insert(AccountHealth::Healthy);
            }
            {
                let mut generations = self.runtime_generations.write().await;
                generations.entry(account_id.clone()).or_insert(0);
            }
            {
                let mut watchers = self
                    .generation_watchers
                    .lock()
                    .expect("generation watcher lock poisoned");
                watchers.entry(account_id).or_insert_with(|| {
                    let (generation_tx, _generation_rx) = watch::channel(0);
                    generation_tx
                });
            }
        }

        Ok(current)
    }

    pub async fn get_auth_material(
        &self,
        account_id: &AccountId,
    ) -> Option<Arc<RuntimeAuthMaterial>> {
        let auth_material = self.auth_material.read().await;
        auth_material.get(account_id).cloned()
    }

    pub async fn set_auth_material(
        &self,
        account_id: &AccountId,
        material: Arc<RuntimeAuthMaterial>,
    ) -> Result<(), AccountRuntimeError> {
        if self.get_session(account_id).await.is_none() {
            return Err(AccountRuntimeError::AccountNotFound(account_id.0.clone()));
        }
        let mut auth_material = self.auth_material.write().await;
        auth_material.insert(account_id.clone(), material);
        Ok(())
    }

    pub fn get_user_labels(&self, account_id: &AccountId) -> Vec<ResolvedMailbox> {
        self.user_labels
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(account_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn set_user_labels(&self, account_id: &AccountId, labels: Vec<ResolvedMailbox>) {
        let mut guard = self.user_labels.write().unwrap_or_else(|e| e.into_inner());
        guard.insert(account_id.clone(), labels);
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
        drop(health);

        if previous != AccountHealth::Unavailable && account_health == AccountHealth::Unavailable {
            let next_generation = {
                let mut generations = self.runtime_generations.write().await;
                let Some(generation) = generations.get_mut(account_id) else {
                    return Err(AccountRuntimeError::AccountNotFound(account_id.0.clone()));
                };
                *generation = generation.saturating_add(1);
                *generation
            };
            if let Some(generation_tx) = self.generation_sender_for(account_id) {
                let _ = generation_tx.send(next_generation);
            }
            {
                let mut auth_material = self.auth_material.write().await;
                auth_material.remove(account_id);
            }
            warn!(
                account_id = %account_id.0,
                generation = next_generation,
                "account transitioned to unavailable; canceled active runtime generation"
            );
        }
        Ok(())
    }

    pub async fn runtime_generation(
        &self,
        account_id: &AccountId,
    ) -> Result<u64, AccountRuntimeError> {
        let generations = self.runtime_generations.read().await;
        generations
            .get(account_id)
            .copied()
            .ok_or_else(|| AccountRuntimeError::AccountNotFound(account_id.0.clone()))
    }

    pub fn subscribe_runtime_generation(
        &self,
        account_id: &AccountId,
    ) -> Result<watch::Receiver<u64>, AccountRuntimeError> {
        let watchers = self
            .generation_watchers
            .lock()
            .expect("generation watcher lock poisoned");
        let Some(generation_tx) = watchers.get(account_id) else {
            return Err(AccountRuntimeError::AccountNotFound(account_id.0.clone()));
        };
        Ok(generation_tx.subscribe())
    }

    pub async fn is_runtime_generation_current(
        &self,
        account_id: &AccountId,
        expected_generation: u64,
    ) -> Result<bool, AccountRuntimeError> {
        Ok(self.runtime_generation(account_id).await? == expected_generation)
    }

    pub async fn ensure_runtime_generation(
        &self,
        account_id: &AccountId,
        expected_generation: u64,
    ) -> Result<(), AccountRuntimeError> {
        let current_generation = self.runtime_generation(account_id).await?;
        if current_generation != expected_generation {
            warn!(
                account_id = %account_id.0,
                expected_generation,
                current_generation,
                "stale runtime generation detected for account"
            );
            return Err(AccountRuntimeError::AccountUnavailable(
                account_id.0.clone(),
            ));
        }
        if matches!(
            self.get_health(account_id).await,
            Some(AccountHealth::Unavailable)
        ) {
            return Err(AccountRuntimeError::AccountUnavailable(
                account_id.0.clone(),
            ));
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

    pub async fn persist_session(
        &self,
        session: Session,
        canonical_user_id: Option<&str>,
    ) -> Result<(), AccountRuntimeError> {
        if let Some(vault_dir) = &self.vault_dir {
            crate::vault::save_session_with_user_id(&session, canonical_user_id, vault_dir)?;
        }
        self.upsert_session(session).await?;
        Ok(())
    }

    pub async fn remove_session(&self, account_id: &AccountId) -> Result<(), AccountRuntimeError> {
        let existed = {
            let mut sessions = self.sessions.write().await;
            sessions.remove(account_id).is_some()
        };
        if !existed {
            return Err(AccountRuntimeError::AccountNotFound(account_id.0.clone()));
        }
        {
            let mut health = self.health.write().await;
            health.remove(account_id);
        }
        {
            let mut auth_material = self.auth_material.write().await;
            auth_material.remove(account_id);
        }
        {
            let mut generations = self.runtime_generations.write().await;
            generations.remove(account_id);
        }
        {
            let mut watchers = self
                .generation_watchers
                .lock()
                .expect("generation watcher lock poisoned");
            watchers.remove(account_id);
        }
        Ok(())
    }

    pub async fn remove_all_sessions(&self) {
        self.sessions.write().await.clear();
        self.health.write().await.clear();
        self.auth_material.write().await.clear();
        self.runtime_generations.write().await.clear();
        self.generation_watchers
            .lock()
            .expect("generation watcher lock poisoned")
            .clear();
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
        let lock = super::token_refresh::lock_for_account(&account_id.0);
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

        let (refreshed, refreshed_api_mode) = match refresh_with_mode_fallback(&existing).await {
            Ok((auth, api_mode)) => (auth, api_mode),
            Err(err) => {
                self.handle_refresh_failure(account_id, &err).await;
                return Err(err.into());
            }
        };

        let mut updated = Session {
            uid: refreshed.uid,
            access_token: refreshed.access_token,
            refresh_token: refreshed.refresh_token,
            api_mode: refreshed_api_mode,
            ..existing
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

        self.upsert_session(updated.clone()).await?;
        let _ = self.set_health(account_id, AccountHealth::Healthy).await;
        Ok(updated)
    }

    async fn handle_refresh_failure(&self, account_id: &AccountId, err: &ApiError) {
        let next_health = refresh_failure_health(err);
        debug!(
            account_id = %account_id.0,
            is_auth_error = is_auth_error(err),
            is_invalid_refresh = is_invalid_refresh_token_error(err),
            "refresh failed; updating account health"
        );
        let _ = self.set_health(account_id, next_health).await;
        if next_health == AccountHealth::Unavailable {
            warn!(
                account_id = %account_id.0,
                "invalid refresh token detected; keeping persisted account session"
            );
        }
    }
}

async fn refresh_with_mode_fallback(
    session: &Session,
) -> Result<
    (
        crate::api::types::RefreshResponse,
        crate::api::types::ApiMode,
    ),
    ApiError,
> {
    auth::refresh_auth_with_mode_fallback(
        session.api_mode,
        &session.uid,
        &session.refresh_token,
        Some(session.access_token.as_str()),
    )
    .await
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

fn refresh_failure_health(err: &ApiError) -> AccountHealth {
    if is_invalid_refresh_token_error(err) {
        AccountHealth::Unavailable
    } else {
        AccountHealth::Degraded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn runtime_generation_defaults_to_zero_and_bumps_on_unavailable() {
        let runtime = RuntimeAccountRegistry::in_memory(vec![session("uid-1", "alice@proton.me")]);
        let account_id = AccountId("uid-1".to_string());
        let mut generation_rx = runtime.subscribe_runtime_generation(&account_id).unwrap();

        assert_eq!(runtime.runtime_generation(&account_id).await.unwrap(), 0);
        assert_eq!(*generation_rx.borrow(), 0);

        runtime
            .set_health(&account_id, AccountHealth::Unavailable)
            .await
            .unwrap();
        generation_rx.changed().await.unwrap();
        assert_eq!(*generation_rx.borrow_and_update(), 1);
        assert_eq!(runtime.runtime_generation(&account_id).await.unwrap(), 1);

        runtime
            .set_health(&account_id, AccountHealth::Unavailable)
            .await
            .unwrap();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(30),
            generation_rx.changed(),
        )
        .await
        .is_err());
        assert_eq!(runtime.runtime_generation(&account_id).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn runtime_generation_guard_rejects_stale_generation() {
        let runtime = RuntimeAccountRegistry::in_memory(vec![session("uid-1", "alice@proton.me")]);
        let account_id = AccountId("uid-1".to_string());
        let initial_generation = runtime.runtime_generation(&account_id).await.unwrap();
        assert!(runtime
            .is_runtime_generation_current(&account_id, initial_generation)
            .await
            .unwrap());

        runtime
            .set_health(&account_id, AccountHealth::Unavailable)
            .await
            .unwrap();

        let err = runtime
            .ensure_runtime_generation(&account_id, initial_generation)
            .await
            .unwrap_err();
        assert!(matches!(err, AccountRuntimeError::AccountUnavailable(_)));
    }

    #[tokio::test]
    async fn runtime_generation_unavailable_transition_is_isolated_per_account() {
        let runtime = RuntimeAccountRegistry::in_memory(vec![
            session("uid-1", "alice@proton.me"),
            session("uid-2", "bob@proton.me"),
        ]);
        let account_a = AccountId("uid-1".to_string());
        let account_b = AccountId("uid-2".to_string());
        let mut generation_b = runtime.subscribe_runtime_generation(&account_b).unwrap();

        runtime
            .set_health(&account_a, AccountHealth::Unavailable)
            .await
            .unwrap();

        assert_eq!(runtime.runtime_generation(&account_a).await.unwrap(), 1);
        assert_eq!(runtime.runtime_generation(&account_b).await.unwrap(), 0);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), generation_b.changed(),)
                .await
                .is_err()
        );
    }

    #[test]
    fn refresh_failure_health_marks_only_invalid_refresh_unavailable() {
        let invalid_refresh = ApiError::Api {
            code: 10013,
            message: "Invalid refresh token".to_string(),
            details: None,
        };
        assert_eq!(
            refresh_failure_health(&invalid_refresh),
            AccountHealth::Unavailable
        );

        let generic_auth = ApiError::Auth("auth failed".to_string());
        assert_eq!(
            refresh_failure_health(&generic_auth),
            AccountHealth::Degraded
        );
    }

    #[tokio::test]
    async fn runtime_registry_unavailable_blocks_access_with_empty_token() {
        let runtime = RuntimeAccountRegistry::in_memory(vec![session("uid-1", "alice@proton.me")]);
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
    async fn invalid_refresh_failure_marks_unavailable_and_keeps_persisted_session() {
        let tmp = tempfile::tempdir().unwrap();
        let session = session("uid-1", "alice@proton.me");
        crate::vault::save_session(&session, tmp.path()).unwrap();

        let runtime = RuntimeAccountRegistry::new(vec![session.clone()], tmp.path().to_path_buf());
        let account_id = AccountId("uid-1".to_string());
        let invalid_refresh = ApiError::Api {
            code: 10013,
            message: "Invalid refresh token".to_string(),
            details: None,
        };

        runtime
            .handle_refresh_failure(&account_id, &invalid_refresh)
            .await;

        let health = runtime.get_health(&account_id).await.unwrap();
        assert_eq!(health, AccountHealth::Unavailable);

        let snapshot = runtime.snapshot().await;
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].health, AccountHealth::Unavailable);

        let persisted = crate::vault::load_session_by_email(tmp.path(), "alice@proton.me").is_ok();
        assert!(persisted);
    }

    #[tokio::test]
    async fn invalid_refresh_failure_keeps_persisted_session_when_email_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let stored = session("uid-1", "stored@proton.me");
        crate::vault::save_session(&stored, tmp.path()).unwrap();

        let runtime = RuntimeAccountRegistry::new(vec![stored.clone()], tmp.path().to_path_buf());
        let account_id = AccountId("uid-1".to_string());

        let invalid_refresh = ApiError::Api {
            code: 10013,
            message: "Invalid refresh token".to_string(),
            details: None,
        };

        runtime
            .handle_refresh_failure(&account_id, &invalid_refresh)
            .await;

        assert!(crate::vault::load_session_by_account_id(tmp.path(), "uid-1").is_ok());
    }
}
