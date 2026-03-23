use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use gluon_rs_mail::{AuthResult, ImapConnector, ImapError, ImapResult, MailboxInfo, MetadataPage};
use tracing::{info, warn};
use zeroize::Zeroize;

use crate::api::client::ProtonClient;
use crate::api::error::is_auth_error;
use crate::api::messages;
use crate::api::types::{self, MessageFilter};
use crate::bridge::accounts::{AccountRuntimeError, RuntimeAccountRegistry, RuntimeAuthMaterial};
use crate::bridge::auth_router::AuthRouter;
use crate::crypto::encrypt as crypto_encrypt;
use crate::crypto::keys::{self, Keyring};
use crate::imap::convert;
use crate::imap::mailbox;
use crate::imap::rfc822;

pub struct ProtonImapConnector {
    api_base_url: String,
    auth_router: AuthRouter,
    runtime_accounts: Arc<RuntimeAccountRegistry>,
}

impl ProtonImapConnector {
    pub fn new(
        api_base_url: String,
        auth_router: AuthRouter,
        runtime_accounts: Arc<RuntimeAccountRegistry>,
    ) -> Arc<Self> {
        Arc::new(Self {
            api_base_url,
            auth_router,
            runtime_accounts,
        })
    }

    fn account_id_typed(&self, account_id: &str) -> super::types::AccountId {
        super::types::AccountId(account_id.to_string())
    }

    fn resolve_api_base_url(&self, api_mode: types::ApiMode) -> String {
        if matches!(api_mode, types::ApiMode::Webmail)
            && self.api_base_url == types::ApiMode::Bridge.base_url()
        {
            types::ApiMode::Webmail.base_url().to_string()
        } else {
            self.api_base_url.clone()
        }
    }

    async fn client_for_account(&self, account_id: &str) -> ImapResult<ProtonClient> {
        let aid = self.account_id_typed(account_id);
        let session = self
            .runtime_accounts
            .with_valid_access_token(&aid)
            .await
            .map_err(|e| ImapError::Upstream(e.to_string()))?;
        ProtonClient::authenticated_with_mode(
            &self.resolve_api_base_url(session.api_mode),
            session.api_mode,
            &session.uid,
            &session.access_token,
        )
        .map_err(|e| ImapError::Upstream(e.to_string()))
    }

    async fn keyrings_for_account(
        &self,
        account_id: &str,
    ) -> ImapResult<(Keyring, HashMap<String, Keyring>)> {
        let aid = self.account_id_typed(account_id);
        let session = self
            .runtime_accounts
            .with_valid_access_token(&aid)
            .await
            .map_err(|e| ImapError::Upstream(e.to_string()))?;

        let passphrase_b64 = session
            .key_passphrase
            .as_ref()
            .ok_or_else(|| ImapError::Upstream("no key passphrase in session".to_string()))?;

        let mut passphrase = base64::engine::general_purpose::STANDARD
            .decode(passphrase_b64)
            .map_err(|e| ImapError::Upstream(format!("invalid key passphrase encoding: {e}")))?;

        let auth_material = self.get_or_fetch_auth_material(account_id).await?;

        let user_keyring = keys::unlock_user_keys(&auth_material.user_keys, &passphrase)
            .map_err(|e| ImapError::Upstream(format!("failed to unlock user keys: {e}")))?;

        let mut addr_keyrings = HashMap::new();
        for addr in &auth_material.addresses {
            if addr.status != 1 || addr.keys.is_empty() {
                continue;
            }
            match keys::unlock_address_keys(&addr.keys, &passphrase, &user_keyring) {
                Ok(kr) => {
                    addr_keyrings.insert(addr.id.clone(), kr);
                }
                Err(e) => {
                    warn!(address = %addr.email, error = %e, "could not unlock address keys");
                }
            }
        }

        passphrase.zeroize();

        if addr_keyrings.is_empty() {
            return Err(ImapError::Upstream(
                "could not unlock any address keys".to_string(),
            ));
        }

        Ok((user_keyring, addr_keyrings))
    }

    async fn get_or_fetch_auth_material(
        &self,
        account_id: &str,
    ) -> ImapResult<Arc<RuntimeAuthMaterial>> {
        let aid = self.account_id_typed(account_id);

        if let Some(material) = self.runtime_accounts.get_auth_material(&aid).await {
            return Ok(material);
        }

        let client = self.client_for_account(account_id).await?;

        let user_resp = crate::api::users::get_user(&client)
            .await
            .map_err(|e| ImapError::Upstream(format!("failed to fetch user info: {e}")))?;
        let addr_resp = crate::api::users::get_addresses(&client)
            .await
            .map_err(|e| ImapError::Upstream(format!("failed to fetch addresses: {e}")))?;

        let material = Arc::new(RuntimeAuthMaterial {
            user_keys: user_resp.user.keys,
            addresses: addr_resp.addresses,
        });
        let _ = self
            .runtime_accounts
            .set_auth_material(&aid, material.clone())
            .await;
        Ok(material)
    }
}

#[async_trait]
impl ImapConnector for ProtonImapConnector {
    async fn authorize(&self, username: &str, password: &str) -> ImapResult<AuthResult> {
        let auth_route = self
            .auth_router
            .resolve_login(username, password)
            .ok_or(ImapError::AuthFailed)?;

        let aid = &auth_route.account_id;
        let mut account_session = self
            .runtime_accounts
            .with_valid_access_token(aid)
            .await
            .map_err(|e| match e {
                AccountRuntimeError::AccountUnavailable(_) => ImapError::AuthFailed,
                other => ImapError::Upstream(other.to_string()),
            })?;

        let mut client = ProtonClient::authenticated_with_mode(
            &self.resolve_api_base_url(account_session.api_mode),
            account_session.api_mode,
            &account_session.uid,
            &account_session.access_token,
        )
        .map_err(|e| ImapError::Upstream(format!("failed to create ProtonClient: {e}")))?;

        let passphrase_b64 = account_session
            .key_passphrase
            .as_ref()
            .ok_or_else(|| ImapError::Upstream("no key passphrase in session".to_string()))?
            .clone();

        let mut passphrase = base64::engine::general_purpose::STANDARD
            .decode(&passphrase_b64)
            .map_err(|e| ImapError::Upstream(format!("invalid key passphrase encoding: {e}")))?;

        // Fetch or retrieve cached auth material
        let auth_material = if let Some(material) =
            self.runtime_accounts.get_auth_material(aid).await
        {
            material
        } else {
            let user_resp = match crate::api::users::get_user(&client).await {
                Ok(r) => r,
                Err(e) if is_auth_error(&e) => {
                    let refreshed = self
                        .runtime_accounts
                        .refresh_session_if_stale(aid, Some(&account_session.access_token))
                        .await
                        .map_err(|e| ImapError::Upstream(format!("token refresh failed: {e}")))?;
                    account_session = refreshed;
                    client = ProtonClient::authenticated_with_mode(
                        &self.resolve_api_base_url(account_session.api_mode),
                        account_session.api_mode,
                        &account_session.uid,
                        &account_session.access_token,
                    )
                    .map_err(|e| ImapError::Upstream(format!("failed to recreate client: {e}")))?;
                    crate::api::users::get_user(&client).await.map_err(|e| {
                        ImapError::Upstream(format!("failed to fetch user info after refresh: {e}"))
                    })?
                }
                Err(e) => {
                    passphrase.zeroize();
                    return Err(ImapError::Upstream(format!(
                        "failed to fetch user info: {e}"
                    )));
                }
            };

            let addr_resp = match crate::api::users::get_addresses(&client).await {
                Ok(r) => r,
                Err(e) if is_auth_error(&e) => {
                    let refreshed = self
                        .runtime_accounts
                        .refresh_session_if_stale(aid, Some(&account_session.access_token))
                        .await
                        .map_err(|e| ImapError::Upstream(format!("token refresh failed: {e}")))?;
                    account_session = refreshed;
                    client = ProtonClient::authenticated_with_mode(
                        &self.resolve_api_base_url(account_session.api_mode),
                        account_session.api_mode,
                        &account_session.uid,
                        &account_session.access_token,
                    )
                    .map_err(|e| ImapError::Upstream(format!("failed to recreate client: {e}")))?;
                    crate::api::users::get_addresses(&client)
                        .await
                        .map_err(|e| {
                            ImapError::Upstream(format!(
                                "failed to fetch addresses after refresh: {e}"
                            ))
                        })?
                }
                Err(e) => {
                    passphrase.zeroize();
                    return Err(ImapError::Upstream(format!(
                        "failed to fetch addresses: {e}"
                    )));
                }
            };

            let material = Arc::new(RuntimeAuthMaterial {
                user_keys: user_resp.user.keys,
                addresses: addr_resp.addresses,
            });
            let _ = self
                .runtime_accounts
                .set_auth_material(aid, material.clone())
                .await;
            material
        };

        // Unlock keys to validate they work
        let user_keyring =
            keys::unlock_user_keys(&auth_material.user_keys, &passphrase).map_err(|e| {
                passphrase.zeroize();
                ImapError::Upstream(format!("failed to unlock user keys: {e}"))
            })?;

        let mut addr_keyrings = HashMap::new();
        for addr in &auth_material.addresses {
            if addr.status != 1 || addr.keys.is_empty() {
                continue;
            }
            match keys::unlock_address_keys(&addr.keys, &passphrase, &user_keyring) {
                Ok(kr) => {
                    addr_keyrings.insert(addr.id.clone(), kr);
                }
                Err(e) => {
                    warn!(address = %addr.email, error = %e, "could not unlock address keys");
                }
            }
        }

        passphrase.zeroize();

        if addr_keyrings.is_empty() {
            return Err(ImapError::Upstream(
                "could not unlock any address keys".to_string(),
            ));
        }

        // Fetch user labels
        let mailboxes = match messages::get_labels(
            &client,
            &[types::LABEL_TYPE_LABEL, types::LABEL_TYPE_FOLDER],
        )
        .await
        {
            Ok(resp) => {
                let labels = mailbox::labels_to_mailboxes(&resp.labels);
                info!(user_labels = labels.len(), "loaded user labels/folders");
                self.runtime_accounts
                    .set_user_labels(&super::types::AccountId(aid.0.clone()), labels.clone());
                labels
                    .into_iter()
                    .map(|l| MailboxInfo {
                        name: l.name,
                        id: l.label_id,
                        special_use: l.special_use,
                        selectable: l.selectable,
                    })
                    .collect()
            }
            Err(e) => {
                warn!(error = %e, "failed to fetch user labels; continuing with system mailboxes only");
                Vec::new()
            }
        };

        info!(
            service = "imap",
            msg = "IMAP login successful via connector",
            email = %auth_route.primary_email,
            "IMAP login successful via connector"
        );

        Ok(AuthResult {
            account_id: aid.0.clone(),
            primary_email: auth_route.primary_email.clone(),
            mailboxes,
        })
    }

    async fn get_message_literal(
        &self,
        account_id: &str,
        message_id: &str,
    ) -> ImapResult<Option<Vec<u8>>> {
        let client = self.client_for_account(account_id).await?;
        let (_user_keyring, addr_keyrings) = self.keyrings_for_account(account_id).await?;

        let msg_resp = match messages::get_message(&client, message_id).await {
            Ok(r) => r,
            Err(e) if is_auth_error(&e) => {
                // Retry after refresh
                let aid = self.account_id_typed(account_id);
                let refreshed = self
                    .runtime_accounts
                    .refresh_session(&aid)
                    .await
                    .map_err(|e| ImapError::Upstream(format!("token refresh failed: {e}")))?;
                let client = ProtonClient::authenticated_with_mode(
                    &self.resolve_api_base_url(refreshed.api_mode),
                    refreshed.api_mode,
                    &refreshed.uid,
                    &refreshed.access_token,
                )
                .map_err(|e| ImapError::Upstream(format!("failed to recreate client: {e}")))?;
                match messages::get_message(&client, message_id).await {
                    Ok(r) => r,
                    Err(err) => {
                        warn!(message_id = %message_id, error = %err, "failed to fetch message after refresh");
                        return Ok(None);
                    }
                }
            }
            Err(e) => {
                warn!(message_id = %message_id, error = %e, "failed to fetch message");
                return Ok(None);
            }
        };

        let msg = &msg_resp.message;
        let keyring = match addr_keyrings.get(&msg.metadata.address_id) {
            Some(kr) => kr,
            None => {
                warn!(address_id = %msg.metadata.address_id, "no keyring for address");
                return Ok(None);
            }
        };

        // Need a fresh client for attachment fetches within build_rfc822
        let client = self.client_for_account(account_id).await?;
        let data = match rfc822::build_rfc822(&client, keyring, msg).await {
            Ok(d) => d,
            Err(e) => {
                warn!(message_id = %message_id, error = %e, "failed to build RFC822");
                return Ok(None);
            }
        };

        Ok(Some(data))
    }

    async fn mark_messages_read(
        &self,
        account_id: &str,
        message_ids: &[&str],
        read: bool,
    ) -> ImapResult<()> {
        let client = self.client_for_account(account_id).await?;
        let result = if read {
            messages::mark_messages_read(&client, message_ids).await
        } else {
            messages::mark_messages_unread(&client, message_ids).await
        };
        result.map_err(|e| ImapError::Upstream(e.to_string()))
    }

    async fn mark_messages_starred(
        &self,
        account_id: &str,
        message_ids: &[&str],
        starred: bool,
    ) -> ImapResult<()> {
        let client = self.client_for_account(account_id).await?;
        let result = if starred {
            messages::label_messages(&client, message_ids, types::STARRED_LABEL).await
        } else {
            messages::unlabel_messages(&client, message_ids, types::STARRED_LABEL).await
        };
        result.map_err(|e| ImapError::Upstream(e.to_string()))
    }

    async fn label_messages(
        &self,
        account_id: &str,
        message_ids: &[&str],
        label_id: &str,
    ) -> ImapResult<()> {
        let client = self.client_for_account(account_id).await?;
        messages::label_messages(&client, message_ids, label_id)
            .await
            .map_err(|e| ImapError::Upstream(e.to_string()))
    }

    async fn unlabel_messages(
        &self,
        account_id: &str,
        message_ids: &[&str],
        label_id: &str,
    ) -> ImapResult<()> {
        let client = self.client_for_account(account_id).await?;
        messages::unlabel_messages(&client, message_ids, label_id)
            .await
            .map_err(|e| ImapError::Upstream(e.to_string()))
    }

    async fn trash_messages(&self, account_id: &str, message_ids: &[&str]) -> ImapResult<()> {
        let client = self.client_for_account(account_id).await?;
        messages::label_messages(&client, message_ids, types::TRASH_LABEL)
            .await
            .map_err(|e| ImapError::Upstream(e.to_string()))
    }

    async fn delete_messages(&self, account_id: &str, message_ids: &[&str]) -> ImapResult<()> {
        let client = self.client_for_account(account_id).await?;
        messages::delete_messages(&client, message_ids)
            .await
            .map_err(|e| ImapError::Upstream(e.to_string()))
    }

    async fn import_message(
        &self,
        account_id: &str,
        label_id: &str,
        flags: i64,
        literal: &[u8],
    ) -> ImapResult<Option<String>> {
        let client = self.client_for_account(account_id).await?;
        let (_user_keyring, addr_keyrings) = self.keyrings_for_account(account_id).await?;
        let auth_material = self.get_or_fetch_auth_material(account_id).await?;

        // Use primary address (lowest order among enabled), fall back to first available
        let primary_addr_id = auth_material
            .addresses
            .iter()
            .filter(|a| a.status == 1 && addr_keyrings.contains_key(&a.id))
            .min_by_key(|a| a.order)
            .map(|a| a.id.clone());

        let (addr_id, keyring) = primary_addr_id
            .as_ref()
            .and_then(|id| addr_keyrings.get(id).map(|kr| (id.as_str(), kr)))
            .or_else(|| {
                addr_keyrings
                    .iter()
                    .next()
                    .map(|(id, kr)| (id.as_str(), kr))
            })
            .ok_or_else(|| ImapError::Upstream("no address keyring available".to_string()))?;

        let encrypted = match crypto_encrypt::encrypt_rfc822(keyring, literal) {
            Ok(enc) => enc,
            Err(e) => {
                warn!(error = %e, "APPEND encryption failed");
                return Ok(None);
            }
        };

        let is_unread = flags & types::MESSAGE_FLAG_RECEIVED != 0;
        let metadata = types::ImportMetadata {
            address_id: addr_id.to_string(),
            label_ids: vec![label_id.to_string()],
            unread: is_unread,
            flags,
        };

        match messages::import_message(&client, &metadata, encrypted).await {
            Ok(res) => {
                info!(message_id = %res.message_id, "APPEND imported upstream");
                Ok(Some(res.message_id))
            }
            Err(e) => {
                warn!(error = %e, "APPEND upstream import failed");
                Ok(None)
            }
        }
    }

    async fn fetch_message_metadata_page(
        &self,
        account_id: &str,
        label_id: &str,
        page: i32,
        page_size: i32,
    ) -> ImapResult<MetadataPage> {
        let client = self.client_for_account(account_id).await?;
        let filter = MessageFilter {
            label_id: Some(label_id.to_string()),
            desc: 1,
            ..Default::default()
        };
        let resp = messages::get_message_metadata(&client, &filter, page, page_size)
            .await
            .map_err(|e| ImapError::Upstream(e.to_string()))?;

        let envelopes = resp
            .messages
            .into_iter()
            .map(convert::to_envelope)
            .collect();

        Ok(MetadataPage {
            messages: envelopes,
            total: resp.total,
        })
    }

    async fn fetch_user_labels(&self, account_id: &str) -> ImapResult<Vec<MailboxInfo>> {
        let client = self.client_for_account(account_id).await?;
        let resp = messages::get_labels(
            &client,
            &[types::LABEL_TYPE_LABEL, types::LABEL_TYPE_FOLDER],
        )
        .await
        .map_err(|e| ImapError::Upstream(e.to_string()))?;

        let labels = mailbox::labels_to_mailboxes(&resp.labels);
        Ok(labels
            .into_iter()
            .map(|l| MailboxInfo {
                name: l.name,
                id: l.label_id,
                special_use: l.special_use,
                selectable: l.selectable,
            })
            .collect())
    }
}
