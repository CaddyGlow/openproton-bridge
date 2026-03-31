use std::collections::HashMap;
use std::sync::Arc;

use gluon_rs_calendar::caldav_router::CalDavHandler;
use gluon_rs_dav::http::DavResponse;
use gluon_rs_dav::Result;

use crate::bridge::accounts::RuntimeAccountRegistry;
use crate::bridge::auth_router::AuthRoute;
use crate::bridge::types::AccountId;
use crate::pim::store::PimStore;

use super::{caldav, push, report};

/// Wraps existing CalDAV handler logic (crypto, API sync, reports, push) behind
/// the `CalDavHandler` trait so the library crate can dispatch to it.
pub struct BridgeCalDavHandler {
    pub pim_stores: HashMap<String, Arc<PimStore>>,
    pub runtime_accounts: Option<Arc<RuntimeAccountRegistry>>,
    pub push_subscriptions: Option<push::PushSubscriptionStore>,
}

#[async_trait::async_trait]
impl CalDavHandler for BridgeCalDavHandler {
    async fn handle_request(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
        account_id: &str,
        primary_email: &str,
    ) -> Result<Option<DavResponse>> {
        let auth = AuthRoute {
            account_id: AccountId(account_id.to_string()),
            primary_email: primary_email.to_string(),
        };

        // WebDAV-Push: POST push-register
        if method == "POST" {
            if let Some(ref push_store) = self.push_subscriptions {
                let body_str = std::str::from_utf8(body).unwrap_or("");
                if body_str.contains("push-register") {
                    return push::handle_push_register(path, body, push_store).map(Some);
                }
            }
        }

        // WebDAV-Push: DELETE subscription
        if method == "DELETE" && path.contains(".push-subscriptions/") {
            if let Some(ref push_store) = self.push_subscriptions {
                return push::handle_push_unsubscribe(path, push_store).map(Some);
            }
        }

        let Some(store) = self.pim_stores.get(account_id) else {
            return Ok(None);
        };

        if method == "REPORT" {
            return report::handle_report(path, body, &auth, store, self.runtime_accounts.as_ref())
                .await;
        }

        caldav::handle_request(
            method,
            path,
            headers,
            body,
            &auth,
            store,
            self.runtime_accounts.as_ref(),
        )
        .await
    }
}
