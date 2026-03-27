use std::sync::Arc;

use crate::bridge::accounts::RuntimeAccountRegistry;
use crate::bridge::types::AccountId;

pub use gluon_rs_mail::GluonMailboxCatalog;
use gluon_rs_mail::ResolvedMailbox;

#[derive(Clone)]
pub struct RuntimeMailboxCatalog {
    runtime_accounts: Arc<RuntimeAccountRegistry>,
}

impl RuntimeMailboxCatalog {
    pub fn new(runtime_accounts: Arc<RuntimeAccountRegistry>) -> Arc<Self> {
        Arc::new(Self { runtime_accounts })
    }
}

impl GluonMailboxCatalog for RuntimeMailboxCatalog {
    fn user_labels(
        &self,
        account_id: Option<&str>,
        fallback_labels: &[ResolvedMailbox],
    ) -> Vec<ResolvedMailbox> {
        match account_id {
            Some(account_id) => self
                .runtime_accounts
                .get_user_labels(&AccountId(account_id.to_string())),
            None => fallback_labels.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{GluonMailboxCatalog, RuntimeMailboxCatalog};
    use crate::api::types::Session;
    use crate::bridge::accounts::RuntimeAccountRegistry;
    use gluon_rs_mail::ResolvedMailbox;

    fn test_session(uid: &str) -> Session {
        Session {
            uid: uid.to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            email: format!("{uid}@example.com"),
            display_name: uid.to_string(),
            api_mode: crate::api::types::ApiMode::Bridge,
            key_passphrase: Some("dGVzdA==".to_string()),
            bridge_password: Some("bridge-pass-1234".to_string()),
        }
    }

    #[test]
    fn runtime_mailbox_catalog_uses_runtime_labels_when_account_is_known() {
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![test_session(
            "uid-1",
        )]));
        runtime.set_user_labels(
            &crate::bridge::types::AccountId("uid-1".to_string()),
            vec![ResolvedMailbox {
                name: "Labels/Projects".to_string(),
                label_id: "label-1".to_string(),
                special_use: None,
                selectable: true,
            }],
        );
        let catalog = RuntimeMailboxCatalog::new(runtime);

        let mailbox = catalog
            .resolve_mailbox(Some("uid-1"), &[], "Labels/Projects")
            .expect("mailbox");
        assert_eq!(mailbox.name, "Labels/Projects");
    }

    #[test]
    fn runtime_mailbox_catalog_falls_back_to_session_labels_when_unknown() {
        let runtime = Arc::new(RuntimeAccountRegistry::in_memory(vec![test_session(
            "uid-1",
        )]));
        let catalog = RuntimeMailboxCatalog::new(runtime);

        let mailbox = catalog
            .resolve_mailbox(
                None,
                &[ResolvedMailbox {
                    name: "Labels/Fallback".to_string(),
                    label_id: "label-fallback".to_string(),
                    special_use: None,
                    selectable: true,
                }],
                "Labels/Fallback",
            )
            .expect("fallback mailbox");
        assert_eq!(mailbox.name, "Labels/Fallback");
    }
}
