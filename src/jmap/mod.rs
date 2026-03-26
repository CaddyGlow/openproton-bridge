use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

use tokio::task::JoinHandle;

use crate::imap::gluon_connector::{GluonImapConnector, GluonUpdate};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JmapDataType {
    Mailbox,
    Email,
}

impl JmapDataType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mailbox => "Mailbox",
            Self::Email => "Email",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JmapChangeSet {
    pub account_id: String,
    pub changed: BTreeSet<JmapDataType>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JmapAccountState {
    pub mailbox_state: u64,
    pub email_state: u64,
}

impl JmapAccountState {
    pub fn mailbox_state_token(&self) -> String {
        self.mailbox_state.to_string()
    }

    pub fn email_state_token(&self) -> String {
        self.email_state.to_string()
    }
}

#[derive(Debug, Default)]
pub struct JmapStateTracker {
    states: RwLock<HashMap<String, JmapAccountState>>,
}

impl JmapStateTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_gluon_update(&self, update: &GluonUpdate) -> Option<JmapChangeSet> {
        let change_set = change_set_from_gluon_update(update)?;
        let mut states = self.states.write().expect("jmap state lock poisoned");
        let state = states.entry(change_set.account_id.clone()).or_default();

        if change_set.changed.contains(&JmapDataType::Mailbox) {
            state.mailbox_state = state.mailbox_state.saturating_add(1);
        }
        if change_set.changed.contains(&JmapDataType::Email) {
            state.email_state = state.email_state.saturating_add(1);
        }

        Some(change_set)
    }

    pub fn spawn_connector_subscription(
        self: Arc<Self>,
        connector: Arc<dyn GluonImapConnector>,
    ) -> JoinHandle<()> {
        let mut updates = connector.subscribe_updates();
        tokio::spawn(async move {
            loop {
                match updates.recv().await {
                    Ok(update) => {
                        let _ = self.apply_gluon_update(&update);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    }

    pub fn state_for_account(&self, account_id: &str) -> JmapAccountState {
        self.states
            .read()
            .expect("jmap state lock poisoned")
            .get(account_id)
            .cloned()
            .unwrap_or_default()
    }
}

pub fn change_set_from_gluon_update(update: &GluonUpdate) -> Option<JmapChangeSet> {
    let account_id = update.account_id()?.to_string();
    let mut changed = BTreeSet::new();

    match update {
        GluonUpdate::Noop => return None,
        GluonUpdate::MailboxCreated { .. }
        | GluonUpdate::MailboxUpdated { .. }
        | GluonUpdate::MailboxUpdatedOrCreated { .. }
        | GluonUpdate::MailboxDeleted { .. }
        | GluonUpdate::MailboxDeletedSilent { .. }
        | GluonUpdate::MailboxIDChanged { .. }
        | GluonUpdate::UIDValidityBumped { .. } => {
            changed.insert(JmapDataType::Mailbox);
        }
        GluonUpdate::MessagesCreated { .. }
        | GluonUpdate::MessageUpdated { .. }
        | GluonUpdate::MessageDeleted { .. }
        | GluonUpdate::MessageFlagsUpdated { .. }
        | GluonUpdate::MessageMailboxesUpdated { .. }
        | GluonUpdate::MessageIDChanged { .. } => {
            changed.insert(JmapDataType::Mailbox);
            changed.insert(JmapDataType::Email);
        }
    }

    Some(JmapChangeSet {
        account_id,
        changed,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{change_set_from_gluon_update, JmapDataType, JmapStateTracker};
    use crate::imap::convert::to_envelope;
    use crate::imap::gluon_connector::{
        GluonImapConnector, GluonMailConnector, GluonMailbox, GluonMessageRef, GluonUpdate,
    };
    use crate::imap::types::{ImapUid, ProtonMessageId, ScopedMailboxId};
    use gluon_rs_mail::{
        AccountBootstrap, CacheLayout, CompatibilityTarget, CompatibleStore, GluonKey,
        StoreBootstrap,
    };
    use tempfile::TempDir;

    #[test]
    fn maps_gluon_updates_into_jmap_change_sets() {
        let change = change_set_from_gluon_update(&GluonUpdate::MessageFlagsUpdated {
            message: GluonMessageRef {
                mailbox: ScopedMailboxId::from_parts(Some("uid-1"), "INBOX"),
                uid: ImapUid::from(7u32),
                proton_id: Some(ProtonMessageId::from("msg-7")),
                mod_seq: 4,
            },
            flags: Some(vec!["\\\\Seen".to_string()]),
        })
        .expect("scoped mailbox");

        assert_eq!(change.account_id, "uid-1");
        assert!(change.changed.contains(&JmapDataType::Mailbox));
        assert!(change.changed.contains(&JmapDataType::Email));
    }

    #[test]
    fn tracks_mailbox_and_email_state_tokens() {
        let tracker = JmapStateTracker::new();
        tracker
            .apply_gluon_update(&GluonUpdate::MailboxCreated {
                mailbox: GluonMailbox {
                    mailbox: ScopedMailboxId::from_parts(Some("uid-1"), "INBOX"),
                    mod_seq: 1,
                },
            })
            .expect("mailbox change");
        tracker
            .apply_gluon_update(&GluonUpdate::MessagesCreated {
                messages: vec![crate::imap::gluon_connector::GluonCreatedMessage {
                    message: GluonMessageRef {
                        mailbox: ScopedMailboxId::from_parts(Some("uid-1"), "INBOX"),
                        uid: ImapUid::from(1u32),
                        proton_id: Some(ProtonMessageId::from("msg-1")),
                        mod_seq: 2,
                    },
                    mailbox_names: vec!["INBOX".to_string()],
                    flags: None,
                }],
                ignore_unknown_mailbox_ids: false,
            })
            .expect("message change");

        let state = tracker.state_for_account("uid-1");
        assert_eq!(state.mailbox_state_token(), "2");
        assert_eq!(state.email_state_token(), "1");
    }

    #[test]
    fn ignores_unscoped_updates() {
        assert!(change_set_from_gluon_update(&GluonUpdate::MailboxCreated {
            mailbox: GluonMailbox {
                mailbox: ScopedMailboxId::from_parts(None, "INBOX"),
                mod_seq: 1,
            },
        })
        .is_none());
    }

    fn test_gluon_connector() -> (Arc<dyn GluonImapConnector>, TempDir) {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let layout = CacheLayout::new(tempdir.path().join("gluon"));
        let gluon_store = Arc::new(
            CompatibleStore::open(StoreBootstrap::new(
                layout,
                CompatibilityTarget::pinned("2046c95ca745"),
                vec![AccountBootstrap::new(
                    "uid-1",
                    "uid-1",
                    GluonKey::try_from_slice(&[7u8; 32]).expect("key"),
                )],
            ))
            .expect("open store"),
        );
        (GluonMailConnector::new(gluon_store), tempdir)
    }

    #[tokio::test]
    async fn connector_subscription_applies_updates_to_jmap_tracker() {
        let (connector, _tempdir) = test_gluon_connector();
        let tracker = Arc::new(JmapStateTracker::new());
        let _task = tracker
            .clone()
            .spawn_connector_subscription(connector.clone());

        connector
            .create_mailbox(&ScopedMailboxId::from_parts(
                Some("uid-1"),
                "Labels/Projects",
            ))
            .await
            .unwrap();
        let _ = connector
            .upsert_metadata(
                &ScopedMailboxId::from_parts(Some("uid-1"), "Labels/Projects"),
                &ProtonMessageId::from("msg-1"),
                to_envelope(crate::api::types::MessageMetadata {
                    id: "msg-1".to_string(),
                    address_id: "addr-1".to_string(),
                    external_id: None,
                    label_ids: vec!["label-1".to_string()],
                    subject: "hello".to_string(),
                    sender: crate::api::types::EmailAddress {
                        name: "Alice".to_string(),
                        address: "alice@example.com".to_string(),
                    },
                    to_list: Vec::new(),
                    cc_list: Vec::new(),
                    bcc_list: Vec::new(),
                    reply_tos: Vec::new(),
                    flags: 0,
                    time: 0,
                    size: 0,
                    unread: 1,
                    is_replied: 0,
                    is_replied_all: 0,
                    is_forwarded: 0,
                    num_attachments: 0,
                }),
            )
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(25)).await;

        let state = tracker.state_for_account("uid-1");
        assert!(state.mailbox_state >= 2);
        assert!(state.email_state >= 1);
    }
}
