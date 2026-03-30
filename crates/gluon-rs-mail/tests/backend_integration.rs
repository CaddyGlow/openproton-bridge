//! Integration tests for the backend layer.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use gluon_rs_mail::backend::state::actions::FlagAction;
use gluon_rs_mail::backend::state::session::SessionPhase;
use gluon_rs_mail::backend::state::snapshot::SessionSnapshot;
use gluon_rs_mail::backend::state::updates::StateUpdate;
use gluon_rs_mail::backend::user::GluonUser;
use gluon_rs_mail::backend::{BackendConfig, GluonBackend};
use gluon_rs_mail::gluon_connector::GluonImapConnector;
use gluon_rs_mail::imap_connector::{AuthResult, ImapConnector, MetadataPage};
use gluon_rs_mail::imap_store::ProtonMessageId;
use gluon_rs_mail::imap_types::{ImapUid, MailboxInfo, MessageEnvelope, ScopedMailboxId};
use gluon_rs_mail::store::CompatibleStore;
use gluon_rs_mail::{
    AccountBootstrap, CacheLayout, CompatibilityTarget, GluonKey, GluonUpdateReceiver, ImapResult,
    StoreBootstrap, StoreSession,
};

// ---------------------------------------------------------------------------
// Stub connectors
// ---------------------------------------------------------------------------

struct StubConnector;

#[async_trait]
impl ImapConnector for StubConnector {
    async fn authorize(&self, _u: &str, _p: &str) -> ImapResult<AuthResult> {
        Ok(AuthResult {
            account_id: "test".to_string(),
            primary_email: "test@example.com".to_string(),
            mailboxes: vec![],
        })
    }

    async fn get_message_literal(&self, _: &str, _: &str) -> ImapResult<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn mark_messages_read(&self, _: &str, _: &[&str], _: bool) -> ImapResult<()> {
        Ok(())
    }

    async fn mark_messages_starred(&self, _: &str, _: &[&str], _: bool) -> ImapResult<()> {
        Ok(())
    }

    async fn label_messages(&self, _: &str, _: &[&str], _: &str) -> ImapResult<()> {
        Ok(())
    }

    async fn unlabel_messages(&self, _: &str, _: &[&str], _: &str) -> ImapResult<()> {
        Ok(())
    }

    async fn trash_messages(&self, _: &str, _: &[&str]) -> ImapResult<()> {
        Ok(())
    }

    async fn delete_messages(&self, _: &str, _: &[&str]) -> ImapResult<()> {
        Ok(())
    }

    async fn import_message(
        &self,
        _: &str,
        _: &str,
        _: i64,
        _: &[u8],
    ) -> ImapResult<Option<String>> {
        Ok(Some("imported-id-1".to_string()))
    }

    async fn fetch_message_metadata_page(
        &self,
        _: &str,
        _: &str,
        _: i32,
        _: i32,
    ) -> ImapResult<MetadataPage> {
        Ok(MetadataPage {
            messages: vec![],
            total: 0,
        })
    }

    async fn fetch_user_labels(&self, _: &str) -> ImapResult<Vec<MailboxInfo>> {
        Ok(vec![])
    }
}

struct StubGluonConnector;

#[async_trait]
impl GluonImapConnector for StubGluonConnector {
    fn subscribe_updates(&self) -> GluonUpdateReceiver {
        let (tx1, rx1) = tokio::sync::broadcast::channel(1);
        let (tx2, rx2) = tokio::sync::broadcast::channel(1);
        drop(tx1);
        drop(tx2);
        GluonUpdateReceiver::new(rx1, rx2)
    }

    async fn get_message_literal(
        &self,
        _: &ScopedMailboxId,
        _: ImapUid,
    ) -> ImapResult<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn upsert_metadata(
        &self,
        _: &ScopedMailboxId,
        _: &ProtonMessageId,
        _: MessageEnvelope,
    ) -> ImapResult<ImapUid> {
        Ok(ImapUid::from(1u32))
    }

    async fn list_uids(&self, _: &ScopedMailboxId) -> ImapResult<Vec<ImapUid>> {
        Ok(vec![])
    }

    async fn mailbox_exists(&self, _: &ScopedMailboxId) -> bool {
        true
    }

    async fn create_mailbox(&self, _: &ScopedMailboxId) -> ImapResult<()> {
        Ok(())
    }

    async fn rename_mailbox(&self, _: &ScopedMailboxId, _: &ScopedMailboxId) -> ImapResult<()> {
        Ok(())
    }

    async fn delete_mailbox(&self, _: &ScopedMailboxId, _: bool) -> ImapResult<()> {
        Ok(())
    }

    async fn remove_message_by_uid(&self, _: &ScopedMailboxId, _: ImapUid) -> ImapResult<()> {
        Ok(())
    }

    async fn remove_message_by_proton_id(
        &self,
        _: &ScopedMailboxId,
        _: &ProtonMessageId,
    ) -> ImapResult<()> {
        Ok(())
    }

    async fn update_message_flags(
        &self,
        _: &ScopedMailboxId,
        _: ImapUid,
        _: Vec<String>,
    ) -> ImapResult<()> {
        Ok(())
    }

    async fn copy_message(
        &self,
        _: &ScopedMailboxId,
        _: &ScopedMailboxId,
        _: ImapUid,
    ) -> ImapResult<Option<ImapUid>> {
        Ok(Some(ImapUid::from(100u32)))
    }

    async fn update_message_mailboxes(
        &self,
        _: &ProtonMessageId,
        _: &[ScopedMailboxId],
        _: &[ScopedMailboxId],
    ) -> ImapResult<()> {
        Ok(())
    }

    async fn store_rfc822(&self, _: &ScopedMailboxId, _: ImapUid, _: Vec<u8>) -> ImapResult<()> {
        Ok(())
    }

    async fn acquire_store_session(&self, _: Option<&str>) -> ImapResult<StoreSession> {
        Err(gluon_rs_mail::ImapError::Upstream(
            "stub: no real store".to_string(),
        ))
    }

    fn resolve_storage_user_id<'a>(&'a self, account_id: Option<&'a str>) -> &'a str {
        account_id.unwrap_or("test")
    }

    fn read_message_blob(&self, _: &str, _: &str) -> ImapResult<Vec<u8>> {
        Ok(vec![])
    }

    fn account_paths(&self, _: &str) -> ImapResult<gluon_rs_mail::AccountPaths> {
        Err(gluon_rs_mail::ImapError::Upstream(
            "stub: no real paths".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_user() -> Arc<GluonUser> {
    GluonUser::new(
        "test-user".to_string(),
        Arc::new(StubConnector),
        Arc::new(StubGluonConnector),
        test_store(),
    )
}

fn test_store() -> Arc<CompatibleStore> {
    let dir = tempfile::tempdir().unwrap();
    let key = GluonKey::try_from_slice(&[7u8; 32]).unwrap();
    let bootstrap = StoreBootstrap::new(
        CacheLayout::new(dir.path().join("gluon")),
        CompatibilityTarget::default(),
        vec![AccountBootstrap::new("test-user", "test-user", key)],
    );
    // Leak the tempdir so it stays alive for the duration of the test.
    std::mem::forget(dir);
    Arc::new(CompatibleStore::open(bootstrap).unwrap())
}

fn test_backend() -> Arc<GluonBackend> {
    GluonBackend::new(BackendConfig::default())
}

fn make_snapshot(name: &str, uids: Vec<u32>, flags: HashMap<u32, Vec<String>>) -> SessionSnapshot {
    let imap_uids: Vec<ImapUid> = uids.iter().map(|&u| ImapUid::from(u)).collect();
    let imap_flags: HashMap<ImapUid, Vec<String>> = flags
        .into_iter()
        .map(|(u, f)| (ImapUid::from(u), f))
        .collect();
    let next_uid = uids.last().map(|u| u + 1).unwrap_or(1);
    SessionSnapshot {
        name: name.to_string(),
        internal_id: 1,
        uid_validity: 1234,
        next_uid,
        uids: imap_uids,
        flags: imap_flags,
        mod_seq: 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_backend_add_remove_user() {
    let backend = test_backend();
    let user = test_user();
    backend.add_user(user.clone());
    assert_eq!(backend.user_count(), 1);
    backend.remove_user(&user.user_id);
    assert_eq!(backend.user_count(), 0);
}

#[tokio::test]
async fn test_backend_get_user() {
    let backend = test_backend();
    let user = test_user();
    backend.add_user(user.clone());

    let found = backend.get_user("test-user");
    assert!(found.is_some());
    assert_eq!(found.unwrap().user_id, "test-user");

    let not_found = backend.get_user("nonexistent");
    assert!(not_found.is_none());
}

#[tokio::test]
async fn test_backend_authenticate_success() {
    let backend = test_backend();
    let user = test_user();
    backend.add_user(user.clone());

    let result = backend.authenticate("anything", "anything").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_session_lifecycle() {
    let user = test_user();
    let mut session = user.new_session(1);
    assert_eq!(session.phase(), SessionPhase::NotAuthenticated);

    session.set_authenticated("test-account".to_string());
    assert_eq!(session.phase(), SessionPhase::Authenticated);
    assert_eq!(session.account_id(), Some("test-account"));

    let snap = make_snapshot("INBOX", vec![1, 2, 3], HashMap::new());
    session.select(snap);
    assert_eq!(session.phase(), SessionPhase::Selected);
    assert!(!session.is_read_only());
    assert!(session.snapshot().is_some());

    session.close_mailbox();
    assert_eq!(session.phase(), SessionPhase::Authenticated);

    session.logout();
    assert_eq!(session.phase(), SessionPhase::Logout);
    assert!(session.snapshot().is_none());
    assert!(session.account_id().is_none());

    user.remove_session(1);
    assert_eq!(user.session_count(), 0);
}

#[tokio::test]
async fn test_cross_session_updates() {
    let user = test_user();
    let _s1 = user.new_session(1);
    let mut s2 = user.new_session(2);

    user.broadcast_update(StateUpdate::MessageFlagsChanged {
        mailbox: "INBOX".to_string(),
        uid: ImapUid::from(1u32),
        flags: vec!["\\Seen".to_string()],
    });

    let updates = s2.drain_pending_updates();
    assert_eq!(updates.len(), 1);
    assert!(matches!(
        &updates[0],
        StateUpdate::MessageFlagsChanged { .. }
    ));

    user.remove_session(1);
    user.remove_session(2);
}

#[tokio::test]
async fn test_snapshot_operations() {
    let mut snap = make_snapshot(
        "INBOX",
        vec![1, 2, 3, 4],
        HashMap::from([
            (1, vec!["\\Seen".to_string()]),
            (2, vec![]),
            (3, vec!["\\Deleted".to_string()]),
            (4, vec!["\\Seen".to_string(), "\\Flagged".to_string()]),
        ]),
    );

    assert_eq!(snap.exists(), 4);
    assert_eq!(snap.unseen_count(), 2);
    assert_eq!(snap.uids_with_flag("\\Deleted"), vec![ImapUid::from(3u32)]);

    // Expunge uid 3.
    let seq = snap.expunge(ImapUid::from(3u32));
    assert_eq!(seq, Some(3));
    assert_eq!(snap.exists(), 3);

    // Append uid 5.
    snap.append(ImapUid::from(5u32), vec!["\\Recent".to_string()]);
    assert_eq!(snap.exists(), 4);
    assert_eq!(snap.seq_to_uid(4), Some(ImapUid::from(5u32)));
}

#[tokio::test]
async fn test_expunge_coordination() {
    let user = test_user();
    let _s1 = user.new_session(1);
    let _s2 = user.new_session(2);

    // Register snapshots.
    user.register_snapshot(1, "INBOX", &[ImapUid::from(1u32), ImapUid::from(2u32)]);
    user.register_snapshot(2, "INBOX", &[ImapUid::from(1u32), ImapUid::from(3u32)]);

    // Session 1 wants to expunge uid 1 -- but session 2 also has it.
    assert!(!user.can_expunge(1, "INBOX", ImapUid::from(1u32)));

    // Session 1 wants to expunge uid 2 -- only session 1 has it.
    assert!(user.can_expunge(1, "INBOX", ImapUid::from(2u32)));

    // Unregister session 2.
    user.unregister_snapshot(2);

    // Now session 1 can expunge uid 1.
    assert!(user.can_expunge(1, "INBOX", ImapUid::from(1u32)));

    user.remove_session(1);
    user.remove_session(2);
}

#[tokio::test]
async fn test_expunge_coordination_case_insensitive() {
    let user = test_user();
    user.new_session(1);
    user.new_session(2);

    user.register_snapshot(1, "INBOX", &[ImapUid::from(5u32)]);
    user.register_snapshot(2, "inbox", &[ImapUid::from(5u32)]);

    // Case-insensitive matching means session 2 blocks session 1.
    assert!(!user.can_expunge(1, "Inbox", ImapUid::from(5u32)));

    user.unregister_snapshot(2);
    assert!(user.can_expunge(1, "Inbox", ImapUid::from(5u32)));
}

#[tokio::test]
async fn test_session_examine_is_read_only() {
    let user = test_user();
    let mut session = user.new_session(1);
    session.set_authenticated("test-account".to_string());

    let snap = make_snapshot("Sent", vec![10], HashMap::new());
    session.examine(snap);
    assert_eq!(session.phase(), SessionPhase::Selected);
    assert!(session.is_read_only());
}

#[tokio::test]
async fn test_apply_update_append() {
    let user = test_user();
    let mut session = user.new_session(1);
    session.set_authenticated("a".to_string());

    let snap = make_snapshot("INBOX", vec![1], HashMap::new());
    session.select(snap);

    let update = StateUpdate::MessageAppended {
        mailbox: "INBOX".to_string(),
        uid: ImapUid::from(2u32),
        flags: vec!["\\Seen".to_string()],
    };
    session.apply_update(&update);

    let snap = session.snapshot().unwrap();
    assert_eq!(snap.exists(), 2);
    assert!(snap.has_uid(ImapUid::from(2u32)));
}

#[tokio::test]
async fn test_snapshot_keywords() {
    let snap = make_snapshot(
        "INBOX",
        vec![1, 2],
        HashMap::from([
            (
                1,
                vec![
                    "\\Seen".to_string(),
                    "$label1".to_string(),
                    "$Forwarded".to_string(),
                ],
            ),
            (2, vec!["$label1".to_string(), "$label2".to_string()]),
        ]),
    );

    let kw = snap.keywords();
    assert_eq!(kw.len(), 3);
    assert!(kw.contains("$label1"));
    assert!(kw.contains("$label2"));
    assert!(kw.contains("$Forwarded"));
}

#[tokio::test]
async fn test_remove_session_unregisters_snapshot() {
    let user = test_user();
    user.new_session(10);
    user.register_snapshot(10, "INBOX", &[ImapUid::from(1u32)]);

    // Another session should be blocked.
    user.new_session(20);
    user.register_snapshot(20, "INBOX", &[ImapUid::from(2u32)]);
    assert!(!user.can_expunge(20, "INBOX", ImapUid::from(1u32)));

    // Remove session 10 -- should also unregister its snapshot.
    user.remove_session(10);
    assert!(user.can_expunge(20, "INBOX", ImapUid::from(1u32)));
}

#[tokio::test]
async fn test_flag_action_compute() {
    // These are tested in the unit tests too, but exercise the public enum.
    assert_eq!(FlagAction::Set, FlagAction::Set);
    assert_ne!(FlagAction::Set, FlagAction::Add);
    assert_ne!(FlagAction::Add, FlagAction::Remove);
}
