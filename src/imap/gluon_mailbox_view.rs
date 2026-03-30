use std::sync::Arc;

use async_trait::async_trait;
use gluon_rs_mail::{
    CompatibleStore, UpstreamMailbox, UpstreamMailboxMessage, UpstreamMailboxSnapshot,
};

use gluon_rs_mail::imap_store::{
    GluonMailboxView, MailboxSnapshot, MailboxStatus, ProtonMessageId, SelectMailboxData,
};
use gluon_rs_mail::{ImapError, ImapResult as Result, ImapUid, MessageEnvelope, ScopedMailboxId};

#[derive(Clone)]
pub struct GluonMailMailboxView {
    store: Arc<CompatibleStore>,
}

impl GluonMailMailboxView {
    pub fn new(store: Arc<CompatibleStore>) -> Arc<Self> {
        Arc::new(Self { store })
    }

    fn storage_user_id_for_account<'a>(&'a self, account_id: &'a str) -> &'a str {
        self.store
            .bootstrap()
            .accounts
            .iter()
            .find(|account| account.account_id == account_id)
            .map(|account| account.storage_user_id.as_str())
            .unwrap_or(account_id)
    }

    fn resolve_parts(mailbox: &ScopedMailboxId) -> (&str, &str) {
        let account_id = mailbox.account_id().unwrap_or("__default__");
        let name = mailbox.mailbox_name();
        let name = if name.is_empty() { "INBOX" } else { name };
        (account_id, name)
    }

    async fn upstream_snapshot(
        &self,
        mailbox: &ScopedMailboxId,
    ) -> Result<Option<UpstreamMailboxSnapshot>> {
        let Some((storage_user_id, mb_id)) = self.resolve_mailbox_parts(mailbox)? else {
            return Ok(None);
        };
        self.store
            .mailbox_snapshot(&storage_user_id, mb_id)
            .map(Some)
            .map_err(map_mail_error)
    }

    fn metadata_for_message(
        &self,
        mailbox: &ScopedMailboxId,
        message: &UpstreamMailboxMessage,
    ) -> MessageEnvelope {
        let (account_id, _) = Self::resolve_parts(mailbox);
        let parsed = self
            .store
            .read_message_blob(
                self.storage_user_id_for_account(account_id),
                &message.summary.internal_id,
            )
            .ok()
            .and_then(|data| parse_metadata_from_rfc822(mailbox, &message.summary, &data));

        parsed.unwrap_or_else(|| fallback_metadata(mailbox, message))
    }

    fn resolve_mailbox_parts(&self, mailbox: &ScopedMailboxId) -> Result<Option<(String, u64)>> {
        let (account_id, mailbox_name) = Self::resolve_parts(mailbox);
        let storage_user_id = self.storage_user_id_for_account(account_id).to_string();
        let mb_id = self
            .store
            .resolve_mailbox_id(&storage_user_id, mailbox_name)
            .map_err(map_mail_error)?;
        Ok(mb_id.map(|id| (storage_user_id, id)))
    }
}

#[async_trait]
impl GluonMailboxView for GluonMailMailboxView {
    async fn get_metadata(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> Result<Option<MessageEnvelope>> {
        let Some((storage_user_id, mailbox_internal_id)) = self.resolve_mailbox_parts(mailbox)?
        else {
            return Ok(None);
        };
        let Some(message) = self
            .store
            .message_by_uid(&storage_user_id, mailbox_internal_id, uid.value())
            .map_err(map_mail_error)?
        else {
            return Ok(None);
        };
        Ok(Some(self.metadata_for_message(mailbox, &message)))
    }

    async fn get_proton_id(
        &self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
    ) -> Result<Option<String>> {
        let Some((storage_user_id, mailbox_internal_id)) = self.resolve_mailbox_parts(mailbox)?
        else {
            return Ok(None);
        };
        self.store
            .message_remote_id_by_uid(&storage_user_id, mailbox_internal_id, uid.value())
            .map_err(map_mail_error)
    }

    async fn get_uid(
        &self,
        mailbox: &ScopedMailboxId,
        proton_id: &ProtonMessageId,
    ) -> Result<Option<ImapUid>> {
        let Some(snapshot) = self.upstream_snapshot(mailbox).await? else {
            return Ok(None);
        };

        Ok(snapshot
            .messages
            .iter()
            .find(|message| message.summary.remote_id == proton_id.as_str())
            .map(|message| ImapUid::from(message.summary.uid)))
    }

    async fn get_rfc822(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<Option<Vec<u8>>> {
        let Some((storage_user_id, mailbox_internal_id)) = self.resolve_mailbox_parts(mailbox)?
        else {
            return Ok(None);
        };
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(&storage_user_id, mailbox_internal_id, uid.value())
            .map_err(map_mail_error)?
        else {
            return Ok(None);
        };

        self.store
            .read_message_blob(&storage_user_id, &internal_id)
            .map(Some)
            .map_err(map_mail_error)
    }

    async fn list_uids(&self, mailbox: &ScopedMailboxId) -> Result<Vec<ImapUid>> {
        let Some(snapshot) = self.upstream_snapshot(mailbox).await? else {
            return Ok(Vec::new());
        };

        Ok(snapshot
            .messages
            .iter()
            .map(|message| ImapUid::from(message.summary.uid))
            .collect())
    }

    async fn mailbox_status(&self, mailbox: &ScopedMailboxId) -> Result<MailboxStatus> {
        let Some(snapshot) = self.upstream_snapshot(mailbox).await? else {
            return Ok(MailboxStatus {
                uid_validity: 1,
                next_uid: 1,
                exists: 0,
                unseen: 0,
            });
        };

        let unseen = snapshot
            .messages
            .iter()
            .filter(|message| !has_seen_flag(&message.summary.flags))
            .count() as u32;

        Ok(MailboxStatus {
            uid_validity: snapshot.mailbox.uid_validity,
            next_uid: snapshot.next_uid,
            exists: snapshot.message_count as u32,
            unseen,
        })
    }

    async fn mailbox_snapshot(&self, mailbox: &ScopedMailboxId) -> Result<MailboxSnapshot> {
        let Some(snapshot) = self.upstream_snapshot(mailbox).await? else {
            return Ok(MailboxSnapshot {
                exists: 0,
                mod_seq: 0,
            });
        };

        Ok(MailboxSnapshot {
            exists: snapshot.message_count as u32,
            mod_seq: computed_mod_seq(&snapshot),
        })
    }

    async fn get_flags(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<Vec<String>> {
        let Some((storage_user_id, mailbox_internal_id)) = self.resolve_mailbox_parts(mailbox)?
        else {
            return Ok(Vec::new());
        };
        let Some(internal_id) = self
            .store
            .message_internal_id_by_uid(&storage_user_id, mailbox_internal_id, uid.value())
            .map_err(map_mail_error)?
        else {
            return Ok(Vec::new());
        };
        self.store
            .message_flags_by_internal_id(&storage_user_id, &internal_id)
            .map_err(map_mail_error)
    }

    async fn seq_to_uid(&self, mailbox: &ScopedMailboxId, seq: u32) -> Result<Option<ImapUid>> {
        if seq == 0 {
            return Ok(None);
        }

        let Some(snapshot) = self.upstream_snapshot(mailbox).await? else {
            return Ok(None);
        };

        Ok(snapshot
            .messages
            .get(seq as usize - 1)
            .map(|message| ImapUid::from(message.summary.uid)))
    }

    async fn uid_to_seq(&self, mailbox: &ScopedMailboxId, uid: ImapUid) -> Result<Option<u32>> {
        let Some(snapshot) = self.upstream_snapshot(mailbox).await? else {
            return Ok(None);
        };

        Ok(snapshot
            .messages
            .iter()
            .position(|message| message.summary.uid == uid.value())
            .map(|index| index as u32 + 1))
    }

    async fn select_mailbox_data(&self, mailbox: &ScopedMailboxId) -> Result<SelectMailboxData> {
        let Some((storage_user_id, mb_internal_id)) = self.resolve_mailbox_parts(mailbox)? else {
            return Ok(SelectMailboxData {
                status: MailboxStatus {
                    uid_validity: 1,
                    next_uid: 1,
                    exists: 0,
                    unseen: 0,
                },
                snapshot: MailboxSnapshot {
                    exists: 0,
                    mod_seq: 0,
                },
                uids: Vec::new(),
                flags: std::collections::HashMap::new(),
                first_unseen_seq: None,
            });
        };

        let select = self
            .store
            .mailbox_select_data(&storage_user_id, mb_internal_id)
            .map_err(map_mail_error)?;

        let count = select.entries.len() as u32;
        let mut unseen = 0u32;
        let mut first_unseen_seq = None;
        let mut uids = Vec::with_capacity(select.entries.len());
        let mut flags = std::collections::HashMap::with_capacity(select.entries.len());
        let mut mod_seq_hash = select.next_uid as u64;

        for (index, entry) in select.entries.iter().enumerate() {
            let uid = ImapUid::from(entry.uid);
            let seen = has_seen_flag(&entry.flags);
            if !seen {
                unseen += 1;
                if first_unseen_seq.is_none() {
                    first_unseen_seq = Some(index as u32 + 1);
                }
            }
            mod_seq_hash = mod_seq_hash.wrapping_mul(1_099_511_628_211);
            mod_seq_hash ^= entry.uid as u64;
            mod_seq_hash ^= entry.flags.len() as u64;
            for flag in &entry.flags {
                for byte in flag.as_bytes() {
                    mod_seq_hash = mod_seq_hash.wrapping_mul(1_099_511_628_211);
                    mod_seq_hash ^= u64::from(*byte);
                }
            }
            uids.push(uid);
            flags.insert(uid, entry.flags.clone());
        }

        Ok(SelectMailboxData {
            status: MailboxStatus {
                uid_validity: select.uid_validity,
                next_uid: select.next_uid,
                exists: count,
                unseen,
            },
            snapshot: MailboxSnapshot {
                exists: count,
                mod_seq: mod_seq_hash,
            },
            uids,
            flags,
            first_unseen_seq,
        })
    }

    async fn select_mailbox_data_fast(
        &self,
        mailbox: &ScopedMailboxId,
    ) -> Result<SelectMailboxData> {
        let Some((storage_user_id, mailbox_internal_id)) = self.resolve_mailbox_parts(mailbox)?
        else {
            return Ok(SelectMailboxData {
                status: MailboxStatus {
                    uid_validity: 1,
                    next_uid: 1,
                    exists: 0,
                    unseen: 0,
                },
                snapshot: MailboxSnapshot {
                    exists: 0,
                    mod_seq: 0,
                },
                uids: Vec::new(),
                flags: std::collections::HashMap::new(),
                first_unseen_seq: None,
            });
        };

        let session = self
            .store
            .session(&storage_user_id)
            .map_err(map_mail_error)?;
        let select = session
            .mailbox_select_data(mailbox_internal_id)
            .map_err(map_mail_error)?;

        let count = select.entries.len() as u32;
        let mut unseen = 0u32;
        let mut first_unseen_seq = None;
        let mut uids = Vec::with_capacity(select.entries.len());
        let mut flags = std::collections::HashMap::with_capacity(select.entries.len());
        let mut mod_seq_hash = select.next_uid as u64;

        for (index, entry) in select.entries.iter().enumerate() {
            let uid = ImapUid::from(entry.uid);
            let seen = has_seen_flag(&entry.flags);
            if !seen {
                unseen += 1;
                if first_unseen_seq.is_none() {
                    first_unseen_seq = Some(index as u32 + 1);
                }
            }
            mod_seq_hash = mod_seq_hash.wrapping_mul(1_099_511_628_211);
            mod_seq_hash ^= entry.uid as u64;
            mod_seq_hash ^= entry.flags.len() as u64;
            for flag in &entry.flags {
                for byte in flag.as_bytes() {
                    mod_seq_hash = mod_seq_hash.wrapping_mul(1_099_511_628_211);
                    mod_seq_hash ^= u64::from(*byte);
                }
            }
            uids.push(uid);
            flags.insert(uid, entry.flags.clone());
        }

        Ok(SelectMailboxData {
            status: MailboxStatus {
                uid_validity: select.uid_validity,
                next_uid: select.next_uid,
                exists: count,
                unseen,
            },
            snapshot: MailboxSnapshot {
                exists: count,
                mod_seq: mod_seq_hash,
            },
            uids,
            flags,
            first_unseen_seq,
        })
    }
}

fn map_mail_error(err: gluon_rs_mail::GluonError) -> ImapError {
    ImapError::Protocol(format!("gluon-rs-mail read adapter failure: {err}"))
}

fn has_seen_flag(flags: &[String]) -> bool {
    flags.iter().any(|flag| flag.eq_ignore_ascii_case("\\Seen"))
}

fn computed_mod_seq(snapshot: &UpstreamMailboxSnapshot) -> u64 {
    let mut hash = snapshot.next_uid as u64;
    for message in &snapshot.messages {
        hash = hash.wrapping_mul(1_099_511_628_211);
        hash ^= message.summary.uid as u64;
        hash ^= message.summary.flags.len() as u64;
        for flag in &message.summary.flags {
            for byte in flag.as_bytes() {
                hash = hash.wrapping_mul(1_099_511_628_211);
                hash ^= u64::from(*byte);
            }
        }
    }
    hash
}

pub use gluon_rs_mail::metadata_parse::{fallback_metadata, parse_metadata_from_rfc822};

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use gluon_rs_mail::{
        AccountBootstrap, CacheLayout, CompatibilityTarget, CompatibleStore, GluonKey, NewMailbox,
        NewMessage, StoreBootstrap,
    };
    use tempfile::tempdir;

    use super::GluonMailMailboxView;
    use crate::imap::rfc822;
    use gluon_rs_mail::{EmailAddress, MessageEnvelope};
    use gluon_rs_mail::{GluonMailboxView, ImapUid, ProtonMessageId, ScopedMailboxId};

    async fn open_store() -> Arc<CompatibleStore> {
        let temp = tempdir().expect("tempdir");
        let cache_root = temp.path().join("gluon");
        let layout = CacheLayout::new(&cache_root);
        let store = CompatibleStore::open(StoreBootstrap::new(
            layout,
            CompatibilityTarget::pinned("2046c95ca745"),
            vec![AccountBootstrap::new(
                "account-1",
                "user-1",
                GluonKey::try_from_slice(&[7u8; 32]).expect("key"),
            )],
        ))
        .expect("open store");
        Box::leak(Box::new(temp));
        Arc::new(store)
    }

    fn mailbox() -> NewMailbox {
        NewMailbox {
            remote_id: "0".to_string(),
            name: "INBOX".to_string(),
            uid_validity: 42,
            subscribed: true,
            attributes: Vec::new(),
            flags: Vec::new(),
            permanent_flags: vec!["\\Seen".to_string(), "\\Flagged".to_string()],
        }
    }

    fn metadata() -> MessageEnvelope {
        MessageEnvelope {
            id: "msg-1".to_string(),
            address_id: "addr-1".to_string(),
            label_ids: vec!["0".to_string()],
            external_id: Some("msg-1@example.test".to_string()),
            subject: "Adapter Subject".to_string(),
            sender: EmailAddress {
                name: "Alice".to_string(),
                address: "alice@example.test".to_string(),
            },
            to_list: vec![EmailAddress {
                name: "Bob".to_string(),
                address: "bob@example.test".to_string(),
            }],
            cc_list: Vec::new(),
            bcc_list: Vec::new(),
            reply_tos: Vec::new(),
            flags: 0,
            time: 1_700_000_000,
            size: 42,
            unread: 0,
            is_replied: 0,
            is_replied_all: 0,
            is_forwarded: 0,
            num_attachments: 0,
        }
    }

    fn message_with_blob(meta: &MessageEnvelope, blob: Vec<u8>) -> NewMessage {
        let header = String::from_utf8_lossy(&blob)
            .split("\r\n\r\n")
            .next()
            .unwrap_or_default()
            .to_string();
        NewMessage {
            internal_id: "internal-1".to_string(),
            remote_id: meta.id.clone(),
            flags: vec!["\\Seen".to_string()],
            blob,
            body: "body".to_string(),
            body_structure: rfc822::build_bodystructure(b"From: a\r\n\r\nbody"),
            envelope: rfc822::build_envelope(meta, &header),
            size: meta.size,
            recent: false,
        }
    }

    fn scoped(account: &str, mailbox: &str) -> ScopedMailboxId {
        ScopedMailboxId::from_parts(Some(account), mailbox)
    }

    #[tokio::test]
    async fn gluon_mail_mailbox_view_reads_snapshot_and_blob_state() {
        let store = open_store().await;
        let mailbox = store
            .create_mailbox("user-1", &mailbox())
            .await
            .expect("create mailbox");
        let meta = metadata();
        let blob = b"Date: Tue, 14 Nov 2023 22:13:20 +0000\r\nFrom: Alice <alice@example.test>\r\nTo: Bob <bob@example.test>\r\nSubject: Adapter Subject\r\nMessage-ID: <msg-1@example.test>\r\n\r\nbody".to_vec();
        store
            .append_message(
                "user-1",
                mailbox.internal_id,
                &message_with_blob(&meta, blob.clone()),
            )
            .await
            .expect("append message");

        let view = GluonMailMailboxView::new(store);
        let scoped = scoped("account-1", "INBOX");
        let uid1 = ImapUid::from(1u32);
        let pid = ProtonMessageId::from("msg-1");

        assert_eq!(view.list_uids(&scoped).await.expect("uids"), vec![uid1]);
        assert_eq!(view.get_uid(&scoped, &pid).await.expect("uid"), Some(uid1));
        assert_eq!(
            view.get_proton_id(&scoped, uid1).await.expect("proton id"),
            Some("msg-1".to_string())
        );
        assert_eq!(
            view.get_rfc822(&scoped, uid1).await.expect("rfc822"),
            Some(blob)
        );

        let status = view.mailbox_status(&scoped).await.expect("status");
        assert_eq!(status.uid_validity, 42);
        assert_eq!(status.next_uid, 2);
        assert_eq!(status.exists, 1);
        assert_eq!(status.unseen, 0);

        let snapshot = view.mailbox_snapshot(&scoped).await.expect("snapshot");
        assert_eq!(snapshot.exists, 1);
        assert!(snapshot.mod_seq > 0);

        assert_eq!(
            view.get_flags(&scoped, uid1).await.expect("flags"),
            vec!["\\Seen".to_string()]
        );
        assert_eq!(view.seq_to_uid(&scoped, 1).await.expect("seq"), Some(uid1));
        assert_eq!(
            view.uid_to_seq(&scoped, uid1).await.expect("uid->seq"),
            Some(1)
        );

        let meta = view
            .get_metadata(&scoped, uid1)
            .await
            .expect("metadata")
            .expect("message metadata");
        assert_eq!(meta.subject, "Adapter Subject");
        assert_eq!(meta.sender.address, "alice@example.test");
        assert_eq!(meta.to_list[0].address, "bob@example.test");
        assert_eq!(meta.unread, 0);
    }

    #[tokio::test]
    async fn gluon_mail_mailbox_view_falls_back_when_blob_is_missing() {
        let store = open_store().await;
        let mailbox = store
            .create_mailbox("user-1", &mailbox())
            .await
            .expect("create mailbox");
        let meta = metadata();
        let message = message_with_blob(&meta, b"Subject: fallback\r\n\r\nbody".to_vec());
        let internal_id = message.internal_id.clone();
        let account_paths = store.account_paths("user-1").expect("account paths");
        store
            .append_message("user-1", mailbox.internal_id, &message)
            .await
            .expect("append message");
        std::fs::remove_file(account_paths.blob_path(&internal_id).expect("blob path"))
            .expect("remove blob");

        let view = GluonMailMailboxView::new(store);
        let scoped = scoped("account-1", "INBOX");
        let meta = view
            .get_metadata(&scoped, ImapUid::from(1u32))
            .await
            .expect("metadata")
            .expect("fallback metadata");

        assert_eq!(meta.id, "msg-1");
        assert_eq!(meta.subject, "");
        assert_eq!(meta.unread, 0);
    }
}
