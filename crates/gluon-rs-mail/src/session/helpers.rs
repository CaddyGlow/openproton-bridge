use std::collections::HashMap;

use tokio::io::AsyncWriteExt;
use tracing::warn;

use super::*;

impl<R, W> ImapSession<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    pub async fn resolve_mailbox(&self, name: &str) -> Option<mailbox::ResolvedMailbox> {
        if let Some(mb) = self.config.mailbox_catalog.resolve_mailbox(
            self.authenticated_account_id.as_deref(),
            &self.user_labels,
            name,
        ) {
            return Some(mb);
        }
        // Fall back to checking the gluon store for dynamically created mailboxes
        let scoped = self.scoped_mailbox_name(name);
        if self.config.gluon_connector.mailbox_exists(&scoped).await {
            return Some(mailbox::ResolvedMailbox {
                name: name.to_string(),
                label_id: name.to_string(),
                special_use: None,
                selectable: true,
            });
        }
        None
    }

    pub fn all_mailboxes(&self) -> Vec<mailbox::ResolvedMailbox> {
        self.config
            .mailbox_catalog
            .all_mailboxes(self.authenticated_account_id.as_deref(), &self.user_labels)
    }

    pub fn scoped_mailbox_name(&self, mailbox: &str) -> ScopedMailboxId {
        ScopedMailboxId::from_parts(self.authenticated_account_id.as_deref(), mailbox)
    }

    pub async fn refresh_selected_snapshot(&mut self) -> Result<()> {
        let Some(mailbox) = self.selected_mailbox.clone() else {
            return Ok(());
        };
        let data = if let (Some(ref mut ss), Some(mb_id)) =
            (&mut self.store_session, self.selected_mailbox_internal_id)
        {
            select_data_from_session(ss, mb_id).await?
        } else {
            let scoped = self.scoped_mailbox_name(&mailbox);
            self.config
                .mailbox_view
                .select_mailbox_data_fast(&scoped)
                .await?
        };
        self.selected_mailbox_uids = data.uids;
        self.selected_mailbox_flags = data.flags;
        self.selected_mailbox_mod_seq = Some(data.snapshot.mod_seq);
        Ok(())
    }

    pub async fn emit_selected_mailbox_exists_update(&mut self) -> Result<()> {
        if self.state != State::Selected {
            return Ok(());
        }
        let Some(mailbox) = self.selected_mailbox.clone() else {
            return Ok(());
        };

        let select_data = if let (Some(ref mut ss), Some(mb_id)) =
            (&mut self.store_session, self.selected_mailbox_internal_id)
        {
            select_data_from_session(ss, mb_id).await?
        } else {
            let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
            self.config
                .mailbox_view
                .select_mailbox_data_fast(&scoped_mailbox)
                .await?
        };

        let previous_mod_seq = self.selected_mailbox_mod_seq.unwrap_or(0);
        let previous_exists = self.selected_mailbox_uids.len() as u32;
        let current_uids = select_data.uids;
        let current_flags = select_data.flags;
        let snapshot = select_data.snapshot;

        let has_uid_change = current_uids != self.selected_mailbox_uids;
        let has_flag_change = current_uids
            .iter()
            .any(|uid| self.selected_mailbox_flags.get(uid) != current_flags.get(uid));

        if snapshot.mod_seq > previous_mod_seq
            || snapshot.exists != previous_exists
            || has_uid_change
            || has_flag_change
        {
            if self.selected_mailbox_mod_seq.is_some() {
                let current_uid_set: HashSet<ImapUid> = current_uids.iter().copied().collect();
                let mut removed_count = 0u32;
                for (idx, uid) in self.selected_mailbox_uids.iter().enumerate() {
                    if !current_uid_set.contains(uid) {
                        let seq = idx as u32 + 1 - removed_count;
                        self.writer.untagged(&format!("{seq} EXPUNGE")).await?;
                        removed_count = removed_count.saturating_add(1);
                    }
                }

                if snapshot.exists != previous_exists {
                    self.writer
                        .untagged(&format!("{} EXISTS", snapshot.exists))
                        .await?;
                }

                for (idx, uid) in current_uids.iter().enumerate() {
                    let Some(new_flags) = current_flags.get(uid) else {
                        continue;
                    };
                    let old_flags = self.selected_mailbox_flags.get(uid);
                    if old_flags.is_none() || old_flags != Some(new_flags) {
                        let flag_str = new_flags.join(" ");
                        self.writer
                            .untagged(&format!("{} FETCH (FLAGS ({}))", idx + 1, flag_str))
                            .await?;
                    }
                }
            } else {
                self.writer
                    .untagged(&format!("{} EXISTS", snapshot.exists))
                    .await?;
            }

            self.selected_mailbox_uids = current_uids;
            self.selected_mailbox_flags = current_flags;
            self.selected_mailbox_mod_seq = Some(snapshot.mod_seq);
        }
        Ok(())
    }

    pub fn resolve_target_uids(
        &self,
        all_uids: &[ImapUid],
        sequence: &SequenceSet,
        uid_mode: bool,
    ) -> Vec<ImapUid> {
        if all_uids.is_empty() {
            return Vec::new();
        }

        let max_uid = all_uids.last().map(|u| u.value()).unwrap_or(0);
        let max_seq = all_uids.len() as u32;

        if uid_mode {
            all_uids
                .iter()
                .filter(|uid| sequence.contains(uid.value(), max_uid))
                .copied()
                .collect()
        } else {
            all_uids
                .iter()
                .enumerate()
                .filter(|(i, _)| sequence.contains(*i as u32 + 1, max_seq))
                .map(|(_, &uid)| uid)
                .collect()
        }
    }

    pub async fn fetch_and_cache_rfc822(
        &mut self,
        mailbox: &ScopedMailboxId,
        uid: ImapUid,
        proton_id: &str,
    ) -> Result<Option<Vec<u8>>> {
        let account_id = match &self.authenticated_account_id {
            Some(id) => id.clone(),
            None => return Ok(None),
        };

        let data = match self
            .config
            .connector
            .get_message_literal(&account_id, proton_id)
            .await
        {
            Ok(Some(d)) => d,
            Ok(None) => return Ok(None),
            Err(e) => {
                warn!(proton_id = %proton_id, error = %e, "connector failed to fetch message");
                return Ok(None);
            }
        };

        self.config
            .mailbox_mutation
            .store_rfc822(mailbox, uid, data.clone())
            .await?;

        Ok(Some(data))
    }
}

pub fn format_mailbox_name(name: &str) -> String {
    if name.is_empty()
        || name.contains(' ')
        || name.contains('"')
        || name.contains('\\')
        || name.contains('(')
        || name.contains(')')
        || name.contains('{')
    {
        format!("\"{}\"", name.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        name.to_string()
    }
}

pub fn extract_header_section(data: &[u8]) -> String {
    let s = String::from_utf8_lossy(data);
    if let Some(pos) = s.find("\r\n\r\n") {
        s[..pos + 4].to_string()
    } else if let Some(pos) = s.find("\n\n") {
        s[..pos + 2].to_string()
    } else {
        s.to_string()
    }
}

pub fn extract_text_section(data: &[u8]) -> Vec<u8> {
    let s = String::from_utf8_lossy(data);
    if let Some(pos) = s.find("\r\n\r\n") {
        data[pos + 4..].to_vec()
    } else if let Some(pos) = s.find("\n\n") {
        data[pos + 2..].to_vec()
    } else {
        data.to_vec()
    }
}

/// Resolve a mailbox name to its internal_id using a pinned StoreSession.
pub async fn resolve_mailbox_internal_id(
    session: &mut crate::store::StoreSession,
    mailbox_name: &str,
) -> Option<u64> {
    let mailboxes = session.list_upstream_mailboxes().ok()?;
    mailboxes
        .into_iter()
        .find(|mb| mb.name.eq_ignore_ascii_case(mailbox_name))
        .map(|mb| mb.internal_id)
}

/// Build SelectMailboxData from a pinned StoreSession, mirroring the logic in
/// GluonMailMailboxView::select_mailbox_data_fast.
pub async fn select_data_from_session(
    session: &mut crate::store::StoreSession,
    mailbox_internal_id: u64,
) -> Result<crate::imap_store::SelectMailboxData> {
    use crate::imap_store::{MailboxSnapshot, MailboxStatus, SelectMailboxData};

    let select = session
        .mailbox_select_data(mailbox_internal_id)
        .map_err(|e| {
            crate::imap_error::ImapError::Protocol(format!("store session select: {e}"))
        })?;

    let count = select.entries.len() as u32;
    let mut unseen = 0u32;
    let mut first_unseen_seq = None;
    let mut uids = Vec::with_capacity(select.entries.len());
    let mut flags = HashMap::with_capacity(select.entries.len());
    let mut mod_seq_hash = select.next_uid as u64;

    for (index, entry) in select.entries.iter().enumerate() {
        let uid = ImapUid::from(entry.uid);
        let seen = entry.flags.iter().any(|f| f.eq_ignore_ascii_case("\\Seen"));
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
