//! Action orchestration: coordinate remote connector calls + local store updates + state broadcasts.

use std::collections::HashMap;

use tracing::warn;

use crate::imap_error::{ImapError, ImapResult};
use crate::imap_types::{ImapUid, ScopedMailboxId};

use super::state::SessionState;
use super::updates::StateUpdate;
use super::user::GluonUser;

/// How to mutate flags on a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagAction {
    /// Replace all flags with the given set.
    Set,
    /// Add flags to the existing set.
    Add,
    /// Remove flags from the existing set.
    Remove,
}

/// Create a mailbox via connector and broadcast update.
pub async fn create_mailbox(user: &GluonUser, name: &str) -> ImapResult<()> {
    let scoped = ScopedMailboxId::from_parts(Some(&user.user_id), name);
    user.gluon_connector.create_mailbox(&scoped).await?;
    user.broadcast_update(StateUpdate::MailboxCreated {
        name: name.to_string(),
    });
    Ok(())
}

/// Delete a mailbox via connector and broadcast update.
pub async fn delete_mailbox(user: &GluonUser, name: &str) -> ImapResult<()> {
    let scoped = ScopedMailboxId::from_parts(Some(&user.user_id), name);
    user.gluon_connector.delete_mailbox(&scoped, false).await?;
    user.broadcast_update(StateUpdate::MailboxDeleted {
        name: name.to_string(),
    });
    Ok(())
}

/// Rename a mailbox via connector and broadcast update.
pub async fn rename_mailbox(user: &GluonUser, old_name: &str, new_name: &str) -> ImapResult<()> {
    let old_scoped = ScopedMailboxId::from_parts(Some(&user.user_id), old_name);
    let new_scoped = ScopedMailboxId::from_parts(Some(&user.user_id), new_name);
    user.gluon_connector
        .rename_mailbox(&old_scoped, &new_scoped)
        .await?;
    user.broadcast_update(StateUpdate::MailboxRenamed {
        old_name: old_name.to_string(),
        new_name: new_name.to_string(),
    });
    Ok(())
}

/// Append a message to a mailbox.
///
/// 1. Import upstream via connector
/// 2. Store metadata + rfc822 in local store (via connector)
/// 3. If mailbox is currently selected, update snapshot
/// 4. Broadcast MessageAppended update
///
/// Returns (uid, uid_validity).
pub async fn append_message(
    user: &GluonUser,
    state: &mut SessionState,
    mailbox_name: &str,
    literal: &[u8],
    flags: &[String],
    date: Option<i64>,
) -> ImapResult<(ImapUid, u32)> {
    let _ = date; // reserved for future use (INTERNALDATE)
    let scoped = ScopedMailboxId::from_parts(Some(&user.user_id), mailbox_name);

    // Compute IMAP flag bitmask for the import API.
    let api_flags = imap_flags_to_api_flags(flags);

    // Resolve mailbox to get uid_validity.
    let mailbox_id = user
        .store
        .resolve_mailbox_id(&user.user_id, mailbox_name)
        .map_err(|e| ImapError::Upstream(format!("resolve mailbox: {e}")))?
        .ok_or_else(|| ImapError::MailboxNotFound(mailbox_name.to_string()))?;

    let session = user
        .store
        .session(&user.user_id)
        .map_err(|e| ImapError::Upstream(format!("store session: {e}")))?;

    let select_data = session
        .mailbox_select_data(mailbox_id)
        .map_err(|e| ImapError::Upstream(format!("select data: {e}")))?;
    let uid_validity = select_data.uid_validity;

    // Import upstream (encrypt + POST).
    let label_id = mailbox_name;
    let proton_id = user
        .connector
        .import_message(&user.user_id, label_id, api_flags, literal)
        .await?;

    // Upsert metadata into the local store so a UID is assigned.
    let envelope = crate::imap_types::MessageEnvelope::default();
    let uid = user
        .gluon_connector
        .upsert_metadata(
            &scoped,
            &crate::imap_store::ProtonMessageId::from(
                proton_id.as_deref().unwrap_or("local-append"),
            ),
            envelope,
        )
        .await?;

    // Store the rfc822 body.
    user.gluon_connector
        .store_rfc822(&scoped, uid, literal.to_vec())
        .await?;

    // Update flags in local store.
    if !flags.is_empty() {
        user.gluon_connector
            .update_message_flags(&scoped, uid, flags.to_vec())
            .await?;
    }

    // Update the session snapshot if this mailbox is selected.
    if let Some(snap) = state.snapshot_mut() {
        if snap.name.eq_ignore_ascii_case(mailbox_name) {
            snap.append(uid, flags.to_vec());
        }
    }

    // Broadcast to other sessions.
    user.broadcast_update(StateUpdate::MessageAppended {
        mailbox: mailbox_name.to_string(),
        uid,
        flags: flags.to_vec(),
    });

    Ok((uid, uid_validity))
}

/// Copy messages from source to destination mailbox.
///
/// 1. For each uid: resolve proton_id from source
/// 2. Call connector label_messages (add to dest)
/// 3. Copy in local store via connector
/// 4. Broadcast MessageAppended for each new uid
///
/// Returns (dest_uid_validity, source_uids, dest_uids).
pub async fn copy_messages(
    user: &GluonUser,
    state: &mut SessionState,
    source_mailbox: &str,
    dest_mailbox: &str,
    uids: &[ImapUid],
) -> ImapResult<(u32, Vec<ImapUid>, Vec<ImapUid>)> {
    let source_scoped = ScopedMailboxId::from_parts(Some(&user.user_id), source_mailbox);
    let dest_scoped = ScopedMailboxId::from_parts(Some(&user.user_id), dest_mailbox);

    let dest_mailbox_id = user
        .store
        .resolve_mailbox_id(&user.user_id, dest_mailbox)
        .map_err(|e| ImapError::Upstream(format!("resolve dest mailbox: {e}")))?
        .ok_or_else(|| ImapError::MailboxNotFound(dest_mailbox.to_string()))?;

    let session = user
        .store
        .session(&user.user_id)
        .map_err(|e| ImapError::Upstream(format!("store session: {e}")))?;

    let dest_select = session
        .mailbox_select_data(dest_mailbox_id)
        .map_err(|e| ImapError::Upstream(format!("dest select data: {e}")))?;
    let dest_uid_validity = dest_select.uid_validity;

    // Collect proton IDs for upstream label operation.
    let mut proton_ids = Vec::new();
    let source_mailbox_id = user
        .store
        .resolve_mailbox_id(&user.user_id, source_mailbox)
        .map_err(|e| ImapError::Upstream(format!("resolve source mailbox: {e}")))?
        .ok_or_else(|| ImapError::MailboxNotFound(source_mailbox.to_string()))?;

    for &uid in uids {
        if let Ok(Some(remote_id)) =
            session.message_remote_id_by_uid(source_mailbox_id, uid.value())
        {
            proton_ids.push(remote_id);
        }
    }

    // Label upstream.
    if !proton_ids.is_empty() {
        let id_refs: Vec<&str> = proton_ids.iter().map(|s| s.as_str()).collect();
        let _ = user
            .connector
            .label_messages(&user.user_id, &id_refs, dest_mailbox)
            .await;
    }

    // Copy locally in the store.
    let mut src_uids = Vec::new();
    let mut dst_uids = Vec::new();

    for &uid in uids {
        match user
            .gluon_connector
            .copy_message(&source_scoped, &dest_scoped, uid)
            .await
        {
            Ok(Some(new_uid)) => {
                src_uids.push(uid);
                dst_uids.push(new_uid);

                // Read flags from source for the broadcast.
                let flags = user
                    .gluon_connector
                    .update_message_flags(&dest_scoped, new_uid, vec![])
                    .await
                    .ok();
                let _ = flags;

                user.broadcast_update(StateUpdate::MessageAppended {
                    mailbox: dest_mailbox.to_string(),
                    uid: new_uid,
                    flags: vec![],
                });
            }
            Ok(None) => {
                warn!(
                    uid = uid.value(),
                    "copy: source message not found, skipping"
                );
            }
            Err(e) => {
                warn!(uid = uid.value(), error = %e, "copy: failed to copy message");
            }
        }
    }

    // Update snapshot if dest is currently selected.
    if let Some(snap) = state.snapshot_mut() {
        if snap.name.eq_ignore_ascii_case(dest_mailbox) {
            for &uid in &dst_uids {
                snap.append(uid, vec![]);
            }
        }
    }

    Ok((dest_uid_validity, src_uids, dst_uids))
}

/// Move messages from source to destination mailbox.
///
/// Performs a copy followed by expunge from source.
///
/// Returns (dest_uid_validity, source_uids, dest_uids, expunged_seqs).
pub async fn move_messages(
    user: &GluonUser,
    state: &mut SessionState,
    source_mailbox: &str,
    dest_mailbox: &str,
    uids: &[ImapUid],
) -> ImapResult<(u32, Vec<ImapUid>, Vec<ImapUid>, Vec<u32>)> {
    let source_scoped = ScopedMailboxId::from_parts(Some(&user.user_id), source_mailbox);

    // Collect proton IDs for upstream move.
    let source_mailbox_id = user
        .store
        .resolve_mailbox_id(&user.user_id, source_mailbox)
        .map_err(|e| ImapError::Upstream(format!("resolve source mailbox: {e}")))?
        .ok_or_else(|| ImapError::MailboxNotFound(source_mailbox.to_string()))?;

    let session = user
        .store
        .session(&user.user_id)
        .map_err(|e| ImapError::Upstream(format!("store session: {e}")))?;

    let mut proton_ids = Vec::new();
    for &uid in uids {
        if let Ok(Some(remote_id)) =
            session.message_remote_id_by_uid(source_mailbox_id, uid.value())
        {
            proton_ids.push(remote_id);
        }
    }

    // Move upstream.
    if !proton_ids.is_empty() {
        let id_refs: Vec<&str> = proton_ids.iter().map(|s| s.as_str()).collect();
        let _ = user
            .connector
            .move_messages(&user.user_id, &id_refs, source_mailbox, dest_mailbox)
            .await;
    }

    // Copy locally.
    let (dest_uid_validity, src_uids, dst_uids) =
        copy_messages(user, state, source_mailbox, dest_mailbox, uids).await?;

    // Expunge from source.
    let mut expunged_seqs = Vec::new();
    for &uid in &src_uids {
        // Remove from local store.
        let _ = user
            .gluon_connector
            .remove_message_by_uid(&source_scoped, uid)
            .await;

        // Update source snapshot if selected.
        if let Some(snap) = state.snapshot_mut() {
            if snap.name.eq_ignore_ascii_case(source_mailbox) {
                if let Some(seq) = snap.expunge(uid) {
                    expunged_seqs.push(seq);
                }
            }
        }

        user.broadcast_update(StateUpdate::MessageExpunged {
            mailbox: source_mailbox.to_string(),
            uid,
        });
    }

    Ok((dest_uid_validity, src_uids, dst_uids, expunged_seqs))
}

/// Store flags on messages.
///
/// 1. Get current flags from snapshot or store
/// 2. Compute new flags based on action (set/add/remove)
/// 3. Update local store
/// 4. Update snapshot
/// 5. Sync upstream: mark_messages_read for \Seen, mark_messages_starred for \Flagged, etc.
/// 6. Broadcast MessageFlagsChanged
///
/// Returns a map of uid -> new flags.
pub async fn store_flags(
    user: &GluonUser,
    state: &mut SessionState,
    mailbox_name: &str,
    uids: &[ImapUid],
    action: FlagAction,
    flags: &[String],
) -> ImapResult<HashMap<ImapUid, Vec<String>>> {
    let scoped = ScopedMailboxId::from_parts(Some(&user.user_id), mailbox_name);
    let mailbox_id = user
        .store
        .resolve_mailbox_id(&user.user_id, mailbox_name)
        .map_err(|e| ImapError::Upstream(format!("resolve mailbox: {e}")))?
        .ok_or_else(|| ImapError::MailboxNotFound(mailbox_name.to_string()))?;

    let session = user
        .store
        .session(&user.user_id)
        .map_err(|e| ImapError::Upstream(format!("store session: {e}")))?;

    let mut result = HashMap::new();

    // Collect proton IDs for upstream sync.
    let mut seen_on_ids = Vec::new();
    let mut seen_off_ids = Vec::new();
    let mut star_on_ids = Vec::new();
    let mut star_off_ids = Vec::new();
    let mut fwd_on_ids = Vec::new();
    let mut fwd_off_ids = Vec::new();

    for &uid in uids {
        let internal_id = match session.message_internal_id_by_uid(mailbox_id, uid.value()) {
            Ok(Some(id)) => id,
            _ => continue,
        };

        let current_flags = session
            .message_flags_by_internal_id(&internal_id)
            .unwrap_or_default();

        let new_flags = compute_flags(&current_flags, flags, action);

        // Persist in local store.
        let _ = session.set_message_flags(&internal_id, &new_flags);

        // Update in-memory snapshot.
        if let Some(snap) = state.snapshot_mut() {
            if snap.name.eq_ignore_ascii_case(mailbox_name) {
                snap.set_flags(uid, new_flags.clone());
            }
        }

        // Also update via connector for event broadcasting.
        let _ = user
            .gluon_connector
            .update_message_flags(&scoped, uid, new_flags.clone())
            .await;

        // Collect proton IDs for upstream sync.
        if let Ok(Some(remote_id)) = session.message_remote_id_by_uid(mailbox_id, uid.value()) {
            let had_seen = current_flags.iter().any(|f| f == "\\Seen");
            let has_seen = new_flags.iter().any(|f| f == "\\Seen");
            if has_seen && !had_seen {
                seen_on_ids.push(remote_id.clone());
            } else if !has_seen && had_seen {
                seen_off_ids.push(remote_id.clone());
            }

            let had_star = current_flags.iter().any(|f| f == "\\Flagged");
            let has_star = new_flags.iter().any(|f| f == "\\Flagged");
            if has_star && !had_star {
                star_on_ids.push(remote_id.clone());
            } else if !has_star && had_star {
                star_off_ids.push(remote_id.clone());
            }

            let had_fwd = current_flags.iter().any(|f| f == "$Forwarded");
            let has_fwd = new_flags.iter().any(|f| f == "$Forwarded");
            if has_fwd && !had_fwd {
                fwd_on_ids.push(remote_id.clone());
            } else if !has_fwd && had_fwd {
                fwd_off_ids.push(remote_id.clone());
            }
        }

        // Broadcast.
        user.broadcast_update(StateUpdate::MessageFlagsChanged {
            mailbox: mailbox_name.to_string(),
            uid,
            flags: new_flags.clone(),
        });

        result.insert(uid, new_flags);
    }

    // Sync upstream in batches.
    sync_flags_upstream(
        user,
        &seen_on_ids,
        &seen_off_ids,
        &star_on_ids,
        &star_off_ids,
        &fwd_on_ids,
        &fwd_off_ids,
    )
    .await;

    Ok(result)
}

/// Expunge messages with \Deleted flag from the currently selected mailbox.
///
/// 1. Find UIDs with \Deleted flag in snapshot
/// 2. Check multi-session coordination
/// 3. For each: sync upstream (trash or delete based on mailbox)
/// 4. Remove from local store
/// 5. Update snapshot
/// 6. Broadcast MessageExpunged
///
/// Returns expunged sequence numbers (in decreasing order for correct IMAP semantics).
pub async fn expunge(user: &GluonUser, state: &mut SessionState) -> ImapResult<Vec<u32>> {
    let snap = state
        .snapshot()
        .ok_or_else(|| ImapError::Protocol("no mailbox selected".to_string()))?;

    let mailbox_name = snap.name.clone();
    let deleted_uids = snap.uids_with_flag("\\Deleted");

    if deleted_uids.is_empty() {
        return Ok(vec![]);
    }

    let scoped = ScopedMailboxId::from_parts(Some(&user.user_id), &mailbox_name);
    let mailbox_id = user
        .store
        .resolve_mailbox_id(&user.user_id, &mailbox_name)
        .map_err(|e| ImapError::Upstream(format!("resolve mailbox: {e}")))?
        .ok_or_else(|| ImapError::MailboxNotFound(mailbox_name.clone()))?;

    let session = user
        .store
        .session(&user.user_id)
        .map_err(|e| ImapError::Upstream(format!("store session: {e}")))?;

    // Collect proton IDs for upstream deletion.
    let mut proton_ids = Vec::new();
    let mut expungeable_uids = Vec::new();

    for &uid in &deleted_uids {
        // Check multi-session coordination.
        if !user.can_expunge(state.session_id, &mailbox_name, uid) {
            continue;
        }
        expungeable_uids.push(uid);
        if let Ok(Some(remote_id)) = session.message_remote_id_by_uid(mailbox_id, uid.value()) {
            proton_ids.push(remote_id);
        }
    }

    // Sync upstream: trash or permanently delete.
    if !proton_ids.is_empty() {
        let id_refs: Vec<&str> = proton_ids.iter().map(|s| s.as_str()).collect();
        let is_trash_or_spam =
            mailbox_name.eq_ignore_ascii_case("Trash") || mailbox_name.eq_ignore_ascii_case("Spam");
        if is_trash_or_spam {
            let _ = user
                .connector
                .delete_messages(&user.user_id, &id_refs)
                .await;
        } else {
            let _ = user.connector.trash_messages(&user.user_id, &id_refs).await;
        }
    }

    // Remove from local store and collect sequence numbers.
    // Process in reverse order so sequence numbers remain valid.
    let mut expunged_seqs = Vec::new();

    for &uid in expungeable_uids.iter().rev() {
        // Remove from store.
        let _ = user
            .gluon_connector
            .remove_message_by_uid(&scoped, uid)
            .await;

        // Remove from snapshot and get the sequence number.
        if let Some(snap) = state.snapshot_mut() {
            if let Some(seq) = snap.expunge(uid) {
                expunged_seqs.push(seq);
            }
        }

        user.broadcast_update(StateUpdate::MessageExpunged {
            mailbox: mailbox_name.clone(),
            uid,
        });
    }

    Ok(expunged_seqs)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute new flags from current flags, the requested flags, and the action.
fn compute_flags(current: &[String], requested: &[String], action: FlagAction) -> Vec<String> {
    match action {
        FlagAction::Set => requested.to_vec(),
        FlagAction::Add => {
            let mut out = current.to_vec();
            for f in requested {
                if !out.iter().any(|e| e == f) {
                    out.push(f.clone());
                }
            }
            out
        }
        FlagAction::Remove => current
            .iter()
            .filter(|f| !requested.contains(f))
            .cloned()
            .collect(),
    }
}

/// Convert IMAP flag strings to an API flag bitmask for import.
fn imap_flags_to_api_flags(flags: &[String]) -> i64 {
    const FLAG_RECEIVED: i64 = 1;
    const FLAG_SENT: i64 = 2;
    const FLAG_IMPORTED: i64 = 16;

    let mut api_flags: i64 = FLAG_RECEIVED | FLAG_IMPORTED;
    if flags.iter().any(|f| f == "\\Seen") {
        // No separate bit needed; absence of Unread is handled upstream.
    }
    if flags.iter().any(|f| f == "\\Answered") {
        api_flags |= FLAG_SENT;
    }
    api_flags
}

/// Sync flag changes upstream in batches.
async fn sync_flags_upstream(
    user: &GluonUser,
    seen_on: &[String],
    seen_off: &[String],
    star_on: &[String],
    star_off: &[String],
    fwd_on: &[String],
    fwd_off: &[String],
) {
    if !seen_on.is_empty() {
        let refs: Vec<&str> = seen_on.iter().map(|s| s.as_str()).collect();
        let _ = user
            .connector
            .mark_messages_read(&user.user_id, &refs, true)
            .await;
    }
    if !seen_off.is_empty() {
        let refs: Vec<&str> = seen_off.iter().map(|s| s.as_str()).collect();
        let _ = user
            .connector
            .mark_messages_read(&user.user_id, &refs, false)
            .await;
    }
    if !star_on.is_empty() {
        let refs: Vec<&str> = star_on.iter().map(|s| s.as_str()).collect();
        let _ = user
            .connector
            .mark_messages_starred(&user.user_id, &refs, true)
            .await;
    }
    if !star_off.is_empty() {
        let refs: Vec<&str> = star_off.iter().map(|s| s.as_str()).collect();
        let _ = user
            .connector
            .mark_messages_starred(&user.user_id, &refs, false)
            .await;
    }
    if !fwd_on.is_empty() {
        let refs: Vec<&str> = fwd_on.iter().map(|s| s.as_str()).collect();
        let _ = user
            .connector
            .mark_messages_forwarded(&user.user_id, &refs, true)
            .await;
    }
    if !fwd_off.is_empty() {
        let refs: Vec<&str> = fwd_off.iter().map(|s| s.as_str()).collect();
        let _ = user
            .connector
            .mark_messages_forwarded(&user.user_id, &refs, false)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_flags_set() {
        let current = vec!["\\Seen".to_string(), "\\Flagged".to_string()];
        let requested = vec!["\\Draft".to_string()];
        let result = compute_flags(&current, &requested, FlagAction::Set);
        assert_eq!(result, vec!["\\Draft".to_string()]);
    }

    #[test]
    fn compute_flags_add() {
        let current = vec!["\\Seen".to_string()];
        let requested = vec!["\\Flagged".to_string(), "\\Seen".to_string()];
        let result = compute_flags(&current, &requested, FlagAction::Add);
        assert_eq!(result, vec!["\\Seen".to_string(), "\\Flagged".to_string()]);
    }

    #[test]
    fn compute_flags_remove() {
        let current = vec![
            "\\Seen".to_string(),
            "\\Flagged".to_string(),
            "\\Draft".to_string(),
        ];
        let requested = vec!["\\Flagged".to_string()];
        let result = compute_flags(&current, &requested, FlagAction::Remove);
        assert_eq!(result, vec!["\\Seen".to_string(), "\\Draft".to_string()]);
    }

    #[test]
    fn api_flags_default() {
        let flags = imap_flags_to_api_flags(&[]);
        assert_eq!(flags, 1 | 16); // RECEIVED | IMPORTED
    }

    #[test]
    fn api_flags_answered() {
        let flags = imap_flags_to_api_flags(&["\\Answered".to_string()]);
        assert_eq!(flags, 1 | 2 | 16); // RECEIVED | SENT | IMPORTED
    }
}
