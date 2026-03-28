use tokio::io::AsyncWriteExt;
use tracing::warn;

use super::*;

impl<R, W> ImapSession<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    pub async fn cmd_store(
        &mut self,
        tag: &str,
        sequence: &SequenceSet,
        action: &StoreAction,
        flags: &[ImapFlag],
        uid_mode: bool,
    ) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        if self.selected_read_only {
            return self.writer.tagged_no(tag, "mailbox is read-only").await;
        }

        self.refresh_selected_snapshot().await?;
        let mailbox = self.selected_mailbox.as_ref().unwrap().clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let mutation = &self.config.mailbox_mutation;
        let all_uids = self.selected_mailbox_uids.clone();

        if all_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "STORE completed").await;
        }

        let target_uids = self.resolve_target_uids(&all_uids, sequence, uid_mode);

        let flag_strings: Vec<String> = flags.iter().map(|f| f.as_str().to_string()).collect();
        let silent = matches!(
            action,
            StoreAction::SetFlagsSilent
                | StoreAction::AddFlagsSilent
                | StoreAction::RemoveFlagsSilent
        );

        // Take pinned session for the store loop to avoid per-message pool.acquire().
        let mut pinned_session = self.store_session.take();
        let pinned_mb_id = self.selected_mailbox_internal_id;

        for &uid in &target_uids {
            // Fast path: use pinned session for flag reads/writes.
            let used_pinned = if let (Some(ref mut ss), Some(mb_id)) =
                (&mut pinned_session, pinned_mb_id)
            {
                if let Ok(Some(internal_id)) = ss.message_internal_id_by_uid(mb_id, uid.value()) {
                    let previous_flags =
                        ss.message_flags_by_internal_id(&internal_id).map_err(|e| {
                            crate::imap_error::ImapError::Protocol(format!(
                                "store session flags: {e}"
                            ))
                        })?;
                    let had_seen = previous_flags.iter().any(|flag| flag == "\\Seen");
                    let had_flagged = previous_flags.iter().any(|flag| flag == "\\Flagged");

                    match action {
                        StoreAction::SetFlags | StoreAction::SetFlagsSilent => {
                            ss.set_message_flags(&internal_id, &flag_strings)
                                .map_err(|e| {
                                    crate::imap_error::ImapError::Protocol(format!(
                                        "store session set_flags: {e}"
                                    ))
                                })?;
                        }
                        StoreAction::AddFlags | StoreAction::AddFlagsSilent => {
                            ss.add_message_flags(&internal_id, &flag_strings)
                                .map_err(|e| {
                                    crate::imap_error::ImapError::Protocol(format!(
                                        "store session add_flags: {e}"
                                    ))
                                })?;
                        }
                        StoreAction::RemoveFlags | StoreAction::RemoveFlagsSilent => {
                            ss.remove_message_flags(&internal_id, &flag_strings)
                                .map_err(|e| {
                                    crate::imap_error::ImapError::Protocol(format!(
                                        "store session remove_flags: {e}"
                                    ))
                                })?;
                        }
                    }

                    if let Some(ref account_id) = self.authenticated_account_id {
                        if let Ok(Some(proton_id)) = ss.message_remote_id_by_uid(mb_id, uid.value())
                        {
                            let current_flags =
                                ss.message_flags_by_internal_id(&internal_id).map_err(|e| {
                                    crate::imap_error::ImapError::Protocol(format!(
                                        "store session flags: {e}"
                                    ))
                                })?;
                            let has_seen = current_flags.iter().any(|flag| flag == "\\Seen");
                            let has_flagged = current_flags.iter().any(|flag| flag == "\\Flagged");

                            if had_seen != has_seen {
                                if let Err(err) = self
                                    .config
                                    .connector
                                    .mark_messages_read(account_id, &[proton_id.as_str()], has_seen)
                                    .await
                                {
                                    warn!(
                                        error = %err,
                                        mailbox = %mailbox,
                                        uid = uid.value(),
                                        proton_id = %proton_id,
                                        "failed to sync seen flag upstream"
                                    );
                                    self.store_session = pinned_session;
                                    return self
                                        .writer
                                        .tagged_no(tag, "STORE failed: upstream mutation failed")
                                        .await;
                                }
                            }

                            if had_flagged != has_flagged {
                                if let Err(err) = self
                                    .config
                                    .connector
                                    .mark_messages_starred(
                                        account_id,
                                        &[proton_id.as_str()],
                                        has_flagged,
                                    )
                                    .await
                                {
                                    warn!(
                                        error = %err,
                                        mailbox = %mailbox,
                                        uid = uid.value(),
                                        proton_id = %proton_id,
                                        "failed to sync flagged state upstream"
                                    );
                                    self.store_session = pinned_session;
                                    return self
                                        .writer
                                        .tagged_no(tag, "STORE failed: upstream mutation failed")
                                        .await;
                                }
                            }
                        }
                    }

                    if !silent {
                        let seq = all_uids
                            .iter()
                            .position(|&u| u == uid)
                            .map(|i| i as u32 + 1)
                            .unwrap_or(0);
                        let current_flags =
                            ss.message_flags_by_internal_id(&internal_id).map_err(|e| {
                                crate::imap_error::ImapError::Protocol(format!(
                                    "store session flags: {e}"
                                ))
                            })?;
                        let flag_str = current_flags.join(" ");
                        let fetch_items = if uid_mode {
                            format!("UID {uid} FLAGS ({flag_str})")
                        } else {
                            format!("FLAGS ({flag_str})")
                        };
                        self.writer
                            .untagged(&format!("{seq} FETCH ({fetch_items})"))
                            .await?;
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            };

            // Fallback: use trait-based mutation path.
            if !used_pinned {
                let previous_flags = mutation.get_flags(&scoped_mailbox, uid).await?;
                let had_seen = previous_flags.iter().any(|flag| flag == "\\Seen");
                let had_flagged = previous_flags.iter().any(|flag| flag == "\\Flagged");

                match action {
                    StoreAction::SetFlags | StoreAction::SetFlagsSilent => {
                        mutation
                            .set_flags(&scoped_mailbox, uid, flag_strings.clone())
                            .await?;
                    }
                    StoreAction::AddFlags | StoreAction::AddFlagsSilent => {
                        mutation
                            .add_flags(&scoped_mailbox, uid, &flag_strings)
                            .await?;
                    }
                    StoreAction::RemoveFlags | StoreAction::RemoveFlagsSilent => {
                        mutation
                            .remove_flags(&scoped_mailbox, uid, &flag_strings)
                            .await?;
                    }
                }

                if let Some(ref account_id) = self.authenticated_account_id {
                    if let Some(proton_id) = mutation.get_proton_id(&scoped_mailbox, uid).await? {
                        let id_ref = proton_id.as_str();
                        let current_flags = mutation.get_flags(&scoped_mailbox, uid).await?;
                        let has_seen = current_flags.iter().any(|flag| flag == "\\Seen");
                        let has_flagged = current_flags.iter().any(|flag| flag == "\\Flagged");

                        if had_seen != has_seen {
                            if let Err(err) = self
                                .config
                                .connector
                                .mark_messages_read(account_id, &[id_ref], has_seen)
                                .await
                            {
                                warn!(
                                    error = %err,
                                    mailbox = %mailbox,
                                    uid = uid.value(),
                                    proton_id = %proton_id,
                                    "failed to sync seen flag upstream"
                                );
                                self.store_session = pinned_session;
                                return self
                                    .writer
                                    .tagged_no(tag, "STORE failed: upstream mutation failed")
                                    .await;
                            }
                        }

                        if had_flagged != has_flagged {
                            if let Err(err) = self
                                .config
                                .connector
                                .mark_messages_starred(account_id, &[id_ref], has_flagged)
                                .await
                            {
                                warn!(
                                    error = %err,
                                    mailbox = %mailbox,
                                    uid = uid.value(),
                                    proton_id = %proton_id,
                                    "failed to sync flagged state upstream"
                                );
                                self.store_session = pinned_session;
                                return self
                                    .writer
                                    .tagged_no(tag, "STORE failed: upstream mutation failed")
                                    .await;
                            }
                        }
                    }
                }

                if !silent {
                    let seq = mutation
                        .uid_to_seq(&scoped_mailbox, uid)
                        .await?
                        .unwrap_or(0);
                    let current_flags = mutation.get_flags(&scoped_mailbox, uid).await?;
                    let flag_str = current_flags.join(" ");
                    let fetch_items = if uid_mode {
                        format!("UID {uid} FLAGS ({flag_str})")
                    } else {
                        format!("FLAGS ({flag_str})")
                    };
                    self.writer
                        .untagged(&format!("{seq} FETCH ({fetch_items})"))
                        .await?;
                }
            }
        }

        self.store_session = pinned_session;
        self.writer.tagged_ok(tag, None, "STORE completed").await
    }
}
