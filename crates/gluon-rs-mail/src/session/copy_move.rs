use std::collections::HashSet;

use tokio::io::AsyncWriteExt;
use tracing::warn;

use super::*;

impl<R, W> ImapSession<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    pub async fn cmd_copy(
        &mut self,
        tag: &str,
        sequence: &SequenceSet,
        dest_name: &str,
        uid_mode: bool,
    ) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        let dest_mb = match self.resolve_mailbox(dest_name).await {
            Some(m) => m,
            None => {
                return self
                    .writer
                    .tagged_no(
                        tag,
                        &format!("[TRYCREATE] mailbox not found: {}", dest_name),
                    )
                    .await;
            }
        };

        self.refresh_selected_snapshot().await?;
        let mailbox = self.selected_mailbox.as_ref().unwrap().clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let scoped_dest_mailbox = self.scoped_mailbox_name(&dest_mb.name);
        if scoped_mailbox == scoped_dest_mailbox {
            return self.writer.tagged_ok(tag, None, "COPY completed").await;
        }

        let mutation = &self.config.mailbox_mutation;
        let all_uids = self.selected_mailbox_uids.clone();

        if all_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "COPY completed").await;
        }

        let target_uids = self.resolve_target_uids(&all_uids, sequence, uid_mode);

        let mut src_uids = Vec::new();
        let mut dst_uids = Vec::new();

        for &uid in &target_uids {
            if let Some(ref account_id) = self.authenticated_account_id {
                if let Some(proton_id) = mutation.get_proton_id(&scoped_mailbox, uid).await? {
                    if let Err(err) = self
                        .config
                        .connector
                        .label_messages(account_id, &[proton_id.as_str()], &dest_mb.label_id)
                        .await
                    {
                        warn!(
                            error = %err,
                            source_mailbox = %mailbox,
                            destination_mailbox = %dest_mb.name,
                            uid = uid.value(),
                            proton_id = %proton_id,
                            "failed to sync copy destination label upstream"
                        );
                        return self
                            .writer
                            .tagged_no(tag, "COPY failed: upstream mutation failed")
                            .await;
                    }
                }
            }

            match self
                .copy_message_local(&scoped_mailbox, &scoped_dest_mailbox, uid)
                .await
            {
                Ok(Some(dest_uid)) => {
                    src_uids.push(uid);
                    dst_uids.push(dest_uid);
                }
                Ok(None) => {}
                Err(err) => {
                    warn!(error = %err, uid = uid.value(), "copy_message_local failed");
                    return self
                        .writer
                        .tagged_no(tag, &format!("[TRYCREATE] COPY failed: {err}"))
                        .await;
                }
            }
        }

        let dest_status = match mutation.mailbox_status(&scoped_dest_mailbox).await {
            Ok(s) => s,
            Err(err) => {
                warn!(error = %err, "failed to get dest mailbox status for COPYUID");
                return self.writer.tagged_ok(tag, None, "COPY completed").await;
            }
        };
        let copyuid_code = format_copyuid(dest_status.uid_validity, &src_uids, &dst_uids);
        self.writer
            .tagged_ok(tag, Some(&copyuid_code), "COPY completed")
            .await
    }

    pub async fn cmd_move(
        &mut self,
        tag: &str,
        sequence: &SequenceSet,
        dest_name: &str,
        uid_mode: bool,
    ) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        if self.selected_read_only {
            return self.writer.tagged_no(tag, "mailbox is read-only").await;
        }

        let dest_mb = match self.resolve_mailbox(dest_name).await {
            Some(m) => m,
            None => {
                return self
                    .writer
                    .tagged_no(
                        tag,
                        &format!("[TRYCREATE] mailbox not found: {}", dest_name),
                    )
                    .await;
            }
        };

        let mailbox = self.selected_mailbox.as_ref().unwrap().clone();
        let source_mb = self
            .resolve_mailbox(&mailbox)
            .await
            .unwrap_or_else(|| dest_mb.clone());
        self.refresh_selected_snapshot().await?;
        let scoped_source_mailbox = self.scoped_mailbox_name(&mailbox);
        let scoped_dest_mailbox = self.scoped_mailbox_name(&dest_mb.name);
        if scoped_source_mailbox == scoped_dest_mailbox {
            return self.writer.tagged_ok(tag, None, "MOVE completed").await;
        }

        let mutation = &self.config.mailbox_mutation;
        let all_uids = self.selected_mailbox_uids.clone();
        if all_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "MOVE completed").await;
        }

        let target_uids = self.resolve_target_uids(&all_uids, sequence, uid_mode);
        if target_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "MOVE completed").await;
        }

        let target_uid_set: HashSet<ImapUid> = target_uids.iter().copied().collect();
        let mut src_uids = Vec::new();
        let mut dst_uids = Vec::new();
        let mut expunged_seqs = Vec::new();
        let mut offset = 0u32;

        for (i, &uid) in all_uids.iter().enumerate() {
            if !target_uid_set.contains(&uid) {
                continue;
            }

            let Some(proton_id) = mutation.get_proton_id(&scoped_source_mailbox, uid).await? else {
                continue;
            };

            let seq = i as u32 + 1 - offset;

            if let Some(ref account_id) = self.authenticated_account_id {
                if let Err(err) = self
                    .config
                    .connector
                    .label_messages(account_id, &[proton_id.as_str()], &dest_mb.label_id)
                    .await
                {
                    warn!(
                        error = %err,
                        source_mailbox = %mailbox,
                        destination_mailbox = %dest_mb.name,
                        uid = uid.value(),
                        proton_id = %proton_id,
                        "failed to sync move destination label upstream"
                    );
                    return self
                        .writer
                        .tagged_no(tag, "MOVE failed: upstream mutation failed")
                        .await;
                }

                if source_mb.label_id != dest_mb.label_id {
                    if let Err(err) = self
                        .config
                        .connector
                        .unlabel_messages(account_id, &[proton_id.as_str()], &source_mb.label_id)
                        .await
                    {
                        warn!(
                            error = %err,
                            source_mailbox = %mailbox,
                            destination_mailbox = %dest_mb.name,
                            uid = uid.value(),
                            proton_id = %proton_id,
                            "failed to sync move source label removal upstream"
                        );
                        return self
                            .writer
                            .tagged_no(tag, "MOVE failed: upstream mutation failed")
                            .await;
                    }
                }
            }

            match self
                .copy_message_local(&scoped_source_mailbox, &scoped_dest_mailbox, uid)
                .await
            {
                Ok(Some(dest_uid)) => {
                    src_uids.push(uid);
                    dst_uids.push(dest_uid);
                    mutation.remove_message(&scoped_source_mailbox, uid).await?;
                    expunged_seqs.push(seq);
                    offset += 1;
                }
                Ok(None) => {}
                Err(err) => {
                    warn!(error = %err, uid = uid.value(), "move copy_message_local failed");
                    return self
                        .writer
                        .tagged_no(tag, &format!("[TRYCREATE] MOVE failed: {err}"))
                        .await;
                }
            }
        }

        let dest_status = match mutation.mailbox_status(&scoped_dest_mailbox).await {
            Ok(s) => s,
            Err(err) => {
                warn!(error = %err, "failed to get dest mailbox status for COPYUID");
                // Emit expunges even if status fails
                for seq in expunged_seqs {
                    self.writer.untagged(&format!("{seq} EXPUNGE")).await?;
                }
                return self.writer.tagged_ok(tag, None, "MOVE completed").await;
            }
        };
        let copyuid_code = format_copyuid(dest_status.uid_validity, &src_uids, &dst_uids);

        for seq in expunged_seqs {
            self.writer.untagged(&format!("{seq} EXPUNGE")).await?;
        }

        self.writer
            .tagged_ok(tag, Some(&copyuid_code), "MOVE completed")
            .await
    }

    pub async fn cmd_uid_expunge(&mut self, tag: &str, sequence: &SequenceSet) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        if self.selected_read_only {
            return self.writer.tagged_no(tag, "mailbox is read-only").await;
        }

        let mailbox = match &self.selected_mailbox {
            Some(m) => m.clone(),
            None => return self.writer.tagged_no(tag, "no mailbox selected").await,
        };
        self.refresh_selected_snapshot().await?;
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let mutation = &self.config.mailbox_mutation;
        let all_uids = self.selected_mailbox_uids.clone();

        if all_uids.is_empty() {
            return self
                .writer
                .tagged_ok(tag, None, "UID EXPUNGE completed")
                .await;
        }

        let max_uid = *all_uids.last().unwrap();
        let cached_flags = &self.selected_mailbox_flags;
        let mut expunged_seqs = Vec::new();
        let mut successfully_expunged_uids = Vec::new();
        let mut offset = 0u32;

        for (i, &uid) in all_uids.iter().enumerate() {
            // Only expunge if UID is in the sequence set AND has \Deleted flag
            if !sequence.contains(uid.value(), max_uid.value()) {
                continue;
            }

            let is_deleted = cached_flags
                .get(&uid)
                .map(|flags| flags.iter().any(|f| f == "\\Deleted"))
                .unwrap_or(false);

            if is_deleted {
                let seq = i as u32 + 1 - offset;

                // Permanently delete if in Trash or Spam, otherwise move to Trash
                if let Some(ref account_id) = self.authenticated_account_id {
                    if let Some(proton_id) = mutation.get_proton_id(&scoped_mailbox, uid).await? {
                        let is_trash_or_spam = self
                            .resolve_mailbox(&mailbox)
                            .await
                            .map(|mb| {
                                mb.label_id == crate::well_known::TRASH_LABEL
                                    || mb.label_id == crate::well_known::SPAM_LABEL
                            })
                            .unwrap_or(false);

                        let result = if is_trash_or_spam {
                            self.config
                                .connector
                                .delete_messages(account_id, &[proton_id.as_str()])
                                .await
                        } else {
                            self.config
                                .connector
                                .trash_messages(account_id, &[proton_id.as_str()])
                                .await
                        };

                        if let Err(err) = result {
                            warn!(
                                error = %err,
                                mailbox = %mailbox,
                                uid = uid.value(),
                                proton_id = %proton_id,
                                permanent = is_trash_or_spam,
                                "failed to sync uid expunge mutation upstream"
                            );
                            return self
                                .writer
                                .tagged_no(tag, "UID EXPUNGE failed: upstream mutation failed")
                                .await;
                        }
                    }
                }

                successfully_expunged_uids.push(uid);
                expunged_seqs.push(seq);
                offset += 1;
            }
        }

        // Batch remove all successfully expunged messages from local store.
        mutation
            .batch_remove_messages(&scoped_mailbox, &successfully_expunged_uids)
            .await?;

        // Update the session's UID and flag snapshots so subsequent commands
        // use the post-expunge view.
        self.selected_mailbox_uids
            .retain(|uid| !successfully_expunged_uids.contains(uid));
        for uid in &successfully_expunged_uids {
            self.selected_mailbox_flags.remove(uid);
        }

        for seq in &expunged_seqs {
            self.writer.untagged(&format!("{} EXPUNGE", seq)).await?;
        }

        self.writer
            .tagged_ok(tag, None, "UID EXPUNGE completed")
            .await
    }

    pub async fn copy_message_local(
        &self,
        source_mailbox: &ScopedMailboxId,
        dest_mailbox: &ScopedMailboxId,
        source_uid: ImapUid,
    ) -> Result<Option<ImapUid>> {
        let mutation = self.config.mailbox_mutation.clone();

        // Try the efficient path: link existing message to dest mailbox
        if let Ok(Some(dest_uid)) = self
            .config
            .gluon_connector
            .copy_message(source_mailbox, dest_mailbox, source_uid)
            .await
        {
            // Copy flags
            if let Ok(flags) = mutation.get_flags(source_mailbox, source_uid).await {
                let _ = mutation.set_flags(dest_mailbox, dest_uid, flags).await;
            }
            return Ok(Some(dest_uid));
        }

        // Fallback: create new message in dest
        let Some(proton_id) = mutation.get_proton_id(source_mailbox, source_uid).await? else {
            return Ok(None);
        };
        let Some(metadata) = mutation.get_metadata(source_mailbox, source_uid).await? else {
            return Ok(None);
        };

        // Generate unique id for the copy to avoid UNIQUE constraint on remote_id
        let copy_id = format!("{}-copy-{}", proton_id, source_uid.value());
        let dest_uid = mutation
            .store_metadata(
                dest_mailbox,
                &ProtonMessageId::from(copy_id.as_str()),
                metadata,
            )
            .await?;

        let flags = mutation.get_flags(source_mailbox, source_uid).await?;
        mutation.set_flags(dest_mailbox, dest_uid, flags).await?;

        if let Some(rfc822) = mutation.get_rfc822(source_mailbox, source_uid).await? {
            mutation
                .store_rfc822(dest_mailbox, dest_uid, rfc822)
                .await?;
        }

        Ok(Some(dest_uid))
    }
}

pub fn format_copyuid(uid_validity: u32, src_uids: &[ImapUid], dst_uids: &[ImapUid]) -> String {
    let src = src_uids
        .iter()
        .map(|u| u.value().to_string())
        .collect::<Vec<_>>()
        .join(",");
    let dst = dst_uids
        .iter()
        .map(|u| u.value().to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!("COPYUID {} {} {}", uid_validity, src, dst)
}
