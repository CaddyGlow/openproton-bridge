use tokio::io::AsyncWriteExt;
use tracing::warn;

use super::*;

impl<R, W> ImapSession<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    pub async fn cmd_expunge(&mut self, tag: &str) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        if self.selected_read_only {
            return self.writer.tagged_no(tag, "mailbox is read-only").await;
        }

        if self.do_expunge(false, Some(tag)).await? {
            self.writer.tagged_ok(tag, None, "EXPUNGE completed").await
        } else {
            Ok(())
        }
    }

    pub async fn do_expunge(&mut self, silent: bool, tag: Option<&str>) -> Result<bool> {
        let mailbox = match &self.selected_mailbox {
            Some(m) => m.clone(),
            None => return Ok(true),
        };
        self.refresh_selected_snapshot().await?;
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let mutation = &self.config.mailbox_mutation;
        let all_uids = self.selected_mailbox_uids.clone();
        let cached_flags = &self.selected_mailbox_flags;

        // Identify deleted UIDs from cached flags (avoids per-message get_flags calls).
        let deleted_uids: Vec<ImapUid> = all_uids
            .iter()
            .filter(|uid| {
                cached_flags
                    .get(uid)
                    .map(|flags| flags.iter().any(|f| f == "\\Deleted"))
                    .unwrap_or(false)
            })
            .copied()
            .collect();

        if deleted_uids.is_empty() {
            return Ok(true);
        }

        let mut expunged_seqs = Vec::new();
        let mut offset = 0u32;
        let mut successfully_expunged_uids = Vec::new();

        // Use pinned session for proton_id lookups if available.
        let mailbox_internal_id = self.selected_mailbox_internal_id;
        let mut session = self.store_session.take();

        for (i, &uid) in all_uids.iter().enumerate() {
            if !deleted_uids.contains(&uid) {
                continue;
            }
            let seq = i as u32 + 1 - offset;

            // Sync upstream: permanently delete if in Trash or Spam, otherwise move to Trash.
            if let Some(ref account_id) = self.authenticated_account_id {
                let proton_id = if let (Some(ref mut sess), Some(mb_id)) =
                    (&mut session, mailbox_internal_id)
                {
                    sess.message_remote_id_by_uid(mb_id, uid.value())
                        .ok()
                        .flatten()
                } else {
                    mutation.get_proton_id(&scoped_mailbox, uid).await?
                };
                if let Some(proton_id) = proton_id {
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
                            "failed to sync expunge mutation upstream"
                        );
                        if let Some(tag) = tag {
                            self.writer
                                .tagged_no(tag, "EXPUNGE failed: upstream mutation failed")
                                .await?;
                            return Ok(false);
                        }
                    }
                }
            }

            successfully_expunged_uids.push(uid);
            expunged_seqs.push(seq);
            offset += 1;
        }

        // Batch remove using pinned session if available, else trait path.
        if let (Some(ref mut sess), Some(mb_id)) = (&mut session, mailbox_internal_id) {
            for &uid in &successfully_expunged_uids {
                if let Ok(Some(internal_id)) = sess.message_internal_id_by_uid(mb_id, uid.value()) {
                    let _ = sess.remove_message_from_mailbox(mb_id, &internal_id);
                }
            }
        } else {
            mutation
                .batch_remove_messages(&scoped_mailbox, &successfully_expunged_uids)
                .await?;
        }

        self.store_session = session;

        // Update the session's UID and flag snapshots so subsequent commands
        // (e.g. FETCH by sequence number) use the post-expunge view.
        self.selected_mailbox_uids
            .retain(|uid| !successfully_expunged_uids.contains(uid));
        for uid in &successfully_expunged_uids {
            self.selected_mailbox_flags.remove(uid);
        }

        if !silent {
            for seq in &expunged_seqs {
                self.writer.untagged(&format!("{} EXPUNGE", seq)).await?;
            }
        }

        Ok(true)
    }
}
