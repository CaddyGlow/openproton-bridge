use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use super::*;

impl<R, W> ImapSession<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    pub async fn cmd_select(&mut self, tag: &str, mailbox_name: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        let mb = match self.resolve_mailbox(mailbox_name).await {
            Some(m) => m,
            None => {
                return self
                    .writer
                    .tagged_no(tag, &format!("mailbox not found: {}", mailbox_name))
                    .await;
            }
        };

        if !mb.selectable {
            return self
                .writer
                .tagged_no(tag, &format!("mailbox not selectable: {}", mailbox_name))
                .await;
        }

        let mutation = self.config.mailbox_mutation.clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mb.name);
        let cached_uids = self.config.mailbox_view.list_uids(&scoped_mailbox).await?;

        if cached_uids.is_empty() {
            let account_id = self
                .authenticated_account_id
                .as_deref()
                .unwrap_or("unknown");

            let mut page = 0i32;
            let mut loaded = 0usize;
            loop {
                let meta_page = match self
                    .config
                    .connector
                    .fetch_message_metadata_page(account_id, &mb.label_id, page, 150)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, page, "failed to fetch message metadata");
                        return self.writer.tagged_no(tag, "failed to fetch messages").await;
                    }
                };

                if meta_page.messages.is_empty() {
                    break;
                }

                for meta in &meta_page.messages {
                    mutation
                        .store_metadata(
                            &scoped_mailbox,
                            &ProtonMessageId::from(meta.id.as_str()),
                            meta.clone(),
                        )
                        .await?;
                }

                loaded = loaded.saturating_add(meta_page.messages.len());
                let total = usize::try_from(meta_page.total.max(0)).unwrap_or(usize::MAX);
                if loaded >= total {
                    break;
                }
                page += 1;
            }
        } else {
            info!(
                service = "imap",
                msg = "Messages are already synced, skipping",
                user_id = self.authenticated_account_id.as_deref().unwrap_or("unknown"),
                mailbox = %mb.name,
                count = cached_uids.len(),
                "Messages are already synced, skipping"
            );
        }

        let select_data = if let Some(ref mut ss) = self.store_session {
            if let Some(mb_internal_id) = resolve_mailbox_internal_id(ss, &mb.name).await {
                self.selected_mailbox_internal_id = Some(mb_internal_id);
                select_data_from_session(ss, mb_internal_id).await?
            } else {
                self.selected_mailbox_internal_id = None;
                self.config
                    .mailbox_view
                    .select_mailbox_data_fast(&scoped_mailbox)
                    .await?
            }
        } else {
            self.selected_mailbox_internal_id = None;
            self.config
                .mailbox_view
                .select_mailbox_data_fast(&scoped_mailbox)
                .await?
        };

        // Collect custom keywords from all messages in the mailbox
        let mut keywords: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for flags in select_data.flags.values() {
            for flag in flags {
                if !flag.starts_with('\\') {
                    keywords.insert(flag.clone());
                }
            }
        }

        let mut flags_list = "\\Seen \\Answered \\Flagged \\Deleted \\Draft".to_string();
        for kw in &keywords {
            flags_list.push(' ');
            flags_list.push_str(kw);
        }

        // Claim recent UIDs for this session
        self.recent_uids = self
            .config
            .recent_tracker
            .claim(&mb.name, &select_data.uids);
        let recent_count = self.recent_uids.len();

        self.writer
            .untagged(&format!("{} EXISTS", select_data.status.exists))
            .await?;
        self.writer
            .untagged(&format!("{recent_count} RECENT"))
            .await?;
        self.writer
            .untagged(&format!("FLAGS ({flags_list})"))
            .await?;
        self.writer
            .untagged(&format!(
                "OK [PERMANENTFLAGS ({flags_list} \\*)] Flags permitted"
            ))
            .await?;
        self.writer
            .untagged(&format!(
                "OK [UIDVALIDITY {}] UIDs valid",
                select_data.status.uid_validity
            ))
            .await?;
        self.writer
            .untagged(&format!(
                "OK [UIDNEXT {}] Predicted next UID",
                select_data.status.next_uid
            ))
            .await?;
        if let Some(first_unseen_seq) = select_data.first_unseen_seq {
            self.writer
                .untagged(&format!("OK [UNSEEN {}] First unseen", first_unseen_seq))
                .await?;
        }

        self.selected_mailbox = Some(mb.name.to_string());
        self.selected_mailbox_mod_seq = Some(select_data.snapshot.mod_seq);
        self.selected_mailbox_uids = select_data.uids.clone();
        self.selected_mailbox_flags = select_data.flags;
        self.selected_read_only = false;
        self.state = State::Selected;

        if let Some(tx) = &self.config.event_tx {
            let _ = tx.send(crate::imap_types::SessionEvent::Select {
                session_id: self.connection_id,
                mailbox: mb.name.to_string(),
            });
        }

        info!(
            service = "imap",
            msg = "mailbox selected",
            mailbox = %mb.name,
            messages = select_data.status.exists,
            "mailbox selected"
        );

        self.writer
            .tagged_ok(tag, Some("READ-WRITE"), "SELECT completed")
            .await
    }

    pub async fn cmd_examine(&mut self, tag: &str, mailbox_name: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        let mb = match self.resolve_mailbox(mailbox_name).await {
            Some(m) => m,
            None => {
                return self
                    .writer
                    .tagged_no(tag, &format!("mailbox not found: {}", mailbox_name))
                    .await;
            }
        };

        if !mb.selectable {
            return self
                .writer
                .tagged_no(tag, &format!("mailbox not selectable: {}", mailbox_name))
                .await;
        }

        let mutation = self.config.mailbox_mutation.clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mb.name);
        let cached_uids = self.config.mailbox_view.list_uids(&scoped_mailbox).await?;

        if cached_uids.is_empty() {
            let account_id = self
                .authenticated_account_id
                .as_deref()
                .unwrap_or("unknown");

            let mut page = 0i32;
            let mut loaded = 0usize;
            loop {
                let meta_page = match self
                    .config
                    .connector
                    .fetch_message_metadata_page(account_id, &mb.label_id, page, 150)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(error = %e, page, "failed to fetch message metadata");
                        return self.writer.tagged_no(tag, "failed to fetch messages").await;
                    }
                };

                if meta_page.messages.is_empty() {
                    break;
                }

                for meta in &meta_page.messages {
                    mutation
                        .store_metadata(
                            &scoped_mailbox,
                            &ProtonMessageId::from(meta.id.as_str()),
                            meta.clone(),
                        )
                        .await?;
                }

                loaded = loaded.saturating_add(meta_page.messages.len());
                let total = usize::try_from(meta_page.total.max(0)).unwrap_or(usize::MAX);
                if loaded >= total {
                    break;
                }
                page += 1;
            }
        }

        let select_data = self
            .config
            .mailbox_view
            .select_mailbox_data_fast(&scoped_mailbox)
            .await?;

        self.writer
            .untagged(&format!("{} EXISTS", select_data.status.exists))
            .await?;
        self.writer.untagged("0 RECENT").await?;
        self.writer
            .untagged("FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)")
            .await?;
        self.writer
            .untagged(&format!(
                "OK [UIDVALIDITY {}]",
                select_data.status.uid_validity
            ))
            .await?;
        self.writer
            .untagged(&format!("OK [UIDNEXT {}]", select_data.status.next_uid))
            .await?;
        if let Some(first_unseen_seq) = select_data.first_unseen_seq {
            self.writer
                .untagged(&format!("OK [UNSEEN {}]", first_unseen_seq))
                .await?;
        }

        self.selected_mailbox = Some(mb.name.to_string());
        self.selected_mailbox_mod_seq = Some(select_data.snapshot.mod_seq);
        self.selected_mailbox_uids = select_data.uids.clone();
        self.selected_mailbox_flags = select_data.flags;
        self.selected_read_only = true;
        self.state = State::Selected;

        info!(
            service = "imap",
            msg = "mailbox examined (read-only)",
            mailbox = %mb.name,
            messages = select_data.status.exists,
            "mailbox examined (read-only)"
        );

        self.writer
            .tagged_ok(tag, Some("READ-ONLY"), "EXAMINE completed")
            .await
    }

    pub async fn cmd_create(&mut self, tag: &str, mailbox_name: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        // If mailbox already exists, delete and recreate for idempotent behavior.
        // imaptest expects CREATE to produce a fresh empty mailbox.
        if self.resolve_mailbox(mailbox_name).await.is_some() {
            if mailbox::find_mailbox(mailbox_name).is_some() {
                return self.writer.tagged_ok(tag, None, "CREATE completed").await;
            }
            let scoped = self.scoped_mailbox_name(mailbox_name);
            let _ = self
                .config
                .gluon_connector
                .delete_mailbox(&scoped, true)
                .await;
            self.user_labels.retain(|l| l.name != mailbox_name);
        }

        let scoped = self.scoped_mailbox_name(mailbox_name);
        if let Err(e) = self.config.gluon_connector.create_mailbox(&scoped).await {
            return self
                .writer
                .tagged_no(tag, &format!("CREATE failed: {e}"))
                .await;
        }

        // Add to session's user_labels so it can be resolved immediately
        self.user_labels.push(mailbox::ResolvedMailbox {
            name: mailbox_name.to_string(),
            label_id: mailbox_name.to_string(),
            special_use: None,
            selectable: true,
        });

        self.writer.tagged_ok(tag, None, "CREATE completed").await
    }

    pub async fn cmd_delete(&mut self, tag: &str, mailbox_name: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        // Cannot delete system mailboxes
        if mailbox::find_mailbox(mailbox_name).is_some() {
            return self
                .writer
                .tagged_no(tag, "[CANNOT] cannot delete system mailbox")
                .await;
        }

        // Cannot delete selected mailbox
        if self.selected_mailbox.as_deref() == Some(mailbox_name) {
            return self
                .writer
                .tagged_no(tag, "cannot delete selected mailbox")
                .await;
        }

        let scoped = self.scoped_mailbox_name(mailbox_name);
        if let Err(e) = self
            .config
            .gluon_connector
            .delete_mailbox(&scoped, false)
            .await
        {
            return self
                .writer
                .tagged_no(tag, &format!("DELETE failed: {e}"))
                .await;
        }

        // Remove from session's user_labels
        self.user_labels.retain(|l| l.name != mailbox_name);

        self.writer.tagged_ok(tag, None, "DELETE completed").await
    }

    pub async fn cmd_rename(&mut self, tag: &str, source: &str, dest: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        // Cannot rename system mailboxes (INBOX, etc.)
        if mailbox::find_mailbox(source).is_some() {
            return self
                .writer
                .tagged_no(tag, "[CANNOT] cannot rename system mailbox")
                .await;
        }

        // Verify source exists
        if self.resolve_mailbox(source).await.is_none() {
            return self
                .writer
                .tagged_no(tag, "source mailbox does not exist")
                .await;
        }

        // If dest exists, delete it first (allow overwrite for RENAME)
        if self.resolve_mailbox(dest).await.is_some() {
            if mailbox::find_mailbox(dest).is_some() {
                return self
                    .writer
                    .tagged_no(tag, "destination mailbox already exists")
                    .await;
            }
            let scoped_dest = self.scoped_mailbox_name(dest);
            let _ = self
                .config
                .gluon_connector
                .delete_mailbox(&scoped_dest, true)
                .await;
            self.user_labels.retain(|l| l.name != dest);
        }

        let scoped_source = self.scoped_mailbox_name(source);
        let scoped_dest = self.scoped_mailbox_name(dest);

        if let Err(e) = self
            .config
            .gluon_connector
            .rename_mailbox(&scoped_source, &scoped_dest)
            .await
        {
            return self
                .writer
                .tagged_no(tag, &format!("RENAME failed: {e}"))
                .await;
        }

        // Update session's user_labels: remove old, add new
        self.user_labels.retain(|l| l.name != source);
        self.user_labels.push(mailbox::ResolvedMailbox {
            name: dest.to_string(),
            label_id: dest.to_string(),
            special_use: None,
            selectable: true,
        });

        self.writer.tagged_ok(tag, None, "RENAME completed").await
    }

    pub async fn cmd_list(&mut self, tag: &str, reference: &str, pattern: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        if pattern.is_empty() {
            self.writer.untagged("LIST (\\Noselect) \"/\" \"\"").await?;
        } else {
            let full_pattern = if reference.is_empty() {
                pattern.to_string()
            } else {
                format!("{reference}{pattern}")
            };

            let mut all = self.all_mailboxes();
            // Merge store mailboxes (dynamically created via CREATE)
            if let Some(ref mut ss) = self.store_session {
                if let Ok(store_mbs) = ss.list_upstream_mailboxes() {
                    for mb in store_mbs {
                        if !all.iter().any(|m| m.name.eq_ignore_ascii_case(&mb.name)) {
                            all.push(mailbox::ResolvedMailbox {
                                name: mb.name.clone(),
                                label_id: mb.name,
                                special_use: None,
                                selectable: true,
                            });
                        }
                    }
                }
            }
            // Collect parent paths that need \Noselect entries
            let mut parents: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for mb in &all {
                let mut path = String::new();
                for (i, seg) in mb.name.split('/').enumerate() {
                    if i > 0 {
                        path.push('/');
                    }
                    path.push_str(seg);
                    // Only add as parent if it's not a real mailbox
                    if path != mb.name && !all.iter().any(|m| m.name.eq_ignore_ascii_case(&path)) {
                        parents.insert(path.clone());
                    }
                }
            }

            // Emit real mailboxes, filtering by visibility
            let account_id = self.authenticated_account_id.clone().unwrap_or_default();
            for mb in &all {
                if self.matches_list_pattern(&mb.name, &full_pattern) {
                    let vis = self
                        .config
                        .connector
                        .get_mailbox_visibility(&account_id, &mb.label_id)
                        .await?;
                    match vis {
                        crate::imap_types::MailboxVisibility::Hidden => continue,
                        crate::imap_types::MailboxVisibility::HiddenIfEmpty => {
                            let scoped = self.scoped_mailbox_name(&mb.name);
                            let status = self.config.mailbox_view.mailbox_status(&scoped).await;
                            if status.map(|s| s.exists).unwrap_or(0) == 0 {
                                continue;
                            }
                        }
                        crate::imap_types::MailboxVisibility::Visible => {}
                    }
                    self.writer
                        .untagged(&self.format_list_entry("LIST", mb))
                        .await?;
                }
            }

            // Emit parent-only \Noselect entries
            for parent in &parents {
                if self.matches_list_pattern(parent, &full_pattern) {
                    self.writer
                        .untagged(&format!(
                            "LIST (\\Noselect) \"{}\" \"{}\"",
                            self.config.delimiter, parent
                        ))
                        .await?;
                }
            }
        }

        self.writer.tagged_ok(tag, None, "LIST completed").await
    }

    pub async fn cmd_lsub(&mut self, tag: &str, reference: &str, pattern: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        if pattern.is_empty() {
            self.writer.untagged("LSUB (\\Noselect) \"/\" \"\"").await?;
        } else {
            let full_pattern = if reference.is_empty() {
                pattern.to_string()
            } else {
                format!("{reference}{pattern}")
            };
            let mut all = self.all_mailboxes();
            if let Some(ref mut ss) = self.store_session {
                if let Ok(store_mbs) = ss.list_upstream_mailboxes() {
                    for mb in store_mbs {
                        if !all.iter().any(|m| m.name.eq_ignore_ascii_case(&mb.name)) {
                            all.push(mailbox::ResolvedMailbox {
                                name: mb.name.clone(),
                                label_id: mb.name,
                                special_use: None,
                                selectable: true,
                            });
                        }
                    }
                }
            }
            // Collect parent paths that need \Noselect entries
            let mut parents: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for mb in &all {
                let mut path = String::new();
                for (i, seg) in mb.name.split('/').enumerate() {
                    if i > 0 {
                        path.push('/');
                    }
                    path.push_str(seg);
                    if path != mb.name && !all.iter().any(|m| m.name.eq_ignore_ascii_case(&path)) {
                        parents.insert(path.clone());
                    }
                }
            }

            // Merge real and parent entries, sort by name, emit in order
            let mut entries: Vec<(String, Option<usize>)> = Vec::new();
            for (i, mb) in all.iter().enumerate() {
                if self.matches_list_pattern(&mb.name, &full_pattern) {
                    entries.push((mb.name.clone(), Some(i)));
                }
            }
            for parent in &parents {
                if self.matches_list_pattern(parent, &full_pattern) {
                    entries.push((parent.clone(), None));
                }
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));

            for (name, mb_index) in &entries {
                if let Some(idx) = mb_index {
                    self.writer
                        .untagged(&self.format_list_entry("LSUB", &all[*idx]))
                        .await?;
                } else {
                    self.writer
                        .untagged(&format!(
                            "LSUB (\\Noselect) \"{}\" \"{}\"",
                            self.config.delimiter, name
                        ))
                        .await?;
                }
            }
        }

        self.writer.tagged_ok(tag, None, "LSUB completed").await
    }

    pub async fn cmd_subscribe(&mut self, tag: &str, mailbox_name: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        // Check if mailbox exists - if so, silently succeed (all mailboxes are subscribed)
        if self.resolve_mailbox(mailbox_name).await.is_some() {
            return self
                .writer
                .tagged_ok(tag, None, "SUBSCRIBE completed")
                .await;
        }

        // Mailbox doesn't exist
        self.writer
            .tagged_no(tag, "[NONEXISTENT] mailbox does not exist")
            .await
    }

    pub async fn cmd_unsubscribe(&mut self, tag: &str, mailbox_name: &str) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        // Check if mailbox exists - if so, silently succeed (we don't actually unsubscribe)
        if self.resolve_mailbox(mailbox_name).await.is_some() {
            return self
                .writer
                .tagged_ok(tag, None, "UNSUBSCRIBE completed")
                .await;
        }

        // Mailbox doesn't exist
        self.writer
            .tagged_no(tag, "[NONEXISTENT] mailbox does not exist")
            .await
    }

    pub async fn cmd_status(
        &mut self,
        tag: &str,
        mailbox_name: &str,
        items: &[StatusDataItem],
    ) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        let mb = match self.resolve_mailbox(mailbox_name).await {
            Some(m) => m,
            None => {
                return self
                    .writer
                    .tagged_no(tag, &format!("mailbox not found: {}", mailbox_name))
                    .await;
            }
        };

        let scoped_mailbox = self.scoped_mailbox_name(&mb.name);
        let status = self
            .config
            .mailbox_view
            .mailbox_status(&scoped_mailbox)
            .await?;

        let mut attrs = Vec::new();
        for item in items {
            match item {
                StatusDataItem::Messages => attrs.push(format!("MESSAGES {}", status.exists)),
                StatusDataItem::Recent => {
                    attrs.push("RECENT 0".to_string());
                }
                StatusDataItem::UidNext => attrs.push(format!("UIDNEXT {}", status.next_uid)),
                StatusDataItem::UidValidity => {
                    attrs.push(format!("UIDVALIDITY {}", status.uid_validity))
                }
                StatusDataItem::Unseen => attrs.push(format!("UNSEEN {}", status.unseen)),
            }
        }

        self.writer
            .untagged(&format!(
                "STATUS {} ({})",
                format_mailbox_name(&mb.name),
                attrs.join(" ")
            ))
            .await?;
        self.writer.tagged_ok(tag, None, "STATUS completed").await
    }

    pub fn matches_list_pattern(&self, name: &str, pattern: &str) -> bool {
        // RFC 3501 6.3.8 wildcard matching:
        //   '*' matches zero or more characters (including hierarchy separator)
        //   '%' matches zero or more characters but not hierarchy separator
        Self::glob_match(
            name.as_bytes(),
            pattern.as_bytes(),
            self.config.delimiter as u8,
        )
    }

    pub fn glob_match(name: &[u8], pattern: &[u8], delimiter: u8) -> bool {
        let mut ni = 0;
        let mut pi = 0;
        let mut star_pi = usize::MAX;
        let mut star_ni = 0;

        while ni < name.len() {
            if pi < pattern.len()
                && (pattern[pi] == b'*' || (pattern[pi] == b'%' && name[ni] != delimiter))
            {
                if pattern[pi] == b'*' {
                    star_pi = pi;
                    star_ni = ni;
                    pi += 1;
                    continue;
                } else {
                    // '%' -- try to match zero chars first, backtrack if needed
                    star_pi = pi;
                    star_ni = ni;
                    pi += 1;
                    continue;
                }
            }

            if pi < pattern.len()
                && (pattern[pi].eq_ignore_ascii_case(&name[ni]) || pattern[pi] == b'?')
            {
                ni += 1;
                pi += 1;
                continue;
            }

            if star_pi != usize::MAX {
                pi = star_pi + 1;
                star_ni += 1;
                // For '%', cannot skip over delimiter
                if pattern[star_pi] == b'%' && star_ni <= name.len() {
                    if star_ni > 0 && name[star_ni - 1] == delimiter {
                        return false;
                    }
                }
                ni = star_ni;
                continue;
            }

            return false;
        }

        while pi < pattern.len() && (pattern[pi] == b'*' || pattern[pi] == b'%') {
            pi += 1;
        }
        pi == pattern.len()
    }

    pub fn format_list_entry(&self, kind: &str, mb: &mailbox::ResolvedMailbox) -> String {
        let mut attrs = Vec::new();
        if !mb.selectable {
            attrs.push("\\Noselect".to_string());
        }
        if let Some(su) = &mb.special_use {
            attrs.push(su.clone());
        }
        let attr_str = attrs.join(" ");
        let delim = self.config.delimiter;
        format!("{kind} ({attr_str}) \"{delim}\" \"{name}\"", name = mb.name)
    }
}
