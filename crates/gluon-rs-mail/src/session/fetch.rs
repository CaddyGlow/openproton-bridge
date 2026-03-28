use std::collections::HashMap;

use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

use super::*;

impl<R, W> ImapSession<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    pub async fn cmd_fetch(
        &mut self,
        tag: &str,
        sequence: &SequenceSet,
        items: &[FetchItem],
        uid_mode: bool,
    ) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        self.refresh_selected_snapshot().await?;
        let mailbox = self.selected_mailbox.as_ref().unwrap().clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let mailbox_view = self.config.mailbox_view.clone();
        let all_uids = self.selected_mailbox_uids.clone();

        if all_uids.is_empty() {
            return self.writer.tagged_ok(tag, None, "FETCH completed").await;
        }

        let max_uid = all_uids.last().map(|u| u.value()).unwrap_or(0);
        let max_seq = all_uids.len() as u32;

        // Expand macro items and ensure UID is included for UID FETCH (RFC 3501 7.4.2)
        let mut expanded = expand_fetch_items(items);
        if uid_mode && !expanded.contains(&FetchItem::Uid) {
            expanded.insert(0, FetchItem::Uid);
        }
        let needs_body_sections = expanded
            .iter()
            .any(|i| matches!(i, FetchItem::BodySection { .. }));
        let needs_full_rfc822 = expanded.iter().any(|i| match i {
            FetchItem::BodySection { section, .. } => {
                !body_section_is_header_only(section.as_deref())
            }
            FetchItem::Rfc822
            | FetchItem::Rfc822Text
            | FetchItem::BodyStructure
            | FetchItem::Body
            | FetchItem::Envelope => true,
            _ => false,
        });
        let needs_metadata = expanded.iter().any(|i| {
            matches!(
                i,
                FetchItem::Envelope
                    | FetchItem::Rfc822Size
                    | FetchItem::Rfc822Header
                    | FetchItem::Rfc822Text
                    | FetchItem::InternalDate
                    | FetchItem::BodyStructure
                    | FetchItem::Body
                    | FetchItem::BodySection { .. }
            )
        });

        // Resolve which messages to fetch from current mailbox snapshot.
        let target_messages: Vec<(ImapUid, u32)> = if uid_mode {
            all_uids
                .iter()
                .enumerate()
                .filter(|(_, uid)| sequence.contains(uid.value(), max_uid))
                .map(|(i, &uid)| (uid, i as u32 + 1))
                .collect()
        } else {
            all_uids
                .iter()
                .enumerate()
                .filter(|(i, _)| sequence.contains(*i as u32 + 1, max_seq))
                .map(|(i, &uid)| (uid, i as u32 + 1))
                .collect()
        };
        let seen_flag = "\\Seen".to_string();
        let user_id = self
            .authenticated_account_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let header_only_body_fetch = needs_body_sections && !needs_full_rfc822;
        let target_fetch_count = target_messages.len() as u32;
        let mut cache_hits = 0u32;
        let mut cache_misses = 0u32;

        // Take the pinned store session for the duration of the fetch loop to
        // avoid per-message pool.acquire() overhead.
        let mut pinned_session = self.store_session.take();
        let pinned_mb_id = self.selected_mailbox_internal_id;
        let pinned_account_paths = if pinned_session.is_some() {
            self.storage_user_id
                .as_deref()
                .and_then(|suid| self.config.gluon_connector.account_paths(suid).ok())
        } else {
            None
        };

        for (uid, seq) in target_messages {
            let meta = if needs_metadata {
                if let (Some(ref mut ss), Some(mb_id), Some(ref ap)) =
                    (&mut pinned_session, pinned_mb_id, &pinned_account_paths)
                {
                    match ss.message_by_uid(mb_id, uid.value(), ap) {
                        Ok(Some(message)) => {
                            let blob_data = if message.blob_exists {
                                self.storage_user_id.as_deref().and_then(|suid| {
                                    self.config
                                        .gluon_connector
                                        .read_message_blob(suid, &message.summary.internal_id)
                                        .ok()
                                })
                            } else {
                                None
                            };
                            let parsed = blob_data.as_deref().and_then(|data| {
                                crate::metadata_parse::parse_metadata_from_rfc822(
                                    &scoped_mailbox,
                                    &message.summary,
                                    data,
                                )
                            });
                            Some(parsed.unwrap_or_else(|| {
                                crate::metadata_parse::fallback_metadata(&scoped_mailbox, &message)
                            }))
                        }
                        Ok(None) => None,
                        Err(_) => mailbox_view.get_metadata(&scoped_mailbox, uid).await?,
                    }
                } else {
                    mailbox_view.get_metadata(&scoped_mailbox, uid).await?
                }
            } else {
                None
            };
            let mut flags = self
                .selected_mailbox_flags
                .get(&uid)
                .cloned()
                .unwrap_or_default();
            if self.recent_uids.contains(&uid) {
                flags.push("\\Recent".to_string());
            }
            let mut has_seen = flags.iter().any(|flag| flag == &seen_flag);

            if needs_body_sections {
                if let Some(ref meta) = meta {
                    debug!(
                        pkg = "gluon/state/mailbox",
                        UID = uid.value(),
                        mboxID = %scoped_mailbox,
                        messageID = %meta.id,
                        msg = "Fetch Body",
                        "Fetch Body"
                    );
                }
            }

            let mut parts: Vec<String> = Vec::with_capacity(expanded.len());
            let mut part_literals: HashMap<usize, Vec<u8>> = HashMap::new();

            let mut rfc822_data = None;
            let needs_rfc822_header_or_text = expanded
                .iter()
                .any(|i| matches!(i, FetchItem::Rfc822Header | FetchItem::Rfc822Text));
            let needs_rfc822_load = (needs_body_sections && !header_only_body_fetch)
                || needs_full_rfc822
                || needs_rfc822_header_or_text;
            if needs_rfc822_load {
                rfc822_data = mailbox_view.get_rfc822(&scoped_mailbox, uid).await?;
                if rfc822_data.is_some() {
                    cache_hits = cache_hits.saturating_add(1);
                } else {
                    cache_misses = cache_misses.saturating_add(1);
                }
                if rfc822_data.is_none() && needs_full_rfc822 {
                    // Fetch + decrypt on demand for full/body/text paths.
                    if let Some(ref meta) = meta {
                        rfc822_data = self
                            .fetch_and_cache_rfc822(&scoped_mailbox, uid, &meta.id)
                            .await?;
                    }
                }
            }

            for item in &expanded {
                match item {
                    FetchItem::Flags => {
                        let flag_str = flags.join(" ");
                        parts.push(format!("FLAGS ({})", flag_str));
                    }
                    FetchItem::Uid => {
                        parts.push(format!("UID {}", uid));
                    }
                    FetchItem::Envelope => {
                        if let Some(ref meta) = meta {
                            // Need the original header for envelope
                            let header = if let Some(ref data) = rfc822_data {
                                extract_header_section(data)
                            } else {
                                String::new()
                            };
                            let env = rfc822::build_envelope(meta, &header);
                            parts.push(format!("ENVELOPE {}", env));
                        }
                    }
                    FetchItem::Rfc822Size => {
                        if let Some(ref data) = rfc822_data {
                            parts.push(format!("RFC822.SIZE {}", data.len()));
                        } else if let Some(ref meta) = meta {
                            parts.push(format!("RFC822.SIZE {}", meta.size));
                        }
                    }
                    FetchItem::Rfc822Header => {
                        let header_data = if let Some(ref data) = rfc822_data {
                            extract_header_section(data).into_bytes()
                        } else if let Some(ref meta) = meta {
                            build_metadata_header_section(meta).into_bytes()
                        } else {
                            Vec::new()
                        };
                        let idx = parts.len();
                        parts.push(format!("RFC822.HEADER {{{}}}", header_data.len()));
                        part_literals.insert(idx, header_data);
                    }
                    FetchItem::Rfc822Text => {
                        let text_data = if let Some(ref data) = rfc822_data {
                            extract_text_section(data)
                        } else {
                            Vec::new()
                        };
                        let idx = parts.len();
                        parts.push(format!("RFC822.TEXT {{{}}}", text_data.len()));
                        part_literals.insert(idx, text_data);
                    }
                    FetchItem::Rfc822 => {
                        let full_data = rfc822_data.clone().unwrap_or_default();
                        let idx = parts.len();
                        parts.push(format!("RFC822 {{{}}}", full_data.len()));
                        part_literals.insert(idx, full_data);
                        // RFC822 (bare) implicitly sets \Seen
                        if !self.selected_read_only && !has_seen {
                            has_seen = true;
                        }
                    }
                    FetchItem::InternalDate => {
                        if let Some(ref meta) = meta {
                            parts.push(format!(
                                "INTERNALDATE {}",
                                rfc822::format_internal_date(meta.time)
                            ));
                        }
                    }
                    FetchItem::BodyStructure => {
                        let structure = if let Some(ref data) = rfc822_data {
                            rfc822::build_bodystructure(data)
                        } else if let Some(ref m) = meta {
                            rfc822::simple_text_structure(m.size as usize)
                        } else {
                            rfc822::simple_text_structure(0)
                        };
                        parts.push(format!("BODYSTRUCTURE {}", structure));
                    }
                    FetchItem::Body => {
                        let body = if let Some(ref data) = rfc822_data {
                            rfc822::build_body(data)
                        } else if let Some(ref m) = meta {
                            rfc822::simple_text_body(m.size as usize)
                        } else {
                            rfc822::simple_text_body(0)
                        };
                        parts.push(format!("BODY {}", body));
                    }
                    FetchItem::BodySection {
                        section,
                        peek,
                        partial,
                    } => {
                        let section_tag = match (section, partial) {
                            (Some(s), Some((origin, _))) => {
                                format!("BODY[{}]<{}>", s, origin)
                            }
                            (Some(s), None) => format!("BODY[{}]", s),
                            (None, Some((origin, _))) => format!("BODY[]<{}>", origin),
                            (None, None) => "BODY[]".to_string(),
                        };

                        let body_data = if let Some(ref data) = rfc822_data {
                            match section {
                                Some(s) => {
                                    let upper = s.to_uppercase();
                                    if upper.starts_with("HEADER.FIELDS") {
                                        let fields = parse_header_field_names(s);
                                        let hdr = extract_header_section(data);
                                        filter_headers_by_fields(&hdr, &fields).into_bytes()
                                    } else if upper == "HEADER" {
                                        extract_header_section(data).into_bytes()
                                    } else if upper == "TEXT" {
                                        extract_text_section(data)
                                    } else if s
                                        .as_bytes()
                                        .first()
                                        .is_some_and(|b| b.is_ascii_digit())
                                    {
                                        rfc822::extract_mime_part(data, s).unwrap_or_default()
                                    } else {
                                        data.clone()
                                    }
                                }
                                None => data.clone(),
                            }
                        } else if let Some(ref meta) = meta {
                            match section {
                                Some(s) => {
                                    let upper = s.to_uppercase();
                                    if upper.starts_with("HEADER.FIELDS") {
                                        let fields = parse_header_field_names(s);
                                        let hdr = build_metadata_header_section(meta);
                                        filter_headers_by_fields(&hdr, &fields).into_bytes()
                                    } else if upper == "HEADER" {
                                        build_metadata_header_section(meta).into_bytes()
                                    } else {
                                        Vec::new()
                                    }
                                }
                                None => Vec::new(),
                            }
                        } else {
                            Vec::new()
                        };

                        // Apply partial range if specified
                        let body_data = if let Some((origin, count)) = partial {
                            let origin = *origin as usize;
                            let count = *count as usize;
                            if origin >= body_data.len() {
                                Vec::new()
                            } else {
                                let end = (origin + count).min(body_data.len());
                                body_data[origin..end].to_vec()
                            }
                        } else {
                            body_data
                        };

                        let idx = parts.len();
                        parts.push(format!("{} {{{}}}", section_tag, body_data.len()));
                        part_literals.insert(idx, body_data);

                        if !peek && !self.selected_read_only {
                            // Set \Seen flag
                            if !has_seen {
                                self.config
                                    .mailbox_mutation
                                    .add_flags(
                                        &scoped_mailbox,
                                        uid,
                                        std::slice::from_ref(&seen_flag),
                                    )
                                    .await?;
                                has_seen = true;
                                // Mark as read on API via connector
                                if let Some(ref meta) = meta {
                                    if let Some(ref account_id) = self.authenticated_account_id {
                                        if let Err(err) = self
                                            .config
                                            .connector
                                            .mark_messages_read(
                                                account_id,
                                                &[meta.id.as_str()],
                                                true,
                                            )
                                            .await
                                        {
                                            warn!(
                                                error = %err,
                                                mailbox = %mailbox,
                                                proton_id = %meta.id,
                                                "failed to sync read state upstream"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            if !parts.is_empty() {
                if part_literals.is_empty() {
                    let parts_str = parts.join(" ");
                    let line = format!("* {} FETCH ({})\r\n", seq, parts_str);
                    self.writer.raw(line.as_bytes()).await?;
                } else {
                    let mut out = Vec::new();
                    out.extend_from_slice(format!("* {} FETCH (", seq).as_bytes());
                    for (i, part) in parts.iter().enumerate() {
                        if i > 0 {
                            out.extend_from_slice(b" ");
                        }
                        out.extend_from_slice(part.as_bytes());
                        if let Some(literal) = part_literals.get(&i) {
                            out.extend_from_slice(b"\r\n");
                            out.extend_from_slice(literal);
                        }
                    }
                    out.extend_from_slice(b")\r\n");
                    self.writer.raw(&out).await?;
                }
            }
        }

        // Restore the pinned store session after the fetch loop.
        self.store_session = pinned_session;

        if needs_body_sections {
            if header_only_body_fetch {
                // Match bridge behavior: header index fetch should avoid RFC822 disk/blob reads.
                info!(
                    service = "imap",
                    msg = "rfc822_cache_miss",
                    user_id = %user_id,
                    mailbox = %mailbox,
                    count = target_fetch_count,
                    "rfc822_cache_miss"
                );
            } else {
                if cache_hits > 0 {
                    info!(
                        service = "imap",
                        msg = "rfc822_cache_hit",
                        user_id = %user_id,
                        mailbox = %mailbox,
                        count = cache_hits,
                        "rfc822_cache_hit"
                    );
                }
                if cache_misses > 0 {
                    info!(
                        service = "imap",
                        msg = "rfc822_cache_miss",
                        user_id = %user_id,
                        mailbox = %mailbox,
                        count = cache_misses,
                        "rfc822_cache_miss"
                    );
                }
            }
        }

        self.writer.flush().await?;
        self.writer.tagged_ok(tag, None, "FETCH completed").await
    }
}

pub fn expand_fetch_items(items: &[FetchItem]) -> Vec<FetchItem> {
    let mut result = Vec::new();
    for item in items {
        match item {
            FetchItem::All => {
                result.extend_from_slice(&[
                    FetchItem::Flags,
                    FetchItem::InternalDate,
                    FetchItem::Rfc822Size,
                    FetchItem::Envelope,
                ]);
            }
            FetchItem::Fast => {
                result.extend_from_slice(&[
                    FetchItem::Flags,
                    FetchItem::InternalDate,
                    FetchItem::Rfc822Size,
                ]);
            }
            FetchItem::Full => {
                result.extend_from_slice(&[
                    FetchItem::Flags,
                    FetchItem::InternalDate,
                    FetchItem::Rfc822Size,
                    FetchItem::Envelope,
                    FetchItem::Body,
                ]);
            }
            _ => result.push(item.clone()),
        }
    }
    result
}

pub fn parse_header_field_names(section: &str) -> Vec<String> {
    if let Some(start) = section.find('(') {
        if let Some(end) = section.find(')') {
            return section[start + 1..end]
                .split_whitespace()
                .map(|s| s.to_uppercase())
                .collect();
        }
    }
    vec![]
}

pub fn body_section_is_header_only(section: Option<&str>) -> bool {
    let Some(section) = section else {
        return false;
    };
    let upper = section.trim().to_uppercase();
    // Only HEADER.FIELDS (specific fields) can be satisfied from metadata.
    // Bare "HEADER" needs the full RFC822 data to return all original headers.
    upper.starts_with("HEADER.FIELDS")
}

pub fn build_metadata_header_section(meta: &crate::imap_types::MessageEnvelope) -> String {
    let mut out = String::new();

    out.push_str("Date: ");
    out.push_str(rfc822::format_internal_date(meta.time).trim_matches('"'));
    out.push_str("\r\n");

    out.push_str("Subject: ");
    out.push_str(&sanitize_header_value(&meta.subject));
    out.push_str("\r\n");

    out.push_str("From: ");
    out.push_str(&format_header_addresses(std::slice::from_ref(&meta.sender)));
    out.push_str("\r\n");

    if !meta.reply_tos.is_empty() {
        out.push_str("Reply-To: ");
        out.push_str(&format_header_addresses(&meta.reply_tos));
        out.push_str("\r\n");
    }
    if !meta.to_list.is_empty() {
        out.push_str("To: ");
        out.push_str(&format_header_addresses(&meta.to_list));
        out.push_str("\r\n");
    }
    if !meta.cc_list.is_empty() {
        out.push_str("Cc: ");
        out.push_str(&format_header_addresses(&meta.cc_list));
        out.push_str("\r\n");
    }
    if !meta.bcc_list.is_empty() {
        out.push_str("Bcc: ");
        out.push_str(&format_header_addresses(&meta.bcc_list));
        out.push_str("\r\n");
    }
    if let Some(external_id) = meta.external_id.as_deref() {
        if !external_id.is_empty() {
            out.push_str("Message-ID: <");
            out.push_str(&sanitize_header_value(external_id));
            out.push_str(">\r\n");
        }
    }
    out.push_str("\r\n");
    out
}

pub fn format_header_addresses(addrs: &[crate::imap_types::EmailAddress]) -> String {
    addrs
        .iter()
        .map(format_header_address)
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn format_header_address(addr: &crate::imap_types::EmailAddress) -> String {
    let address = sanitize_header_value(&addr.address);
    let name = sanitize_header_value(&addr.name);
    if name.trim().is_empty() {
        return address;
    }
    let escaped_name = name.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\" <{}>", escaped_name, address)
}

pub fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .map(|c| if c == '\r' || c == '\n' { ' ' } else { c })
        .collect()
}

pub fn filter_headers_by_fields(header_section: &str, fields: &[String]) -> String {
    let mut result = String::new();
    let mut current_name = String::new();
    let mut current_value = String::new();
    let mut in_header = false;

    for line in header_section.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of previous header
            if in_header {
                current_value.push_str(line);
                current_value.push_str("\r\n");
            }
        } else {
            // Flush previous header if it matches
            if in_header && fields.iter().any(|f| f.eq_ignore_ascii_case(&current_name)) {
                result.push_str(&current_value);
            }
            // Start new header
            if let Some(colon) = line.find(':') {
                current_name = line[..colon].to_string();
                current_value = format!("{}\r\n", line);
                in_header = true;
            } else {
                in_header = false;
            }
        }
    }
    // Flush last header
    if in_header && fields.iter().any(|f| f.eq_ignore_ascii_case(&current_name)) {
        result.push_str(&current_value);
    }
    // Blank line to terminate headers
    result.push_str("\r\n");
    result
}
