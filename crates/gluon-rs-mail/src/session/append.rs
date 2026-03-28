use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use super::*;

impl<R, W> ImapSession<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    pub async fn cmd_append(
        &mut self,
        tag: &str,
        mailbox_name: &str,
        flags: &[ImapFlag],
        append_date: &Option<String>,
        literal_size: u32,
    ) -> Result<()> {
        if self.state == State::NotAuthenticated {
            return self.writer.tagged_no(tag, "not authenticated").await;
        }

        let mb = match self.resolve_mailbox(mailbox_name).await {
            Some(m) => m,
            None => {
                // Consume and discard the literal before responding
                self.writer.continuation("Ready").await?;
                let mut discard = vec![0u8; literal_size as usize];
                tokio::io::AsyncReadExt::read_exact(&mut self.reader, &mut discard).await?;
                let mut crlf = [0u8; 2];
                let _ = tokio::io::AsyncReadExt::read_exact(&mut self.reader, &mut crlf).await;
                return self
                    .writer
                    .tagged_no(
                        tag,
                        &format!("[TRYCREATE] mailbox not found: {}", mailbox_name),
                    )
                    .await;
            }
        };

        if literal_size as usize > self.config.limits.max_message_size {
            self.writer.continuation("Ready").await?;
            let mut discard = vec![0u8; literal_size as usize];
            tokio::io::AsyncReadExt::read_exact(&mut self.reader, &mut discard).await?;
            let mut crlf = [0u8; 2];
            let _ = tokio::io::AsyncReadExt::read_exact(&mut self.reader, &mut crlf).await;
            return self
                .writer
                .tagged_no(tag, "message exceeds maximum allowed size")
                .await;
        }

        if !mb.selectable {
            self.writer.continuation("Ready").await?;
            let mut discard = vec![0u8; literal_size as usize];
            tokio::io::AsyncReadExt::read_exact(&mut self.reader, &mut discard).await?;
            let mut crlf = [0u8; 2];
            let _ = tokio::io::AsyncReadExt::read_exact(&mut self.reader, &mut crlf).await;
            return self.writer.tagged_no(tag, "mailbox not selectable").await;
        }

        // Send continuation and read the literal data
        self.writer.continuation("Ready").await?;
        let mut literal = vec![0u8; literal_size as usize];
        tokio::io::AsyncReadExt::read_exact(&mut self.reader, &mut literal).await?;
        // Consume trailing CRLF after literal
        let mut crlf = [0u8; 2];
        let _ = tokio::io::AsyncReadExt::read_exact(&mut self.reader, &mut crlf).await;

        // Build metadata from the RFC822 message using mailparse
        let parsed_mail = mailparse::parse_mail(&literal).ok();
        let get_hdr = |name: &str| -> Option<String> {
            parsed_mail.as_ref().and_then(|p| {
                use mailparse::MailHeaderMap;
                p.get_headers().get_first_value(name)
            })
        };

        let subject = get_hdr("Subject").unwrap_or_default();
        let from_str = get_hdr("From").unwrap_or_default();
        let sender = parse_append_address(&from_str);
        let to_list = get_hdr("To")
            .map(|v| parse_address_list_header(&v))
            .unwrap_or_default();
        let cc_list = get_hdr("Cc")
            .map(|v| parse_address_list_header(&v))
            .unwrap_or_default();
        let bcc_list = get_hdr("Bcc")
            .map(|v| parse_address_list_header(&v))
            .unwrap_or_default();
        let reply_tos = get_hdr("Reply-To")
            .map(|v| parse_address_list_header(&v))
            .unwrap_or_default();
        let external_id = get_hdr("Message-Id").or_else(|| get_hdr("Message-ID"));

        // Use APPEND date argument if provided, else Date header, else now
        let time = append_date
            .as_deref()
            .and_then(parse_rfc2822_date)
            .or_else(|| extract_sent_date(&literal))
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64
            });

        let is_unread = !flags.iter().any(|f| matches!(f, ImapFlag::Seen));

        // Try to import upstream via connector.
        let import_flags =
            crate::well_known::MESSAGE_FLAG_RECEIVED | crate::well_known::MESSAGE_FLAG_IMPORTED;
        let proton_id = if let Some(ref account_id) = self.authenticated_account_id {
            match self
                .config
                .connector
                .import_message(account_id, &mb.label_id, import_flags, &literal)
                .await
            {
                Ok(id) => id,
                Err(e) => {
                    warn!(error = %e, "APPEND upstream import failed; storing locally only");
                    None
                }
            }
        } else {
            None
        };

        let proton_id = proton_id.unwrap_or_else(|| {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!("local-append-{ts}")
        });

        let meta = crate::imap_types::MessageEnvelope {
            id: proton_id.clone(),
            address_id: String::new(),
            label_ids: vec![mb.label_id.clone()],
            external_id,
            subject,
            sender,
            to_list,
            cc_list,
            bcc_list,
            reply_tos,
            flags: 0,
            time,
            size: literal.len() as i64,
            unread: if is_unread { 1 } else { 0 },
            is_replied: 0,
            is_replied_all: 0,
            is_forwarded: 0,
            num_attachments: 0,
        };

        let mutation = self.config.mailbox_mutation.clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mb.name);
        let proton_msg_id = ProtonMessageId::from(proton_id.as_str());
        let uid = mutation
            .store_metadata(&scoped_mailbox, &proton_msg_id, meta)
            .await?;
        mutation.store_rfc822(&scoped_mailbox, uid, literal).await?;

        // Apply flags
        let flag_strs: Vec<String> = flags.iter().map(|f| f.as_str().to_string()).collect();
        if !flag_strs.is_empty() {
            mutation
                .set_flags(&scoped_mailbox, uid, flag_strs.clone())
                .await?;
        }

        let status = mutation.mailbox_status(&scoped_mailbox).await?;
        let appenduid_code = format!("APPENDUID {} {}", status.uid_validity, uid);

        // If the target is the currently selected mailbox, update local state and notify
        if self.selected_mailbox.as_deref() == Some(&mb.name) {
            self.selected_mailbox_uids.push(uid);
            self.selected_mailbox_flags.insert(uid, flag_strs.clone());
            self.writer
                .untagged(&format!("{} EXISTS", status.exists))
                .await?;
            self.writer.untagged("0 RECENT").await?;
        }

        info!(
            mailbox = %mb.name,
            uid = uid.value(),
            size = literal_size,
            "APPEND completed"
        );

        self.writer
            .tagged_ok(tag, Some(&appenduid_code), "APPEND completed")
            .await
    }
}

pub fn parse_append_address(value: &str) -> crate::imap_types::EmailAddress {
    if let Ok(addrs) = mailparse::addrparse(value) {
        if let Some(addr) = addrs.first() {
            match addr {
                mailparse::MailAddr::Single(info) => {
                    return crate::imap_types::EmailAddress {
                        name: info.display_name.clone().unwrap_or_default(),
                        address: info.addr.clone(),
                    };
                }
                mailparse::MailAddr::Group(info) => {
                    if let Some(first) = info.addrs.first() {
                        return crate::imap_types::EmailAddress {
                            name: first.display_name.clone().unwrap_or_default(),
                            address: first.addr.clone(),
                        };
                    }
                }
            }
        }
    }
    // Fallback for unparseable
    crate::imap_types::EmailAddress {
        name: String::new(),
        address: value.trim().to_string(),
    }
}

pub fn parse_address_list_header(value: &str) -> Vec<crate::imap_types::EmailAddress> {
    match mailparse::addrparse(value) {
        Ok(addrs) => addrs
            .iter()
            .flat_map(|addr| match addr {
                mailparse::MailAddr::Single(info) => vec![crate::imap_types::EmailAddress {
                    name: info.display_name.clone().unwrap_or_default(),
                    address: info.addr.clone(),
                }],
                mailparse::MailAddr::Group(info) => info
                    .addrs
                    .iter()
                    .map(|a| crate::imap_types::EmailAddress {
                        name: a.display_name.clone().unwrap_or_default(),
                        address: a.addr.clone(),
                    })
                    .collect(),
            })
            .collect(),
        Err(_) => value
            .split(',')
            .map(|s| parse_append_address(s.trim()))
            .filter(|a| !a.address.is_empty())
            .collect(),
    }
}
