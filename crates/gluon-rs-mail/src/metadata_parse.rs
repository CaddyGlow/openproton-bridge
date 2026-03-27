//! Parse RFC822 message data into `MessageEnvelope` metadata.
//!
//! Used by the IMAP session and store adapters to build metadata from raw
//! message bodies without depending on upstream API types.

use mailparse::{addrparse, dateparse, DispositionType, MailAddr, MailHeaderMap, ParsedMail};

use crate::imap_types::{EmailAddress, MessageEnvelope, ScopedMailboxId};
use crate::store::UpstreamMailboxMessage;

/// Parse RFC822 data into a `MessageEnvelope`.
///
/// Returns `None` if the data cannot be parsed.
pub fn parse_metadata_from_rfc822(
    mailbox: &ScopedMailboxId,
    summary: &crate::store::UpstreamMessageSummary,
    data: &[u8],
) -> Option<MessageEnvelope> {
    let parsed = mailparse::parse_mail(data).ok()?;
    let header = parsed.get_headers();
    let label_id = mailbox_label_id(mailbox, &summary.remote_id);
    let date_header = header.get_first_value("Date");
    let time = date_header
        .as_deref()
        .and_then(|value| dateparse(value).ok())
        .unwrap_or(0);

    Some(MessageEnvelope {
        id: summary.remote_id.clone(),
        address_id: String::new(),
        label_ids: vec![label_id],
        external_id: header.get_first_value("Message-ID"),
        subject: header.get_first_value("Subject").unwrap_or_default(),
        sender: first_address(&parsed, "From"),
        to_list: addresses(&parsed, "To"),
        cc_list: addresses(&parsed, "Cc"),
        bcc_list: addresses(&parsed, "Bcc"),
        reply_tos: addresses(&parsed, "Reply-To"),
        flags: 0,
        time,
        size: summary.size,
        unread: if has_seen_flag(&summary.flags) { 0 } else { 1 },
        is_replied: 0,
        is_replied_all: 0,
        is_forwarded: 0,
        num_attachments: count_attachments(&parsed) as i32,
    })
}

/// Build a minimal fallback `MessageEnvelope` when RFC822 parsing fails.
pub fn fallback_metadata(
    mailbox: &ScopedMailboxId,
    message: &UpstreamMailboxMessage,
) -> MessageEnvelope {
    MessageEnvelope {
        id: message.summary.remote_id.clone(),
        address_id: String::new(),
        label_ids: vec![mailbox_label_id(mailbox, &message.summary.remote_id)],
        external_id: None,
        subject: String::new(),
        sender: EmailAddress {
            name: String::new(),
            address: String::new(),
        },
        to_list: Vec::new(),
        cc_list: Vec::new(),
        bcc_list: Vec::new(),
        reply_tos: Vec::new(),
        flags: 0,
        time: 0,
        size: message.summary.size,
        unread: if has_seen_flag(&message.summary.flags) {
            0
        } else {
            1
        },
        is_replied: 0,
        is_replied_all: 0,
        is_forwarded: 0,
        num_attachments: 0,
    }
}

fn mailbox_label_id(scoped: &ScopedMailboxId, fallback: &str) -> String {
    crate::mailbox::find_mailbox(scoped.mailbox_name())
        .map(|mailbox| mailbox.label_id.to_string())
        .unwrap_or_else(|| fallback.to_string())
}

fn has_seen_flag(flags: &[String]) -> bool {
    flags.iter().any(|flag| flag.eq_ignore_ascii_case("\\Seen"))
}

fn first_address(parsed: &ParsedMail<'_>, header_name: &str) -> EmailAddress {
    addresses(parsed, header_name)
        .into_iter()
        .next()
        .unwrap_or(EmailAddress {
            name: String::new(),
            address: String::new(),
        })
}

fn addresses(parsed: &ParsedMail<'_>, header_name: &str) -> Vec<EmailAddress> {
    parsed
        .headers
        .iter()
        .filter(|header| header.get_key_ref().eq_ignore_ascii_case(header_name))
        .map(|header| header.get_value())
        .filter_map(|value| addrparse(&value).ok())
        .flat_map(|parsed| parsed.iter().cloned().collect::<Vec<_>>())
        .flat_map(mail_addr_to_email_addresses)
        .collect()
}

fn mail_addr_to_email_addresses(addr: MailAddr) -> Vec<EmailAddress> {
    match addr {
        MailAddr::Single(info) => vec![EmailAddress {
            name: info.display_name.unwrap_or_default(),
            address: info.addr,
        }],
        MailAddr::Group(group) => group
            .addrs
            .into_iter()
            .map(|info| EmailAddress {
                name: info.display_name.unwrap_or_default(),
                address: info.addr,
            })
            .collect(),
    }
}

fn count_attachments(parsed: &ParsedMail<'_>) -> usize {
    let mut count = 0usize;
    for subpart in &parsed.subparts {
        let disposition = subpart.get_content_disposition();
        if matches!(disposition.disposition, DispositionType::Attachment) {
            count += 1;
        }
        count += count_attachments(subpart);
    }
    count
}
