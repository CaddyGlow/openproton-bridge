use crate::api::client::ProtonClient;
use crate::api::messages;
use crate::api::types::{EmailAddress, Message, MessageMetadata};
use crate::crypto::decrypt;
use crate::crypto::keys::Keyring;

use super::Result;

/// Build RFC 822 message bytes from a decrypted Proton message.
///
/// Uses the original headers from msg.header + decrypted body.
/// For messages with attachments, builds multipart/mixed.
pub async fn build_rfc822(
    client: &ProtonClient,
    keyring: &Keyring,
    msg: &Message,
) -> Result<Vec<u8>> {
    let decrypted_body = decrypt::decrypt_message_body(keyring, &msg.body)?;
    let body_text = String::from_utf8_lossy(&decrypted_body);

    // Parse and filter original headers - strip content-related headers we will set ourselves
    let filtered_headers = filter_headers(&msg.header);

    let mut output = Vec::new();

    if msg.attachments.is_empty() {
        // Simple message: headers + content-type + body
        output.extend_from_slice(filtered_headers.as_bytes());
        output.extend_from_slice(b"MIME-Version: 1.0\r\n");

        if msg.mime_type == "text/html" {
            output.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n");
        } else {
            output.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
        }
        output.extend_from_slice(b"Content-Transfer-Encoding: 8bit\r\n");
        output.extend_from_slice(b"\r\n");
        output.extend_from_slice(body_text.as_bytes());
    } else {
        // Multipart message with attachments
        let boundary = format!("----=_Part_{:016x}", rand::random::<u64>());

        output.extend_from_slice(filtered_headers.as_bytes());
        output.extend_from_slice(b"MIME-Version: 1.0\r\n");
        output.extend_from_slice(
            format!(
                "Content-Type: multipart/mixed; boundary=\"{}\"\r\n",
                boundary
            )
            .as_bytes(),
        );
        output.extend_from_slice(b"\r\n");

        // Body part
        output.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        if msg.mime_type == "text/html" {
            output.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n");
        } else {
            output.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
        }
        output.extend_from_slice(b"Content-Transfer-Encoding: 8bit\r\n");
        output.extend_from_slice(b"\r\n");
        output.extend_from_slice(body_text.as_bytes());
        output.extend_from_slice(b"\r\n");

        // Attachment parts
        for att in &msg.attachments {
            match fetch_and_decrypt_attachment(client, keyring, &att.key_packets, &att.id).await {
                Ok(att_data) => {
                    output.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
                    output.extend_from_slice(
                        format!("Content-Type: {}; name=\"{}\"\r\n", att.mime_type, att.name)
                            .as_bytes(),
                    );
                    output.extend_from_slice(b"Content-Transfer-Encoding: base64\r\n");
                    output.extend_from_slice(
                        format!(
                            "Content-Disposition: attachment; filename=\"{}\"\r\n",
                            att.name
                        )
                        .as_bytes(),
                    );
                    output.extend_from_slice(b"\r\n");

                    // Base64 encode the attachment data in 76-char lines
                    use base64::engine::general_purpose::STANDARD as BASE64;
                    use base64::Engine;
                    let encoded = BASE64.encode(&att_data);
                    for chunk in encoded.as_bytes().chunks(76) {
                        output.extend_from_slice(chunk);
                        output.extend_from_slice(b"\r\n");
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        attachment_id = %att.id,
                        error = %e,
                        "failed to decrypt attachment, skipping"
                    );
                }
            }
        }

        // Closing boundary
        output.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    }

    Ok(output)
}

async fn fetch_and_decrypt_attachment(
    client: &ProtonClient,
    keyring: &Keyring,
    key_packets_b64: &str,
    attachment_id: &str,
) -> Result<Vec<u8>> {
    let encrypted_data = messages::get_attachment(client, attachment_id).await?;
    let decrypted = decrypt::decrypt_attachment(keyring, key_packets_b64, &encrypted_data)?;
    Ok(decrypted)
}

/// Filter out Content-Type, Content-Transfer-Encoding, MIME-Version from original headers.
fn filter_headers(header: &str) -> String {
    let mut result = String::new();
    let mut skip = false;

    for line in header.split('\n') {
        let line = line.trim_end_matches('\r');

        // Continuation line (starts with whitespace)
        if line.starts_with(' ') || line.starts_with('\t') {
            if !skip {
                result.push_str(line);
                result.push_str("\r\n");
            }
            continue;
        }

        let lower = line.to_lowercase();
        skip = lower.starts_with("content-type:")
            || lower.starts_with("content-transfer-encoding:")
            || lower.starts_with("mime-version:");

        if !skip && !line.is_empty() {
            result.push_str(line);
            result.push_str("\r\n");
        }
    }

    result
}

/// Build an IMAP ENVELOPE response string from metadata and parsed headers.
///
/// Format per RFC 3501 section 7.4.2:
/// ("date" "subject" ((from)) ((sender)) ((reply-to)) ((to)) ((cc)) (NIL) "in-reply-to" "message-id")
pub fn build_envelope(meta: &MessageMetadata, header: &str) -> String {
    let date = format_imap_date(meta.time);
    let subject = imap_quote(&meta.subject);
    let from = format_address_list(std::slice::from_ref(&meta.sender));
    let to = format_address_list(&meta.to_list);
    let cc = format_address_list(&meta.cc_list);
    let bcc = format_address_list(&meta.bcc_list);

    let in_reply_to = extract_header(header, "In-Reply-To")
        .map(|v| imap_quote(&v))
        .unwrap_or_else(|| "NIL".to_string());
    let message_id = extract_header(header, "Message-Id")
        .or_else(|| extract_header(header, "Message-ID"))
        .map(|v| imap_quote(&v))
        .unwrap_or_else(|| "NIL".to_string());

    format!(
        "({} {} {} {} {} {} {} {} {} {})",
        imap_quote(&date),
        subject,
        from,
        from, // sender = from per convention
        from, // reply-to = from per convention
        to,
        cc,
        bcc,
        in_reply_to,
        message_id,
    )
}

fn format_address_list(addrs: &[EmailAddress]) -> String {
    if addrs.is_empty() {
        return "NIL".to_string();
    }
    let parts: Vec<String> = addrs
        .iter()
        .map(|a| {
            let (local, domain) = match a.address.split_once('@') {
                Some((l, d)) => (l, d),
                None => (a.address.as_str(), ""),
            };
            format!(
                "({} NIL {} {})",
                imap_quote(&a.name),
                imap_quote(local),
                imap_quote(domain),
            )
        })
        .collect();
    format!("({})", parts.join(""))
}

fn imap_quote(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".to_string();
    }
    // Escape backslashes and double quotes
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\"", escaped)
}

fn format_imap_date(timestamp: i64) -> String {
    // Convert unix timestamp to IMAP date format: "DD-Mon-YYYY HH:MM:SS +0000"
    let secs = timestamp;
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let mut year = 1970i64;
    let mut remaining_days = days_since_epoch;

    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            366
        } else {
            365
        };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_months = [
        31,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let mut month = 0usize;
    for (i, &dim) in days_in_months.iter().enumerate() {
        if remaining_days < dim {
            month = i;
            break;
        }
        remaining_days -= dim;
    }

    let day = remaining_days + 1;

    format!(
        "{:02}-{}-{:04} {:02}:{:02}:{:02} +0000",
        day, month_names[month], year, hours, minutes, seconds
    )
}

pub fn format_internal_date(timestamp: i64) -> String {
    let date = format_imap_date(timestamp);
    format!("\"{}\"", date)
}

fn extract_header(header: &str, name: &str) -> Option<String> {
    let search = format!("{}:", name);
    let search_lower = search.to_lowercase();

    for line in header.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.to_lowercase().starts_with(&search_lower) {
            return Some(line[search.len()..].trim().to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_headers() {
        let header = "From: alice@proton.me\r\nContent-Type: text/html\r\nSubject: Hello\r\nMIME-Version: 1.0\r\nTo: bob@proton.me\r\n";
        let filtered = filter_headers(header);
        assert!(filtered.contains("From: alice@proton.me"));
        assert!(filtered.contains("Subject: Hello"));
        assert!(filtered.contains("To: bob@proton.me"));
        assert!(!filtered.contains("Content-Type"));
        assert!(!filtered.contains("MIME-Version"));
    }

    #[test]
    fn test_filter_headers_multiline() {
        let header = "From: alice@proton.me\r\nContent-Type: multipart/mixed;\r\n boundary=\"abc\"\r\nSubject: Hello\r\n";
        let filtered = filter_headers(header);
        assert!(filtered.contains("From: alice@proton.me"));
        assert!(filtered.contains("Subject: Hello"));
        assert!(!filtered.contains("Content-Type"));
        assert!(!filtered.contains("boundary"));
    }

    #[test]
    fn test_build_envelope() {
        let meta = MessageMetadata {
            id: "msg-1".to_string(),
            address_id: "addr-1".to_string(),
            label_ids: vec!["0".to_string()],
            subject: "Test Subject".to_string(),
            sender: EmailAddress {
                name: "Alice".to_string(),
                address: "alice@proton.me".to_string(),
            },
            to_list: vec![EmailAddress {
                name: "Bob".to_string(),
                address: "bob@proton.me".to_string(),
            }],
            cc_list: vec![],
            bcc_list: vec![],
            time: 1700000000,
            size: 1024,
            unread: 0,
            num_attachments: 0,
        };

        let header = "Message-ID: <test@proton.me>\r\nIn-Reply-To: <prev@proton.me>\r\n";
        let envelope = build_envelope(&meta, header);

        assert!(envelope.starts_with('('));
        assert!(envelope.ends_with(')'));
        assert!(envelope.contains("\"Test Subject\""));
        assert!(envelope.contains("\"alice\""));
        assert!(envelope.contains("\"proton.me\""));
        assert!(envelope.contains("\"bob\""));
        assert!(envelope.contains("\"<test@proton.me>\""));
        assert!(envelope.contains("\"<prev@proton.me>\""));
    }

    #[test]
    fn test_build_envelope_nil_fields() {
        let meta = MessageMetadata {
            id: "msg-1".to_string(),
            address_id: "addr-1".to_string(),
            label_ids: vec!["0".to_string()],
            subject: "Test".to_string(),
            sender: EmailAddress {
                name: "Alice".to_string(),
                address: "alice@proton.me".to_string(),
            },
            to_list: vec![],
            cc_list: vec![],
            bcc_list: vec![],
            time: 1700000000,
            size: 1024,
            unread: 0,
            num_attachments: 0,
        };

        let envelope = build_envelope(&meta, "");
        // to, cc, bcc should be NIL when empty
        assert!(envelope.contains("NIL"));
    }

    #[test]
    fn test_format_imap_date() {
        let date = format_imap_date(1700000000);
        // 2023-11-14 22:13:20 UTC
        assert_eq!(date, "14-Nov-2023 22:13:20 +0000");
    }

    #[test]
    fn test_format_internal_date() {
        let date = format_internal_date(1700000000);
        assert_eq!(date, "\"14-Nov-2023 22:13:20 +0000\"");
    }

    #[test]
    fn test_imap_quote() {
        assert_eq!(imap_quote("hello"), "\"hello\"");
        assert_eq!(imap_quote(""), "\"\"");
        assert_eq!(imap_quote("say \"hi\""), "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn test_extract_header() {
        let header = "From: alice@proton.me\r\nMessage-ID: <test@proton.me>\r\nSubject: Hi\r\n";
        assert_eq!(
            extract_header(header, "Message-ID"),
            Some("<test@proton.me>".to_string())
        );
        assert_eq!(
            extract_header(header, "From"),
            Some("alice@proton.me".to_string())
        );
        assert_eq!(extract_header(header, "X-Missing"), None);
    }

    #[test]
    fn test_format_address_list() {
        let addrs = vec![
            EmailAddress {
                name: "Alice".to_string(),
                address: "alice@proton.me".to_string(),
            },
            EmailAddress {
                name: "Bob".to_string(),
                address: "bob@example.com".to_string(),
            },
        ];
        let result = format_address_list(&addrs);
        assert!(result.starts_with('('));
        assert!(result.ends_with(')'));
        assert!(result.contains("\"Alice\""));
        assert!(result.contains("\"alice\""));
        assert!(result.contains("\"proton.me\""));
        assert!(result.contains("\"Bob\""));
        assert!(result.contains("\"bob\""));
        assert!(result.contains("\"example.com\""));
    }

    #[test]
    fn test_format_address_list_empty() {
        assert_eq!(format_address_list(&[]), "NIL");
    }
}
