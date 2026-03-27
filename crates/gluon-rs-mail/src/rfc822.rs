use mailparse::{MailHeaderMap, ParsedMail};

use crate::imap_types::{EmailAddress, MessageEnvelope};

/// Build an IMAP BODY response from RFC822 data.
///
/// Format per RFC 3501 section 7.4.2:
/// Non-multipart: (type subtype (params) id desc encoding size [lines])
/// Multipart: ((part1)(part2)... "subtype")
pub fn build_body(data: &[u8]) -> String {
    match mailparse::parse_mail(data) {
        Ok(parsed) => build_body_from_parsed(&parsed),
        Err(_) => simple_text_body(data.len()),
    }
}

fn build_body_from_parsed(parsed: &ParsedMail) -> String {
    let mime = &parsed.ctype.mimetype;

    if mime.starts_with("multipart/") {
        let subtype = mime.split('/').nth(1).unwrap_or("mixed").to_uppercase();
        if parsed.subparts.is_empty() {
            return simple_text_body(parsed.raw_bytes.len());
        }
        let parts: Vec<String> = parsed
            .subparts
            .iter()
            .map(|p| build_body_from_parsed(p))
            .collect();
        format!("({} \"{}\")", parts.join(""), subtype)
    } else if mime.starts_with("message/rfc822") {
        let (type_main, subtype) = split_mime_type(mime);
        let encoding = parsed_encoding(parsed);
        let body_raw = body_bytes_of(parsed);
        let body_size = body_raw.len();
        let body_lines = count_lines(&body_raw);
        // message/rfc822: type subtype params id desc enc octets lines
        // then the envelope, body, and line count of the encapsulated message
        // For simplicity, use the basic form matching existing behavior.
        format!(
            "(\"{}\" \"{}\" (\"CHARSET\" \"UTF-8\") NIL NIL \"{}\" {} {})",
            type_main, subtype, encoding, body_size, body_lines
        )
    } else {
        let (type_main, subtype) = split_mime_type(mime);
        let charset = parsed_charset(parsed);
        let encoding = parsed_encoding(parsed);
        let body_raw = body_bytes_of(parsed);
        let body_size = body_raw.len();
        let body_lines = count_lines(&body_raw);
        format!(
            "(\"{}\" \"{}\" (\"CHARSET\" \"{}\") NIL NIL \"{}\" {} {})",
            type_main, subtype, charset, encoding, body_size, body_lines
        )
    }
}

/// Build an IMAP BODYSTRUCTURE response from RFC822 data.
///
/// Format per RFC 3501 section 7.4.2:
/// Non-multipart: (type subtype (params) id desc encoding size lines md5 dsp lang loc)
/// Multipart: ((part1)(part2)... "subtype" (params) dsp lang loc)
pub fn build_bodystructure(data: &[u8]) -> String {
    match mailparse::parse_mail(data) {
        Ok(parsed) => build_bodystructure_from_parsed(&parsed),
        Err(_) => simple_text_structure(data.len()),
    }
}

fn build_bodystructure_from_parsed(parsed: &ParsedMail) -> String {
    let mime = &parsed.ctype.mimetype;

    if mime.starts_with("multipart/") {
        let subtype = mime.split('/').nth(1).unwrap_or("mixed").to_uppercase();
        let boundary = parsed
            .ctype
            .params
            .get("boundary")
            .cloned()
            .unwrap_or_default();

        if parsed.subparts.is_empty() {
            return simple_text_structure(parsed.raw_bytes.len());
        }
        let parts: Vec<String> = parsed
            .subparts
            .iter()
            .map(|p| build_bodystructure_from_parsed(p))
            .collect();
        format!(
            "({} \"{}\" (\"BOUNDARY\" \"{}\") NIL NIL)",
            parts.join(""),
            subtype,
            boundary
        )
    } else {
        let (type_main, subtype) = split_mime_type(mime);
        let charset = parsed_charset(parsed);
        let encoding = parsed_encoding(parsed);
        let content_id = parsed_content_id(parsed);
        let disposition = parsed_content_disposition(parsed);
        let body_raw = body_bytes_of(parsed);
        let body_size = body_raw.len();
        let body_lines = count_lines(&body_raw);

        format!(
            "(\"{}\" \"{}\" (\"CHARSET\" \"{}\") {} NIL \"{}\" {} {} NIL {} NIL NIL)",
            type_main, subtype, charset, content_id, encoding, body_size, body_lines, disposition
        )
    }
}

/// Build a simple text/plain BODYSTRUCTURE (fallback)
pub fn simple_text_body(size: usize) -> String {
    format!(
        "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"8BIT\" {} 0)",
        size
    )
}

pub fn simple_text_structure(size: usize) -> String {
    format!(
        "(\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"8BIT\" {} 0 NIL NIL NIL)",
        size
    )
}

// -- mailparse-based helpers for BODYSTRUCTURE/BODY building --

fn split_mime_type(mime: &str) -> (String, String) {
    let (t, s) = mime.split_once('/').unwrap_or(("text", "plain"));
    (t.to_uppercase(), s.to_string())
}

fn parsed_charset(parsed: &ParsedMail) -> String {
    parsed
        .ctype
        .params
        .get("charset")
        .cloned()
        .unwrap_or_else(|| "UTF-8".to_string())
}

fn parsed_encoding(parsed: &ParsedMail) -> String {
    parsed
        .get_headers()
        .get_first_value("Content-Transfer-Encoding")
        .map(|v| v.trim().to_uppercase())
        .unwrap_or_else(|| "7BIT".to_string())
}

fn parsed_content_id(parsed: &ParsedMail) -> String {
    parsed
        .get_headers()
        .get_first_value("Content-ID")
        .or_else(|| parsed.get_headers().get_first_value("Content-Id"))
        .map(|v| imap_quote(v.trim()))
        .unwrap_or_else(|| "NIL".to_string())
}

fn parsed_content_disposition(parsed: &ParsedMail) -> String {
    parsed
        .get_headers()
        .get_first_value("Content-Disposition")
        .map(|raw| format_content_disposition_raw(&raw))
        .unwrap_or_else(|| "NIL".to_string())
}

fn format_content_disposition_raw(raw: &str) -> String {
    let mut parts = raw.splitn(2, ';');
    let disp_type = parts.next().unwrap_or("").trim().to_lowercase();
    if disp_type.is_empty() {
        return "NIL".to_string();
    }

    let params_str = parts.next().unwrap_or("").trim();
    if params_str.is_empty() {
        return format!("(\"{}\" NIL)", disp_type.to_uppercase());
    }

    let mut param_pairs = Vec::new();
    for param in params_str.split(';') {
        let param = param.trim();
        if let Some((key, val)) = param.split_once('=') {
            let key = key.trim().to_uppercase();
            let val = val.trim().trim_matches('"').trim_matches('\'');
            param_pairs.push(format!("\"{}\" \"{}\"", key, val));
        }
    }

    if param_pairs.is_empty() {
        format!("(\"{}\" NIL)", disp_type.to_uppercase())
    } else {
        format!(
            "(\"{}\" ({}))",
            disp_type.to_uppercase(),
            param_pairs.join(" ")
        )
    }
}

/// Return the body bytes (after headers) of a ParsedMail node.
fn body_bytes_of(parsed: &ParsedMail) -> Vec<u8> {
    let raw = parsed.raw_bytes;
    if let Some(pos) = find_header_end(raw) {
        raw[pos..].to_vec()
    } else {
        Vec::new()
    }
}

/// Strip the trailing CRLF (or LF) that RFC 2046 5.1.1 attaches to the boundary
/// delimiter rather than the body content.
fn strip_trailing_crlf(mut data: Vec<u8>) -> Vec<u8> {
    if data.ends_with(b"\r\n") {
        data.truncate(data.len() - 2);
    } else if data.ends_with(b"\n") {
        data.truncate(data.len() - 1);
    }
    data
}

fn count_lines(data: &[u8]) -> usize {
    let text = String::from_utf8_lossy(data);
    text.lines().count()
}

/// Find the offset where the body starts (after the blank line separating headers from body).
fn find_header_end(raw: &[u8]) -> Option<usize> {
    // Look for \r\n\r\n first, then \n\n
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(pos + 4);
    }
    if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        return Some(pos + 2);
    }
    None
}

/// Extract the raw header bytes (including trailing blank line separator) from a ParsedMail node.
fn headers_bytes_of(parsed: &ParsedMail) -> Vec<u8> {
    let raw = parsed.raw_bytes;
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        raw[..pos + 4].to_vec()
    } else if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        raw[..pos + 2].to_vec()
    } else {
        raw.to_vec()
    }
}

/// Extract just the header block (without trailing blank line) from a ParsedMail node.
fn header_block_of(parsed: &ParsedMail) -> Vec<u8> {
    let raw = parsed.raw_bytes;
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        // Include the trailing \r\n of the last header line
        raw[..pos + 2].to_vec()
    } else if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        raw[..pos + 1].to_vec()
    } else {
        raw.to_vec()
    }
}

// -- Section spec parsing --

enum PartQualifier<'a> {
    Body,
    Mime,
    Header,
    Text,
    HeaderFields(&'a str),
}

fn parse_section_spec(section: &str) -> (Vec<usize>, PartQualifier<'_>) {
    let mut indices = Vec::new();
    let mut rest = section;

    loop {
        let num_end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if num_end == 0 {
            break;
        }
        if let Ok(n) = rest[..num_end].parse::<usize>() {
            indices.push(n);
            rest = &rest[num_end..];
            if rest.starts_with('.') {
                rest = &rest[1..];
            } else {
                break;
            }
        } else {
            break;
        }
    }

    let terminal = if rest.is_empty() {
        PartQualifier::Body
    } else {
        let upper = rest.to_uppercase();
        if upper == "MIME" {
            PartQualifier::Mime
        } else if upper == "HEADER" {
            PartQualifier::Header
        } else if upper == "TEXT" {
            PartQualifier::Text
        } else if upper.starts_with("HEADER.FIELDS") {
            PartQualifier::HeaderFields(rest)
        } else {
            PartQualifier::Body
        }
    };

    (indices, terminal)
}

/// Extract a specific MIME part from RFC822 data by part number.
///
/// Part specs: "1" = first part, "2" = second part, "2.1" = first sub-part of second part.
/// Qualifiers: "1.MIME" = MIME headers, "1.HEADER" = headers, "1.TEXT" = body text.
/// Returns None if the part doesn't exist.
pub fn extract_mime_part(data: &[u8], part_spec: &str) -> Option<Vec<u8>> {
    let (indices, qualifier) = parse_section_spec(part_spec);
    if indices.is_empty() {
        return None;
    }

    // Navigate to the target part using owned data (supports re-parsing for message/rfc822)
    let target_raw = navigate_to_raw_part(data, &indices)?;

    let target = mailparse::parse_mail(&target_raw).ok()?;

    match qualifier {
        PartQualifier::Body => {
            if target.ctype.mimetype.starts_with("message/") {
                Some(body_bytes_of(&target))
            } else {
                target.get_body_raw().ok().map(strip_trailing_crlf)
            }
        }
        PartQualifier::Mime => Some(header_block_of(&target)),
        PartQualifier::Header => Some(header_block_of(&target)),
        PartQualifier::Text => Some(body_bytes_of(&target)),
        PartQualifier::HeaderFields(spec) => {
            let fields = parse_header_field_names(spec);
            let hdrs = headers_bytes_of(&target);
            let hdr_text = String::from_utf8_lossy(&hdrs);
            let header_section = hdr_text
                .split("\r\n\r\n")
                .next()
                .or_else(|| hdr_text.split("\n\n").next())
                .unwrap_or(&hdr_text);
            Some(filter_headers_by_field_names(header_section, &fields).into_bytes())
        }
    }
}

/// Navigate the MIME tree to find the raw bytes of the target part.
///
/// Returns the raw bytes of the MIME part (including its headers) so the
/// caller can re-parse it. This owned approach naturally handles message/rfc822
/// by re-parsing the embedded message body at each step.
fn navigate_to_raw_part(data: &[u8], indices: &[usize]) -> Option<Vec<u8>> {
    let mut current = data.to_vec();

    for &idx in indices {
        if idx == 0 {
            return None;
        }

        let parsed = mailparse::parse_mail(&current).ok()?;

        if parsed.ctype.mimetype.starts_with("message/") {
            // message/rfc822: get the body (the embedded message), then parse it
            // and index into its parts
            let embedded_raw = body_bytes_of(&parsed);
            let embedded = mailparse::parse_mail(&embedded_raw).ok()?;

            if embedded.subparts.is_empty() {
                // Single-part embedded message: part 1 = the message itself
                if idx != 1 {
                    return None;
                }
                current = embedded.raw_bytes.to_vec();
            } else {
                // Multipart embedded message
                if idx > embedded.subparts.len() {
                    return None;
                }
                current = embedded.subparts[idx - 1].raw_bytes.to_vec();
            }
        } else if !parsed.subparts.is_empty() {
            // Multipart: index into subparts
            if idx > parsed.subparts.len() {
                return None;
            }
            current = parsed.subparts[idx - 1].raw_bytes.to_vec();
        } else {
            // Non-multipart: only part 1 is valid (the message itself)
            if idx != 1 {
                return None;
            }
            // current stays as-is
        }
    }

    Some(current)
}

fn parse_header_field_names(spec: &str) -> Vec<String> {
    // spec looks like "HEADER.FIELDS (From To Subject)" or "HEADER.FIELDS.NOT (Bcc)"
    if let Some(start) = spec.find('(') {
        if let Some(end) = spec.find(')') {
            return spec[start + 1..end]
                .split_whitespace()
                .map(|s| s.to_lowercase())
                .collect();
        }
    }
    Vec::new()
}

fn filter_headers_by_field_names(header_section: &str, fields: &[String]) -> String {
    let mut result = String::new();
    for line in header_section.split('\n') {
        let line = line.trim_end_matches('\r');
        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].trim().to_lowercase();
            if fields.iter().any(|f| f == &name) {
                result.push_str(line);
                result.push_str("\r\n");
            }
        }
    }
    result.push_str("\r\n");
    result
}

/// Build an IMAP ENVELOPE response string from metadata and parsed headers.
///
/// Format per RFC 3501 section 7.4.2:
/// ("date" "subject" ((from)) ((sender)) ((reply-to)) ((to)) ((cc)) (NIL) "in-reply-to" "message-id")
pub fn build_envelope(meta: &MessageEnvelope, header: &str) -> String {
    // Date: use the Date header if available, fall back to internal timestamp
    let date = extract_header(header, "Date").unwrap_or_else(|| format_imap_date(meta.time));
    let subject = imap_quote_nil(&meta.subject);
    let from = format_address_list(std::slice::from_ref(&meta.sender));

    // Sender: extract from header; RFC 3501 says NIL means same as From
    let sender = extract_header(header, "Sender")
        .and_then(|v| parse_header_address(&v))
        .map(|a| format_address_list(std::slice::from_ref(&a)))
        .unwrap_or_else(|| from.clone());

    // Reply-To: extract from header; RFC 2822 says defaults to From if absent
    let reply_to = if !meta.reply_tos.is_empty() {
        format_address_list(&meta.reply_tos)
    } else {
        extract_header(header, "Reply-To")
            .and_then(|v| parse_header_address(&v))
            .map(|a| format_address_list(std::slice::from_ref(&a)))
            .unwrap_or_else(|| from.clone())
    };

    let to = format_address_list(&meta.to_list);
    let cc = format_address_list(&meta.cc_list);
    let bcc = format_address_list(&meta.bcc_list);

    let in_reply_to = extract_header(header, "In-Reply-To")
        .map(|v| imap_quote(&v))
        .unwrap_or_else(|| "NIL".to_string());
    let message_id = extract_header(header, "Message-Id")
        .or_else(|| extract_header(header, "Message-ID"))
        .or_else(|| meta.external_id.clone())
        .map(|v| imap_quote(&v))
        .unwrap_or_else(|| "NIL".to_string());

    format!(
        "({} {} {} {} {} {} {} {} {} {})",
        imap_quote(&date),
        subject,
        from,
        sender,
        reply_to,
        to,
        cc,
        bcc,
        in_reply_to,
        message_id,
    )
}

/// Parse a simple address from a header value like "Name <user@domain>" or "user@domain".
fn parse_header_address(value: &str) -> Option<EmailAddress> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(addrs) = mailparse::addrparse(value) {
        match addrs.first()? {
            mailparse::MailAddr::Single(info) => Some(EmailAddress {
                name: info.display_name.clone().unwrap_or_default(),
                address: info.addr.clone(),
            }),
            mailparse::MailAddr::Group(info) => info.addrs.first().map(|a| EmailAddress {
                name: a.display_name.clone().unwrap_or_default(),
                address: a.addr.clone(),
            }),
        }
    } else if value.contains('@') {
        Some(EmailAddress {
            name: String::new(),
            address: value.to_string(),
        })
    } else {
        None
    }
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
                imap_quote_nil(&a.name),
                imap_quote(local),
                imap_quote(domain),
            )
        })
        .collect();
    format!("({})", parts.join(""))
}

fn imap_quote_nil(s: &str) -> String {
    if s.is_empty() {
        return "NIL".to_string();
    }
    imap_quote(s)
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
    // Use mailparse for proper folded-header handling (continuation lines).
    let header_bytes = if let Some(pos) = header.find("\r\n\r\n") {
        &header[..pos]
    } else if let Some(pos) = header.find("\n\n") {
        &header[..pos]
    } else {
        header
    };
    let headers = mailparse::parse_headers(header_bytes.as_bytes()).ok()?.0;
    headers.get_first_value(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imap_types::{EmailAddress, MessageEnvelope};

    #[test]
    fn test_build_envelope() {
        let meta = MessageEnvelope {
            id: "msg-1".to_string(),
            address_id: "addr-1".to_string(),
            label_ids: vec!["0".to_string()],
            external_id: None,
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
            reply_tos: vec![],
            flags: 0,
            time: 1700000000,
            size: 1024,
            unread: 0,
            is_replied: 0,
            is_replied_all: 0,
            is_forwarded: 0,
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
        let meta = MessageEnvelope {
            id: "msg-1".to_string(),
            address_id: "addr-1".to_string(),
            label_ids: vec!["0".to_string()],
            external_id: None,
            subject: "Test".to_string(),
            sender: EmailAddress {
                name: "Alice".to_string(),
                address: "alice@proton.me".to_string(),
            },
            to_list: vec![],
            cc_list: vec![],
            bcc_list: vec![],
            reply_tos: vec![],
            flags: 0,
            time: 1700000000,
            size: 1024,
            unread: 0,
            is_replied: 0,
            is_replied_all: 0,
            is_forwarded: 0,
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

    #[test]
    fn test_build_bodystructure_simple_text() {
        let msg = b"Content-Type: text/plain; charset=UTF-8\r\n\r\nHello World";
        let structure = build_bodystructure(msg);
        assert!(structure.contains("\"TEXT\""));
        assert!(structure.contains("\"plain\""));
        assert!(structure.contains("\"UTF-8\""));
    }

    #[test]
    fn test_build_bodystructure_html() {
        let msg = b"Content-Type: text/html; charset=UTF-8\r\n\r\n<html><body>Hello</body></html>";
        let structure = build_bodystructure(msg);
        assert!(structure.contains("\"TEXT\""));
        assert!(structure.contains("\"html\""));
    }

    #[test]
    fn test_build_bodystructure_multipart() {
        let msg = b"Content-Type: multipart/mixed; boundary=\"abc123\"\r\n\r\n--abc123\r\nContent-Type: text/plain\r\n\r\nHello\r\n--abc123\r\nContent-Type: application/pdf; name=\"doc.pdf\"\r\n\r\nPDFDATA\r\n--abc123--";
        let structure = build_bodystructure(msg);
        assert!(structure.contains("\"MIXED\""));
        assert!(structure.contains("\"abc123\""));
    }

    #[test]
    fn test_simple_text_structure() {
        let structure = simple_text_structure(1024);
        assert!(structure.contains("\"TEXT\""));
        assert!(structure.contains("\"PLAIN\""));
        assert!(structure.contains("1024"));
    }

    #[test]
    fn test_extract_mime_part_simple_multipart() {
        let msg = b"Content-Type: multipart/mixed; boundary=\"sep\"\r\n\r\n--sep\r\nContent-Type: text/plain\r\n\r\nHello world\r\n--sep\r\nContent-Type: text/html\r\n\r\n<p>Hello</p>\r\n--sep--\r\n";

        let part1 = extract_mime_part(msg, "1").unwrap();
        assert_eq!(String::from_utf8_lossy(&part1), "Hello world");

        let part2 = extract_mime_part(msg, "2").unwrap();
        assert_eq!(String::from_utf8_lossy(&part2), "<p>Hello</p>");

        assert!(extract_mime_part(msg, "3").is_none());
        assert!(extract_mime_part(msg, "0").is_none());
    }

    #[test]
    fn test_extract_mime_part_with_mime_qualifier() {
        let msg = b"Content-Type: multipart/mixed; boundary=\"sep\"\r\n\r\n--sep\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello\r\n--sep--\r\n";

        let mime = extract_mime_part(msg, "1.MIME").unwrap();
        let mime_str = String::from_utf8_lossy(&mime);
        assert!(mime_str.contains("Content-Type: text/plain"));
    }

    #[test]
    fn test_extract_mime_part_nonexistent() {
        let msg = b"Content-Type: text/plain\r\n\r\nSimple message";

        // For non-multipart, part 1 is the message itself
        let part1 = extract_mime_part(msg, "1");
        assert!(part1.is_some());

        // Part 2 doesn't exist
        assert!(extract_mime_part(msg, "2").is_none());
    }

    #[test]
    fn test_parsed_content_id() {
        let msg = b"Content-Type: text/plain\r\nContent-ID: <abc123@proton.me>\r\n\r\nbody";
        let parsed = mailparse::parse_mail(msg).unwrap();
        assert_eq!(parsed_content_id(&parsed), "\"<abc123@proton.me>\"");
    }

    #[test]
    fn test_parsed_content_id_missing() {
        let msg = b"Content-Type: text/plain\r\n\r\nbody";
        let parsed = mailparse::parse_mail(msg).unwrap();
        assert_eq!(parsed_content_id(&parsed), "NIL");
    }

    #[test]
    fn test_parsed_content_disposition_attachment() {
        let msg = b"Content-Type: text/plain\r\nContent-Disposition: attachment; filename=\"test.pdf\"\r\n\r\nbody";
        let parsed = mailparse::parse_mail(msg).unwrap();
        let disp = parsed_content_disposition(&parsed);
        assert!(disp.contains("\"ATTACHMENT\""), "disp={disp}");
        assert!(disp.contains("\"FILENAME\""), "disp={disp}");
        assert!(disp.contains("\"test.pdf\""), "disp={disp}");
    }

    #[test]
    fn test_parsed_content_disposition_inline() {
        let msg = b"Content-Type: text/plain\r\nContent-Disposition: inline\r\n\r\nbody";
        let parsed = mailparse::parse_mail(msg).unwrap();
        let disp = parsed_content_disposition(&parsed);
        assert!(disp.contains("\"INLINE\""), "disp={disp}");
    }

    #[test]
    fn test_parsed_content_disposition_missing() {
        let msg = b"Content-Type: text/plain\r\n\r\nbody";
        let parsed = mailparse::parse_mail(msg).unwrap();
        assert_eq!(parsed_content_disposition(&parsed), "NIL");
    }

    #[test]
    fn test_extract_mime_part_message_rfc822() {
        let inner = "From: inner@example.com\r\nSubject: Inner\r\nContent-Type: text/plain\r\n\r\nInner body";
        let msg = format!(
            "Content-Type: multipart/mixed; boundary=\"outer\"\r\n\r\n\
             --outer\r\n\
             Content-Type: message/rfc822\r\n\r\n\
             {}\r\n\
             --outer--\r\n",
            inner
        );

        // BODY[1] of a message/rfc822 part should return the embedded message body
        let part1 = extract_mime_part(msg.as_bytes(), "1").unwrap();
        let part1_str = String::from_utf8_lossy(&part1);
        assert!(
            part1_str.contains("From: inner@example.com"),
            "got: {part1_str}"
        );

        // BODY[1.1] should navigate into the embedded message's first part
        let part1_1 = extract_mime_part(msg.as_bytes(), "1.1").unwrap();
        let part1_1_str = String::from_utf8_lossy(&part1_1);
        assert_eq!(part1_1_str, "Inner body");
    }

    #[test]
    fn test_extract_mime_part_nested_multipart_in_rfc822() {
        let msg = "Content-Type: multipart/mixed; boundary=\"outer\"\r\n\r\n\
            --outer\r\n\
            Content-Type: message/rfc822\r\n\r\n\
            From: nested@example.com\r\n\
            Content-Type: multipart/alternative; boundary=\"inner\"\r\n\r\n\
            --inner\r\n\
            Content-Type: text/plain\r\n\r\n\
            Plain text\r\n\
            --inner\r\n\
            Content-Type: text/html\r\n\r\n\
            <p>HTML</p>\r\n\
            --inner--\r\n\
            --outer--\r\n";

        // 1.1 = first part of the embedded message's multipart/alternative
        let p = extract_mime_part(msg.as_bytes(), "1.1").unwrap();
        assert_eq!(String::from_utf8_lossy(&p), "Plain text");

        // 1.2 = second part
        let p = extract_mime_part(msg.as_bytes(), "1.2").unwrap();
        assert_eq!(String::from_utf8_lossy(&p), "<p>HTML</p>");
    }

    #[test]
    fn test_bodystructure_includes_content_id_and_disposition() {
        let msg = b"Content-Type: multipart/mixed; boundary=\"sep\"\r\n\r\n--sep\r\nContent-Type: image/png\r\nContent-ID: <img1@proton.me>\r\nContent-Disposition: inline\r\n\r\nPNGDATA\r\n--sep--";
        let bs = build_bodystructure(msg);
        assert!(bs.contains("\"<img1@proton.me>\""), "bs={bs}");
        assert!(bs.contains("\"INLINE\""), "bs={bs}");
    }
}
