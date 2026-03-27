use crate::imap_types::{EmailAddress, MessageEnvelope};

/// Build an IMAP BODYSTRUCTURE response from RFC822 data.
///
/// Format per RFC 3501 section 7.4.2:
/// Non-multipart: (type subtype (params) id desc encoding size [lines] [md5] [disposition] [language] [location])
/// Multipart: ((part1)(part2)... "subtype" (params) [disposition] [language] [location])
pub fn build_body(data: &[u8]) -> String {
    let text = String::from_utf8_lossy(data);
    let (header_section, body_section) = split_header_body(&text);
    let content_type = extract_content_type(&header_section);

    match &content_type {
        ContentType::Multipart { subtype, boundary } => {
            let parts = parse_multipart_parts(&body_section, boundary);
            let part_bodies: Vec<String> = parts.iter().map(|p| build_part_body(p)).collect();

            if part_bodies.is_empty() {
                simple_text_body(data.len())
            } else {
                format!("({} \"{}\")", part_bodies.join(""), subtype.to_uppercase())
            }
        }
        ContentType::Simple {
            type_main,
            subtype,
            charset,
        } => {
            let encoding = extract_content_transfer_encoding(&header_section);
            let body_size = body_section.len();
            let body_lines = body_section.lines().count();

            format!(
                "(\"{}\" \"{}\" (\"CHARSET\" \"{}\") NIL NIL \"{}\" {} {})",
                type_main.to_uppercase(),
                subtype,
                charset,
                encoding.to_uppercase(),
                body_size,
                body_lines
            )
        }
    }
}

pub fn build_bodystructure(data: &[u8]) -> String {
    let text = String::from_utf8_lossy(data);
    let (header_section, body_section) = split_header_body(&text);

    // Parse Content-Type header
    let content_type = extract_content_type(&header_section);

    match &content_type {
        ContentType::Multipart { subtype, boundary } => {
            // Parse multipart parts
            let parts = parse_multipart_parts(&body_section, boundary);
            let part_structures: Vec<String> =
                parts.iter().map(|p| build_part_structure(p)).collect();

            if part_structures.is_empty() {
                // Fallback to simple text if no parts found
                simple_text_structure(data.len())
            } else {
                format!(
                    "({} \"{}\" (\"BOUNDARY\" \"{}\") NIL NIL)",
                    part_structures.join(""),
                    subtype.to_uppercase(),
                    boundary
                )
            }
        }
        ContentType::Simple {
            type_main,
            subtype,
            charset,
        } => {
            let encoding = extract_content_transfer_encoding(&header_section);
            let content_id = extract_content_id(&header_section);
            let disposition = extract_content_disposition(&header_section);
            let body_size = body_section.len();
            let body_lines = body_section.lines().count();

            // RFC 3501 Section 7.4.2 BODYSTRUCTURE field order for text:
            // type subtype params id desc enc octets lines md5 dsp lang loc
            format!(
                "(\"{}\" \"{}\" (\"CHARSET\" \"{}\") {} NIL \"{}\" {} {} NIL {} NIL NIL)",
                type_main.to_uppercase(),
                subtype,
                charset,
                content_id,
                encoding.to_uppercase(),
                body_size,
                body_lines,
                disposition
            )
        }
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

#[derive(Debug)]
enum ContentType {
    Simple {
        type_main: String,
        subtype: String,
        charset: String,
    },
    Multipart {
        subtype: String,
        boundary: String,
    },
}

fn extract_content_type(header: &str) -> ContentType {
    let ct_line = header
        .lines()
        .find(|line| line.to_lowercase().starts_with("content-type:"))
        .unwrap_or("Content-Type: text/plain; charset=UTF-8");

    let value = ct_line
        .split_once(':')
        .map(|(_, v)| v.trim())
        .unwrap_or("text/plain");

    // Handle multipart
    if value.to_lowercase().starts_with("multipart/") {
        let subtype = value
            .split('/')
            .nth(1)
            .and_then(|s| s.split(';').next())
            .unwrap_or("mixed")
            .trim()
            .to_string();

        let boundary = extract_param(value, "boundary").unwrap_or_default();

        return ContentType::Multipart { subtype, boundary };
    }

    // Parse type/subtype
    let (type_main, subtype) = value
        .split(';')
        .next()
        .and_then(|s| s.split_once('/'))
        .map(|(t, s)| (t.trim().to_string(), s.trim().to_string()))
        .unwrap_or_else(|| ("text".to_string(), "plain".to_string()));

    let charset = extract_param(value, "charset").unwrap_or_else(|| "UTF-8".to_string());

    ContentType::Simple {
        type_main,
        subtype,
        charset,
    }
}

fn extract_param(value: &str, param_name: &str) -> Option<String> {
    let search = format!("{}=", param_name.to_lowercase());
    for part in value.split(';') {
        let part = part.trim();
        if part.to_lowercase().starts_with(&search) {
            let val = &part[search.len()..];
            // Remove surrounding quotes
            let val = val.trim_matches('"').trim_matches('\'');
            return Some(val.to_string());
        }
    }
    None
}

fn extract_content_id(header: &str) -> String {
    extract_header(header, "Content-ID")
        .or_else(|| extract_header(header, "Content-Id"))
        .map(|v| imap_quote(&v))
        .unwrap_or_else(|| "NIL".to_string())
}

fn extract_content_disposition(header: &str) -> String {
    let raw = extract_header(header, "Content-Disposition");
    let raw = match raw {
        Some(v) => v,
        None => return "NIL".to_string(),
    };

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

fn extract_content_transfer_encoding(header: &str) -> String {
    header
        .lines()
        .find(|line| {
            line.to_lowercase()
                .starts_with("content-transfer-encoding:")
        })
        .and_then(|line| line.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_else(|| "7BIT".to_string())
}

fn split_header_body(text: &str) -> (String, String) {
    if let Some(pos) = text.find("\r\n\r\n") {
        (text[..pos].to_string(), text[pos + 4..].to_string())
    } else if let Some(pos) = text.find("\n\n") {
        (text[..pos].to_string(), text[pos + 2..].to_string())
    } else {
        (text.to_string(), String::new())
    }
}

fn parse_multipart_parts(body: &str, boundary: &str) -> Vec<String> {
    let delimiter = format!("--{}", boundary);
    let mut parts = Vec::new();

    for section in body.split(&delimiter) {
        // Strip the leading CRLF/LF that follows the boundary line.
        let section = section
            .strip_prefix("\r\n")
            .unwrap_or(section.strip_prefix('\n').unwrap_or(section));
        if section.is_empty() {
            continue;
        }
        // End delimiter: after splitting by `--boundary`, the closing `--boundary--`
        // produces a section starting with "--". This is the epilogue marker; stop here.
        if section.starts_with("--") {
            break;
        }
        // Per RFC 2046 section 5.1.1, the CRLF immediately preceding a boundary
        // delimiter belongs to the boundary, not the preceding body part.
        let section = section
            .strip_suffix("\r\n")
            .unwrap_or(section.strip_suffix('\n').unwrap_or(section));
        parts.push(section.to_string());
    }

    parts
}

fn build_part_structure(part: &str) -> String {
    let (header, body) = split_header_body(part);
    let content_type = extract_content_type(&header);

    match content_type {
        ContentType::Simple {
            type_main,
            subtype,
            charset,
        } => {
            let encoding = extract_content_transfer_encoding(&header);
            let content_id = extract_content_id(&header);
            let disposition = extract_content_disposition(&header);
            let body_size = body.len();
            let lines = body.lines().count();

            format!(
                "(\"{}\" \"{}\" (\"CHARSET\" \"{}\") {} NIL \"{}\" {} {} NIL {} NIL NIL)",
                type_main.to_uppercase(),
                subtype,
                charset,
                content_id,
                encoding.to_uppercase(),
                body_size,
                lines,
                disposition
            )
        }
        ContentType::Multipart { subtype, boundary } => {
            // Nested multipart
            let parts = parse_multipart_parts(&body, &boundary);
            let part_structures: Vec<String> =
                parts.iter().map(|p| build_part_structure(p)).collect();

            format!(
                "({} \"{}\" (\"BOUNDARY\" \"{}\") NIL NIL)",
                part_structures.join(""),
                subtype.to_uppercase(),
                boundary
            )
        }
    }
}

fn build_part_body(part: &str) -> String {
    let (header, body) = split_header_body(part);
    let content_type = extract_content_type(&header);

    match content_type {
        ContentType::Simple {
            type_main,
            subtype,
            charset,
        } => {
            let encoding = extract_content_transfer_encoding(&header);
            let body_size = body.len();
            let lines = body.lines().count();

            format!(
                "(\"{}\" \"{}\" (\"CHARSET\" \"{}\") NIL NIL \"{}\" {} {})",
                type_main.to_uppercase(),
                subtype,
                charset,
                encoding.to_uppercase(),
                body_size,
                lines
            )
        }
        ContentType::Multipart { subtype, boundary } => {
            let parts = parse_multipart_parts(&body, &boundary);
            let part_bodies: Vec<String> = parts.iter().map(|p| build_part_body(p)).collect();
            format!("({} \"{}\")", part_bodies.join(""), subtype.to_uppercase())
        }
    }
}

/// Extract a specific MIME part from RFC822 data by part number.
///
/// Part specs: "1" = first part, "2" = second part, "2.1" = first sub-part of second part.
/// Returns None if the part doesn't exist.
pub fn extract_mime_part(data: &[u8], part_spec: &str) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(data);

    // Parse the part spec suffix for MIME/HEADER/TEXT qualifiers
    let (numbers, qualifier) = parse_part_spec(part_spec);
    if numbers.is_empty() {
        return None;
    }

    let part_text = navigate_to_part(&text, &numbers)?;

    match qualifier {
        PartQualifier::Body => {
            let (_, body) = split_header_body(&part_text);
            Some(body.into_bytes())
        }
        PartQualifier::Mime => {
            let (header, _) = split_header_body(&part_text);
            Some(format!("{}\r\n", header).into_bytes())
        }
        PartQualifier::Header => {
            let (header, _) = split_header_body(&part_text);
            Some(format!("{}\r\n", header).into_bytes())
        }
        PartQualifier::Text => {
            let (_, body) = split_header_body(&part_text);
            Some(body.into_bytes())
        }
    }
}

enum PartQualifier {
    Body,
    Mime,
    Header,
    Text,
}

fn parse_part_spec(spec: &str) -> (Vec<usize>, PartQualifier) {
    let upper = spec.to_uppercase();

    // Check for trailing qualifiers like "1.MIME", "1.2.HEADER", "1.TEXT"
    if let Some(pos) = upper.rfind(".MIME") {
        if pos > 0 && upper[pos..] == *".MIME" {
            let nums = parse_part_numbers(&spec[..pos]);
            return (nums, PartQualifier::Mime);
        }
    }
    if let Some(pos) = upper.rfind(".HEADER") {
        if pos > 0 && upper[pos..] == *".HEADER" {
            let nums = parse_part_numbers(&spec[..pos]);
            return (nums, PartQualifier::Header);
        }
    }
    if let Some(pos) = upper.rfind(".TEXT") {
        if pos > 0 && upper[pos..] == *".TEXT" {
            let nums = parse_part_numbers(&spec[..pos]);
            return (nums, PartQualifier::Text);
        }
    }

    let nums = parse_part_numbers(spec);
    (nums, PartQualifier::Body)
}

fn parse_part_numbers(s: &str) -> Vec<usize> {
    s.split('.')
        .filter_map(|p| p.parse::<usize>().ok())
        .collect()
}

fn navigate_to_part(text: &str, numbers: &[usize]) -> Option<String> {
    if numbers.is_empty() {
        return None;
    }

    let mut current = text.to_string();

    for &num in numbers {
        if num == 0 {
            return None;
        }

        let (header, body) = split_header_body(&current);
        let content_type = extract_content_type(&header);

        match content_type {
            ContentType::Multipart { boundary, .. } => {
                let parts = parse_multipart_parts(&body, &boundary);
                if num > parts.len() {
                    return None;
                }
                current = parts[num - 1].clone();
            }
            ContentType::Simple { .. } => {
                // For non-multipart, only part 1 is valid (the message itself)
                if num != 1 {
                    return None;
                }
                // current stays as-is
            }
        }
    }

    Some(current)
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
    if let Some(lt) = value.find('<') {
        let name = value[..lt].trim().trim_matches('"').to_string();
        let addr = value[lt + 1..].trim_end_matches('>').trim().to_string();
        Some(EmailAddress {
            name,
            address: addr,
        })
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
    fn test_extract_content_type_simple() {
        let header = "Content-Type: text/html; charset=iso-8859-1";
        let ct = extract_content_type(header);
        match ct {
            ContentType::Simple {
                type_main,
                subtype,
                charset,
            } => {
                assert_eq!(type_main, "text");
                assert_eq!(subtype, "html");
                assert_eq!(charset, "iso-8859-1");
            }
            _ => panic!("expected Simple"),
        }
    }

    #[test]
    fn test_extract_content_type_multipart() {
        let header = "Content-Type: multipart/alternative; boundary=\"boundary123\"";
        let ct = extract_content_type(header);
        match ct {
            ContentType::Multipart { subtype, boundary } => {
                assert_eq!(subtype, "alternative");
                assert_eq!(boundary, "boundary123");
            }
            _ => panic!("expected Multipart"),
        }
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
    fn test_extract_content_id() {
        let header = "Content-ID: <abc123@proton.me>";
        assert_eq!(extract_content_id(header), "\"<abc123@proton.me>\"");
    }

    #[test]
    fn test_extract_content_id_missing() {
        let header = "Content-Type: text/plain";
        assert_eq!(extract_content_id(header), "NIL");
    }

    #[test]
    fn test_extract_content_disposition_attachment() {
        let header = "Content-Disposition: attachment; filename=\"test.pdf\"";
        let disp = extract_content_disposition(header);
        assert!(disp.contains("\"ATTACHMENT\""), "disp={disp}");
        assert!(disp.contains("\"FILENAME\""), "disp={disp}");
        assert!(disp.contains("\"test.pdf\""), "disp={disp}");
    }

    #[test]
    fn test_extract_content_disposition_inline() {
        let header = "Content-Disposition: inline";
        let disp = extract_content_disposition(header);
        assert!(disp.contains("\"INLINE\""), "disp={disp}");
    }

    #[test]
    fn test_extract_content_disposition_missing() {
        let header = "Content-Type: text/plain";
        assert_eq!(extract_content_disposition(header), "NIL");
    }

    #[test]
    fn test_bodystructure_includes_content_id_and_disposition() {
        let msg = b"Content-Type: multipart/mixed; boundary=\"sep\"\r\n\r\n--sep\r\nContent-Type: image/png\r\nContent-ID: <img1@proton.me>\r\nContent-Disposition: inline\r\n\r\nPNGDATA\r\n--sep--";
        let bs = build_bodystructure(msg);
        assert!(bs.contains("\"<img1@proton.me>\""), "bs={bs}");
        assert!(bs.contains("\"INLINE\""), "bs={bs}");
    }
}
