use regex::Regex;

use crate::etag;
use crate::http::DavResponse;

#[derive(Debug, Clone)]
pub struct ReportItem {
    pub href: String,
    pub etag: Option<String>,
    pub data: Option<String>,
    pub content_type: &'static str,
    pub not_found: bool,
}

pub fn multistatus_report_response(items: &[ReportItem]) -> DavResponse {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:cal="urn:ietf:params:xml:ns:caldav">"#,
    );
    for item in items {
        xml.push_str("<d:response><d:href>");
        xml.push_str(&item.href);
        xml.push_str("</d:href>");
        if item.not_found {
            xml.push_str(
                "<d:propstat><d:prop/><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>",
            );
        } else {
            xml.push_str("<d:propstat><d:prop>");
            if let Some(etag) = &item.etag {
                xml.push_str("<d:getetag>");
                xml.push_str(etag);
                xml.push_str("</d:getetag>");
            }
            if let Some(data) = &item.data {
                if item.content_type.contains("calendar") {
                    xml.push_str("<cal:calendar-data>");
                } else {
                    xml.push_str("<card:address-data>");
                }
                xml.push_str(&crate::xml::escape_xml(data));
                if item.content_type.contains("calendar") {
                    xml.push_str("</cal:calendar-data>");
                } else {
                    xml.push_str("</card:address-data>");
                }
            }
            xml.push_str("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>");
        }
        xml.push_str("</d:response>");
    }
    xml.push_str("</d:multistatus>");
    DavResponse {
        status: "207 Multi-Status",
        headers: vec![("Content-Type", "application/xml; charset=utf-8".to_string())],
        body: xml.into_bytes(),
    }
}

pub fn sync_collection_response(items: &[ReportItem], sync_token: &str) -> DavResponse {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:cal="urn:ietf:params:xml:ns:caldav">"#,
    );
    for item in items {
        xml.push_str("<d:response><d:href>");
        xml.push_str(&item.href);
        xml.push_str("</d:href>");
        if item.not_found {
            xml.push_str("<d:status>HTTP/1.1 404 Not Found</d:status>");
        } else {
            xml.push_str("<d:propstat><d:prop>");
            if let Some(ref tag) = item.etag {
                xml.push_str("<d:getetag>");
                xml.push_str(tag);
                xml.push_str("</d:getetag>");
            }
            if let Some(ref data) = item.data {
                if item.content_type.contains("calendar") {
                    xml.push_str("<cal:calendar-data>");
                } else {
                    xml.push_str("<card:address-data>");
                }
                xml.push_str(&crate::xml::escape_xml(data));
                if item.content_type.contains("calendar") {
                    xml.push_str("</cal:calendar-data>");
                } else {
                    xml.push_str("</card:address-data>");
                }
            }
            xml.push_str("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>");
        }
        xml.push_str("</d:response>");
    }
    xml.push_str("<d:sync-token>");
    xml.push_str(sync_token);
    xml.push_str("</d:sync-token>");
    xml.push_str("</d:multistatus>");
    DavResponse {
        status: "207 Multi-Status",
        headers: vec![("Content-Type", "application/xml; charset=utf-8".to_string())],
        body: xml.into_bytes(),
    }
}

pub fn invalid_report_payload_response(reason: &str, path: &str, body_text: &str) -> DavResponse {
    tracing::warn!(
        reason,
        path,
        body_len = body_text.len(),
        "invalid REPORT payload"
    );
    DavResponse {
        status: "400 Bad Request",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: format!("invalid REPORT payload: {reason}\n").into_bytes(),
    }
}

pub fn not_implemented_report() -> DavResponse {
    DavResponse {
        status: "501 Not Implemented",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"report not supported\n".to_vec(),
    }
}

pub fn make_contact_report_item(
    account_id: &str,
    contact_id: &str,
    updated_at_ms: i64,
    vcard_data: Option<String>,
) -> ReportItem {
    ReportItem {
        href: format!("/dav/{account_id}/addressbooks/default/{contact_id}.vcf"),
        etag: Some(etag::from_updated_ms(contact_id, updated_at_ms)),
        data: vcard_data,
        content_type: "text/vcard; charset=utf-8",
        not_found: false,
    }
}

pub fn make_calendar_event_report_item(
    account_id: &str,
    calendar_id: &str,
    event_id: &str,
    updated_at_ms: i64,
    ics_data: Option<String>,
) -> ReportItem {
    ReportItem {
        href: format!("/dav/{account_id}/calendars/{calendar_id}/{event_id}.ics"),
        etag: Some(etag::from_updated_ms(event_id, updated_at_ms)),
        data: ics_data,
        content_type: "text/calendar; charset=utf-8",
        not_found: false,
    }
}

pub fn extract_xml_element<'a>(xml: &'a str, tag_name: &str) -> Option<&'a str> {
    let open_pattern = format!("<{tag_name}");
    let open_start = xml.find(&open_pattern)?;
    let after_tag = &xml[open_start + open_pattern.len()..];
    let content_start = after_tag.find('>')? + 1;
    let content = &after_tag[content_start..];
    let close_pattern = format!("</{tag_name}");
    let close_pos = content.find(&close_pattern)?;
    Some(&content[..close_pos])
}

pub fn extract_xml_start_tags(xml: &str, parent_tag: &str) -> Vec<String> {
    let open_pattern = format!("<{parent_tag}");
    let close_pattern = format!("</{parent_tag}");
    let Some(open_start) = xml.find(&open_pattern) else {
        return Vec::new();
    };
    let after_tag = &xml[open_start + open_pattern.len()..];
    let Some(content_start) = after_tag.find('>') else {
        return Vec::new();
    };
    let content = &after_tag[content_start + 1..];
    let Some(close_pos) = content.find(&close_pattern) else {
        return Vec::new();
    };
    let inner = &content[..close_pos];
    let tag_re = Regex::new(r"<([A-Za-z0-9_:-]+)").expect("tag regex should compile");
    tag_re
        .captures_iter(inner)
        .filter_map(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
        .collect()
}

pub fn extract_xml_attribute(tag: &str, name: &str) -> Option<String> {
    let pattern = format!(
        r#"(?is)\b{name}\s*=\s*(?:\"(?P<double>[^"]*)\"|'(?P<single>[^']*)')"#,
        name = regex::escape(name)
    );
    let re = Regex::new(&pattern).ok()?;
    re.captures(tag)
        .and_then(|caps| caps.name("double").or_else(|| caps.name("single")))
        .map(|value| value.as_str().to_string())
}

pub fn extract_sync_token(body: &str) -> Option<String> {
    extract_xml_element(body, "sync-token")
        .or_else(|| extract_xml_element(body, "d:sync-token"))
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

pub fn has_named_xml_tag(xml: &str, tag_local_name: &str) -> bool {
    xml.contains(tag_local_name)
}

pub fn is_xml_like(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with('<') && trimmed.contains('>')
}

pub fn parse_ics_timestamp(value: &str) -> Option<i64> {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() < 8 {
        return None;
    }
    let year: i64 = digits[0..4].parse().ok()?;
    let month: i64 = digits[4..6].parse().ok()?;
    let day: i64 = digits[6..8].parse().ok()?;
    let (hour, minute, second) = if digits.len() >= 14 {
        (
            digits[8..10].parse::<i64>().ok()?,
            digits[10..12].parse::<i64>().ok()?,
            digits[12..14].parse::<i64>().ok()?,
        )
    } else {
        (0, 0, 0)
    };

    fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
        let y = if m <= 2 { y - 1 } else { y };
        let era = y.div_euclid(400);
        let yoe = y.rem_euclid(400);
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146097 + doe - 719468
    }
    let days = days_from_civil(year, month, day);
    Some(days * 86400 + hour * 3600 + minute * 60 + second)
}

pub fn parse_ics_date(value: &str) -> Option<i64> {
    parse_ics_timestamp(value)
}

pub fn parse_calendar_collection_path<'a>(path: &'a str, account_id: &str) -> Option<&'a str> {
    let prefix = format!("/dav/{account_id}/calendars/");
    let rest = path.strip_prefix(&prefix)?;
    let trimmed = rest.trim_end_matches('/');
    if trimmed.is_empty() || trimmed.contains('/') {
        return None;
    }
    Some(trimmed)
}
