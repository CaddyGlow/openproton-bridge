use std::sync::Arc;

use regex::Regex;

use crate::bridge::auth_router::AuthRoute;
use crate::pim::dav::{
    CalDavRepository, CardDavRepository, DavSyncStateRepository, StoreBackedDavAdapter,
};
use crate::pim::query::{CalendarEventRange, QueryPage};
use crate::pim::store::PimStore;

use super::discovery;
use super::error::{DavError, Result};
use super::etag;
use super::http::DavResponse;

pub fn handle_report(
    raw_path: &str,
    body: &[u8],
    auth: &AuthRoute,
    store: &Arc<PimStore>,
) -> Result<Option<DavResponse>> {
    let path = normalize_path(raw_path);
    let body_text = std::str::from_utf8(body)
        .map_err(|_| DavError::InvalidRequest("REPORT body is not utf-8"))?;
    let adapter = StoreBackedDavAdapter::new(store.clone());

    let card_collection = discovery::default_addressbook_path(&auth.account_id.0);

    if path == card_collection {
        if body_text.contains("addressbook-query") {
            return Ok(Some(addressbook_query(&adapter, &auth.account_id.0)?));
        }
        if body_text.contains("sync-collection") {
            return Ok(Some(carddav_sync_collection(
                &adapter,
                &auth.account_id.0,
                body_text,
            )?));
        }
        return Ok(Some(not_implemented_report()));
    }

    if let Some(calendar_id) = parse_calendar_collection_path(&path, &auth.account_id.0) {
        if body_text.contains("calendar-query") {
            return Ok(Some(calendar_query(
                &adapter,
                store,
                &auth.account_id.0,
                &calendar_id,
                body_text,
            )?));
        }
        if body_text.contains("calendar-multiget") {
            return Ok(Some(calendar_multiget(
                &adapter,
                store,
                &auth.account_id.0,
                &calendar_id,
                body_text,
            )?));
        }
        if body_text.contains("sync-collection") {
            return Ok(Some(caldav_sync_collection(
                &adapter,
                store,
                &auth.account_id.0,
                &calendar_id,
                body_text,
            )?));
        }
        return Ok(Some(not_implemented_report()));
    }

    Ok(None)
}

fn addressbook_query(adapter: &StoreBackedDavAdapter, account_id: &str) -> Result<DavResponse> {
    let contacts = adapter
        .list_contacts(
            false,
            QueryPage {
                limit: 500,
                offset: 0,
            },
        )
        .map_err(|err| DavError::Backend(err.to_string()))?;
    let items = contacts
        .iter()
        .map(|contact| ReportItem {
            href: format!("/dav/{account_id}/addressbooks/default/{}.vcf", contact.id),
            etag: etag::from_updated_ms(&contact.id, contact.updated_at_ms),
            calendar_data: None,
            not_found: false,
        })
        .collect::<Vec<_>>();
    tracing::debug!(
        report = "addressbook-query",
        account_id,
        item_count = items.len(),
        "dav report assembled"
    );
    Ok(multistatus_response(&items, None))
}

fn calendar_query(
    adapter: &StoreBackedDavAdapter,
    store: &Arc<PimStore>,
    account_id: &str,
    calendar_id: &str,
    body: &str,
) -> Result<DavResponse> {
    let range = parse_calendar_time_range(body);
    let events = adapter
        .list_calendar_events(
            calendar_id,
            false,
            range,
            QueryPage {
                limit: 500,
                offset: 0,
            },
        )
        .map_err(|err| DavError::Backend(err.to_string()))?;
    let items = events
        .iter()
        .map(|event| ReportItem {
            href: format!("/dav/{account_id}/calendars/{calendar_id}/{}.ics", event.id),
            etag: etag::from_updated_ms(&event.id, event.updated_at_ms),
            calendar_data: load_calendar_data(store, &event.id, false),
            not_found: false,
        })
        .collect::<Vec<_>>();
    let item_count = items.len();
    let payload_count = items
        .iter()
        .filter(|item| item.calendar_data.is_some())
        .count();
    tracing::debug!(
        report = "calendar-query",
        account_id,
        calendar_id,
        item_count,
        payload_count,
        "dav report assembled"
    );
    Ok(multistatus_response(&items, None))
}

fn calendar_multiget(
    adapter: &StoreBackedDavAdapter,
    store: &Arc<PimStore>,
    account_id: &str,
    calendar_id: &str,
    body: &str,
) -> Result<DavResponse> {
    let hrefs = extract_report_hrefs(body);
    let mut items = Vec::with_capacity(hrefs.len());
    for href in hrefs {
        let Some(event_id) = parse_event_id_from_href(&href, account_id, calendar_id) else {
            continue;
        };
        let event = adapter
            .get_calendar_event(&event_id, false)
            .map_err(|err| DavError::Backend(err.to_string()))?;
        let Some(event) = event else {
            items.push(ReportItem {
                href,
                etag: String::new(),
                calendar_data: None,
                not_found: true,
            });
            continue;
        };
        items.push(ReportItem {
            href,
            etag: etag::from_updated_ms(&event.id, event.updated_at_ms),
            calendar_data: load_calendar_data(store, &event.id, false),
            not_found: false,
        });
    }
    let item_count = items.len();
    let payload_count = items
        .iter()
        .filter(|item| item.calendar_data.is_some())
        .count();
    let not_found_count = items.iter().filter(|item| item.not_found).count();
    tracing::debug!(
        report = "calendar-multiget",
        account_id,
        calendar_id,
        item_count,
        payload_count,
        not_found_count,
        "dav report assembled"
    );
    Ok(multistatus_response(&items, None))
}

fn carddav_sync_collection(
    adapter: &StoreBackedDavAdapter,
    account_id: &str,
    body: &str,
) -> Result<DavResponse> {
    let contacts = adapter
        .list_contacts(
            true,
            QueryPage {
                limit: 500,
                offset: 0,
            },
        )
        .map_err(|err| DavError::Backend(err.to_string()))?;
    let since = extract_sync_token(body).and_then(|token| token.parse::<i64>().ok());
    let current_token = contacts
        .iter()
        .map(|item| item.updated_at_ms)
        .max()
        .unwrap_or_else(epoch_millis);
    adapter
        .set_sync_state_int(&sync_scope("carddav", account_id), current_token)
        .map_err(|err| DavError::Backend(err.to_string()))?;
    let items = contacts
        .iter()
        .filter(|contact| since.is_none_or(|token| contact.updated_at_ms > token))
        .map(|contact| ReportItem {
            href: format!("/dav/{account_id}/addressbooks/default/{}.vcf", contact.id),
            etag: etag::from_updated_ms(&contact.id, contact.updated_at_ms),
            calendar_data: None,
            not_found: false,
        })
        .collect::<Vec<_>>();
    tracing::debug!(
        report = "sync-collection",
        protocol = "carddav",
        account_id,
        item_count = items.len(),
        sync_token = current_token,
        "dav report assembled"
    );
    Ok(multistatus_response(
        &items,
        Some(current_token.to_string()),
    ))
}

fn caldav_sync_collection(
    adapter: &StoreBackedDavAdapter,
    store: &Arc<PimStore>,
    account_id: &str,
    calendar_id: &str,
    body: &str,
) -> Result<DavResponse> {
    let events = adapter
        .list_calendar_events(
            calendar_id,
            true,
            CalendarEventRange::default(),
            QueryPage {
                limit: 500,
                offset: 0,
            },
        )
        .map_err(|err| DavError::Backend(err.to_string()))?;
    let since = extract_sync_token(body).and_then(|token| token.parse::<i64>().ok());
    let current_token = events
        .iter()
        .map(|item| item.updated_at_ms)
        .max()
        .unwrap_or_default();
    adapter
        .set_sync_state_int(&caldav_sync_scope(account_id, calendar_id), current_token)
        .map_err(|err| DavError::Backend(err.to_string()))?;
    let items = events
        .iter()
        .filter(|event| since.is_none_or(|token| event.updated_at_ms > token))
        .map(|event| ReportItem {
            href: format!("/dav/{account_id}/calendars/{calendar_id}/{}.ics", event.id),
            etag: if event.deleted {
                String::new()
            } else {
                etag::from_updated_ms(&event.id, event.updated_at_ms)
            },
            calendar_data: if event.deleted {
                None
            } else {
                load_calendar_data(store, &event.id, true)
            },
            not_found: event.deleted,
        })
        .collect::<Vec<_>>();
    let item_count = items.len();
    let payload_count = items
        .iter()
        .filter(|item| item.calendar_data.is_some())
        .count();
    let tombstone_count = items.iter().filter(|item| item.not_found).count();
    tracing::debug!(
        report = "sync-collection",
        protocol = "caldav",
        account_id,
        calendar_id,
        item_count,
        payload_count,
        tombstone_count,
        sync_token = current_token,
        "dav report assembled"
    );
    Ok(multistatus_response(
        &items,
        Some(sync_token_uri(account_id, calendar_id, current_token)),
    ))
}

fn parse_calendar_time_range(body: &str) -> CalendarEventRange {
    let start = extract_attr(body, "start").and_then(parse_ics_datetime);
    let end = extract_attr(body, "end").and_then(parse_ics_datetime);
    CalendarEventRange {
        start_time_from: start,
        start_time_to: end,
    }
}

fn extract_attr(body: &str, name: &str) -> Option<String> {
    let needle = format!(r#"{name}=""#);
    let (_, rest) = body.split_once(&needle)?;
    let (value, _) = rest.split_once('"')?;
    Some(value.to_string())
}

fn extract_sync_token(body: &str) -> Option<String> {
    let (_, rest) = body.split_once("<d:sync-token>")?;
    let (token, _) = rest.split_once("</d:sync-token>")?;
    Some(token.trim().to_string())
}

fn parse_ics_datetime(value: String) -> Option<i64> {
    let value = value.trim();
    if value.len() >= 15 && value.contains('T') {
        let cleaned = value.trim_end_matches('Z');
        let year = cleaned.get(0..4)?.parse::<i32>().ok()?;
        let month = cleaned.get(4..6)?.parse::<u32>().ok()?;
        let day = cleaned.get(6..8)?.parse::<u32>().ok()?;
        let hour = cleaned.get(9..11)?.parse::<u32>().ok()?;
        let minute = cleaned.get(11..13)?.parse::<u32>().ok()?;
        let second = cleaned.get(13..15)?.parse::<u32>().ok()?;
        return to_unix_utc(year, month, day, hour, minute, second);
    }
    None
}

fn to_unix_utc(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 || day > 31 || hour > 23 || minute > 59 || second > 59
    {
        return None;
    }
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    for m in 1..month {
        days += days_in_month(year, m) as i64;
    }
    days += (day - 1) as i64;
    Some(days * 86_400 + (hour as i64) * 3_600 + (minute as i64) * 60 + second as i64)
}

fn is_leap(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(year) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

#[derive(Debug, Clone)]
struct ReportItem {
    href: String,
    etag: String,
    calendar_data: Option<String>,
    not_found: bool,
}

fn multistatus_response(items: &[ReportItem], sync_token: Option<String>) -> DavResponse {
    let mut body = String::from(
        r#"<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">"#,
    );
    for item in items {
        body.push_str("<d:response><d:href>");
        body.push_str(&escape_xml(&item.href));
        if item.not_found {
            body.push_str("</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response>");
            continue;
        }
        body.push_str("</d:href><d:propstat><d:prop><d:getetag>");
        body.push_str(&escape_xml(&item.etag));
        body.push_str("</d:getetag>");
        if let Some(calendar_data) = &item.calendar_data {
            body.push_str("<cal:calendar-data>");
            body.push_str(&escape_xml(calendar_data));
            body.push_str("</cal:calendar-data>");
        }
        body.push_str("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>");
    }
    if let Some(token) = sync_token {
        body.push_str("<d:sync-token>");
        body.push_str(&escape_xml(&token));
        body.push_str("</d:sync-token>");
    }
    body.push_str("</d:multistatus>");

    DavResponse {
        status: "207 Multi-Status",
        headers: vec![("Content-Type", "application/xml; charset=utf-8".to_string())],
        body: body.into_bytes(),
    }
}

fn sync_scope(protocol: &str, account_id: &str) -> String {
    format!("dav:{protocol}:{account_id}:sync-token")
}

fn caldav_sync_scope(account_id: &str, calendar_id: &str) -> String {
    format!("dav:caldav:{account_id}:{calendar_id}:sync-token")
}

fn sync_token_uri(account_id: &str, calendar_id: &str, version: i64) -> String {
    format!(
        "https://openproton.local/dav/{account_id}/calendars/{calendar_id}/sync/{}",
        version.max(0)
    )
}

fn load_calendar_data(store: &PimStore, event_id: &str, include_deleted: bool) -> Option<String> {
    store
        .get_calendar_event_payload(event_id, include_deleted)
        .ok()
        .flatten()
        .map(|event| render_report_calendar_data(&event))
}

fn render_report_calendar_data(event: &crate::api::calendar::CalendarEvent) -> String {
    extract_ics_payload(event).unwrap_or_else(|| {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//OpenProton Bridge//EN\r\nBEGIN:VEVENT\r\nUID:{}\r\nDTSTART:{}\r\nDTEND:{}\r\nSUMMARY:OpenProton Event\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
            event.uid,
            format_ics_datetime(event.start_time),
            format_ics_datetime(event.end_time)
        )
    })
}

fn extract_ics_payload(event: &crate::api::calendar::CalendarEvent) -> Option<String> {
    event
        .shared_events
        .iter()
        .chain(event.calendar_events.iter())
        .chain(event.personal_events.iter())
        .chain(event.attendees_events.iter())
        .find(|part| part.data.contains("BEGIN:VCALENDAR"))
        .map(|part| normalize_ics_newlines(&part.data))
}

fn extract_report_hrefs(body: &str) -> Vec<String> {
    let href_re = Regex::new(
        r"(?is)<(?:[A-Za-z0-9_-]+:)?href\b[^>]*>\s*(?P<href>.*?)\s*</(?:[A-Za-z0-9_-]+:)?href>",
    )
    .expect("href regex should compile");
    href_re
        .captures_iter(body)
        .filter_map(|caps| {
            let href = caps.name("href")?.as_str().trim();
            (!href.is_empty()).then(|| href.to_string())
        })
        .collect()
}

fn parse_event_id_from_href(href: &str, account_id: &str, calendar_id: &str) -> Option<String> {
    let href_path = normalize_report_href_path(href)?;
    let prefix = format!("/dav/{account_id}/calendars/{calendar_id}/");
    let remainder = href_path.strip_prefix(&prefix)?;
    let event_id = remainder.strip_suffix(".ics")?;
    if event_id.is_empty() || event_id.contains('/') {
        return None;
    }
    Some(event_id.to_string())
}

fn normalize_report_href_path(href: &str) -> Option<String> {
    if href.starts_with('/') {
        return Some(href.to_string());
    }
    reqwest::Url::parse(href)
        .ok()
        .map(|url| url.path().to_string())
}

fn normalize_ics_newlines(raw: &str) -> String {
    raw.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
}

fn format_ics_datetime(unix_seconds: i64) -> String {
    let (year, month, day, hour, minute, second) = from_unix_utc(unix_seconds);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

fn from_unix_utc(unix_seconds: i64) -> (i32, u32, u32, u32, u32, u32) {
    let mut days = unix_seconds.div_euclid(86_400);
    let mut seconds_of_day = unix_seconds.rem_euclid(86_400);
    let mut year = 1970i32;
    loop {
        let diy = if is_leap(year) { 366 } else { 365 };
        if days < diy {
            break;
        }
        days -= diy;
        year += 1;
    }

    let mut month = 1u32;
    loop {
        let dim = days_in_month(year, month) as i64;
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }

    let day = (days + 1) as u32;
    let hour = (seconds_of_day / 3_600) as u32;
    seconds_of_day %= 3_600;
    let minute = (seconds_of_day / 60) as u32;
    let second = (seconds_of_day % 60) as u32;
    (year, month, day, hour, minute, second)
}

fn parse_calendar_collection_path(path: &str, account_id: &str) -> Option<String> {
    let mut segments = path.trim_matches('/').split('/').filter(|s| !s.is_empty());
    if segments.next()? != "dav" {
        return None;
    }
    if segments.next()? != account_id {
        return None;
    }
    if segments.next()? != "calendars" {
        return None;
    }
    let calendar_id = segments.next()?;
    if calendar_id.is_empty() || segments.next().is_some() {
        return None;
    }
    Some(calendar_id.to_string())
}

fn not_implemented_report() -> DavResponse {
    DavResponse {
        status: "501 Not Implemented",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"report not implemented\n".to_vec(),
    }
}

fn normalize_path(path: &str) -> String {
    path.split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(path)
        .to_string()
}

fn escape_xml(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

fn epoch_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::{
        extract_report_hrefs, extract_sync_token, parse_calendar_collection_path,
        parse_calendar_time_range, parse_event_id_from_href,
    };

    #[test]
    fn parses_sync_token_from_report_body() {
        let token = extract_sync_token(
            "<d:sync-collection><d:sync-token>123</d:sync-token></d:sync-collection>",
        );
        assert_eq!(token.as_deref(), Some("123"));
    }

    #[test]
    fn parses_calendar_time_range_attributes() {
        let range = parse_calendar_time_range(
            r#"<cal:calendar-query><cal:filter><cal:comp-filter name="VCALENDAR"><cal:comp-filter name="VEVENT"><cal:time-range start="20260305T120000Z" end="20260305T130000Z"/></cal:comp-filter></cal:comp-filter></cal:filter></cal:calendar-query>"#,
        );
        assert!(range.start_time_from.is_some());
        assert!(range.start_time_to.is_some());
    }

    #[test]
    fn parses_calendar_collection_path_for_account() {
        let parsed = parse_calendar_collection_path("/dav/uid-1/calendars/work/", "uid-1");
        assert_eq!(parsed.as_deref(), Some("work"));

        assert!(parse_calendar_collection_path("/dav/uid-2/calendars/work/", "uid-1").is_none());
        assert!(parse_calendar_collection_path("/dav/uid-1/calendars/", "uid-1").is_none());
    }

    #[test]
    fn parses_event_id_from_absolute_multiget_href() {
        let parsed = parse_event_id_from_href(
            "https://127.0.0.1:8080/dav/uid-1/calendars/work/event-1.ics",
            "uid-1",
            "work",
        );
        assert_eq!(parsed.as_deref(), Some("event-1"));
    }

    #[test]
    fn extracts_hrefs_with_arbitrary_namespace_prefixes() {
        let hrefs = extract_report_hrefs(
            r#"<c:calendar-multiget xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:D="DAV:"><D:href>https://127.0.0.1:8080/dav/uid-1/calendars/work/event-1.ics</D:href><href>/dav/uid-1/calendars/work/event-2.ics</href></c:calendar-multiget>"#,
        );
        assert_eq!(
            hrefs,
            vec![
                "https://127.0.0.1:8080/dav/uid-1/calendars/work/event-1.ics".to_string(),
                "/dav/uid-1/calendars/work/event-2.ics".to_string()
            ]
        );
    }
}
