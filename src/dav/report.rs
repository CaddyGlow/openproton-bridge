use std::sync::Arc;

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
    let cal_collection = discovery::default_calendar_path(&auth.account_id.0);

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

    if path == cal_collection {
        if body_text.contains("calendar-query") {
            return Ok(Some(calendar_query(
                &adapter,
                &auth.account_id.0,
                body_text,
            )?));
        }
        if body_text.contains("sync-collection") {
            return Ok(Some(caldav_sync_collection(
                &adapter,
                &auth.account_id.0,
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
        })
        .collect::<Vec<_>>();
    Ok(multistatus_response(&items, None))
}

fn calendar_query(
    adapter: &StoreBackedDavAdapter,
    account_id: &str,
    body: &str,
) -> Result<DavResponse> {
    let range = parse_calendar_time_range(body);
    let events = adapter
        .list_calendar_events(
            "default",
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
            href: format!("/dav/{account_id}/calendars/default/{}.ics", event.id),
            etag: etag::from_updated_ms(&event.id, event.updated_at_ms),
        })
        .collect::<Vec<_>>();
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
        })
        .collect::<Vec<_>>();
    Ok(multistatus_response(
        &items,
        Some(current_token.to_string()),
    ))
}

fn caldav_sync_collection(
    adapter: &StoreBackedDavAdapter,
    account_id: &str,
    body: &str,
) -> Result<DavResponse> {
    let events = adapter
        .list_calendar_events(
            "default",
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
        .unwrap_or_else(epoch_millis);
    adapter
        .set_sync_state_int(&sync_scope("caldav", account_id), current_token)
        .map_err(|err| DavError::Backend(err.to_string()))?;
    let items = events
        .iter()
        .filter(|event| since.is_none_or(|token| event.updated_at_ms > token))
        .map(|event| ReportItem {
            href: format!("/dav/{account_id}/calendars/default/{}.ics", event.id),
            etag: etag::from_updated_ms(&event.id, event.updated_at_ms),
        })
        .collect::<Vec<_>>();
    Ok(multistatus_response(
        &items,
        Some(current_token.to_string()),
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
}

fn multistatus_response(items: &[ReportItem], sync_token: Option<String>) -> DavResponse {
    let mut body =
        String::from(r#"<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:">"#);
    for item in items {
        body.push_str("<d:response><d:href>");
        body.push_str(&escape_xml(&item.href));
        body.push_str("</d:href><d:propstat><d:prop><d:getetag>");
        body.push_str(&escape_xml(&item.etag));
        body.push_str(
            "</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
        );
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
    use super::{extract_sync_token, parse_calendar_time_range};

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
}
