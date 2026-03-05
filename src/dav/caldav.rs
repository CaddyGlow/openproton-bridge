use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::calendar::CalendarEvent;
use crate::api::calendar::{Calendar, CalendarEventPart};
use crate::bridge::auth_router::AuthRoute;
use crate::pim::dav::{CalDavRepository, DeleteMode, StoreBackedDavAdapter};
use crate::pim::query::{CalendarEventRange, QueryPage};
use crate::pim::store::PimStore;

use super::error::{DavError, Result};
use super::etag;
use super::http::DavResponse;

pub fn handle_request(
    method: &str,
    raw_path: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
    auth: &AuthRoute,
    store: &Arc<PimStore>,
) -> Result<Option<DavResponse>> {
    let path = normalize_path(raw_path);
    let calendars_root = format!("/dav/{}/calendars/", auth.account_id.0);
    let adapter = StoreBackedDavAdapter::new(store.clone());

    if let Some(calendar_id) = parse_calendar_collection_id(&calendars_root, &path) {
        return match method {
            "GET" | "HEAD" => {
                let count = adapter
                    .list_calendar_events(
                        &calendar_id,
                        false,
                        CalendarEventRange::default(),
                        QueryPage::default(),
                    )
                    .map_err(|err| DavError::Backend(err.to_string()))?
                    .len();
                let mut response = DavResponse {
                    status: "200 OK",
                    headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
                    body: format!("calendar events={count}\n").into_bytes(),
                };
                if method == "HEAD" {
                    response.body.clear();
                }
                Ok(Some(response))
            }
            "MKCALENDAR" => {
                let exists = adapter
                    .get_calendar(&calendar_id, false)
                    .map_err(|err| DavError::Backend(err.to_string()))?
                    .is_some();
                if exists {
                    return Ok(Some(DavResponse {
                        status: "405 Method Not Allowed",
                        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
                        body: b"calendar already exists\n".to_vec(),
                    }));
                }
                adapter
                    .upsert_calendar(&Calendar {
                        id: calendar_id,
                        name: "Calendar".to_string(),
                        description: "".to_string(),
                        color: "#3A7AFE".to_string(),
                        display: 1,
                        calendar_type: 0,
                        flags: 0,
                    })
                    .map_err(|err| DavError::Backend(err.to_string()))?;
                Ok(Some(DavResponse {
                    status: "201 Created",
                    headers: Vec::new(),
                    body: Vec::new(),
                }))
            }
            "DELETE" => {
                let exists = adapter
                    .get_calendar(&calendar_id, false)
                    .map_err(|err| DavError::Backend(err.to_string()))?
                    .is_some();
                if !exists {
                    return Ok(Some(not_found_response()));
                }
                adapter
                    .delete_calendar(&calendar_id, DeleteMode::Soft)
                    .map_err(|err| DavError::Backend(err.to_string()))?;
                Ok(Some(DavResponse {
                    status: "204 No Content",
                    headers: Vec::new(),
                    body: Vec::new(),
                }))
            }
            _ => Ok(None),
        };
    }

    let Some((calendar_id, event_id)) = parse_event_resource_id(&calendars_root, &path) else {
        return Ok(None);
    };

    match method {
        "GET" | "HEAD" => {
            let stored = adapter
                .get_calendar_event(&event_id, false)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            let Some(stored) = stored else {
                return Ok(Some(not_found_response()));
            };
            let payload = store
                .get_calendar_event_payload(&event_id, false)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            let ics = payload.map(|event| render_ics(&event)).unwrap_or_else(|| {
                render_minimal_ics(&stored.uid, stored.start_time, stored.end_time)
            });
            let mut response = DavResponse {
                status: "200 OK",
                headers: vec![
                    ("Content-Type", "text/calendar; charset=utf-8".to_string()),
                    (
                        "ETag",
                        etag::from_updated_ms(&stored.id, stored.updated_at_ms),
                    ),
                ],
                body: ics.into_bytes(),
            };
            if method == "HEAD" {
                response.body.clear();
            }
            Ok(Some(response))
        }
        "PUT" => {
            let existing = adapter
                .get_calendar_event(&event_id, true)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            let current_etag = existing
                .as_ref()
                .map(|stored| etag::from_updated_ms(&stored.id, stored.updated_at_ms));
            if !etag::if_match_satisfied(headers.get("if-match"), current_etag.as_deref()) {
                return Ok(Some(precondition_failed_response()));
            }
            if !etag::if_none_match_satisfied(headers.get("if-none-match"), current_etag.as_deref())
            {
                return Ok(Some(precondition_failed_response()));
            }

            ensure_calendar_exists(&adapter, &calendar_id)?;
            let payload = std::str::from_utf8(body)
                .map_err(|_| DavError::InvalidRequest("CalDAV PUT body is not utf-8"))?;
            let now = epoch_seconds();
            let create_time = now;
            let event = parse_ics(&event_id, &calendar_id, payload, create_time, now);
            adapter
                .upsert_calendar_event(&event)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            let stored = adapter
                .get_calendar_event(&event_id, false)
                .map_err(|err| DavError::Backend(err.to_string()))?
                .ok_or_else(|| DavError::Backend("event missing after upsert".to_string()))?;
            let status = if existing.is_some() {
                "204 No Content"
            } else {
                "201 Created"
            };
            Ok(Some(DavResponse {
                status,
                headers: vec![(
                    "ETag",
                    etag::from_updated_ms(&stored.id, stored.updated_at_ms),
                )],
                body: Vec::new(),
            }))
        }
        "DELETE" => {
            let existing = adapter
                .get_calendar_event(&event_id, false)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            let Some(existing) = existing else {
                return Ok(Some(not_found_response()));
            };
            let current_etag = etag::from_updated_ms(&existing.id, existing.updated_at_ms);
            if !etag::if_match_satisfied(headers.get("if-match"), Some(current_etag.as_str())) {
                return Ok(Some(precondition_failed_response()));
            }
            adapter
                .delete_calendar_event(&event_id, DeleteMode::Soft)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            Ok(Some(DavResponse {
                status: "204 No Content",
                headers: Vec::new(),
                body: Vec::new(),
            }))
        }
        _ => Ok(None),
    }
}

fn ensure_calendar_exists(adapter: &StoreBackedDavAdapter, calendar_id: &str) -> Result<()> {
    let exists = adapter
        .get_calendar(calendar_id, true)
        .map_err(|err| DavError::Backend(err.to_string()))?
        .is_some();
    if !exists {
        adapter
            .upsert_calendar(&Calendar {
                id: calendar_id.to_string(),
                name: "Calendar".to_string(),
                description: "".to_string(),
                color: "#3A7AFE".to_string(),
                display: 1,
                calendar_type: 0,
                flags: 0,
            })
            .map_err(|err| DavError::Backend(err.to_string()))?;
    }
    Ok(())
}

fn parse_calendar_collection_id(calendars_root: &str, path: &str) -> Option<String> {
    if !path.starts_with(calendars_root) {
        return None;
    }
    let remainder = path.strip_prefix(calendars_root)?;
    if remainder.is_empty() || !remainder.ends_with('/') {
        return None;
    }
    let id = remainder.trim_end_matches('/');
    if id.is_empty() || id.contains('/') {
        None
    } else {
        Some(id.to_string())
    }
}

fn parse_event_resource_id(calendars_root: &str, path: &str) -> Option<(String, String)> {
    if !path.starts_with(calendars_root) {
        return None;
    }
    let remainder = path.strip_prefix(calendars_root)?;
    let (calendar_id, file_name) = remainder.split_once('/')?;
    if calendar_id.is_empty() || file_name.is_empty() || !file_name.ends_with(".ics") {
        return None;
    }
    let event_id = file_name.trim_end_matches(".ics");
    if event_id.is_empty() {
        return None;
    }
    Some((calendar_id.to_string(), event_id.to_string()))
}

fn parse_ics(
    id: &str,
    calendar_id: &str,
    raw: &str,
    create_time: i64,
    edit_time: i64,
) -> CalendarEvent {
    let mut uid = None;
    let mut dtstart = None;
    let mut dtend = None;

    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if let Some((name, value)) = line.split_once(':') {
            let name_upper = name.to_ascii_uppercase();
            if name_upper == "UID" {
                uid = Some(value.trim().to_string());
            } else if name_upper.starts_with("DTSTART") {
                dtstart = parse_ics_datetime(value.trim());
            } else if name_upper.starts_with("DTEND") {
                dtend = parse_ics_datetime(value.trim());
            }
        }
    }

    let start_time = dtstart.unwrap_or(edit_time);
    let end_time = dtend.unwrap_or(start_time + 3600);
    let uid = uid.unwrap_or_else(|| format!("uid-{id}"));

    CalendarEvent {
        id: id.to_string(),
        uid,
        calendar_id: calendar_id.to_string(),
        shared_event_id: format!("shared-{id}"),
        create_time,
        last_edit_time: edit_time,
        start_time,
        end_time,
        start_timezone: "UTC".to_string(),
        end_timezone: "UTC".to_string(),
        full_day: 0,
        author: String::new(),
        permissions: 0,
        attendees: vec![],
        shared_key_packet: String::new(),
        calendar_key_packet: String::new(),
        shared_events: vec![],
        calendar_events: vec![CalendarEventPart {
            member_id: String::new(),
            kind: 0,
            data: raw.to_string(),
            signature: None,
            author: None,
        }],
        attendees_events: vec![],
        personal_events: vec![],
    }
}

fn render_ics(event: &CalendarEvent) -> String {
    let summary = "OpenProton Event";
    format!(
        "BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//OpenProton Bridge//EN\nBEGIN:VEVENT\nUID:{}\nDTSTART:{}\nDTEND:{}\nSUMMARY:{}\nEND:VEVENT\nEND:VCALENDAR\n",
        event.uid,
        format_ics_datetime(event.start_time),
        format_ics_datetime(event.end_time),
        summary
    )
}

fn render_minimal_ics(uid: &str, start_time: i64, end_time: i64) -> String {
    format!(
        "BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//OpenProton Bridge//EN\nBEGIN:VEVENT\nUID:{}\nDTSTART:{}\nDTEND:{}\nSUMMARY:OpenProton Event\nEND:VEVENT\nEND:VCALENDAR\n",
        uid,
        format_ics_datetime(start_time),
        format_ics_datetime(end_time)
    )
}

fn parse_ics_datetime(value: &str) -> Option<i64> {
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
    if value.len() == 8 {
        let year = value.get(0..4)?.parse::<i32>().ok()?;
        let month = value.get(4..6)?.parse::<u32>().ok()?;
        let day = value.get(6..8)?.parse::<u32>().ok()?;
        return to_unix_utc(year, month, day, 0, 0, 0);
    }
    None
}

fn format_ics_datetime(unix_seconds: i64) -> String {
    let (year, month, day, hour, minute, second) = from_unix_utc(unix_seconds);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
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

fn not_found_response() -> DavResponse {
    DavResponse {
        status: "404 Not Found",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"not found\n".to_vec(),
    }
}

fn precondition_failed_response() -> DavResponse {
    DavResponse {
        status: "412 Precondition Failed",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"precondition failed\n".to_vec(),
    }
}

fn normalize_path(path: &str) -> String {
    path.split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(path)
        .to_string()
}

fn epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::{format_ics_datetime, parse_ics_datetime};

    #[test]
    fn parses_and_formats_ics_timestamps() {
        let ts = parse_ics_datetime("20260305T123456Z").expect("parse timestamp");
        assert_eq!(format_ics_datetime(ts), "20260305T123456Z");
    }
}
