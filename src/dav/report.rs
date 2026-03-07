use std::sync::Arc;
use std::time::Duration;

use regex::Regex;

use crate::api::{calendar, client::ProtonClient};
use crate::bridge::accounts::RuntimeAccountRegistry;
use crate::bridge::auth_router::AuthRoute;
use crate::bridge::types::AccountId;
use crate::pim::dav::{
    CalDavRepository, CardDavRepository, DavSyncStateRepository, StoreBackedDavAdapter,
};
use crate::pim::query::{CalendarEventRange, QueryPage};
use crate::pim::store::PimStore;
use crate::pim::sync_calendar;

use super::calendar_crypto::{self, CalendarDecryptContext};
use super::discovery;
use super::error::{DavError, Result};
use super::etag;
use super::http::DavResponse;

const CALDAV_EMPTY_SYNC_BACKFILL_SCOPE: &str = "calendar.dav_last_backfill_ms";
const CALDAV_EMPTY_SYNC_BACKFILL_COOLDOWN: Duration = Duration::from_secs(300);

pub async fn handle_report(
    raw_path: &str,
    body: &[u8],
    auth: &AuthRoute,
    store: &Arc<PimStore>,
    runtime_accounts: Option<&Arc<RuntimeAccountRegistry>>,
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
            let decrypt_context =
                build_decrypt_context(runtime_accounts, &auth.account_id.0, &calendar_id).await;
            return Ok(Some(calendar_query(
                &adapter,
                store,
                &auth.account_id.0,
                &calendar_id,
                body_text,
                decrypt_context.as_ref(),
            )?));
        }
        if body_text.contains("calendar-multiget") {
            let decrypt_context =
                build_decrypt_context(runtime_accounts, &auth.account_id.0, &calendar_id).await;
            return Ok(Some(calendar_multiget(
                &adapter,
                store,
                &auth.account_id.0,
                &calendar_id,
                body_text,
                decrypt_context.as_ref(),
            )?));
        }
        if body_text.contains("sync-collection") {
            let decrypt_context =
                build_decrypt_context(runtime_accounts, &auth.account_id.0, &calendar_id).await;
            return Ok(Some(
                caldav_sync_collection(
                    &adapter,
                    store,
                    runtime_accounts,
                    &auth.account_id.0,
                    &calendar_id,
                    body_text,
                    decrypt_context.as_ref(),
                )
                .await?,
            ));
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
            content_type: Some("text/vcard; charset=utf-8".to_string()),
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
    decrypt_context: Option<&CalendarDecryptContext>,
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
            calendar_data: load_calendar_data(store, &event.id, false, decrypt_context),
            content_type: Some("text/calendar; charset=utf-8".to_string()),
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
    decrypt_context: Option<&CalendarDecryptContext>,
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
                content_type: None,
                not_found: true,
            });
            continue;
        };
        items.push(ReportItem {
            href,
            etag: etag::from_updated_ms(&event.id, event.updated_at_ms),
            calendar_data: load_calendar_data(store, &event.id, false, decrypt_context),
            content_type: Some("text/calendar; charset=utf-8".to_string()),
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
    debug_calendar_multiget_sample(account_id, calendar_id, &items);
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
    let since = extract_sync_token_version(body);
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
            content_type: Some("text/vcard; charset=utf-8".to_string()),
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

async fn caldav_sync_collection(
    adapter: &StoreBackedDavAdapter,
    store: &Arc<PimStore>,
    runtime_accounts: Option<&Arc<RuntimeAccountRegistry>>,
    account_id: &str,
    calendar_id: &str,
    body: &str,
    decrypt_context: Option<&CalendarDecryptContext>,
) -> Result<DavResponse> {
    maybe_backfill_empty_caldav_sync(adapter, store, runtime_accounts, account_id, calendar_id)
        .await?;
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
    let since = extract_sync_token_version(body);
    let current_token = calendar_collection_sync_version(adapter, calendar_id, Some(&events))?;
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
                load_calendar_data(store, &event.id, true, decrypt_context)
            },
            content_type: if event.deleted {
                None
            } else {
                Some("text/calendar; charset=utf-8".to_string())
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

async fn maybe_backfill_empty_caldav_sync(
    adapter: &StoreBackedDavAdapter,
    store: &Arc<PimStore>,
    runtime_accounts: Option<&Arc<RuntimeAccountRegistry>>,
    account_id: &str,
    calendar_id: &str,
) -> Result<()> {
    let cached_events = adapter
        .list_calendar_events(
            calendar_id,
            false,
            CalendarEventRange::default(),
            QueryPage {
                limit: 1,
                offset: 0,
            },
        )
        .map_err(|err| DavError::Backend(err.to_string()))?;
    if !cached_events.is_empty() {
        return Ok(());
    }

    if !backfill_cooldown_elapsed(adapter)? {
        return Ok(());
    }

    let Some(runtime_accounts) = runtime_accounts else {
        return Ok(());
    };

    let session = runtime_accounts
        .with_valid_access_token(&AccountId(account_id.to_string()))
        .await
        .map_err(|err| DavError::Backend(err.to_string()))?;
    let client = ProtonClient::authenticated_with_mode(
        session.api_mode.base_url(),
        session.api_mode,
        &session.uid,
        &session.access_token,
    )
    .map_err(|err| DavError::Backend(err.to_string()))?;

    tracing::info!(
        account_id,
        calendar_id,
        "backfilling calendar cache before initial CalDAV sync"
    );
    sync_calendar::bootstrap_calendars(
        &client,
        store.as_ref(),
        &calendar::CalendarEventsQuery::default(),
    )
    .await
    .map_err(|err| DavError::Backend(err.to_string()))?;
    adapter
        .set_sync_state_int(CALDAV_EMPTY_SYNC_BACKFILL_SCOPE, epoch_millis())
        .map_err(|err| DavError::Backend(err.to_string()))?;
    Ok(())
}

fn backfill_cooldown_elapsed(adapter: &StoreBackedDavAdapter) -> Result<bool> {
    let Some(last_backfill_ms) = adapter
        .get_sync_state_int(CALDAV_EMPTY_SYNC_BACKFILL_SCOPE)
        .map_err(|err| DavError::Backend(err.to_string()))?
    else {
        return Ok(true);
    };
    Ok(epoch_millis().saturating_sub(last_backfill_ms)
        >= CALDAV_EMPTY_SYNC_BACKFILL_COOLDOWN.as_millis() as i64)
}

pub(crate) fn calendar_collection_sync_version(
    adapter: &StoreBackedDavAdapter,
    calendar_id: &str,
    cached_events: Option<&[crate::pim::types::StoredCalendarEvent]>,
) -> Result<i64> {
    let calendar_version = adapter
        .get_calendar(calendar_id, true)
        .map_err(|err| DavError::Backend(err.to_string()))?
        .map(|calendar| calendar.updated_at_ms)
        .unwrap_or_default();
    let event_version = if let Some(events) = cached_events {
        events.iter().map(|event| event.updated_at_ms).max()
    } else {
        adapter
            .list_calendar_events(
                calendar_id,
                true,
                CalendarEventRange::default(),
                QueryPage {
                    limit: 500,
                    offset: 0,
                },
            )
            .map_err(|err| DavError::Backend(err.to_string()))?
            .iter()
            .map(|event| event.updated_at_ms)
            .max()
    }
    .unwrap_or_default();
    Ok(calendar_version.max(event_version))
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
    extract_xml_text(body, "sync-token")
}

fn extract_sync_token_version(body: &str) -> Option<i64> {
    let token = extract_sync_token(body)?;
    token
        .parse::<i64>()
        .ok()
        .or_else(|| sync_token_version_from_uri(&token))
}

fn sync_token_version_from_uri(token: &str) -> Option<i64> {
    token
        .trim()
        .trim_end_matches('/')
        .rsplit('/')
        .next()?
        .parse::<i64>()
        .ok()
}

fn extract_xml_text(body: &str, local_name: &str) -> Option<String> {
    let pattern = format!(
        r"(?is)<(?:[A-Za-z0-9_-]+:)?{tag}\b[^>]*>\s*(?P<value>.*?)\s*</(?:[A-Za-z0-9_-]+:)?{tag}>",
        tag = regex::escape(local_name)
    );
    let re = Regex::new(&pattern).ok()?;
    let value = re.captures(body)?.name("value")?.as_str().trim();
    Some(value.to_string())
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
    content_type: Option<String>,
    not_found: bool,
}

fn multistatus_response(items: &[ReportItem], sync_token: Option<String>) -> DavResponse {
    let mut body = String::from(
        r#"<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">"#,
    );
    for item in items {
        body.push_str(&render_report_item_xml(item));
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

fn debug_calendar_multiget_sample(account_id: &str, calendar_id: &str, items: &[ReportItem]) {
    let Some(item) = items.iter().find(|item| !item.not_found) else {
        return;
    };
    let Some(calendar_data) = item.calendar_data.as_deref() else {
        return;
    };
    tracing::debug!(
        report = "calendar-multiget",
        account_id,
        calendar_id,
        href = %item.href,
        etag = %item.etag,
        content_type = item.content_type.as_deref().unwrap_or(""),
        content_length = calendar_data.len(),
        calendar_data = calendar_data,
        response_xml = render_report_item_xml(item),
        "dav calendar-multiget sample item"
    );
}

fn render_report_item_xml(item: &ReportItem) -> String {
    let mut body = String::from("<d:response><d:href>");
    body.push_str(&escape_xml(&item.href));
    if item.not_found {
        body.push_str("</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response>");
        return body;
    }
    body.push_str("</d:href><d:propstat><d:prop><d:getetag>");
    body.push_str(&escape_xml(&item.etag));
    body.push_str("</d:getetag>");
    if let Some(content_type) = &item.content_type {
        body.push_str("<d:getcontenttype>");
        body.push_str(&escape_xml(content_type));
        body.push_str("</d:getcontenttype>");
    }
    if let Some(calendar_data) = &item.calendar_data {
        body.push_str("<d:getcontentlength>");
        body.push_str(&calendar_data.len().to_string());
        body.push_str("</d:getcontentlength>");
        body.push_str("<cal:calendar-data>");
        body.push_str(&escape_xml(calendar_data));
        body.push_str("</cal:calendar-data>");
    }
    body.push_str("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>");
    body
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

async fn build_decrypt_context(
    runtime_accounts: Option<&Arc<RuntimeAccountRegistry>>,
    account_id: &str,
    calendar_id: &str,
) -> Option<CalendarDecryptContext> {
    let runtime_accounts = runtime_accounts?;
    calendar_crypto::build_calendar_decrypt_context(runtime_accounts, account_id, calendar_id).await
}

fn load_calendar_data(
    store: &PimStore,
    event_id: &str,
    include_deleted: bool,
    decrypt_context: Option<&CalendarDecryptContext>,
) -> Option<String> {
    store
        .get_calendar_event_payload(event_id, include_deleted)
        .ok()
        .flatten()
        .map(|event| render_report_calendar_data(&event, decrypt_context))
}

fn render_report_calendar_data(
    event: &crate::api::calendar::CalendarEvent,
    decrypt_context: Option<&CalendarDecryptContext>,
) -> String {
    calendar_crypto::best_event_ics(event, decrypt_context).unwrap_or_else(|| {
        format!(
            "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//OpenProton Bridge//EN\r\nBEGIN:VEVENT\r\nUID:{}\r\nDTSTART:{}\r\nDTEND:{}\r\nSUMMARY:OpenProton Event\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
            event.uid,
            format_ics_datetime(event.start_time),
            format_ics_datetime(event.end_time)
        )
    })
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
    decode_percent_component(event_id)
}

fn normalize_report_href_path(href: &str) -> Option<String> {
    if href.starts_with('/') {
        return decode_percent_path(href);
    }
    reqwest::Url::parse(href)
        .ok()
        .and_then(|url| decode_percent_path(url.path()))
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
    decode_percent_component(calendar_id)
}

fn decode_percent_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;

    while idx < bytes.len() {
        if bytes[idx] == b'%' {
            let high = hex_value(*bytes.get(idx + 1)?)?;
            let low = hex_value(*bytes.get(idx + 2)?)?;
            out.push((high << 4) | low);
            idx += 3;
            continue;
        }
        out.push(bytes[idx]);
        idx += 1;
    }

    String::from_utf8(out).ok()
}

fn decode_percent_component(value: &str) -> Option<String> {
    let decoded = decode_percent_path(value)?;
    if decoded.is_empty() || decoded.contains('/') {
        None
    } else {
        Some(decoded)
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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
        if !is_valid_xml_char(ch) {
            continue;
        }
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

fn is_valid_xml_char(ch: char) -> bool {
    matches!(
        ch as u32,
        0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
    )
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
        backfill_cooldown_elapsed, escape_xml, extract_report_hrefs, extract_sync_token,
        extract_sync_token_version, multistatus_response, parse_calendar_collection_path,
        parse_calendar_time_range, parse_event_id_from_href, ReportItem,
        CALDAV_EMPTY_SYNC_BACKFILL_SCOPE,
    };
    use crate::pim::dav::{DavSyncStateRepository, StoreBackedDavAdapter};
    use crate::pim::store::PimStore;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn test_adapter() -> StoreBackedDavAdapter {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("account.db");
        Box::leak(Box::new(tmp));
        StoreBackedDavAdapter::new(Arc::new(PimStore::new(db_path).unwrap()))
    }

    #[test]
    fn parses_sync_token_from_report_body() {
        let token = extract_sync_token(
            "<d:sync-collection><d:sync-token>123</d:sync-token></d:sync-collection>",
        );
        assert_eq!(token.as_deref(), Some("123"));
    }

    #[test]
    fn parses_sync_token_with_default_namespace_and_uri_version() {
        let token = extract_sync_token(
            r#"<sync-collection xmlns="DAV:"><sync-token>https://openproton.local/dav/uid-1/calendars/work/sync/456</sync-token></sync-collection>"#,
        );
        assert_eq!(
            token.as_deref(),
            Some("https://openproton.local/dav/uid-1/calendars/work/sync/456")
        );
        assert_eq!(
            extract_sync_token_version(
                r#"<sync-collection xmlns="DAV:"><sync-token>https://openproton.local/dav/uid-1/calendars/work/sync/456</sync-token></sync-collection>"#,
            ),
            Some(456)
        );
    }

    #[test]
    fn backfill_cooldown_blocks_immediate_repeat_attempts() {
        let adapter = test_adapter();
        assert!(backfill_cooldown_elapsed(&adapter).unwrap());

        adapter
            .set_sync_state_int(CALDAV_EMPTY_SYNC_BACKFILL_SCOPE, super::epoch_millis())
            .unwrap();
        assert!(!backfill_cooldown_elapsed(&adapter).unwrap());
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
        let encoded =
            parse_calendar_collection_path("/dav/uid-1/calendars/35HQnSLUjSZs%3D%3D/", "uid-1");
        assert_eq!(encoded.as_deref(), Some("35HQnSLUjSZs=="));

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
        let encoded = parse_event_id_from_href(
            "https://127.0.0.1:8080/dav/uid-1/calendars/35HQnSLUjSZs%3D%3D/event%3D1.ics",
            "uid-1",
            "35HQnSLUjSZs==",
        );
        assert_eq!(encoded.as_deref(), Some("event=1"));
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

    #[test]
    fn multistatus_includes_content_metadata_for_calendar_items() {
        let calendar_data =
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let response = multistatus_response(
            &[ReportItem {
                href: "/dav/uid-1/calendars/work/event-1.ics".to_string(),
                etag: "\"etag-1\"".to_string(),
                calendar_data: Some(calendar_data.to_string()),
                content_type: Some("text/calendar; charset=utf-8".to_string()),
                not_found: false,
            }],
            None,
        );
        let body = String::from_utf8(response.body).expect("response body should be utf-8");
        assert!(body.contains("<d:getcontenttype>text/calendar; charset=utf-8</d:getcontenttype>"));
        assert!(body.contains(&format!(
            "<d:getcontentlength>{}</d:getcontentlength>",
            calendar_data.len()
        )));
        assert!(body.contains("<cal:calendar-data>"));
    }

    #[test]
    fn escape_xml_drops_invalid_control_characters() {
        let escaped = escape_xml("ok\u{0}bad\u{8}<tag>");
        assert_eq!(escaped, "okbad&lt;tag&gt;");
    }
}
