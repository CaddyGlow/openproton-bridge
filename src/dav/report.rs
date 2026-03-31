use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use serde_json::Value;

use crate::api::{calendar, client::ProtonClient};
use crate::bridge::accounts::RuntimeAccountRegistry;
use crate::bridge::auth_router::AuthRoute;
use crate::bridge::types::AccountId;
use crate::pim::store::PimStore;
use crate::pim::sync_calendar;
use crate::pim::{CalendarEventRange, QueryPage};

use gluon_rs_dav::discovery;
use gluon_rs_dav::etag;
use gluon_rs_dav::http::DavResponse;
use gluon_rs_dav::{DavError, Result};

use super::calendar_crypto::{self, CalendarDecryptContext};

const CALDAV_EMPTY_SYNC_BACKFILL_COOLDOWN: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
struct CalendarQueryRequest {
    range: CalendarEventRange,
    component_filters: Vec<String>,
    prop_filters: Vec<String>,
}

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
    if body_text.trim().is_empty() {
        return Ok(Some(invalid_report_payload_response(
            "REPORT body is missing or empty",
            &path,
            body_text,
        )));
    }

    let card_collection = discovery::default_addressbook_path(&auth.account_id.0);

    if path == card_collection {
        if body_text.contains("addressbook-query") {
            if let Err(err) = parse_addressbook_query_request(body_text) {
                return Ok(Some(invalid_report_payload_response(
                    &err.to_string(),
                    &path,
                    body_text,
                )));
            }
            return Ok(Some(addressbook_query(store, &auth.account_id.0)?));
        }
        if body_text.contains("sync-collection") {
            return Ok(Some(carddav_sync_collection(
                store,
                &auth.account_id.0,
                body_text,
            )?));
        }
        if is_xml_like(body_text) {
            return Ok(Some(invalid_report_payload_response(
                "unsupported CardDAV REPORT payload",
                &path,
                body_text,
            )));
        }
        return Ok(Some(not_implemented_report()));
    }

    if let Some(calendar_id) = parse_calendar_collection_path(&path, &auth.account_id.0) {
        if has_named_xml_tag(body_text, "calendar-query") {
            let query = match parse_calendar_query_request(body_text) {
                Ok(query) => query,
                Err(err) => {
                    return Ok(Some(invalid_report_payload_response(
                        &err.to_string(),
                        &path,
                        body_text,
                    )))
                }
            };
            let decrypt_context =
                build_decrypt_context(runtime_accounts, &auth.account_id.0, &calendar_id).await;
            return Ok(Some(calendar_query(
                store,
                &auth.account_id.0,
                &calendar_id,
                &query,
                decrypt_context.as_ref(),
            )?));
        }
        if has_named_xml_tag(body_text, "calendar-multiget") {
            let hrefs = match parse_calendar_multiget_hrefs(body_text) {
                Ok(hrefs) => hrefs,
                Err(err) => {
                    return Ok(Some(invalid_report_payload_response(
                        &err.to_string(),
                        &path,
                        body_text,
                    )))
                }
            };
            let decrypt_context =
                build_decrypt_context(runtime_accounts, &auth.account_id.0, &calendar_id).await;
            return Ok(Some(calendar_multiget(
                store,
                &auth.account_id.0,
                &calendar_id,
                &hrefs,
                decrypt_context.as_ref(),
            )?));
        }
        if has_named_xml_tag(body_text, "sync-collection") {
            let sync_token = match parse_sync_collection_token(body_text) {
                Ok(sync_token) => sync_token,
                Err(err) => {
                    return Ok(Some(invalid_report_payload_response(
                        &err.to_string(),
                        &path,
                        body_text,
                    )))
                }
            };
            let decrypt_context =
                build_decrypt_context(runtime_accounts, &auth.account_id.0, &calendar_id).await;
            return Ok(Some(
                caldav_sync_collection(
                    store,
                    runtime_accounts,
                    &auth.account_id.0,
                    &calendar_id,
                    sync_token,
                    decrypt_context.as_ref(),
                )
                .await?,
            ));
        }
        if is_xml_like(body_text) {
            return Ok(Some(invalid_report_payload_response(
                "unsupported CalDAV REPORT payload",
                &path,
                body_text,
            )));
        }
        return Ok(Some(not_implemented_report()));
    }

    Ok(None)
}

fn addressbook_query(store: &PimStore, account_id: &str) -> Result<DavResponse> {
    let contacts = store
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
    store: &Arc<PimStore>,
    account_id: &str,
    calendar_id: &str,
    query: &CalendarQueryRequest,
    decrypt_context: Option<&CalendarDecryptContext>,
) -> Result<DavResponse> {
    let range = query.range.clone();
    let events = store
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
        component_filters = ?query.component_filters,
        prop_filters = ?query.prop_filters,
        item_count,
        payload_count,
        "dav report assembled"
    );
    Ok(multistatus_response(&items, None))
}

fn calendar_multiget(
    store: &Arc<PimStore>,
    account_id: &str,
    calendar_id: &str,
    hrefs: &[String],
    decrypt_context: Option<&CalendarDecryptContext>,
) -> Result<DavResponse> {
    let mut items = Vec::with_capacity(hrefs.len());
    let mut seen_event_ids = HashSet::new();
    for href in hrefs {
        let Some(event_id) = parse_event_id_from_href(&href, account_id, calendar_id) else {
            continue;
        };
        if !seen_event_ids.insert(event_id.clone()) {
            continue;
        }
        let event = store
            .get_calendar_event(&event_id, false)
            .map_err(|err| DavError::Backend(err.to_string()))?;
        let Some(event) = event else {
            items.push(ReportItem {
                href: href.clone(),
                etag: String::new(),
                calendar_data: None,
                content_type: None,
                not_found: true,
            });
            continue;
        };
        items.push(ReportItem {
            href: href.clone(),
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

fn carddav_sync_collection(store: &PimStore, account_id: &str, body: &str) -> Result<DavResponse> {
    let contacts = store
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
    store
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
    store: &Arc<PimStore>,
    runtime_accounts: Option<&Arc<RuntimeAccountRegistry>>,
    account_id: &str,
    calendar_id: &str,
    request_sync_token: i64,
    decrypt_context: Option<&CalendarDecryptContext>,
) -> Result<DavResponse> {
    maybe_backfill_empty_caldav_sync(store, runtime_accounts, account_id, calendar_id).await?;
    let events = store
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
    let prior_sync_token = store
        .get_sync_state_int(&caldav_sync_scope(account_id, calendar_id))
        .map_err(|err| DavError::Backend(err.to_string()))?;
    let since = if prior_sync_token.is_some() {
        Some(request_sync_token)
    } else {
        None
    };
    let current_token = calendar_collection_sync_version(store, calendar_id, Some(&events))?;
    store
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
        prior_sync_known = prior_sync_token.is_some(),
        request_sync_token = request_sync_token,
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
    store: &Arc<PimStore>,
    runtime_accounts: Option<&Arc<RuntimeAccountRegistry>>,
    account_id: &str,
    calendar_id: &str,
) -> Result<()> {
    let cached_events = store
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

    if !backfill_cooldown_elapsed(store, account_id, calendar_id)? {
        tracing::debug!(
            account_id,
            calendar_id,
            "skipping CalDAV backfill because cooldown is still active"
        );
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
    store
        .set_sync_state_int(
            &caldav_backfill_scope(account_id, calendar_id),
            epoch_millis(),
        )
        .map_err(|err| DavError::Backend(err.to_string()))?;
    Ok(())
}

fn backfill_cooldown_elapsed(
    store: &PimStore,
    account_id: &str,
    calendar_id: &str,
) -> Result<bool> {
    let Some(last_backfill_ms) = store
        .get_sync_state_int(&caldav_backfill_scope(account_id, calendar_id))
        .map_err(|err| DavError::Backend(err.to_string()))?
    else {
        return Ok(true);
    };
    Ok(epoch_millis().saturating_sub(last_backfill_ms)
        >= CALDAV_EMPTY_SYNC_BACKFILL_COOLDOWN.as_millis() as i64)
}

fn caldav_backfill_scope(account_id: &str, calendar_id: &str) -> String {
    format!("calendar.dav_last_backfill_ms.{account_id}.{calendar_id}")
}

pub(crate) fn calendar_collection_sync_version(
    store: &PimStore,
    calendar_id: &str,
    cached_events: Option<&[crate::pim::StoredCalendarEvent]>,
) -> Result<i64> {
    let calendar_version = store
        .get_calendar(calendar_id, true)
        .map_err(|err| DavError::Backend(err.to_string()))?
        .map(|calendar| calendar.updated_at_ms)
        .unwrap_or_default();
    let event_version = if let Some(events) = cached_events {
        events.iter().map(|event| event.updated_at_ms).max()
    } else {
        store
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

fn parse_calendar_query_request(body: &str) -> Result<CalendarQueryRequest> {
    let query = extract_xml_element(body, "calendar-query").ok_or(DavError::InvalidRequest(
        "calendar-query request is malformed",
    ))?;

    let range = parse_calendar_time_range_request(&query)?;

    let filter = extract_xml_element(&query, "filter");
    let component_filters = filter
        .as_deref()
        .map(|filter| {
            extract_xml_start_tags(filter, "comp-filter")
                .into_iter()
                .filter_map(|tag| extract_xml_attribute(&tag, "name"))
                .collect()
        })
        .unwrap_or_default();

    let prop_filters = filter
        .as_deref()
        .map(|filter| {
            extract_xml_start_tags(filter, "prop-filter")
                .into_iter()
                .filter_map(|tag| extract_xml_attribute(&tag, "name"))
                .collect()
        })
        .unwrap_or_default();

    Ok(CalendarQueryRequest {
        range,
        component_filters,
        prop_filters,
    })
}

fn parse_addressbook_query_request(body: &str) -> Result<()> {
    let query = extract_xml_element(body, "addressbook-query").ok_or(DavError::InvalidRequest(
        "addressbook-query request is malformed",
    ))?;
    if extract_xml_start_tags(&query, "prop-filter")
        .into_iter()
        .any(|tag| extract_xml_attribute(&tag, "name").is_none())
    {
        return Err(DavError::InvalidRequest(
            "addressbook-query property filters must include name attribute",
        ));
    }
    Ok(())
}

fn parse_sync_collection_token(body: &str) -> Result<i64> {
    // Interop: several CalDAV clients send initial sync-collection REPORTs with
    // missing/empty sync-token. Treat those as an initial sync from token 0.
    let Some(token) = extract_sync_token(body) else {
        return Ok(0);
    };
    let token = token.trim();
    if token.is_empty() {
        return Ok(0);
    }
    token
        .parse::<i64>()
        .ok()
        .or_else(|| sync_token_version_from_uri(token))
        .ok_or(DavError::InvalidRequest(
            "sync-collection sync-token is malformed",
        ))
}

fn parse_calendar_time_range_request(body: &str) -> Result<CalendarEventRange> {
    let Some(time_range) = extract_xml_start_tags(body, "time-range")
        .into_iter()
        .next()
    else {
        return Ok(CalendarEventRange::default());
    };

    let start = match extract_xml_attribute(&time_range, "start") {
        Some(value) => Some(parse_ics_timestamp(&value).ok_or(DavError::InvalidRequest(
            "calendar-query has invalid time-range start",
        ))?),
        None => None,
    };

    let end = match extract_xml_attribute(&time_range, "end") {
        Some(value) => Some(parse_ics_timestamp(&value).ok_or(DavError::InvalidRequest(
            "calendar-query has invalid time-range end",
        ))?),
        None => None,
    };

    if let (Some(start), Some(end)) = (start, end) {
        if start > end {
            return Err(DavError::InvalidRequest(
                "calendar-query time-range start must be before end",
            ));
        }
    }

    Ok(CalendarEventRange {
        start_time_from: start,
        start_time_to: end,
    })
}

fn parse_calendar_multiget_hrefs(body: &str) -> Result<Vec<String>> {
    let multiget = extract_xml_element(body, "calendar-multiget").ok_or(
        DavError::InvalidRequest("calendar-multiget request is malformed"),
    )?;

    let hrefs = extract_report_hrefs(&multiget)
        .into_iter()
        .filter(|href| !href.trim().is_empty())
        .collect::<Vec<_>>();

    if hrefs.is_empty() {
        return Err(DavError::InvalidRequest(
            "calendar-multiget requires at least one href",
        ));
    }

    let mut unique_hrefs = Vec::with_capacity(hrefs.len());
    let mut seen = HashSet::new();
    for href in hrefs {
        if seen.insert(href.clone()) {
            unique_hrefs.push(href);
        }
    }

    Ok(unique_hrefs)
}

fn has_named_xml_tag(body: &str, local_name: &str) -> bool {
    let pattern = format!(
        r"(?is)<(?:[A-Za-z0-9_-]+:)?{tag}\b",
        tag = regex::escape(local_name)
    );
    Regex::new(&pattern)
        .ok()
        .is_some_and(|re| re.is_match(body))
}

fn extract_xml_elements(body: &str, local_name: &str) -> Vec<String> {
    let pattern = format!(
        r"(?is)<(?:[A-Za-z0-9_-]+:)?{tag}\b[^>]*>(?P<value>.*?)</(?:[A-Za-z0-9_-]+:)?{tag}>",
        tag = regex::escape(local_name)
    );
    let Ok(re) = Regex::new(&pattern) else {
        return Vec::new();
    };

    re.captures_iter(body)
        .filter_map(|caps| caps.name("value"))
        .map(|capture| capture.as_str().to_string())
        .collect()
}

fn extract_xml_element(body: &str, local_name: &str) -> Option<String> {
    extract_xml_elements(body, local_name).into_iter().next()
}

fn extract_xml_start_tags(body: &str, local_name: &str) -> Vec<String> {
    let pattern = format!(
        r"(?is)<(?:[A-Za-z0-9_-]+:)?{tag}\b[^>]*>",
        tag = regex::escape(local_name)
    );
    let Ok(re) = Regex::new(&pattern) else {
        return Vec::new();
    };

    re.find_iter(body)
        .map(|tag| tag.as_str().to_string())
        .collect()
}

fn extract_xml_attribute(tag: &str, name: &str) -> Option<String> {
    let pattern = format!(
        r#"(?is)\b{name}\s*=\s*(?:\"(?P<double>[^"]*)\"|'(?P<single>[^']*)')"#,
        name = regex::escape(name)
    );
    let Ok(re) = Regex::new(&pattern) else {
        return None;
    };
    re.captures(tag)
        .and_then(|caps| caps.name("double").or_else(|| caps.name("single")))
        .map(|value| value.as_str().to_string())
}

fn parse_ics_timestamp(value: &str) -> Option<i64> {
    let compact = value.replace('-', "");
    parse_ics_datetime(value.to_string())
        .or_else(|| parse_ics_datetime(compact.clone()))
        .or_else(|| parse_ics_date(value))
        .or_else(|| parse_ics_date(&compact))
}

fn parse_ics_date(value: &str) -> Option<i64> {
    let value = value.trim();
    if value.len() != 8 {
        return None;
    }
    let year = value.get(0..4)?.parse::<i32>().ok()?;
    let month = value.get(4..6)?.parse::<u32>().ok()?;
    let day = value.get(6..8)?.parse::<u32>().ok()?;
    to_unix_utc(year, month, day, 0, 0, 0)
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
        .get_calendar_event_payload_with_raw(event_id, include_deleted)
        .ok()
        .flatten()
        .map(|(event, raw)| render_report_calendar_data(&event, Some(&raw), decrypt_context))
}

fn render_report_calendar_data(
    event: &crate::api::calendar::CalendarEvent,
    raw_json: Option<&Value>,
    decrypt_context: Option<&CalendarDecryptContext>,
) -> String {
    if let Some(ics) = calendar_crypto::best_event_ics(event, decrypt_context) {
        if !has_renderable_vevent_shape(ics.as_str()) {
            tracing::warn!(
                event_id = %event.id,
                calendar_id = %event.calendar_id,
                decrypted_context = decrypt_context.is_some(),
                "dav calendar-data selected ICS missing required VEVENT properties; using fallback"
            );
        } else {
            let mut enriched = ics.clone();
            let mut fields =
                calendar_crypto::best_event_text_fields(event, decrypt_context, Some(ics.as_str()));
            if let Some(raw) = raw_json {
                fill_missing_text_fields_from_raw_json(&mut fields, raw);
            }
            let has_summary = has_ics_property(ics.as_str(), "SUMMARY");
            let has_location = has_ics_property(ics.as_str(), "LOCATION");
            let has_description = has_ics_property(ics.as_str(), "DESCRIPTION");

            let mut added_summary = false;
            let mut added_location = false;
            let mut added_description = false;

            if !has_summary {
                if let Some(value) = fields
                    .summary
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(escape_ics_text_value)
                {
                    if insert_ics_property(&mut enriched, "SUMMARY", &value) {
                        added_summary = true;
                    }
                }
            }
            if !has_location {
                if let Some(value) = fields
                    .location
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(escape_ics_text_value)
                {
                    if insert_ics_property(&mut enriched, "LOCATION", &value) {
                        added_location = true;
                    }
                }
            }
            if !has_description {
                if let Some(value) = fields
                    .description
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(escape_ics_text_value)
                {
                    if insert_ics_property(&mut enriched, "DESCRIPTION", &value) {
                        added_description = true;
                    }
                }
            }

            if added_summary || added_location || added_description {
                tracing::debug!(
                    event_id = %event.id,
                    calendar_id = %event.calendar_id,
                    had_summary = has_summary,
                    had_location = has_location,
                    had_description = has_description,
                    added_summary,
                    added_location,
                    added_description,
                    decrypted_context = decrypt_context.is_some(),
                    "dav calendar-data sparse ICS enriched with recovered text fields"
                );
                return enriched;
            }

            let recovered_summary = fields
                .summary
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty());
            let recovered_location = fields
                .location
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty());
            let recovered_description = fields
                .description
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty());
            let missing_summary = !has_summary;
            let missing_location = !has_location;
            let missing_description = !has_description;
            let missing_but_recoverable = (missing_summary && recovered_summary)
                || (missing_location && recovered_location)
                || (missing_description && recovered_description);

            if missing_summary || missing_location || missing_description {
                if missing_but_recoverable {
                    tracing::warn!(
                        event_id = %event.id,
                        calendar_id = %event.calendar_id,
                        has_summary = !missing_summary,
                        has_location = !missing_location,
                        has_description = !missing_description,
                        recovered_summary,
                        recovered_location,
                        recovered_description,
                        decrypted_context = decrypt_context.is_some(),
                        "dav calendar-data sparse ICS could not be enriched"
                    );
                } else {
                    tracing::debug!(
                        event_id = %event.id,
                        calendar_id = %event.calendar_id,
                        has_summary = !missing_summary,
                        has_location = !missing_location,
                        has_description = !missing_description,
                        recovered_summary,
                        recovered_location,
                        recovered_description,
                        decrypted_context = decrypt_context.is_some(),
                        "dav calendar-data sparse ICS could not be enriched"
                    );
                }
            }

            return ics;
        }
    }

    let mut fallback_fields = calendar_crypto::best_event_text_fields(event, decrypt_context, None);
    if let Some(raw) = raw_json {
        fill_missing_text_fields_from_raw_json(&mut fallback_fields, raw);
    }
    let summary = fallback_fields
        .summary
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(escape_ics_text_value)
        .unwrap_or_else(|| "OpenProton Event".to_string());
    let location = fallback_fields
        .location
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(escape_ics_text_value);
    let description = fallback_fields
        .description
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(escape_ics_text_value);

    tracing::warn!(
        event_id = %event.id,
        calendar_id = %event.calendar_id,
        has_summary = !summary.is_empty(),
        has_location = location.is_some(),
        has_description = description.is_some(),
        decrypted_context = decrypt_context.is_some(),
        "dav calendar-data fallback rendered without best-event ICS candidate"
    );

    let mut ics = String::new();
    ics.push_str("BEGIN:VCALENDAR\r\n");
    ics.push_str("VERSION:2.0\r\n");
    ics.push_str("PRODID:-//OpenProton Bridge//EN\r\n");
    ics.push_str("BEGIN:VEVENT\r\n");
    ics.push_str("UID:");
    ics.push_str(&escape_ics_text_value(&event.uid));
    ics.push_str("\r\nDTSTART:");
    ics.push_str(&format_ics_datetime(event.start_time));
    ics.push_str("\r\nDTEND:");
    ics.push_str(&format_ics_datetime(event.end_time));
    ics.push_str("\r\nSUMMARY:");
    ics.push_str(&summary);
    if let Some(location) = location {
        ics.push_str("\r\nLOCATION:");
        ics.push_str(&location);
    }
    if let Some(description) = description {
        ics.push_str("\r\nDESCRIPTION:");
        ics.push_str(&description);
    }
    ics.push_str("\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n");
    ics
}

fn fill_missing_text_fields_from_raw_json(
    fields: &mut calendar_crypto::EventTextFields,
    raw: &Value,
) {
    if fields.summary.is_none() {
        fields.summary = find_first_string_value(raw, &["Summary", "Title", "Name"]);
    }
    if fields.location.is_none() {
        fields.location = find_first_string_value(raw, &["Location", "Place", "Address"]);
    }
    if fields.description.is_none() {
        fields.description = find_first_string_value(raw, &["Description", "Notes"]);
    }
}

fn find_first_string_value(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(Value::String(s)) = map.get(*key) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
            for nested in map.values() {
                if let Some(found) = find_first_string_value(nested, keys) {
                    return Some(found);
                }
            }
            None
        }
        Value::Array(items) => items
            .iter()
            .find_map(|item| find_first_string_value(item, keys)),
        _ => None,
    }
}

fn escape_ics_text_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace("\r\n", "\\n")
        .replace('\n', "\\n")
        .replace('\r', "\\n")
        .replace(';', "\\;")
        .replace(',', "\\,")
}

fn has_ics_property(ics: &str, property: &str) -> bool {
    let prefix = format!("{property}:");
    let folded_prefix = format!("{property};");
    ics.lines()
        .any(|line| line.starts_with(&prefix) || line.starts_with(&folded_prefix))
}

fn has_renderable_vevent_shape(ics: &str) -> bool {
    let upper = ics.to_ascii_uppercase();
    if !upper.contains("BEGIN:VEVENT") {
        return true;
    }
    has_ics_property(ics, "UID") && has_ics_property(ics, "DTSTART")
}

fn insert_ics_property(ics: &mut String, property: &str, value: &str) -> bool {
    let marker = "\r\nEND:VEVENT";
    let Some(pos) = ics.find(marker) else {
        return false;
    };
    let insertion = format!("\r\n{property}:{value}");
    ics.insert_str(pos, &insertion);
    true
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

fn invalid_report_payload_response(message: &str, path: &str, body: &str) -> DavResponse {
    tracing::warn!(
        path = %path,
        reason = %message,
        body_snippet = %report_body_snippet(body, 320),
        "dav report rejected with bad request"
    );
    DavResponse {
        status: "400 Bad Request",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: message.as_bytes().to_vec(),
    }
}

fn report_body_snippet(body: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(max_chars.min(body.len()));
    let mut count = 0usize;
    let mut truncated = false;
    for ch in body.chars() {
        if count >= max_chars {
            truncated = true;
            break;
        }
        let normalized = match ch {
            '\r' | '\n' | '\t' => ' ',
            _ if ch.is_control() => continue,
            _ => ch,
        };
        out.push(normalized);
        count += 1;
    }
    if truncated {
        out.push_str("...");
    }
    out.trim().to_string()
}

fn is_xml_like(body: &str) -> bool {
    let trimmed = body.trim();
    if !trimmed.starts_with('<') {
        return false;
    }
    let Ok(re) = Regex::new(r"(?is)<[^>]+>") else {
        return false;
    };
    re.is_match(trimmed)
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
        backfill_cooldown_elapsed, caldav_backfill_scope, escape_xml, extract_report_hrefs,
        extract_sync_token, extract_sync_token_version, handle_report, multistatus_response,
        parse_addressbook_query_request, parse_calendar_collection_path,
        parse_calendar_multiget_hrefs, parse_calendar_query_request,
        parse_calendar_time_range_request, parse_event_id_from_href, parse_sync_collection_token,
        render_report_calendar_data, DavError, ReportItem,
    };
    use crate::api::calendar::{CalendarEvent, CalendarEventPart};
    use crate::bridge::auth_router::AuthRoute;
    use crate::bridge::types::AccountId;
    use crate::pim::store::PimStore;
    use std::sync::Arc;
    use tempfile::tempdir;

    const FIXTURE_CAL_QUERY_TIME_RANGE: &str =
        include_str!("../../tests/fixtures/rfc-6352-4791/golden/calendar-query-time-range.xml");
    const FIXTURE_CAL_QUERY_FLEXIBLE_TIME_RANGE: &str = include_str!(
        "../../tests/fixtures/rfc-6352-4791/golden/calendar-query-flexible-time-range.xml"
    );
    const FIXTURE_CAL_QUERY_FILTERS: &str =
        include_str!("../../tests/fixtures/rfc-6352-4791/golden/calendar-query-filters.xml");
    const FIXTURE_CAL_MULTIGET_DEDUP: &str =
        include_str!("../../tests/fixtures/rfc-6352-4791/golden/calendar-multiget-dedup.xml");
    const FIXTURE_CAL_QUERY_INVALID_TIME_RANGE: &str = include_str!(
        "../../tests/fixtures/rfc-6352-4791/must_fail/calendar-query-malformed-time-range.xml"
    );
    const FIXTURE_CAL_MULTIGET_EMPTY: &str = include_str!(
        "../../tests/fixtures/rfc-6352-4791/must_fail/calendar-multiget-empty-hrefs.xml"
    );
    const FIXTURE_CARD_QUERY_MALFORMED: &str = include_str!(
        "../../tests/fixtures/rfc-6352-4791/must_fail/addressbook-query-malformed.xml"
    );
    const FIXTURE_CAL_SYNC_TOKEN_MALFORMED: &str = include_str!(
        "../../tests/fixtures/rfc-6352-4791/must_fail/calendar-sync-token-malformed.xml"
    );

    fn store() -> Arc<PimStore> {
        let tmp = tempdir().unwrap();
        let contacts_db = tmp.path().join("contacts.db");
        let calendar_db = tmp.path().join("calendar.db");
        Box::leak(Box::new(tmp));
        Arc::new(PimStore::new(contacts_db, calendar_db).unwrap())
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
    fn accepts_sync_collection_without_token_as_initial_sync() {
        let token = parse_sync_collection_token(
            r#"<sync-collection xmlns="DAV:"><sync-level>1</sync-level><prop><getetag/></prop></sync-collection>"#,
        )
        .expect("missing sync-token should be treated as initial sync");
        assert_eq!(token, 0);
    }

    #[test]
    fn accepts_empty_sync_collection_token_as_initial_sync() {
        let token = parse_sync_collection_token(
            r#"<sync-collection xmlns="DAV:"><sync-token>   </sync-token><sync-level>1</sync-level><prop><getetag/></prop></sync-collection>"#,
        )
        .expect("empty sync-token should be treated as initial sync");
        assert_eq!(token, 0);
    }

    #[tokio::test]
    async fn unknown_xml_report_payload_returns_bad_request_for_carddav_collection() {
        let store = store();
        let response = handle_report(
            "/dav/uid-1/addressbooks/default/",
            br#"<unknown-report xmlns="DAV:"><foo>bar</foo></unknown-report>"#,
            &AuthRoute {
                account_id: AccountId("uid-1".to_string()),
                primary_email: "alice@proton.me".to_string(),
            },
            &store,
            None,
        )
        .await
        .expect("handler")
        .expect("response");
        assert_eq!(response.status, "400 Bad Request");
        let body = String::from_utf8(response.body).expect("utf8");
        assert!(body.contains("unsupported CardDAV REPORT payload"));
    }

    #[tokio::test]
    async fn unknown_xml_report_payload_returns_bad_request_for_caldav_collection() {
        let store = store();
        let response = handle_report(
            "/dav/uid-1/calendars/default/",
            br#"<unknown-report xmlns="DAV:"><foo>bar</foo></unknown-report>"#,
            &AuthRoute {
                account_id: AccountId("uid-1".to_string()),
                primary_email: "alice@proton.me".to_string(),
            },
            &store,
            None,
        )
        .await
        .expect("handler")
        .expect("response");
        assert_eq!(response.status, "400 Bad Request");
        let body = String::from_utf8(response.body).expect("utf8");
        assert!(body.contains("unsupported CalDAV REPORT payload"));
    }

    #[test]
    fn backfill_cooldown_blocks_immediate_repeat_attempts() {
        let store = store();
        assert!(backfill_cooldown_elapsed(&store, "uid-1", "work").unwrap());

        store
            .set_sync_state_int(
                &caldav_backfill_scope("uid-1", "work"),
                super::epoch_millis(),
            )
            .unwrap();
        assert!(!backfill_cooldown_elapsed(&store, "uid-1", "work").unwrap());
        assert!(backfill_cooldown_elapsed(&store, "uid-1", "other").unwrap());
    }

    #[test]
    fn parses_calendar_time_range_attributes() {
        let range = parse_calendar_time_range_request(FIXTURE_CAL_QUERY_TIME_RANGE)
            .expect("valid time-range should parse");
        assert!(range.start_time_from.is_some());
        assert!(range.start_time_to.is_some());
    }

    #[test]
    fn parses_flexible_time_range_timestamps() {
        let range = parse_calendar_time_range_request(FIXTURE_CAL_QUERY_FLEXIBLE_TIME_RANGE)
            .expect("valid time-range should parse");
        assert!(range.start_time_from.is_some());
        assert!(range.start_time_to.is_some());
    }

    #[test]
    fn parses_calendar_query_request_filters_and_range() {
        let parsed = parse_calendar_query_request(FIXTURE_CAL_QUERY_FILTERS)
            .expect("valid query should parse");

        assert_eq!(parsed.component_filters, vec!["VCALENDAR", "VEVENT"]);
        assert_eq!(parsed.prop_filters, vec!["SUMMARY"]);
        assert!(parsed.range.start_time_from.is_some());
        assert!(parsed.range.start_time_to.is_some());
    }

    #[test]
    fn rejects_invalid_calendar_query_time_range_start() {
        let err = parse_calendar_query_request(FIXTURE_CAL_QUERY_INVALID_TIME_RANGE)
            .expect_err("invalid time should reject");
        assert!(matches!(err, DavError::InvalidRequest(_)));
    }

    #[test]
    fn rejects_invalid_addressbook_query_without_prop_filter_name() {
        let err = parse_addressbook_query_request(FIXTURE_CARD_QUERY_MALFORMED)
            .expect_err("invalid addressbook-query should reject");
        assert!(matches!(err, DavError::InvalidRequest(_)));
    }

    #[test]
    fn rejects_empty_calendar_multiget() {
        let err = parse_calendar_multiget_hrefs(FIXTURE_CAL_MULTIGET_EMPTY)
            .expect_err("missing href should reject");
        assert!(matches!(err, DavError::InvalidRequest(_)));
    }

    #[test]
    fn rejects_malformed_sync_collection_token() {
        let err = parse_sync_collection_token(FIXTURE_CAL_SYNC_TOKEN_MALFORMED)
            .expect_err("invalid sync-token should reject");
        assert!(matches!(err, DavError::InvalidRequest(_)));
    }

    #[test]
    fn deduplicates_calendar_multiget_hrefs() {
        let hrefs = parse_calendar_multiget_hrefs(FIXTURE_CAL_MULTIGET_DEDUP)
            .expect("valid multiget should parse");

        assert_eq!(
            hrefs,
            vec![
                "https://127.0.0.1:8080/dav/uid-1/calendars/work/event-1.ics".to_string(),
                "https://127.0.0.1:8080/dav/uid-1/calendars/work/event-2.ics".to_string(),
            ]
        );
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
    fn fallback_calendar_data_uses_extracted_text_properties() {
        let event = CalendarEvent {
            id: "event-1".to_string(),
            uid: "uid-1".to_string(),
            calendar_id: "work".to_string(),
            start_time: 1_772_675_200,
            end_time: 1_772_678_800,
            calendar_events: vec![CalendarEventPart {
                member_id: String::new(),
                kind: 0,
                data: "SUMMARY:Roadmap Review\nLOCATION:Paris\nDESCRIPTION:Quarterly planning"
                    .to_string(),
                signature: None,
                author: None,
            }],
            ..CalendarEvent::default()
        };

        let rendered = render_report_calendar_data(&event, None, None);
        assert!(rendered.contains("SUMMARY:Roadmap Review\r\n"));
        assert!(rendered.contains("LOCATION:Paris\r\n"));
        assert!(rendered.contains("DESCRIPTION:Quarterly planning\r\n"));
    }

    #[test]
    fn enriches_sparse_ics_with_recovered_text_properties() {
        let event = CalendarEvent {
            id: "event-3".to_string(),
            uid: "uid-3".to_string(),
            calendar_id: "work".to_string(),
            start_time: 1_772_675_200,
            end_time: 1_772_678_800,
            calendar_events: vec![CalendarEventPart {
                member_id: String::new(),
                kind: 0,
                data: "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:uid-3\r\nDTSTART:20260305T120000Z\r\nDTEND:20260305T130000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n".to_string(),
                signature: None,
                author: None,
            }],
            shared_events: vec![CalendarEventPart {
                member_id: String::new(),
                kind: 0,
                data: "SUMMARY:Recovered title\nLOCATION:Recovered place\nDESCRIPTION:Recovered notes"
                    .to_string(),
                signature: None,
                author: None,
            }],
            ..CalendarEvent::default()
        };

        let rendered = render_report_calendar_data(&event, None, None);
        assert!(rendered.contains("SUMMARY:Recovered title\r\n"));
        assert!(rendered.contains("LOCATION:Recovered place\r\n"));
        assert!(rendered.contains("DESCRIPTION:Recovered notes\r\n"));
    }

    #[test]
    fn fallback_calendar_data_escapes_text_values() {
        let event = CalendarEvent {
            id: "event-2".to_string(),
            uid: "uid-2".to_string(),
            calendar_id: "work".to_string(),
            start_time: 1_772_675_200,
            end_time: 1_772_678_800,
            calendar_events: vec![CalendarEventPart {
                member_id: String::new(),
                kind: 0,
                data:
                    "SUMMARY:Sync, Team; Core\nLOCATION:HQ\\Floor 3\nDESCRIPTION:Line 1, Team; Core"
                        .to_string(),
                signature: None,
                author: None,
            }],
            ..CalendarEvent::default()
        };

        let rendered = render_report_calendar_data(&event, None, None);
        assert!(rendered.contains("SUMMARY:Sync\\, Team\\; Core\r\n"));
        assert!(rendered.contains("LOCATION:HQ\\\\Floor 3\r\n"));
        assert!(rendered.contains("DESCRIPTION:Line 1\\, Team\\; Core\r\n"));
    }

    #[test]
    fn enriches_sparse_ics_with_raw_json_fields() {
        let event = CalendarEvent {
            id: "event-4".to_string(),
            uid: "uid-4".to_string(),
            calendar_id: "work".to_string(),
            start_time: 1_772_675_200,
            end_time: 1_772_678_800,
            shared_events: vec![CalendarEventPart {
                member_id: String::new(),
                kind: 3,
                data: "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:uid-4\r\nSUMMARY:Only summary in ICS\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n".to_string(),
                signature: None,
                author: None,
            }],
            ..CalendarEvent::default()
        };
        let raw = serde_json::json!({
            "Summary": "Only summary in ICS",
            "Location": "From raw JSON",
            "Description": "From raw notes"
        });

        let rendered = render_report_calendar_data(&event, Some(&raw), None);
        assert!(rendered.contains("SUMMARY:Only summary in ICS\r\n"));
        assert!(rendered.contains("LOCATION:From raw JSON\r\n"));
        assert!(rendered.contains("DESCRIPTION:From raw notes\r\n"));
    }

    #[test]
    fn falls_back_when_selected_ics_lacks_dtstart() {
        let event = CalendarEvent {
            id: "event-5".to_string(),
            uid: "uid-5".to_string(),
            calendar_id: "work".to_string(),
            start_time: 1_772_675_200,
            end_time: 1_772_678_800,
            shared_events: vec![CalendarEventPart {
                member_id: String::new(),
                kind: 3,
                data: "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:uid-5\r\nSUMMARY:Sparse entry\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n".to_string(),
                signature: None,
                author: None,
            }],
            ..CalendarEvent::default()
        };

        let rendered = render_report_calendar_data(&event, None, None);
        assert!(rendered.contains("UID:uid-5\r\n"));
        assert!(rendered.contains("DTSTART:"));
        assert!(rendered.contains("DTEND:"));
        assert!(rendered.contains("SUMMARY:Sparse entry\r\n"));
    }

    #[test]
    fn escape_xml_drops_invalid_control_characters() {
        let escaped = escape_xml("ok\u{0}bad\u{8}<tag>");
        assert_eq!(escaped, "okbad&lt;tag&gt;");
    }
}
