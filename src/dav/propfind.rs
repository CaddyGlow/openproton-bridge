use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use regex::Regex;

use crate::bridge::auth_router::AuthRoute;
use crate::pim::dav::CalDavRepository;
use crate::pim::query::QueryPage;
use crate::pim::store::PimStore;
use crate::pim::types::StoredCalendar;

use super::discovery;
use super::error::{DavError, Result};
use super::http::DavResponse;
use super::xml::{multistatus_xml_for_propfind, DavPropResource, DavPropfindMode, DavResourceKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavDepth {
    Zero,
    One,
    Infinity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AccountResource {
    Principal,
    ScheduleInbox,
    ScheduleOutbox,
    AddressbooksHome,
    AddressbookDefault,
    CalendarsHome,
    CalendarCollection(String),
}

pub fn parse_depth(headers: &HashMap<String, String>) -> Result<DavDepth> {
    let Some(depth) = headers.get("depth").map(|value| value.trim()) else {
        return Ok(DavDepth::Infinity);
    };
    match depth {
        "0" => Ok(DavDepth::Zero),
        "1" => Ok(DavDepth::One),
        "infinity" => Ok(DavDepth::Infinity),
        _ => Err(DavError::InvalidRequest("invalid Depth header")),
    }
}

pub fn handle_propfind(
    raw_path: &str,
    body: &[u8],
    headers: &HashMap<String, String>,
    auth: &AuthRoute,
) -> Result<DavResponse> {
    handle_propfind_with_store(raw_path, body, headers, auth, None)
}

pub fn handle_propfind_with_store(
    raw_path: &str,
    body: &[u8],
    headers: &HashMap<String, String>,
    auth: &AuthRoute,
    store: Option<&Arc<PimStore>>,
) -> Result<DavResponse> {
    let depth = parse_depth(headers)?;
    let path = normalize_path(raw_path);
    let mode = parse_propfind_mode(body)?;

    if path == discovery::PRINCIPAL_ME_PATH {
        let resources = principal_resources(auth, depth);
        return Ok(multistatus_response(resources, &mode));
    }

    let Some((account_id, target)) = parse_account_resource_path(&path) else {
        return Ok(not_found_response());
    };
    if account_id != auth.account_id.0 {
        return Ok(forbidden_response());
    }

    let resources = match target {
        AccountResource::Principal => principal_resources(auth, depth),
        AccountResource::ScheduleInbox => vec![schedule_inbox_resource(auth)],
        AccountResource::ScheduleOutbox => vec![schedule_outbox_resource(auth)],
        AccountResource::AddressbooksHome => addressbook_home_resources(auth, depth),
        AccountResource::AddressbookDefault => vec![default_addressbook_resource(auth)],
        AccountResource::CalendarsHome => calendar_home_resources(auth, depth, store),
        AccountResource::CalendarCollection(calendar_id) => {
            let calendar = store.and_then(|store| {
                let adapter = crate::pim::dav::StoreBackedDavAdapter::new(store.clone());
                adapter.get_calendar(&calendar_id, false).ok().flatten()
            });
            vec![calendar_collection_resource(
                auth,
                &calendar_id,
                calendar.as_ref(),
                store.map(Arc::as_ref),
            )]
        }
    };
    Ok(multistatus_response(resources, &mode))
}

fn principal_resources(auth: &AuthRoute, depth: DavDepth) -> Vec<DavPropResource> {
    let mut resources = vec![principal_resource(auth)];
    if depth != DavDepth::Zero {
        resources.push(addressbook_home_resource(auth));
        resources.push(calendar_home_resource(auth));
    }
    resources
}

fn addressbook_home_resources(auth: &AuthRoute, depth: DavDepth) -> Vec<DavPropResource> {
    let mut resources = vec![addressbook_home_resource(auth)];
    if depth != DavDepth::Zero {
        resources.push(default_addressbook_resource(auth));
    }
    resources
}

fn calendar_home_resources(
    auth: &AuthRoute,
    depth: DavDepth,
    store: Option<&Arc<PimStore>>,
) -> Vec<DavPropResource> {
    let mut resources = vec![calendar_home_resource(auth)];
    if depth != DavDepth::Zero {
        let mut calendar_ids = HashSet::new();
        if let Some(store) = store {
            let adapter = crate::pim::dav::StoreBackedDavAdapter::new(store.clone());
            if let Ok(calendars) = adapter.list_calendars(
                false,
                QueryPage {
                    limit: 500,
                    offset: 0,
                },
            ) {
                for calendar in calendars {
                    if !should_advertise_calendar(&calendar) {
                        continue;
                    }
                    calendar_ids.insert(calendar.id.clone());
                    resources.push(calendar_collection_resource(
                        auth,
                        &calendar.id,
                        Some(&calendar),
                        Some(store.as_ref()),
                    ));
                }
            }
        }
        if calendar_ids.is_empty() {
            resources.push(default_calendar_resource(auth));
        }
    }
    resources
}

fn non_empty_display_name(name: String) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn principal_resource(auth: &AuthRoute) -> DavPropResource {
    let principal = discovery::principal_path(&auth.account_id.0);
    DavPropResource {
        href: principal.clone(),
        display_name: auth.primary_email.clone(),
        kind: DavResourceKind::Principal,
        current_user_principal: Some(principal),
        principal_url: Some(discovery::principal_path(&auth.account_id.0)),
        principal_collection_set: Some(discovery::principal_collection_set_path()),
        addressbook_home_set: Some(discovery::addressbook_home_path(&auth.account_id.0)),
        calendar_home_set: Some(discovery::calendar_home_path(&auth.account_id.0)),
        calendar_user_addresses: vec![format!("mailto:{}", auth.primary_email)],
        schedule_inbox_url: None,
        schedule_outbox_url: None,
        owner: Some(discovery::principal_path(&auth.account_id.0)),
        current_user_privileges: vec!["read", "write", "write-properties", "bind", "unbind"],
        quota_available_bytes: None,
        quota_used_bytes: None,
        resource_id: Some(auth.account_id.0.clone()),
        calendar_free_busy_set: Vec::new(),
        schedule_calendar_transp: None,
        schedule_default_calendar_url: None,
        calendar_color: None,
        calendar_description: None,
        calendar_ctag: None,
        sync_token: None,
        supported_calendar_components: Vec::new(),
        supported_reports: vec![
            "expand-property",
            "principal-property-search",
            "principal-search-property-set",
        ],
    }
}

fn schedule_inbox_resource(auth: &AuthRoute) -> DavPropResource {
    DavPropResource {
        href: discovery::schedule_inbox_path(&auth.account_id.0),
        display_name: "Inbox".to_string(),
        kind: DavResourceKind::ScheduleInbox,
        current_user_principal: None,
        principal_url: None,
        principal_collection_set: None,
        addressbook_home_set: None,
        calendar_home_set: None,
        calendar_user_addresses: Vec::new(),
        schedule_inbox_url: None,
        schedule_outbox_url: None,
        owner: Some(discovery::principal_path(&auth.account_id.0)),
        current_user_privileges: vec!["read", "write"],
        quota_available_bytes: None,
        quota_used_bytes: None,
        resource_id: None,
        calendar_free_busy_set: Vec::new(),
        schedule_calendar_transp: None,
        schedule_default_calendar_url: None,
        calendar_color: None,
        calendar_description: None,
        calendar_ctag: None,
        sync_token: None,
        supported_calendar_components: Vec::new(),
        supported_reports: Vec::new(),
    }
}

fn schedule_outbox_resource(auth: &AuthRoute) -> DavPropResource {
    DavPropResource {
        href: discovery::schedule_outbox_path(&auth.account_id.0),
        display_name: "Outbox".to_string(),
        kind: DavResourceKind::ScheduleOutbox,
        current_user_principal: None,
        principal_url: None,
        principal_collection_set: None,
        addressbook_home_set: None,
        calendar_home_set: None,
        calendar_user_addresses: Vec::new(),
        schedule_inbox_url: None,
        schedule_outbox_url: None,
        owner: Some(discovery::principal_path(&auth.account_id.0)),
        current_user_privileges: vec!["read", "write"],
        quota_available_bytes: None,
        quota_used_bytes: None,
        resource_id: None,
        calendar_free_busy_set: Vec::new(),
        schedule_calendar_transp: None,
        schedule_default_calendar_url: None,
        calendar_color: None,
        calendar_description: None,
        calendar_ctag: None,
        sync_token: None,
        supported_calendar_components: Vec::new(),
        supported_reports: Vec::new(),
    }
}

fn addressbook_home_resource(auth: &AuthRoute) -> DavPropResource {
    DavPropResource {
        href: discovery::addressbook_home_path(&auth.account_id.0),
        display_name: "Address Books".to_string(),
        kind: DavResourceKind::AddressbookHome,
        current_user_principal: None,
        principal_url: None,
        principal_collection_set: None,
        addressbook_home_set: None,
        calendar_home_set: None,
        calendar_user_addresses: Vec::new(),
        schedule_inbox_url: None,
        schedule_outbox_url: None,
        owner: Some(discovery::principal_path(&auth.account_id.0)),
        current_user_privileges: vec!["read"],
        quota_available_bytes: None,
        quota_used_bytes: None,
        resource_id: None,
        calendar_free_busy_set: Vec::new(),
        schedule_calendar_transp: None,
        schedule_default_calendar_url: None,
        calendar_color: None,
        calendar_description: None,
        calendar_ctag: None,
        sync_token: None,
        supported_calendar_components: Vec::new(),
        supported_reports: Vec::new(),
    }
}

fn default_addressbook_resource(auth: &AuthRoute) -> DavPropResource {
    DavPropResource {
        href: discovery::default_addressbook_path(&auth.account_id.0),
        display_name: "Default Address Book".to_string(),
        kind: DavResourceKind::Addressbook,
        current_user_principal: None,
        principal_url: None,
        principal_collection_set: None,
        addressbook_home_set: None,
        calendar_home_set: None,
        calendar_user_addresses: Vec::new(),
        schedule_inbox_url: None,
        schedule_outbox_url: None,
        owner: Some(discovery::principal_path(&auth.account_id.0)),
        current_user_privileges: vec!["read"],
        quota_available_bytes: None,
        quota_used_bytes: None,
        resource_id: None,
        calendar_free_busy_set: Vec::new(),
        schedule_calendar_transp: None,
        schedule_default_calendar_url: None,
        calendar_color: None,
        calendar_description: None,
        calendar_ctag: None,
        sync_token: None,
        supported_calendar_components: Vec::new(),
        supported_reports: Vec::new(),
    }
}

fn calendar_home_resource(auth: &AuthRoute) -> DavPropResource {
    DavPropResource {
        href: discovery::calendar_home_path(&auth.account_id.0),
        display_name: "Calendars".to_string(),
        kind: DavResourceKind::CalendarHome,
        current_user_principal: None,
        principal_url: None,
        principal_collection_set: None,
        addressbook_home_set: None,
        calendar_home_set: None,
        calendar_user_addresses: Vec::new(),
        schedule_inbox_url: None,
        schedule_outbox_url: None,
        owner: Some(discovery::principal_path(&auth.account_id.0)),
        current_user_privileges: vec!["read"],
        quota_available_bytes: None,
        quota_used_bytes: None,
        resource_id: None,
        calendar_free_busy_set: Vec::new(),
        schedule_calendar_transp: None,
        schedule_default_calendar_url: None,
        calendar_color: None,
        calendar_description: None,
        calendar_ctag: None,
        sync_token: None,
        supported_calendar_components: Vec::new(),
        supported_reports: Vec::new(),
    }
}

fn default_calendar_resource(auth: &AuthRoute) -> DavPropResource {
    calendar_collection_resource(auth, "default", None, None)
}

fn calendar_collection_resource(
    auth: &AuthRoute,
    calendar_id: &str,
    calendar: Option<&StoredCalendar>,
    store: Option<&PimStore>,
) -> DavPropResource {
    let display_name = calendar_display_name(calendar_id, calendar);
    let href = format!("/dav/{}/calendars/{calendar_id}/", auth.account_id.0);
    let version = calendar_collection_version(calendar_id, calendar, store);
    DavPropResource {
        href: href.clone(),
        display_name,
        kind: DavResourceKind::Calendar,
        current_user_principal: None,
        principal_url: None,
        principal_collection_set: None,
        addressbook_home_set: None,
        calendar_home_set: None,
        calendar_user_addresses: Vec::new(),
        schedule_inbox_url: None,
        schedule_outbox_url: None,
        owner: Some(discovery::principal_path(&auth.account_id.0)),
        current_user_privileges: vec!["read", "write", "write-properties", "bind", "unbind"],
        quota_available_bytes: Some(1_000_000_000),
        quota_used_bytes: Some(0),
        resource_id: Some(calendar_id.to_string()),
        calendar_free_busy_set: vec![href.clone()],
        schedule_calendar_transp: None,
        schedule_default_calendar_url: None,
        calendar_color: calendar
            .and_then(|calendar| non_empty_display_name(calendar.color.clone())),
        calendar_description: calendar
            .and_then(|calendar| non_empty_display_name(calendar.description.clone())),
        calendar_ctag: Some(calendar_collection_tag(
            &auth.account_id.0,
            calendar_id,
            version,
        )),
        sync_token: Some(calendar_sync_token(
            &auth.account_id.0,
            calendar_id,
            version,
        )),
        supported_calendar_components: vec!["VEVENT"],
        supported_reports: vec!["calendar-query", "calendar-multiget", "sync-collection"],
    }
}

fn calendar_collection_version(
    calendar_id: &str,
    calendar: Option<&StoredCalendar>,
    store: Option<&PimStore>,
) -> i64 {
    let base_version = calendar.map(|calendar| calendar.updated_at_ms).unwrap_or_default();
    let store_version = store
        .and_then(|store| store.calendar_collection_version(calendar_id).ok())
        .unwrap_or_default();
    base_version.max(store_version)
}

fn calendar_display_name(calendar_id: &str, calendar: Option<&StoredCalendar>) -> String {
    if let Some(calendar) = calendar {
        if let Some(display_name) = non_empty_display_name(calendar.name.clone()) {
            return display_name;
        }

        if calendar.calendar_type == 2 {
            return "Primary Calendar".to_string();
        }
    }

    if calendar_id == "default" {
        "Default Calendar".to_string()
    } else {
        "Calendar".to_string()
    }
}

fn should_advertise_calendar(calendar: &StoredCalendar) -> bool {
    calendar.calendar_type >= 0 && !looks_like_local_uuid(&calendar.id)
}

fn looks_like_local_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    let bytes = value.as_bytes();
    for (idx, byte) in bytes.iter().enumerate() {
        let is_hyphen = matches!(idx, 8 | 13 | 18 | 23);
        if is_hyphen {
            if *byte != b'-' {
                return false;
            }
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn calendar_collection_tag(account_id: &str, calendar_id: &str, version: i64) -> String {
    format!("{account_id}-{calendar_id}-{}", version.max(0))
}

fn calendar_sync_token(account_id: &str, calendar_id: &str, version: i64) -> String {
    format!(
        "https://openproton.local/dav/{account_id}/calendars/{calendar_id}/sync/{}",
        version.max(0)
    )
}

fn parse_account_resource_path(path: &str) -> Option<(String, AccountResource)> {
    let mut segments = path
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty());
    if segments.next()? != "dav" {
        return None;
    }
    let account_id = segments.next()?.to_string();
    let target = match (segments.next()?, segments.next(), segments.next()) {
        ("principal", None, None) => AccountResource::Principal,
        ("principal", Some("inbox"), None) => AccountResource::ScheduleInbox,
        ("principal", Some("outbox"), None) => AccountResource::ScheduleOutbox,
        ("addressbooks", None, None) => AccountResource::AddressbooksHome,
        ("addressbooks", Some("default"), None) => AccountResource::AddressbookDefault,
        ("calendars", None, None) => AccountResource::CalendarsHome,
        ("calendars", Some(calendar_id), None) => {
            if calendar_id.is_empty() {
                return None;
            }
            AccountResource::CalendarCollection(calendar_id.to_string())
        }
        _ => return None,
    };
    Some((account_id, target))
}

fn multistatus_response(resources: Vec<DavPropResource>, mode: &DavPropfindMode) -> DavResponse {
    DavResponse {
        status: "207 Multi-Status",
        headers: vec![("Content-Type", "application/xml; charset=utf-8".to_string())],
        body: multistatus_xml_for_propfind(&resources, mode),
    }
}

fn parse_propfind_mode(body: &[u8]) -> Result<DavPropfindMode> {
    if body.is_empty() {
        return Ok(DavPropfindMode::AllProp);
    }
    let body = std::str::from_utf8(body)
        .map_err(|_| DavError::InvalidRequest("PROPFIND body is not utf-8"))?;
    if body.contains("propname") {
        return Ok(DavPropfindMode::PropName);
    }
    if !body.contains("prop") {
        return Ok(DavPropfindMode::AllProp);
    }
    let prop_re = Regex::new(
        r"(?is)<(?:[A-Za-z0-9_-]+:)?prop\b[^>]*>(?P<body>.*?)</(?:[A-Za-z0-9_-]+:)?prop>",
    )
    .expect("prop regex should compile");
    let tag_re = Regex::new(r"(?is)<(?:[A-Za-z0-9_-]+:)?(?P<name>[A-Za-z0-9_-]+)\b")
        .expect("tag regex should compile");
    let Some(prop_body) = prop_re
        .captures(body)
        .and_then(|caps| caps.name("body"))
        .map(|m| m.as_str())
    else {
        return Ok(DavPropfindMode::AllProp);
    };
    let requested = tag_re
        .captures_iter(prop_body)
        .filter_map(|caps| caps.name("name"))
        .map(|name| name.as_str().to_string())
        .filter(|name| name != "prop")
        .collect::<HashSet<_>>();
    if requested.is_empty() {
        Ok(DavPropfindMode::AllProp)
    } else {
        Ok(DavPropfindMode::Prop(requested))
    }
}

fn forbidden_response() -> DavResponse {
    DavResponse {
        status: "403 Forbidden",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"forbidden\n".to_vec(),
    }
}

fn not_found_response() -> DavResponse {
    DavResponse {
        status: "404 Not Found",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"not found\n".to_vec(),
    }
}

fn normalize_path(path: &str) -> String {
    let mut normalized = path
        .split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(path)
        .trim()
        .to_string();
    if normalized.is_empty() {
        normalized = "/".to_string();
    }
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    if normalized.ends_with('/') {
        normalized
    } else {
        format!("{normalized}/")
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::api::calendar::{Calendar, CalendarEvent, CalendarEventPart};
    use crate::bridge::auth_router::AuthRoute;
    use crate::bridge::types::AccountId;
    use crate::pim::store::PimStore;

    use super::{handle_propfind, handle_propfind_with_store, parse_depth, DavDepth};

    fn auth() -> AuthRoute {
        AuthRoute {
            account_id: AccountId("uid-1".to_string()),
            primary_email: "alice@proton.me".to_string(),
        }
    }

    fn store() -> Arc<PimStore> {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let db_path = tmp.path().join("account.db");
        Box::leak(Box::new(tmp));
        Arc::new(PimStore::new(db_path).expect("store"))
    }

    #[test]
    fn parses_depth_values() {
        let mut headers = HashMap::new();
        headers.insert("depth".to_string(), "1".to_string());
        assert_eq!(parse_depth(&headers).unwrap(), DavDepth::One);
    }

    #[test]
    fn propfind_principal_me_returns_multistatus() {
        let response =
            handle_propfind("/dav/principals/me/", &[], &HashMap::new(), &auth()).expect("response");
        let body = String::from_utf8(response.body).expect("utf8");
        assert_eq!(response.status, "207 Multi-Status");
        assert!(body.contains("<d:multistatus"));
        assert!(body.contains("/dav/uid-1/principal/"));
    }

    #[test]
    fn propfind_rejects_cross_account_paths() {
        let response =
            handle_propfind("/dav/uid-2/principal/", &[], &HashMap::new(), &auth()).expect("response");
        assert_eq!(response.status, "403 Forbidden");
    }

    #[test]
    fn propfind_calendar_home_uses_non_empty_names_and_skips_fake_default_when_store_has_rows() {
        let store = store();
        store
            .upsert_calendar(&Calendar {
                id: "cal-1".to_string(),
                name: "".to_string(),
                description: "".to_string(),
                color: "#000000".to_string(),
                display: 1,
                calendar_type: 0,
                flags: 0,
            })
            .expect("upsert calendar");

        let mut headers = HashMap::new();
        headers.insert("depth".to_string(), "1".to_string());
        let response =
            handle_propfind_with_store("/dav/uid-1/calendars/", &[], &headers, &auth(), Some(&store))
                .expect("response");
        let body = String::from_utf8(response.body).expect("utf8");

        assert!(body.contains("/dav/uid-1/calendars/cal-1/"));
        assert!(body.contains("<d:displayname>Calendar</d:displayname>"));
        assert!(!body.contains("/dav/uid-1/calendars/default/"));
    }

    #[test]
    fn propfind_primary_calendar_uses_readable_fallback_name() {
        let store = store();
        store
            .upsert_calendar(&Calendar {
                id: "opaque-cal-id".to_string(),
                name: "".to_string(),
                description: "".to_string(),
                color: "".to_string(),
                display: 1,
                calendar_type: 2,
                flags: 0,
            })
            .expect("upsert calendar");

        let response = handle_propfind_with_store(
            "/dav/uid-1/calendars/opaque-cal-id/",
            &[],
            &HashMap::new(),
            &auth(),
            Some(&store),
        )
        .expect("response");
        let body = String::from_utf8(response.body).expect("utf8");

        assert!(body.contains("<d:displayname>Primary Calendar</d:displayname>"));
        assert!(!body.contains("<d:displayname>Calendar opaque-cal-id</d:displayname>"));
    }

    #[test]
    fn propfind_calendar_home_skips_local_uuid_calendars() {
        let store = store();
        store
            .upsert_calendar(&Calendar {
                id: "7A60F3B9-C6B7-429D-8AB6-8029FB968C50".to_string(),
                name: "Apple Local".to_string(),
                description: "".to_string(),
                color: "".to_string(),
                display: 1,
                calendar_type: -1,
                flags: 0,
            })
            .expect("upsert local calendar");
        store
            .upsert_calendar(&Calendar {
                id: "cal-1".to_string(),
                name: "Work".to_string(),
                description: "".to_string(),
                color: "".to_string(),
                display: 1,
                calendar_type: 0,
                flags: 0,
            })
            .expect("upsert proton calendar");

        let mut headers = HashMap::new();
        headers.insert("depth".to_string(), "1".to_string());
        let response =
            handle_propfind_with_store("/dav/uid-1/calendars/", &[], &headers, &auth(), Some(&store))
                .expect("response");
        let body = String::from_utf8(response.body).expect("utf8");

        assert!(body.contains("/dav/uid-1/calendars/cal-1/"));
        assert!(!body.contains("/dav/uid-1/calendars/7A60F3B9-C6B7-429D-8AB6-8029FB968C50/"));
    }

    #[test]
    fn propfind_calendar_collection_ctag_tracks_event_updates() {
        let store = store();
        store
            .upsert_calendar(&Calendar {
                id: "work".to_string(),
                name: "Work".to_string(),
                description: "".to_string(),
                color: "#3A7AFE".to_string(),
                display: 1,
                calendar_type: 0,
                flags: 0,
            })
            .expect("upsert calendar");

        let initial = handle_propfind_with_store(
            "/dav/uid-1/calendars/work/",
            &[],
            &HashMap::new(),
            &auth(),
            Some(&store),
        )
        .expect("response");
        let initial_body = String::from_utf8(initial.body).expect("utf8");

        std::thread::sleep(std::time::Duration::from_millis(2));
        store
            .upsert_calendar_event(&CalendarEvent {
                id: "evt-1".to_string(),
                uid: "evt-1".to_string(),
                calendar_id: "work".to_string(),
                shared_event_id: "shared-evt-1".to_string(),
                create_time: 1,
                last_edit_time: 2,
                start_time: 1_741_178_800,
                end_time: 1_741_182_400,
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
                    data: "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_string(),
                    signature: None,
                    author: None,
                }],
                attendees_events: vec![],
                personal_events: vec![],
            })
            .expect("upsert event");

        let updated = handle_propfind_with_store(
            "/dav/uid-1/calendars/work/",
            &[],
            &HashMap::new(),
            &auth(),
            Some(&store),
        )
        .expect("response");
        let updated_body = String::from_utf8(updated.body).expect("utf8");

        assert!(initial_body.contains("<cs:getctag>uid-1-work-"));
        assert!(updated_body.contains("<cs:getctag>uid-1-work-"));
        assert_ne!(initial_body, updated_body);
    }

    #[test]
    fn propfind_prop_request_filters_to_requested_properties() {
        let store = store();
        store
            .upsert_calendar(&Calendar {
                id: "work".to_string(),
                name: "Work".to_string(),
                description: "Team".to_string(),
                color: "#00AAFF".to_string(),
                display: 1,
                calendar_type: 0,
                flags: 0,
            })
            .expect("upsert calendar");

        let mut headers = HashMap::new();
        headers.insert("depth".to_string(), "0".to_string());
        let body = br#"<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/"><d:prop><d:displayname/><cs:getctag/></d:prop></d:propfind>"#;
        let response = handle_propfind_with_store(
            "/dav/uid-1/calendars/work/",
            body,
            &headers,
            &auth(),
            Some(&store),
        )
        .expect("response");
        let wire = String::from_utf8(response.body).expect("utf8");

        assert!(wire.contains("<d:displayname>Work</d:displayname>"));
        assert!(wire.contains("<cs:getctag>"));
        assert!(!wire.contains("<d:sync-token>"));
        assert!(!wire.contains("<d:supported-report-set>"));
    }
}
