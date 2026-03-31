use gluon_rs_dav::discovery;
use gluon_rs_dav::propfind::non_empty_display_name;
use gluon_rs_dav::types::AuthContext;
use gluon_rs_dav::xml::{DavPropResource, DavResourceKind, WebDavPushConfig};

use crate::store::CalendarStore;
use crate::types::StoredCalendar;

pub fn calendar_home_resource(auth: &AuthContext) -> DavPropResource {
    DavPropResource {
        href: discovery::calendar_home_path(&auth.account_id),
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
        owner: Some(discovery::principal_path(&auth.account_id)),
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
        push_config: None,
    }
}

pub fn calendar_collection_resource(
    auth: &AuthContext,
    calendar_id: &str,
    calendar: Option<&StoredCalendar>,
    store: Option<&CalendarStore>,
    vapid_public_key: Option<&str>,
) -> DavPropResource {
    let display_name = calendar_display_name(calendar_id, calendar, store);
    let href = format!("/dav/{}/calendars/{calendar_id}/", auth.account_id);
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
        owner: Some(discovery::principal_path(&auth.account_id)),
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
            &auth.account_id,
            calendar_id,
            version,
        )),
        sync_token: Some(calendar_sync_token(&auth.account_id, calendar_id, version)),
        supported_calendar_components: vec!["VEVENT"],
        supported_reports: vec!["calendar-query", "calendar-multiget", "sync-collection"],
        push_config: vapid_public_key.map(|key| WebDavPushConfig {
            vapid_public_key: key.to_string(),
            topic: format!("{}/{calendar_id}", auth.account_id),
        }),
    }
}

pub fn default_calendar_resource(auth: &AuthContext) -> DavPropResource {
    calendar_collection_resource(auth, "default", None, None, None)
}

pub fn should_advertise_calendar(calendar: &StoredCalendar) -> bool {
    calendar.calendar_type >= 0 && !gluon_rs_dav::looks_like_local_uuid(&calendar.id)
}

fn calendar_collection_version(
    calendar_id: &str,
    calendar: Option<&StoredCalendar>,
    store: Option<&CalendarStore>,
) -> i64 {
    let base_version = calendar
        .map(|calendar| calendar.updated_at_ms)
        .unwrap_or_default();
    let store_version = store
        .and_then(|store| store.calendar_collection_version(calendar_id).ok())
        .unwrap_or_default();
    base_version.max(store_version)
}

fn calendar_display_name(
    calendar_id: &str,
    calendar: Option<&StoredCalendar>,
    store: Option<&CalendarStore>,
) -> String {
    if let Some(calendar) = calendar {
        if let Some(display_name) = non_empty_display_name(calendar.name.clone()) {
            return display_name;
        }
    }

    if let Some(store) = store {
        if let Ok(Some(member_name)) = store.get_calendar_member_name(calendar_id) {
            return member_name;
        }
    }

    if calendar_id == "default" {
        "Default Calendar".to_string()
    } else {
        "Calendar".to_string()
    }
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
