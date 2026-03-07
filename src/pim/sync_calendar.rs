use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

use crate::api::calendar;
use crate::api::client::ProtonClient;

use super::store::PimStore;
use super::{PimError, Result};

const CALENDAR_LAST_HORIZON_SYNC_KEY: &str = "calendar.last_horizon_sync_ms";

fn is_remote_calendar_id(calendar_id: &str) -> bool {
    !looks_like_local_uuid(calendar_id)
}

fn looks_like_local_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }

    value.chars().enumerate().all(|(index, ch)| {
        (matches!(index, 8 | 13 | 18 | 23) && ch == '-') || ch.is_ascii_hexdigit()
    })
}

#[derive(Debug, Clone, Default)]
pub struct BootstrapCalendarsSummary {
    pub calendars_seen: usize,
    pub calendars_soft_deleted: usize,
    pub members_upserted: usize,
    pub keys_upserted: usize,
    pub settings_upserted: usize,
    pub events_upserted: usize,
    pub events_soft_deleted: usize,
}

pub async fn bootstrap_calendars(
    client: &ProtonClient,
    store: &PimStore,
    event_query: &calendar::CalendarEventsQuery,
) -> Result<BootstrapCalendarsSummary> {
    let calendars = super::run_with_api_retry(|| calendar::get_calendars(client))
        .await
        .map_err(map_api_error)?;
    let mut seen_calendar_ids = HashSet::new();
    let mut summary = BootstrapCalendarsSummary::default();

    for cal in calendars {
        seen_calendar_ids.insert(cal.id.clone());
        store.upsert_calendar(&cal)?;
        summary.calendars_seen += 1;

        let members = super::run_with_api_retry(|| calendar::get_calendar_members(client, &cal.id))
            .await
            .map_err(map_api_error)?;
        for member in members {
            store.upsert_calendar_member(&member)?;
            summary.members_upserted += 1;
        }

        let keys = super::run_with_api_retry(|| calendar::get_calendar_keys(client, &cal.id))
            .await
            .map_err(map_api_error)?;
        for key in keys {
            store.upsert_calendar_key(&key)?;
            summary.keys_upserted += 1;
        }

        let settings =
            super::run_with_api_retry(|| calendar::get_calendar_settings(client, &cal.id))
                .await
                .map_err(map_api_error)?;
        store.upsert_calendar_settings(&settings)?;
        summary.settings_upserted += 1;

        let latest_model_event_id = super::run_with_api_retry(|| {
            calendar::get_calendar_model_event_latest(client, &cal.id)
        })
        .await
        .map_err(map_api_error)?;
        store.set_sync_state_text(
            &format!("calendar.{}.model_event_id", cal.id),
            &latest_model_event_id,
        )?;

        let events = super::run_with_api_retry(|| {
            calendar::get_calendar_events(client, &cal.id, event_query)
        })
        .await
        .map_err(map_api_error)?;
        let mut fetched_event_ids = HashSet::new();
        for event in events {
            if !event.id.trim().is_empty() {
                fetched_event_ids.insert(event.id.clone());
            }
            store.upsert_calendar_event(&event)?;
            summary.events_upserted += 1;
        }
        summary.events_soft_deleted += reconcile_removed_calendar_events(
            store,
            &cal.id,
            &fetched_event_ids,
            event_query.start,
            event_query.end,
        )?;
    }

    let cached_ids = load_cached_calendar_ids(store)?;
    for cached_id in cached_ids {
        if !seen_calendar_ids.contains(&cached_id) {
            store.soft_delete_calendar(&cached_id)?;
            summary.calendars_soft_deleted += 1;
            summary.events_soft_deleted +=
                reconcile_removed_calendar_events(store, &cached_id, &HashSet::new(), None, None)?;
        }
    }

    let finished_at_ms = epoch_millis() as i64;
    store.set_sync_state_int("calendar.last_full_sync_ms", finished_at_ms)?;
    store.set_sync_state_int(CALENDAR_LAST_HORIZON_SYNC_KEY, finished_at_ms)?;
    Ok(summary)
}

fn load_cached_calendar_ids(store: &PimStore) -> Result<HashSet<String>> {
    let conn = Connection::open(store.db_path())?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    let mut stmt = conn.prepare("SELECT id FROM pim_calendars WHERE deleted = 0")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let ids = rows
        .collect::<std::result::Result<HashSet<String>, _>>()?
        .into_iter()
        .filter(|calendar_id| is_remote_calendar_id(calendar_id))
        .collect();
    Ok(ids)
}

#[derive(Debug, Clone, Default)]
pub struct RefreshCalendarEventsSummary {
    pub calendars_scanned: usize,
    pub events_upserted: usize,
    pub events_soft_deleted: usize,
}

pub async fn refresh_calendar_event_horizon(
    client: &ProtonClient,
    store: &PimStore,
    event_query: &calendar::CalendarEventsQuery,
) -> Result<RefreshCalendarEventsSummary> {
    let mut summary = RefreshCalendarEventsSummary::default();
    for calendar_id in load_active_calendar_ids(store)? {
        summary.calendars_scanned += 1;
        let events = super::run_with_api_retry(|| {
            calendar::get_calendar_events(client, &calendar_id, event_query)
        })
        .await
        .map_err(map_api_error)?;
        let mut fetched_event_ids = HashSet::new();
        for event in events {
            if !event.id.trim().is_empty() {
                fetched_event_ids.insert(event.id.clone());
            }
            store.upsert_calendar_event(&event)?;
            summary.events_upserted += 1;
        }
        summary.events_soft_deleted += reconcile_removed_calendar_events(
            store,
            &calendar_id,
            &fetched_event_ids,
            event_query.start,
            event_query.end,
        )?;
    }
    store.set_sync_state_int(CALENDAR_LAST_HORIZON_SYNC_KEY, epoch_millis() as i64)?;
    Ok(summary)
}

fn load_active_calendar_ids(store: &PimStore) -> Result<Vec<String>> {
    let conn = Connection::open(store.db_path())?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    let mut stmt = conn.prepare("SELECT id FROM pim_calendars WHERE deleted = 0 ORDER BY id")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    Ok(rows
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|calendar_id| is_remote_calendar_id(calendar_id))
        .collect())
}

fn reconcile_removed_calendar_events(
    store: &PimStore,
    calendar_id: &str,
    fetched_event_ids: &HashSet<String>,
    start_from: Option<i64>,
    start_to: Option<i64>,
) -> Result<usize> {
    let mut soft_deleted = 0usize;
    let cached_ids = load_cached_calendar_event_ids(store, calendar_id, start_from, start_to)?;
    for event_id in cached_ids {
        if !fetched_event_ids.contains(&event_id) {
            store.soft_delete_calendar_event(&event_id)?;
            soft_deleted += 1;
        }
    }
    Ok(soft_deleted)
}

fn load_cached_calendar_event_ids(
    store: &PimStore,
    calendar_id: &str,
    start_from: Option<i64>,
    start_to: Option<i64>,
) -> Result<HashSet<String>> {
    let conn = Connection::open(store.db_path())?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    let mut stmt = conn.prepare(
        "SELECT id
         FROM pim_calendar_events
         WHERE calendar_id = ?1
           AND deleted = 0
           AND (?2 IS NULL OR start_time >= ?2)
           AND (?3 IS NULL OR start_time <= ?3)",
    )?;
    let rows = stmt.query_map(
        rusqlite::params![calendar_id, start_from, start_to],
        |row| row.get::<_, String>(0),
    )?;
    Ok(rows.collect::<std::result::Result<HashSet<_>, _>>()?)
}

fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn map_api_error(err: crate::api::error::ApiError) -> PimError {
    PimError::InvalidState(format!("calendar bootstrap API error: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::calendar::CalendarEventsQuery;
    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup_authenticated_client(server: &MockServer) -> ProtonClient {
        ProtonClient::authenticated(&server.uri(), "test-uid", "test-token").unwrap()
    }

    fn setup_store() -> PimStore {
        let tmp = tempdir().unwrap();
        let db_path = tmp.path().join("account.db");
        Box::leak(Box::new(tmp));
        PimStore::new(db_path).unwrap()
    }

    async fn mount_calendar_bootstrap_mocks(
        server: &MockServer,
        calendar_id: &str,
        model_id: &str,
    ) {
        let member_id = format!("member-{calendar_id}");
        let key_id = format!("key-{calendar_id}");
        let settings_id = format!("settings-{calendar_id}");
        let event_id = format!("event-{calendar_id}");
        let event_uid = format!("uid-{calendar_id}");

        Mock::given(method("GET"))
            .and(path(format!("/calendar/v1/{calendar_id}/members")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Members": [{
                    "ID": member_id,
                    "CalendarID": calendar_id,
                    "Email": "alice@proton.me",
                    "Color": "#00AAFF",
                    "Display": 1,
                    "Permissions": 2
                }]
            })))
            .mount(server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/calendar/v1/{calendar_id}/keys")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Keys": [{
                    "ID": key_id,
                    "CalendarID": calendar_id,
                    "PassphraseID": "pp-1",
                    "PrivateKey": "private",
                    "Flags": 0
                }]
            })))
            .mount(server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/calendar/v1/{calendar_id}/settings")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "CalendarSettings": {
                    "ID": settings_id,
                    "CalendarID": calendar_id,
                    "DefaultEventDuration": 30,
                    "DefaultPartDayNotifications": [],
                    "DefaultFullDayNotifications": []
                }
            })))
            .mount(server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!(
                "/calendar/v1/{calendar_id}/modelevents/latest"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "CalendarModelEventID": model_id
            })))
            .mount(server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/calendar/v1/{calendar_id}/events")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Events": [{
                    "ID": event_id,
                    "UID": event_uid,
                    "CalendarID": calendar_id,
                    "SharedEventID": "shared-1",
                    "CreateTime": 1700000000,
                    "LastEditTime": 1700000001,
                    "StartTime": 1700001000,
                    "StartTimezone": "UTC",
                    "EndTime": 1700004600,
                    "EndTimezone": "UTC",
                    "FullDay": 0,
                    "Author": "alice@proton.me",
                    "Permissions": 2
                }]
            })))
            .mount(server)
            .await;
    }

    fn calendar_event_json(
        calendar_id: &str,
        event_id: &str,
        start_time: i64,
    ) -> serde_json::Value {
        serde_json::json!({
            "ID": event_id,
            "UID": format!("uid-{event_id}"),
            "CalendarID": calendar_id,
            "SharedEventID": format!("shared-{event_id}"),
            "CreateTime": 1700000000,
            "LastEditTime": 1700000001,
            "StartTime": start_time,
            "StartTimezone": "UTC",
            "EndTime": start_time + 3600,
            "EndTimezone": "UTC",
            "FullDay": 0,
            "Author": "alice@proton.me",
            "Permissions": 2
        })
    }

    #[tokio::test]
    async fn bootstrap_calendars_multi_calendar_upserts_all_resources() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;
        let store = setup_store();

        Mock::given(method("GET"))
            .and(path("/calendar/v1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Calendars": [
                    {
                        "ID": "cal-1",
                        "Name": "Personal",
                        "Description": "Main",
                        "Color": "#00AAFF",
                        "Display": 1,
                        "Type": 0,
                        "Flags": 0
                    },
                    {
                        "ID": "cal-2",
                        "Name": "Work",
                        "Description": "Work",
                        "Color": "#FFAA00",
                        "Display": 1,
                        "Type": 0,
                        "Flags": 0
                    }
                ]
            })))
            .mount(&server)
            .await;

        mount_calendar_bootstrap_mocks(&server, "cal-1", "cme-1").await;
        mount_calendar_bootstrap_mocks(&server, "cal-2", "cme-2").await;

        let summary = bootstrap_calendars(&client, &store, &CalendarEventsQuery::default())
            .await
            .unwrap();

        assert_eq!(summary.calendars_seen, 2);
        assert_eq!(summary.members_upserted, 2);
        assert_eq!(summary.keys_upserted, 2);
        assert_eq!(summary.settings_upserted, 2);
        assert_eq!(summary.events_upserted, 2);
        assert_eq!(summary.events_soft_deleted, 0);

        let conn = Connection::open(store.db_path()).unwrap();
        let calendars_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pim_calendars WHERE deleted = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let events_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pim_calendar_events WHERE deleted = 0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(calendars_count, 2);
        assert_eq!(events_count, 2);
    }

    #[tokio::test]
    async fn bootstrap_calendars_persists_cursors_and_last_sync_state() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;
        let store = setup_store();

        Mock::given(method("GET"))
            .and(path("/calendar/v1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Calendars": [{
                    "ID": "cal-1",
                    "Name": "Personal",
                    "Description": "Main",
                    "Color": "#00AAFF",
                    "Display": 1,
                    "Type": 0,
                    "Flags": 0
                }]
            })))
            .mount(&server)
            .await;

        mount_calendar_bootstrap_mocks(&server, "cal-1", "cme-100").await;

        let summary = bootstrap_calendars(&client, &store, &CalendarEventsQuery::default())
            .await
            .unwrap();

        assert_eq!(summary.calendars_seen, 1);
        assert_eq!(summary.events_soft_deleted, 0);
        assert_eq!(
            store
                .get_sync_state_text("calendar.cal-1.model_event_id")
                .unwrap()
                .as_deref(),
            Some("cme-100")
        );
        let last_sync = store
            .get_sync_state_int("calendar.last_full_sync_ms")
            .unwrap()
            .unwrap();
        assert!(last_sync > 0);
    }

    #[tokio::test]
    async fn bootstrap_calendars_soft_deletes_missing_cached_calendars() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;
        let store = setup_store();

        store
            .upsert_calendar(&calendar::Calendar {
                id: "stale-cal".to_string(),
                name: "Stale".to_string(),
                description: "".to_string(),
                color: "#000000".to_string(),
                display: 1,
                calendar_type: 0,
                flags: 0,
            })
            .unwrap();

        Mock::given(method("GET"))
            .and(path("/calendar/v1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Calendars": [{
                    "ID": "cal-1",
                    "Name": "Personal",
                    "Description": "Main",
                    "Color": "#00AAFF",
                    "Display": 1,
                    "Type": 0,
                    "Flags": 0
                }]
            })))
            .mount(&server)
            .await;

        mount_calendar_bootstrap_mocks(&server, "cal-1", "cme-1").await;

        let summary = bootstrap_calendars(&client, &store, &CalendarEventsQuery::default())
            .await
            .unwrap();

        assert_eq!(summary.calendars_soft_deleted, 1);
        assert_eq!(summary.events_soft_deleted, 0);
        let conn = Connection::open(store.db_path()).unwrap();
        let stale_deleted: i64 = conn
            .query_row(
                "SELECT deleted FROM pim_calendars WHERE id = 'stale-cal'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stale_deleted, 1);
    }

    #[tokio::test]
    async fn refresh_calendar_event_horizon_updates_event_rows_and_state() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;
        let store = setup_store();

        store
            .upsert_calendar(&calendar::Calendar {
                id: "cal-1".to_string(),
                name: "Personal".to_string(),
                description: "".to_string(),
                color: "#00AAFF".to_string(),
                display: 1,
                calendar_type: 0,
                flags: 0,
            })
            .unwrap();

        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Events": [{
                    "ID": "event-horizon-1",
                    "UID": "uid-horizon-1",
                    "CalendarID": "cal-1",
                    "SharedEventID": "shared-1",
                    "CreateTime": 1700000000,
                    "LastEditTime": 1700000001,
                    "StartTime": 1700001000,
                    "StartTimezone": "UTC",
                    "EndTime": 1700004600,
                    "EndTimezone": "UTC",
                    "FullDay": 0,
                    "Author": "alice@proton.me",
                    "Permissions": 2
                }]
            })))
            .mount(&server)
            .await;

        let summary =
            refresh_calendar_event_horizon(&client, &store, &CalendarEventsQuery::default())
                .await
                .unwrap();
        assert_eq!(summary.calendars_scanned, 1);
        assert_eq!(summary.events_upserted, 1);
        assert_eq!(summary.events_soft_deleted, 0);

        let conn = Connection::open(store.db_path()).unwrap();
        let event_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pim_calendar_events WHERE deleted = 0 AND id = 'event-horizon-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(event_count, 1);

        let last_horizon = store
            .get_sync_state_int("calendar.last_horizon_sync_ms")
            .unwrap()
            .unwrap();
        assert!(last_horizon > 0);
    }

    #[tokio::test]
    async fn bootstrap_calendars_soft_deletes_missing_events_for_seen_calendar() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;
        let store = setup_store();

        store
            .upsert_calendar(&calendar::Calendar {
                id: "cal-1".to_string(),
                name: "Personal".to_string(),
                description: "".to_string(),
                color: "#00AAFF".to_string(),
                display: 1,
                calendar_type: 0,
                flags: 0,
            })
            .unwrap();
        store
            .upsert_calendar_event(&calendar::CalendarEvent {
                id: "event-keep".to_string(),
                uid: "uid-event-keep".to_string(),
                calendar_id: "cal-1".to_string(),
                shared_event_id: "shared-keep".to_string(),
                create_time: 1700000000,
                last_edit_time: 1700000001,
                start_time: 1700001000,
                end_time: 1700004600,
                start_timezone: "UTC".to_string(),
                end_timezone: "UTC".to_string(),
                full_day: 0,
                author: "alice@proton.me".to_string(),
                permissions: 2,
                ..calendar::CalendarEvent::default()
            })
            .unwrap();
        store
            .upsert_calendar_event(&calendar::CalendarEvent {
                id: "event-stale".to_string(),
                uid: "uid-event-stale".to_string(),
                calendar_id: "cal-1".to_string(),
                shared_event_id: "shared-stale".to_string(),
                create_time: 1700000000,
                last_edit_time: 1700000001,
                start_time: 1700002000,
                end_time: 1700005600,
                start_timezone: "UTC".to_string(),
                end_timezone: "UTC".to_string(),
                full_day: 0,
                author: "alice@proton.me".to_string(),
                permissions: 2,
                ..calendar::CalendarEvent::default()
            })
            .unwrap();

        Mock::given(method("GET"))
            .and(path("/calendar/v1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Calendars": [{
                    "ID": "cal-1",
                    "Name": "Personal",
                    "Description": "",
                    "Color": "#00AAFF",
                    "Display": 1,
                    "Type": 0,
                    "Flags": 0
                }]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/members"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Members": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Keys": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/settings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "CalendarSettings": {
                    "ID": "settings-1",
                    "CalendarID": "cal-1",
                    "DefaultEventDuration": 30,
                    "DefaultPartDayNotifications": [],
                    "DefaultFullDayNotifications": []
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/modelevents/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "CalendarModelEventID": "cme-1"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Events": [calendar_event_json("cal-1", "event-keep", 1700001000)]
            })))
            .mount(&server)
            .await;

        let summary = bootstrap_calendars(&client, &store, &CalendarEventsQuery::default())
            .await
            .unwrap();
        assert_eq!(summary.events_soft_deleted, 1);

        let conn = Connection::open(store.db_path()).unwrap();
        let keep_deleted: i64 = conn
            .query_row(
                "SELECT deleted FROM pim_calendar_events WHERE id = 'event-keep'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let stale_deleted: i64 = conn
            .query_row(
                "SELECT deleted FROM pim_calendar_events WHERE id = 'event-stale'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(keep_deleted, 0);
        assert_eq!(stale_deleted, 1);
    }

    #[tokio::test]
    async fn refresh_calendar_event_horizon_soft_deletes_missing_events_in_window() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;
        let store = setup_store();

        store
            .upsert_calendar(&calendar::Calendar {
                id: "cal-1".to_string(),
                name: "Personal".to_string(),
                description: "".to_string(),
                color: "#00AAFF".to_string(),
                display: 1,
                calendar_type: 0,
                flags: 0,
            })
            .unwrap();
        store
            .upsert_calendar_event(&calendar::CalendarEvent {
                id: "event-keep".to_string(),
                uid: "uid-event-keep".to_string(),
                calendar_id: "cal-1".to_string(),
                shared_event_id: "shared-keep".to_string(),
                create_time: 1700000000,
                last_edit_time: 1700000001,
                start_time: 1700001000,
                end_time: 1700004600,
                start_timezone: "UTC".to_string(),
                end_timezone: "UTC".to_string(),
                full_day: 0,
                author: "alice@proton.me".to_string(),
                permissions: 2,
                ..calendar::CalendarEvent::default()
            })
            .unwrap();
        store
            .upsert_calendar_event(&calendar::CalendarEvent {
                id: "event-delete-in-range".to_string(),
                uid: "uid-event-delete-in-range".to_string(),
                calendar_id: "cal-1".to_string(),
                shared_event_id: "shared-delete".to_string(),
                create_time: 1700000000,
                last_edit_time: 1700000001,
                start_time: 1700002000,
                end_time: 1700005600,
                start_timezone: "UTC".to_string(),
                end_timezone: "UTC".to_string(),
                full_day: 0,
                author: "alice@proton.me".to_string(),
                permissions: 2,
                ..calendar::CalendarEvent::default()
            })
            .unwrap();
        store
            .upsert_calendar_event(&calendar::CalendarEvent {
                id: "event-out-of-range".to_string(),
                uid: "uid-event-out-of-range".to_string(),
                calendar_id: "cal-1".to_string(),
                shared_event_id: "shared-out".to_string(),
                create_time: 1700000000,
                last_edit_time: 1700000001,
                start_time: 1701000000,
                end_time: 1701003600,
                start_timezone: "UTC".to_string(),
                end_timezone: "UTC".to_string(),
                full_day: 0,
                author: "alice@proton.me".to_string(),
                permissions: 2,
                ..calendar::CalendarEvent::default()
            })
            .unwrap();

        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Events": [calendar_event_json("cal-1", "event-keep", 1700001000)]
            })))
            .mount(&server)
            .await;

        let summary = refresh_calendar_event_horizon(
            &client,
            &store,
            &CalendarEventsQuery {
                start: Some(1700000000),
                end: Some(1700009999),
                ..CalendarEventsQuery::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(summary.events_soft_deleted, 1);

        let conn = Connection::open(store.db_path()).unwrap();
        let keep_deleted: i64 = conn
            .query_row(
                "SELECT deleted FROM pim_calendar_events WHERE id = 'event-keep'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let in_range_deleted: i64 = conn
            .query_row(
                "SELECT deleted FROM pim_calendar_events WHERE id = 'event-delete-in-range'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let out_of_range_deleted: i64 = conn
            .query_row(
                "SELECT deleted FROM pim_calendar_events WHERE id = 'event-out-of-range'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(keep_deleted, 0);
        assert_eq!(in_range_deleted, 1);
        assert_eq!(out_of_range_deleted, 0);
    }

    #[test]
    fn uuid_calendar_ids_are_local_only() {
        assert!(!is_remote_calendar_id(
            "7A60F3B9-C6B7-429D-8AB6-8029FB968C50"
        ));
        assert!(is_remote_calendar_id(
            "35HQnSLUjSZsGBFNsioWA79AyBUbGDJkH3eqjkjgN-QJZRbawPZMsZFHGJOO5cns43YKn_zMH6PWdFwmYkGPsg=="
        ));
    }
}
