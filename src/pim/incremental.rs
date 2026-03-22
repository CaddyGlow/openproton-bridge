use std::collections::HashSet;

use serde_json::Value;

use crate::api::calendar;
use crate::api::client::ProtonClient;
use crate::api::contacts;
use crate::api::events as api_events;
use crate::api::types::{TypedEventItem, TypedEventPayload};

use super::store::PimStore;
use super::{PimError, Result};

const MODEL_EVENT_SWEEP_LIMIT: usize = 10;

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IncrementalPimSummary {
    pub contacts_refreshed: usize,
    pub contacts_deleted: usize,
    pub calendars_refreshed: usize,
    pub calendars_deleted: usize,
    pub calendar_events_upserted: usize,
    pub calendar_events_deleted: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CalendarModelApplySummary {
    events_upserted: usize,
    events_deleted: usize,
}

pub async fn apply_incremental_event(
    client: &ProtonClient,
    store: &PimStore,
    payload: &Value,
) -> Result<IncrementalPimSummary> {
    let Some(typed) = api_events::parse_typed_event_payload(payload) else {
        return Ok(IncrementalPimSummary::default());
    };

    if !typed.has_recognized_event_fields() {
        return Ok(IncrementalPimSummary::default());
    }

    let mut summary = IncrementalPimSummary::default();
    apply_contact_deltas(client, store, &typed, &mut summary).await?;
    apply_calendar_deltas(client, store, &typed, &mut summary).await?;
    Ok(summary)
}

async fn apply_contact_deltas(
    client: &ProtonClient,
    store: &PimStore,
    typed: &TypedEventPayload,
    summary: &mut IncrementalPimSummary,
) -> Result<()> {
    let mut contacts_to_refresh = HashSet::new();
    let mut contacts_to_delete = HashSet::new();

    if let Some(contacts) = typed.contacts.as_ref() {
        for item in contacts {
            if item.id.trim().is_empty() {
                continue;
            }
            if item.is_delete() {
                contacts_to_delete.insert(item.id.clone());
            } else {
                contacts_to_refresh.insert(item.id.clone());
            }
        }
    }

    if let Some(contact_emails) = typed.contact_emails.as_ref() {
        for item in contact_emails {
            if let Some(contact_id) = extract_contact_id(item) {
                contacts_to_refresh.insert(contact_id);
            }
        }
    }

    for contact_id in contacts_to_delete {
        store.soft_delete_contact(&contact_id)?;
        summary.contacts_deleted += 1;
    }

    for contact_id in contacts_to_refresh {
        match contacts::get_contact(client, &contact_id).await {
            Ok(contact) => {
                store.upsert_contact(&contact)?;
                summary.contacts_refreshed += 1;
            }
            Err(err) if is_probably_not_found(&err) => {
                store.soft_delete_contact(&contact_id)?;
                summary.contacts_deleted += 1;
            }
            Err(err) => return Err(pim_api_error("incremental contacts refresh", err)),
        }
    }

    Ok(())
}

async fn apply_calendar_deltas(
    client: &ProtonClient,
    store: &PimStore,
    typed: &TypedEventPayload,
    summary: &mut IncrementalPimSummary,
) -> Result<()> {
    let mut calendars_to_refresh = HashSet::new();
    let mut calendars_to_delete = HashSet::new();
    let mut member_change_without_calendar = false;

    if let Some(calendars) = typed.calendars.as_ref() {
        for item in calendars {
            if item.id.trim().is_empty() {
                continue;
            }
            if item.is_delete() {
                calendars_to_delete.insert(item.id.clone());
            } else {
                calendars_to_refresh.insert(item.id.clone());
            }
        }
    }

    if let Some(calendar_members) = typed.calendar_members.as_ref() {
        for item in calendar_members {
            if let Some(calendar_id) = extract_calendar_id(item) {
                calendars_to_refresh.insert(calendar_id);
            } else {
                member_change_without_calendar = true;
            }
        }
    }

    if member_change_without_calendar && calendars_to_refresh.is_empty() {
        let active_ids: Vec<String> = store
            .calendar()
            .list_active_calendar_ids_limited(MODEL_EVENT_SWEEP_LIMIT)?
            .into_iter()
            .filter(|id| is_remote_calendar_id(id))
            .collect();
        for calendar_id in active_ids {
            calendars_to_refresh.insert(calendar_id);
        }
    }

    for calendar_id in calendars_to_delete {
        store.soft_delete_calendar(&calendar_id)?;
        summary.calendars_deleted += 1;
    }

    for calendar_id in calendars_to_refresh {
        match calendar::get_calendar(client, &calendar_id).await {
            Ok(entry) => {
                store.upsert_calendar(&entry)?;
                summary.calendars_refreshed += 1;
            }
            Err(err) if is_probably_not_found(&err) => {
                store.soft_delete_calendar(&calendar_id)?;
                summary.calendars_deleted += 1;
                continue;
            }
            Err(err) => return Err(pim_api_error("incremental calendar refresh", err)),
        }

        let members = calendar::get_calendar_members(client, &calendar_id)
            .await
            .map_err(|err| pim_api_error("incremental calendar members refresh", err))?;
        for member in members {
            store.upsert_calendar_member(&member)?;
        }

        let keys = calendar::get_calendar_keys(client, &calendar_id)
            .await
            .map_err(|err| pim_api_error("incremental calendar keys refresh", err))?;
        for key in keys {
            store.upsert_calendar_key(&key)?;
        }

        let settings = calendar::get_calendar_settings(client, &calendar_id)
            .await
            .map_err(|err| pim_api_error("incremental calendar settings refresh", err))?;
        store.upsert_calendar_settings(&settings)?;

        let model = apply_calendar_model_events(client, store, &calendar_id).await?;
        summary.calendar_events_upserted += model.events_upserted;
        summary.calendar_events_deleted += model.events_deleted;
    }

    Ok(())
}

async fn apply_calendar_model_events(
    client: &ProtonClient,
    store: &PimStore,
    calendar_id: &str,
) -> Result<CalendarModelApplySummary> {
    let cursor_key = format!("calendar.{calendar_id}.model_event_id");
    let cursor = match store.get_sync_state_text(&cursor_key)? {
        Some(cursor) if !cursor.trim().is_empty() => cursor,
        _ => {
            let latest = calendar::get_calendar_model_event_latest(client, calendar_id)
                .await
                .map_err(|err| pim_api_error("incremental model-event latest", err))?;
            store.set_sync_state_text(&cursor_key, &latest)?;
            return Ok(CalendarModelApplySummary::default());
        }
    };

    let response = calendar::get_calendar_model_events_since(client, calendar_id, &cursor)
        .await
        .map_err(|err| pim_api_error("incremental model-event since", err))?;

    let mut summary = CalendarModelApplySummary::default();

    for model_event in response.calendar_events {
        let is_delete = model_event.is_delete();
        let Some(event_id) = model_event.id else {
            continue;
        };

        if is_delete {
            store.soft_delete_calendar_event(&event_id)?;
            summary.events_deleted += 1;
            continue;
        }

        match calendar::get_calendar_event(client, calendar_id, &event_id).await {
            Ok(event) => {
                store.upsert_calendar_event(&event)?;
                summary.events_upserted += 1;
            }
            Err(err) if is_probably_not_found(&err) => {
                store.soft_delete_calendar_event(&event_id)?;
                summary.events_deleted += 1;
            }
            Err(err) => return Err(pim_api_error("incremental calendar event refresh", err)),
        }
    }

    if !response.calendar_keys.is_empty() {
        let keys = calendar::get_calendar_keys(client, calendar_id)
            .await
            .map_err(|err| pim_api_error("incremental calendar keys update", err))?;
        for key in keys {
            store.upsert_calendar_key(&key)?;
        }
    }

    if !response.calendar_settings.is_empty() {
        let settings = calendar::get_calendar_settings(client, calendar_id)
            .await
            .map_err(|err| pim_api_error("incremental calendar settings update", err))?;
        store.upsert_calendar_settings(&settings)?;
    }

    store.set_sync_state_text(&cursor_key, &response.calendar_model_event_id)?;
    Ok(summary)
}

fn extract_contact_id(item: &TypedEventItem) -> Option<String> {
    item.extra
        .get("ContactID")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .or_else(|| {
            item.extra
                .get("ContactEmail")
                .and_then(|value| find_string_field(value, "ContactID"))
        })
        .or_else(|| {
            item.extra
                .get("Contact")
                .and_then(|value| find_string_field(value, "ID"))
        })
}

fn extract_calendar_id(item: &TypedEventItem) -> Option<String> {
    item.extra
        .get("CalendarID")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .or_else(|| {
            item.extra
                .get("Member")
                .and_then(|value| find_string_field(value, "CalendarID"))
        })
        .or_else(|| {
            item.extra
                .get("CalendarMember")
                .and_then(|value| find_string_field(value, "CalendarID"))
        })
}

fn find_string_field(value: &Value, key: &str) -> Option<String> {
    match value {
        Value::Object(map) => {
            if let Some(found) = map.get(key).and_then(|entry| entry.as_str()) {
                return Some(found.to_string());
            }
            map.values().find_map(|entry| find_string_field(entry, key))
        }
        Value::Array(entries) => entries
            .iter()
            .find_map(|entry| find_string_field(entry, key)),
        _ => None,
    }
}

fn is_probably_not_found(err: &crate::api::error::ApiError) -> bool {
    match err {
        crate::api::error::ApiError::Api { code, message, .. } => {
            *code == 404
                || message.to_ascii_lowercase().contains("not found")
                || message.to_ascii_lowercase().contains("unknown")
        }
        _ => false,
    }
}

fn pim_api_error(context: &str, err: crate::api::error::ApiError) -> PimError {
    PimError::InvalidState(format!("{context}: {err}"))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::api::calendar;
    use crate::api::contacts::{Contact, ContactCard, ContactEmail, ContactMetadata};

    fn setup_store() -> PimStore {
        let tmp = tempdir().unwrap();
        let contacts_db = tmp.path().join("contacts.db");
        let calendar_db = tmp.path().join("calendar.db");
        Box::leak(Box::new(tmp));
        PimStore::new(contacts_db, calendar_db).unwrap()
    }

    fn seed_contact(store: &PimStore, id: &str, name: &str) {
        store
            .upsert_contact(&Contact {
                metadata: ContactMetadata {
                    id: id.to_string(),
                    name: name.to_string(),
                    uid: format!("uid-{id}"),
                    size: 1,
                    create_time: 1,
                    modify_time: 1,
                    contact_emails: vec![ContactEmail {
                        id: format!("email-{id}"),
                        email: format!("{id}@proton.me"),
                        name: name.to_string(),
                        kind: vec![],
                        defaults: None,
                        order: None,
                        contact_id: id.to_string(),
                        label_ids: vec![],
                        last_used_time: None,
                    }],
                    label_ids: vec![],
                },
                cards: vec![ContactCard {
                    card_type: 0,
                    data: "BEGIN:VCARD".to_string(),
                    signature: None,
                }],
            })
            .unwrap();
    }

    fn seed_calendar_with_event(store: &PimStore, calendar_id: &str, event_id: &str) {
        store
            .upsert_calendar(&calendar::Calendar {
                id: calendar_id.to_string(),
                name: "Seed".to_string(),
                description: "".to_string(),
                color: "#00AAFF".to_string(),
                display: 1,
                calendar_type: 0,
                flags: 0,
            })
            .unwrap();
        store
            .upsert_calendar_event(&calendar::CalendarEvent {
                id: event_id.to_string(),
                uid: format!("uid-{event_id}"),
                calendar_id: calendar_id.to_string(),
                shared_event_id: "shared-seed".to_string(),
                create_time: 1700000000,
                ..calendar::CalendarEvent::default()
            })
            .unwrap();
    }

    #[tokio::test]
    async fn apply_incremental_event_is_noop_without_typed_fields() {
        let server = MockServer::start().await;
        let client = ProtonClient::authenticated(&server.uri(), "uid-1", "token-1").unwrap();
        let store = setup_store();

        let summary = apply_incremental_event(&client, &store, &serde_json::json!({"foo": "bar"}))
            .await
            .unwrap();
        assert_eq!(summary, IncrementalPimSummary::default());
    }

    #[tokio::test]
    async fn apply_incremental_event_handles_contact_refresh_and_delete() {
        let server = MockServer::start().await;
        let client = ProtonClient::authenticated(&server.uri(), "uid-1", "token-1").unwrap();
        let store = setup_store();
        seed_contact(&store, "contact-del", "Del");

        Mock::given(method("GET"))
            .and(path("/contacts/v4/contact-upsert"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Contact": {
                    "ID": "contact-upsert",
                    "Name": "Alice",
                    "UID": "uid-contact-upsert",
                    "Size": 10,
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000001,
                    "ContactEmails": [{
                        "ID": "email-upsert",
                        "Email": "alice@proton.me",
                        "Name": "Alice",
                        "ContactID": "contact-upsert",
                        "Kind": []
                    }],
                    "Cards": [{
                        "Type": 0,
                        "Data": "BEGIN:VCARD"
                    }]
                }
            })))
            .mount(&server)
            .await;

        let payload = serde_json::json!({
            "Contacts": [
                { "Action": 2, "Contact": { "ID": "contact-upsert" } },
                { "Action": 0, "Contact": { "ID": "contact-del" } }
            ]
        });

        let summary = apply_incremental_event(&client, &store, &payload)
            .await
            .unwrap();
        assert_eq!(summary.contacts_refreshed, 1);
        assert_eq!(summary.contacts_deleted, 1);
    }

    #[tokio::test]
    async fn apply_incremental_event_handles_calendar_refresh_and_model_events() {
        let server = MockServer::start().await;
        let client = ProtonClient::authenticated(&server.uri(), "uid-1", "token-1").unwrap();
        let store = setup_store();

        seed_calendar_with_event(&store, "cal-1", "event-del");
        store
            .set_sync_state_text("calendar.cal-1.model_event_id", "cme-old")
            .unwrap();

        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Calendar": {
                    "ID": "cal-1", "Name": "Personal", "Description": "Main",
                    "Color": "#00AAFF", "Display": 1, "Type": 0, "Flags": 0
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/members"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Members": [{"ID": "member-1", "CalendarID": "cal-1", "Email": "alice@proton.me", "Color": "#00AAFF", "Display": 1, "Permissions": 2}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Keys": [{"ID": "key-1", "CalendarID": "cal-1", "PassphraseID": "pp-1", "PrivateKey": "private", "Flags": 0}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/settings"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "CalendarSettings": {"ID": "settings-1", "CalendarID": "cal-1", "DefaultEventDuration": 30, "DefaultPartDayNotifications": [], "DefaultFullDayNotifications": []}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/modelevents/cme-old"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "CalendarModelEventID": "cme-new",
                "CalendarEvents": [
                    {"Action": 2, "CalendarEvent": {"ID": "event-upsert"}},
                    {"Action": 0, "CalendarEvent": {"ID": "event-del"}}
                ]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/events/event-upsert"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Event": {
                    "ID": "event-upsert", "UID": "uid-event-upsert", "CalendarID": "cal-1",
                    "SharedEventID": "shared-1", "CreateTime": 1700000000, "LastEditTime": 1700000001,
                    "StartTime": 1700001000, "StartTimezone": "UTC", "EndTime": 1700004600,
                    "EndTimezone": "UTC", "FullDay": 0, "Author": "alice@proton.me", "Permissions": 2
                }
            })))
            .mount(&server)
            .await;

        let payload = serde_json::json!({
            "Calendars": [
                {"Action": 2, "Calendar": {"ID": "cal-1"}}
            ]
        });

        let summary = apply_incremental_event(&client, &store, &payload)
            .await
            .unwrap();
        assert_eq!(summary.calendars_refreshed, 1);
        assert_eq!(summary.calendar_events_upserted, 1);
        assert_eq!(summary.calendar_events_deleted, 1);
        assert_eq!(
            store
                .get_sync_state_text("calendar.cal-1.model_event_id")
                .unwrap()
                .as_deref(),
            Some("cme-new")
        );
    }
}
