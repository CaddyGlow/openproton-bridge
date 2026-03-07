use async_trait::async_trait;
use serde::de::{DeserializeOwned, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::client::{check_api_response, send_logged, ProtonClient};
use super::error::{ApiError, Result};

async fn decode_api_json<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    serde_json::from_value(json).map_err(ApiError::Json)
}

fn deserialize_string_or_default<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_i32_or_default<'de, D>(deserializer: D) -> std::result::Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<i32>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_i64_or_default<'de, D>(deserializer: D) -> std::result::Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<i64>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_vec_or_default<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Calendar {
    #[serde(rename = "ID", default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub display: i32,
    #[serde(rename = "Type", default)]
    pub calendar_type: i32,
    #[serde(default)]
    pub flags: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarKey {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "CalendarID")]
    pub calendar_id: String,
    #[serde(rename = "PassphraseID")]
    pub passphrase_id: String,
    pub private_key: String,
    pub flags: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarMember {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "CalendarID")]
    pub calendar_id: String,
    pub email: String,
    pub color: String,
    pub display: i32,
    pub permissions: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct MemberPassphrase {
    #[serde(rename = "MemberID")]
    pub member_id: String,
    pub passphrase: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarPassphrase {
    #[serde(rename = "ID")]
    pub id: String,
    pub flags: i64,
    #[serde(default)]
    pub member_passphrases: Vec<MemberPassphrase>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarNotificationSetting {
    #[serde(rename = "Type")]
    pub kind: i32,
    pub trigger: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarSettings {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "CalendarID")]
    pub calendar_id: String,
    pub default_event_duration: i32,
    #[serde(default)]
    pub default_part_day_notifications: Vec<CalendarNotificationSetting>,
    #[serde(default)]
    pub default_full_day_notifications: Vec<CalendarNotificationSetting>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarAttendee {
    #[serde(
        rename = "ID",
        default,
        deserialize_with = "deserialize_string_or_default"
    )]
    pub id: String,
    #[serde(default, deserialize_with = "deserialize_string_or_default")]
    pub token: String,
    #[serde(default, deserialize_with = "deserialize_i32_or_default")]
    pub status: i32,
    #[serde(default, deserialize_with = "deserialize_i32_or_default")]
    pub permissions: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarEventPart {
    #[serde(
        rename = "MemberID",
        default,
        deserialize_with = "deserialize_string_or_default"
    )]
    pub member_id: String,
    #[serde(
        rename = "Type",
        default,
        deserialize_with = "deserialize_i32_or_default"
    )]
    pub kind: i32,
    #[serde(default, deserialize_with = "deserialize_string_or_default")]
    pub data: String,
    pub signature: Option<String>,
    pub author: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarEvent {
    #[serde(
        rename = "ID",
        default,
        deserialize_with = "deserialize_string_or_default"
    )]
    pub id: String,
    #[serde(
        rename = "UID",
        default,
        deserialize_with = "deserialize_string_or_default"
    )]
    pub uid: String,
    #[serde(
        rename = "CalendarID",
        default,
        deserialize_with = "deserialize_string_or_default"
    )]
    pub calendar_id: String,
    #[serde(
        rename = "SharedEventID",
        default,
        deserialize_with = "deserialize_string_or_default"
    )]
    pub shared_event_id: String,
    #[serde(default, deserialize_with = "deserialize_i64_or_default")]
    pub create_time: i64,
    #[serde(default, deserialize_with = "deserialize_i64_or_default")]
    pub last_edit_time: i64,
    #[serde(default, deserialize_with = "deserialize_i64_or_default")]
    pub start_time: i64,
    #[serde(default, deserialize_with = "deserialize_string_or_default")]
    pub start_timezone: String,
    #[serde(default, deserialize_with = "deserialize_i64_or_default")]
    pub end_time: i64,
    #[serde(default, deserialize_with = "deserialize_string_or_default")]
    pub end_timezone: String,
    #[serde(default, deserialize_with = "deserialize_i32_or_default")]
    pub full_day: i32,
    #[serde(default, deserialize_with = "deserialize_string_or_default")]
    pub author: String,
    #[serde(default, deserialize_with = "deserialize_i32_or_default")]
    pub permissions: i32,
    #[serde(default, deserialize_with = "deserialize_vec_or_default")]
    pub attendees: Vec<CalendarAttendee>,
    #[serde(default, deserialize_with = "deserialize_string_or_default")]
    pub shared_key_packet: String,
    #[serde(default, deserialize_with = "deserialize_string_or_default")]
    pub calendar_key_packet: String,
    #[serde(default, deserialize_with = "deserialize_vec_or_default")]
    pub shared_events: Vec<CalendarEventPart>,
    #[serde(default, deserialize_with = "deserialize_vec_or_default")]
    pub calendar_events: Vec<CalendarEventPart>,
    #[serde(default, deserialize_with = "deserialize_vec_or_default")]
    pub attendees_events: Vec<CalendarEventPart>,
    #[serde(default, deserialize_with = "deserialize_vec_or_default")]
    pub personal_events: Vec<CalendarEventPart>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarBootstrap {
    #[serde(default)]
    pub keys: Vec<CalendarKey>,
    pub passphrase: CalendarPassphrase,
    #[serde(default)]
    pub members: Vec<CalendarMember>,
    #[serde(rename = "CalendarSettings")]
    pub calendar_settings: CalendarSettings,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CalendarsResponse {
    calendars: Vec<Calendar>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CalendarResponse {
    calendar: Calendar,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CalendarKeysResponse {
    keys: Vec<CalendarKey>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CalendarMembersResponse {
    members: Vec<CalendarMember>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CalendarPassphraseResponse {
    passphrase: CalendarPassphrase,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CalendarBootstrapResponse {
    #[serde(flatten)]
    bootstrap: CalendarBootstrap,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CalendarSettingsResponse {
    #[serde(rename = "CalendarSettings")]
    calendar_settings: CalendarSettings,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CalendarEventsResponse {
    #[serde(default)]
    events: Vec<CalendarEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CalendarEventResponse {
    event: CalendarEvent,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CountResponse {
    total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarModelEventItem {
    pub id: Option<String>,
    pub action: Option<i64>,
    pub raw: Value,
}

impl CalendarModelEventItem {
    pub fn is_create(&self) -> bool {
        self.action == Some(1)
    }

    pub fn is_update(&self) -> bool {
        matches!(self.action, Some(2 | 3))
    }

    pub fn is_delete(&self) -> bool {
        self.action == Some(0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CalendarModelEventsResponse {
    pub calendar_model_event_id: String,
    pub calendar_events: Vec<CalendarModelEventItem>,
    pub calendar_keys: Vec<CalendarModelEventItem>,
    pub calendar_passphrases: Vec<CalendarModelEventItem>,
    pub calendar_settings: Vec<CalendarModelEventItem>,
    pub calendar_alarms: Vec<CalendarModelEventItem>,
    pub calendar_subscriptions: Vec<CalendarModelEventItem>,
}

fn parse_action_code(action: Option<&Value>) -> Option<i64> {
    let action = action?;
    match action {
        Value::Number(value) => value.as_i64(),
        Value::String(value) => value.parse::<i64>().ok(),
        _ => None,
    }
}

fn extract_nested_id(value: &Value) -> Option<String> {
    match value {
        Value::Object(obj) => {
            if let Some(id) = obj.get("ID").and_then(|v| v.as_str()) {
                return Some(id.to_string());
            }
            for nested in obj.values() {
                if let Some(id) = extract_nested_id(nested) {
                    return Some(id);
                }
            }
            None
        }
        Value::Array(values) => values.iter().find_map(extract_nested_id),
        _ => None,
    }
}

fn parse_model_event_entry(
    value: Value,
    fallback_id: Option<String>,
) -> Option<CalendarModelEventItem> {
    match value {
        Value::Object(fields) => {
            let id = fields
                .get("ID")
                .and_then(|value| value.as_str())
                .map(str::to_string)
                .or_else(|| fields.values().find_map(extract_nested_id))
                .or(fallback_id);
            let action = parse_action_code(fields.get("Action"));
            let raw = Value::Object(fields);
            Some(CalendarModelEventItem { id, action, raw })
        }
        Value::Null => fallback_id.map(|id| CalendarModelEventItem {
            id: Some(id),
            action: Some(0),
            raw: Value::Null,
        }),
        Value::String(value) => {
            let id = fallback_id.or_else(|| Some(value.clone()));
            Some(CalendarModelEventItem {
                id,
                action: None,
                raw: Value::String(value),
            })
        }
        primitive => fallback_id.map(|id| CalendarModelEventItem {
            id: Some(id),
            action: parse_action_code(Some(&primitive)),
            raw: primitive,
        }),
    }
}

fn parse_model_event_bucket(bucket: Option<&Value>) -> Vec<CalendarModelEventItem> {
    let Some(bucket) = bucket else {
        return Vec::new();
    };

    match bucket {
        Value::Null => Vec::new(),
        Value::Array(entries) => entries
            .iter()
            .cloned()
            .filter_map(|entry| parse_model_event_entry(entry, None))
            .collect(),
        Value::Object(entries) => {
            let is_single_entry = entries.contains_key("Action")
                || entries.contains_key("ID")
                || entries
                    .values()
                    .any(|value| value.is_object() && value.get("ID").is_some());

            if is_single_entry {
                return parse_model_event_entry(Value::Object(entries.clone()), None)
                    .into_iter()
                    .collect();
            }

            entries
                .iter()
                .filter_map(|(fallback_id, entry)| {
                    parse_model_event_entry(entry.clone(), Some(fallback_id.clone()))
                })
                .collect()
        }
        single => parse_model_event_entry(single.clone(), None)
            .into_iter()
            .collect(),
    }
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarEventsQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(rename = "Type", skip_serializing_if = "Option::is_none")]
    pub event_type: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "UID")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "RecurrenceID")]
    pub recurrence_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarCreateRequest {
    pub address_id: String,
    pub name: String,
    pub description: String,
    pub color: String,
    pub display: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarPassphraseSetup {
    pub data_packet: String,
    pub key_packets: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CalendarSetupKeyRequest {
    pub address_id: String,
    pub signature: String,
    pub private_key: String,
    pub passphrase: CalendarPassphraseSetup,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SyncCalendarAttendee {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub status: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SyncCalendarEventPart {
    #[serde(rename = "Type")]
    pub kind: i32,
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct SyncCalendarEventPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_organizer: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_attendee_addresses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calendar_key_packet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calendar_event_content: Option<Vec<SyncCalendarEventPart>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_key_packet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_event_content: Option<Vec<SyncCalendarEventPart>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub personal_event_content: Option<SyncCalendarEventPart>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attendees_event_content: Option<Vec<SyncCalendarEventPart>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attendees: Option<Vec<SyncCalendarAttendee>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "UID")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "SharedEventID")]
    pub shared_event_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SyncEventOperation {
    Create {
        #[serde(rename = "Overwrite")]
        #[serde(skip_serializing_if = "Option::is_none")]
        overwrite: Option<i32>,
        #[serde(rename = "Event")]
        event: SyncCalendarEventPayload,
    },
    Update {
        #[serde(rename = "ID")]
        id: String,
        #[serde(rename = "Event")]
        event: SyncCalendarEventPayload,
    },
    Delete {
        #[serde(rename = "ID")]
        id: String,
        #[serde(rename = "DeletionReason")]
        #[serde(skip_serializing_if = "Option::is_none")]
        deletion_reason: Option<i32>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SyncMultipleEventsRequest {
    #[serde(rename = "MemberID")]
    pub member_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_import: Option<i32>,
    pub events: Vec<SyncEventOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SyncSingleEventRequest {
    #[serde(rename = "MemberID")]
    pub member_id: String,
    pub permissions: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_organizer: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_attendee_addresses: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calendar_key_packet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calendar_event_content: Option<Vec<SyncCalendarEventPart>>,
    pub shared_key_packet: String,
    pub shared_event_content: Vec<SyncCalendarEventPart>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub personal_event_content: Option<SyncCalendarEventPart>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attendees_event_content: Option<Vec<SyncCalendarEventPart>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attendees: Option<Vec<SyncCalendarAttendee>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateParticipationStatusRequest {
    pub status: i32,
    pub update_time: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdatePersonalPartRequest {
    #[serde(rename = "MemberID")]
    pub member_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub personal_event_content: Option<SyncCalendarEventPart>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateCalendarSettingsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_event_duration: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_part_day_notifications: Option<Vec<CalendarNotificationSetting>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_full_day_notifications: Option<Vec<CalendarNotificationSetting>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SyncEventResult {
    pub index: i64,
    pub response: SyncEventResultResponse,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SyncEventResultResponse {
    pub code: i64,
    #[serde(default)]
    pub event: Option<CalendarEvent>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SyncMultipleEventsResponse {
    pub code: i64,
    #[serde(default)]
    pub responses: Vec<SyncEventResult>,
}

pub async fn get_calendars(client: &ProtonClient) -> Result<Vec<Calendar>> {
    let res: CalendarsResponse =
        decode_api_json(send_logged(client.get("/calendar/v1")).await?).await?;
    Ok(res.calendars)
}

pub async fn get_calendar(client: &ProtonClient, calendar_id: &str) -> Result<Calendar> {
    let path = format!("/calendar/v1/{calendar_id}");
    let res: CalendarResponse = decode_api_json(send_logged(client.get(&path)).await?).await?;
    Ok(res.calendar)
}

pub async fn create_calendar(
    client: &ProtonClient,
    req: &CalendarCreateRequest,
) -> Result<Calendar> {
    let res: CalendarResponse =
        decode_api_json(send_logged(client.post("/calendar/v1").json(req)).await?).await?;
    Ok(res.calendar)
}

pub async fn update_calendar(
    client: &ProtonClient,
    calendar_id: &str,
    req: &CalendarCreateRequest,
) -> Result<Calendar> {
    let path = format!("/calendar/v1/{calendar_id}");
    let res: CalendarResponse =
        decode_api_json(send_logged(client.put(&path).json(req)).await?).await?;
    Ok(res.calendar)
}

pub async fn delete_calendar(client: &ProtonClient, calendar_id: &str) -> Result<()> {
    let path = format!("/calendar/v1/{calendar_id}");
    let _json: serde_json::Value =
        decode_api_json(send_logged(client.delete(&path)).await?).await?;
    Ok(())
}

pub async fn get_calendar_bootstrap(
    client: &ProtonClient,
    calendar_id: &str,
) -> Result<CalendarBootstrap> {
    let path = format!("/calendar/v1/{calendar_id}/bootstrap");
    let res: CalendarBootstrapResponse =
        decode_api_json(send_logged(client.get(&path)).await?).await?;
    Ok(res.bootstrap)
}

pub async fn get_calendar_keys(
    client: &ProtonClient,
    calendar_id: &str,
) -> Result<Vec<CalendarKey>> {
    let path = format!("/calendar/v1/{calendar_id}/keys");
    let res: CalendarKeysResponse = decode_api_json(send_logged(client.get(&path)).await?).await?;
    Ok(res.keys)
}

pub async fn setup_calendar_key(
    client: &ProtonClient,
    calendar_id: &str,
    req: &CalendarSetupKeyRequest,
) -> Result<serde_json::Value> {
    let path = format!("/calendar/v1/{calendar_id}/keys");
    decode_api_json(send_logged(client.post(&path).json(req)).await?).await
}

pub async fn reactivate_calendar_key(
    client: &ProtonClient,
    calendar_id: &str,
    key_id: &str,
    private_key: &str,
) -> Result<serde_json::Value> {
    let path = format!("/calendar/v1/{calendar_id}/keys/{key_id}");
    let body = serde_json::json!({ "PrivateKey": private_key });
    decode_api_json(send_logged(client.put(&path).json(&body)).await?).await
}

pub async fn get_calendar_members(
    client: &ProtonClient,
    calendar_id: &str,
) -> Result<Vec<CalendarMember>> {
    let path = format!("/calendar/v1/{calendar_id}/members");
    let res: CalendarMembersResponse =
        decode_api_json(send_logged(client.get(&path)).await?).await?;
    Ok(res.members)
}

pub async fn get_calendar_passphrase(
    client: &ProtonClient,
    calendar_id: &str,
) -> Result<CalendarPassphrase> {
    let path = format!("/calendar/v1/{calendar_id}/passphrase");
    let res: CalendarPassphraseResponse =
        decode_api_json(send_logged(client.get(&path)).await?).await?;
    Ok(res.passphrase)
}

pub async fn get_calendar_settings(
    client: &ProtonClient,
    calendar_id: &str,
) -> Result<CalendarSettings> {
    let path = format!("/calendar/v1/{calendar_id}/settings");
    let res: CalendarSettingsResponse =
        decode_api_json(send_logged(client.get(&path)).await?).await?;
    Ok(res.calendar_settings)
}

pub async fn update_calendar_settings(
    client: &ProtonClient,
    calendar_id: &str,
    req: &UpdateCalendarSettingsRequest,
) -> Result<serde_json::Value> {
    let path = format!("/calendar/v1/{calendar_id}/settings");
    decode_api_json(send_logged(client.put(&path).json(req)).await?).await
}

pub async fn count_calendar_events(client: &ProtonClient, calendar_id: &str) -> Result<i64> {
    let path = format!("/calendar/v1/{calendar_id}/events/count");
    let res: CountResponse = decode_api_json(send_logged(client.get(&path)).await?).await?;
    Ok(res.total)
}

pub async fn get_calendar_model_event_latest(
    client: &ProtonClient,
    calendar_id: &str,
) -> Result<String> {
    let path = format!("/calendar/v1/{calendar_id}/modelevents/latest");
    let json: Value = decode_api_json(send_logged(client.get(&path)).await?).await?;
    json.get("CalendarModelEventID")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| {
            ApiError::Auth(
                "missing CalendarModelEventID in model-event latest response".to_string(),
            )
        })
}

pub async fn get_calendar_model_events_since(
    client: &ProtonClient,
    calendar_id: &str,
    model_event_id: &str,
) -> Result<CalendarModelEventsResponse> {
    let path = format!("/calendar/v1/{calendar_id}/modelevents/{model_event_id}");
    let json: Value = decode_api_json(send_logged(client.get(&path)).await?).await?;

    let calendar_model_event_id = json
        .get("CalendarModelEventID")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| model_event_id.to_string());

    Ok(CalendarModelEventsResponse {
        calendar_model_event_id,
        calendar_events: parse_model_event_bucket(json.get("CalendarEvents")),
        calendar_keys: parse_model_event_bucket(json.get("CalendarKeys")),
        calendar_passphrases: parse_model_event_bucket(json.get("CalendarPassphrases")),
        calendar_settings: parse_model_event_bucket(json.get("CalendarSettings")),
        calendar_alarms: parse_model_event_bucket(json.get("CalendarAlarms")),
        calendar_subscriptions: parse_model_event_bucket(json.get("CalendarSubscriptions")),
    })
}

pub async fn get_calendar_events(
    client: &ProtonClient,
    calendar_id: &str,
    query: &CalendarEventsQuery,
) -> Result<Vec<CalendarEvent>> {
    let path = format!("/calendar/v1/{calendar_id}/events");
    let req = client.get(&path).query(query);
    let res: CalendarEventsResponse = decode_api_json(send_logged(req).await?).await?;
    Ok(res.events)
}

pub async fn get_calendar_events_by_uid(
    client: &ProtonClient,
    query: &CalendarEventsQuery,
) -> Result<Vec<CalendarEvent>> {
    let req = client.get("/calendar/v1/events").query(query);
    let res: CalendarEventsResponse = decode_api_json(send_logged(req).await?).await?;
    Ok(res.events)
}

pub async fn get_calendar_event(
    client: &ProtonClient,
    calendar_id: &str,
    event_id: &str,
) -> Result<CalendarEvent> {
    let path = format!("/calendar/v1/{calendar_id}/events/{event_id}");
    let res: CalendarEventResponse = decode_api_json(send_logged(client.get(&path)).await?).await?;
    Ok(res.event)
}

pub async fn sync_calendar_events(
    client: &ProtonClient,
    calendar_id: &str,
    req: &SyncMultipleEventsRequest,
) -> Result<SyncMultipleEventsResponse> {
    let path = format!("/calendar/v1/{calendar_id}/events/sync");
    decode_api_json(send_logged(client.put(&path).json(req)).await?).await
}

pub async fn create_calendar_event_direct(
    client: &ProtonClient,
    calendar_id: &str,
    req: &SyncSingleEventRequest,
) -> Result<CalendarEvent> {
    let path = format!("/calendar/v1/{calendar_id}/events");
    let res: CalendarEventResponse =
        decode_api_json(send_logged(client.post(&path).json(req)).await?).await?;
    Ok(res.event)
}

pub async fn update_calendar_event_direct(
    client: &ProtonClient,
    calendar_id: &str,
    event_id: &str,
    req: &SyncSingleEventRequest,
) -> Result<CalendarEvent> {
    let path = format!("/calendar/v1/{calendar_id}/events/{event_id}");
    let res: CalendarEventResponse =
        decode_api_json(send_logged(client.put(&path).json(req)).await?).await?;
    Ok(res.event)
}

pub async fn delete_calendar_event_direct(
    client: &ProtonClient,
    calendar_id: &str,
    event_id: &str,
) -> Result<()> {
    let path = format!("/calendar/v1/{calendar_id}/events/{event_id}");
    let _json: serde_json::Value =
        decode_api_json(send_logged(client.delete(&path)).await?).await?;
    Ok(())
}

pub async fn update_event_participation_status(
    client: &ProtonClient,
    calendar_id: &str,
    event_id: &str,
    attendee_id: &str,
    req: &UpdateParticipationStatusRequest,
) -> Result<CalendarEvent> {
    let path = format!("/calendar/v1/{calendar_id}/events/{event_id}/attendees/{attendee_id}");
    let res: CalendarEventResponse =
        decode_api_json(send_logged(client.put(&path).json(req)).await?).await?;
    Ok(res.event)
}

pub async fn update_event_personal_part(
    client: &ProtonClient,
    calendar_id: &str,
    event_id: &str,
    req: &UpdatePersonalPartRequest,
) -> Result<CalendarEvent> {
    let path = format!("/calendar/v1/{calendar_id}/events/{event_id}/personal");
    let res: CalendarEventResponse =
        decode_api_json(send_logged(client.put(&path).json(req)).await?).await?;
    Ok(res.event)
}

#[async_trait]
pub trait CalendarApi {
    async fn get_calendars(&self) -> Result<Vec<Calendar>>;
    async fn get_calendar(&self, calendar_id: &str) -> Result<Calendar>;
    async fn get_calendar_model_event_latest(&self, calendar_id: &str) -> Result<String>;
    async fn get_calendar_model_events_since(
        &self,
        calendar_id: &str,
        model_event_id: &str,
    ) -> Result<CalendarModelEventsResponse>;
    async fn get_calendar_keys(&self, calendar_id: &str) -> Result<Vec<CalendarKey>>;
    async fn get_calendar_members(&self, calendar_id: &str) -> Result<Vec<CalendarMember>>;
    async fn get_calendar_passphrase(&self, calendar_id: &str) -> Result<CalendarPassphrase>;
    async fn get_calendar_events(
        &self,
        calendar_id: &str,
        query: &CalendarEventsQuery,
    ) -> Result<Vec<CalendarEvent>>;
    async fn get_calendar_event(&self, calendar_id: &str, event_id: &str) -> Result<CalendarEvent>;
    async fn sync_calendar_events(
        &self,
        calendar_id: &str,
        req: &SyncMultipleEventsRequest,
    ) -> Result<SyncMultipleEventsResponse>;
    async fn update_event_participation_status(
        &self,
        calendar_id: &str,
        event_id: &str,
        attendee_id: &str,
        req: &UpdateParticipationStatusRequest,
    ) -> Result<CalendarEvent>;
    async fn update_event_personal_part(
        &self,
        calendar_id: &str,
        event_id: &str,
        req: &UpdatePersonalPartRequest,
    ) -> Result<CalendarEvent>;
}

#[async_trait]
impl CalendarApi for ProtonClient {
    async fn get_calendars(&self) -> Result<Vec<Calendar>> {
        get_calendars(self).await
    }

    async fn get_calendar(&self, calendar_id: &str) -> Result<Calendar> {
        get_calendar(self, calendar_id).await
    }

    async fn get_calendar_model_event_latest(&self, calendar_id: &str) -> Result<String> {
        get_calendar_model_event_latest(self, calendar_id).await
    }

    async fn get_calendar_model_events_since(
        &self,
        calendar_id: &str,
        model_event_id: &str,
    ) -> Result<CalendarModelEventsResponse> {
        get_calendar_model_events_since(self, calendar_id, model_event_id).await
    }

    async fn get_calendar_keys(&self, calendar_id: &str) -> Result<Vec<CalendarKey>> {
        get_calendar_keys(self, calendar_id).await
    }

    async fn get_calendar_members(&self, calendar_id: &str) -> Result<Vec<CalendarMember>> {
        get_calendar_members(self, calendar_id).await
    }

    async fn get_calendar_passphrase(&self, calendar_id: &str) -> Result<CalendarPassphrase> {
        get_calendar_passphrase(self, calendar_id).await
    }

    async fn get_calendar_events(
        &self,
        calendar_id: &str,
        query: &CalendarEventsQuery,
    ) -> Result<Vec<CalendarEvent>> {
        get_calendar_events(self, calendar_id, query).await
    }

    async fn get_calendar_event(&self, calendar_id: &str, event_id: &str) -> Result<CalendarEvent> {
        get_calendar_event(self, calendar_id, event_id).await
    }

    async fn sync_calendar_events(
        &self,
        calendar_id: &str,
        req: &SyncMultipleEventsRequest,
    ) -> Result<SyncMultipleEventsResponse> {
        sync_calendar_events(self, calendar_id, req).await
    }

    async fn update_event_participation_status(
        &self,
        calendar_id: &str,
        event_id: &str,
        attendee_id: &str,
        req: &UpdateParticipationStatusRequest,
    ) -> Result<CalendarEvent> {
        update_event_participation_status(self, calendar_id, event_id, attendee_id, req).await
    }

    async fn update_event_personal_part(
        &self,
        calendar_id: &str,
        event_id: &str,
        req: &UpdatePersonalPartRequest,
    ) -> Result<CalendarEvent> {
        update_event_personal_part(self, calendar_id, event_id, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup_authenticated_client(server: &MockServer) -> ProtonClient {
        ProtonClient::authenticated(&server.uri(), "test-uid", "test-token").unwrap()
    }

    #[tokio::test]
    async fn test_get_calendars_tolerates_missing_name_field() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/calendar/v1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Calendars": [{
                    "ID": "cal-1",
                    "Description": "desc",
                    "Color": "#112233",
                    "Display": 1,
                    "Type": 0,
                    "Flags": 0
                }]
            })))
            .mount(&server)
            .await;

        let calendars = get_calendars(&client).await.unwrap();
        assert_eq!(calendars.len(), 1);
        assert_eq!(calendars[0].id, "cal-1");
        assert_eq!(calendars[0].name, "");
        assert_eq!(calendars[0].description, "desc");
    }

    #[test]
    fn parse_model_event_bucket_extracts_nested_ids_and_actions() {
        let payload = serde_json::json!([
            {"Action": 1, "Calendar": {"ID": "cal-1"}},
            {"Action": 2, "CalendarEvent": {"ID": "event-1"}},
            {"Action": 0, "CalendarSubscription": {"ID": "sub-1"}}
        ]);

        let parsed = parse_model_event_bucket(Some(&payload));
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].id.as_deref(), Some("cal-1"));
        assert!(parsed[0].is_create());
        assert_eq!(parsed[1].id.as_deref(), Some("event-1"));
        assert!(parsed[1].is_update());
        assert_eq!(parsed[2].id.as_deref(), Some("sub-1"));
        assert!(parsed[2].is_delete());
    }

    #[tokio::test]
    async fn test_get_calendar_model_event_latest() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/modelevents/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "CalendarModelEventID": "cme-2"
            })))
            .mount(&server)
            .await;

        let latest = get_calendar_model_event_latest(&client, "cal-1")
            .await
            .unwrap();
        assert_eq!(latest, "cme-2");
    }

    #[tokio::test]
    async fn test_get_calendar_model_events_since_parses_action_buckets() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/modelevents/cme-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "CalendarModelEventID": "cme-3",
                "CalendarEvents": [
                    {"Action": 1, "CalendarEvent": {"ID": "evt-1"}},
                    {"Action": 2, "CalendarEvent": {"ID": "evt-2"}},
                    {"Action": 0, "CalendarEvent": {"ID": "evt-3"}}
                ],
                "CalendarKeys": [
                    {"Action": 2, "Key": {"ID": "key-1"}}
                ]
            })))
            .mount(&server)
            .await;

        let resp = get_calendar_model_events_since(&client, "cal-1", "cme-2")
            .await
            .unwrap();

        assert_eq!(resp.calendar_model_event_id, "cme-3");
        assert_eq!(resp.calendar_events.len(), 3);
        assert_eq!(resp.calendar_events[0].id.as_deref(), Some("evt-1"));
        assert!(resp.calendar_events[0].is_create());
        assert!(resp.calendar_events[1].is_update());
        assert!(resp.calendar_events[2].is_delete());
        assert_eq!(resp.calendar_keys.len(), 1);
        assert_eq!(resp.calendar_keys[0].id.as_deref(), Some("key-1"));
    }

    #[tokio::test]
    async fn test_get_calendar_events_with_query_params() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/events"))
            .and(query_param("Start", "100"))
            .and(query_param("End", "200"))
            .and(query_param("Timezone", "UTC"))
            .and(query_param("Type", "2"))
            .and(query_param("Page", "0"))
            .and(query_param("PageSize", "50"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Events": [{
                    "ID": "evt-1",
                    "UID": "uid-1",
                    "CalendarID": "cal-1",
                    "CreateTime": 1700000000,
                    "LastEditTime": 1700000001
                }]
            })))
            .mount(&server)
            .await;

        let events = get_calendar_events(
            &client,
            "cal-1",
            &CalendarEventsQuery {
                start: Some(100),
                end: Some(200),
                timezone: Some("UTC".to_string()),
                event_type: Some(2),
                page: Some(0),
                page_size: Some(50),
                uid: None,
                recurrence_id: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt-1");
    }

    #[tokio::test]
    async fn test_get_calendar_events_tolerates_null_scalar_and_array_fields() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/calendar/v1/cal-1/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Events": [{
                    "ID": "evt-null-1",
                    "UID": "uid-null-1",
                    "CalendarID": "cal-1",
                    "SharedEventID": null,
                    "CreateTime": null,
                    "LastEditTime": null,
                    "StartTime": null,
                    "StartTimezone": null,
                    "EndTime": null,
                    "EndTimezone": null,
                    "FullDay": null,
                    "Author": null,
                    "Permissions": null,
                    "Attendees": null,
                    "SharedKeyPacket": null,
                    "CalendarKeyPacket": null,
                    "SharedEvents": null,
                    "CalendarEvents": null,
                    "AttendeesEvents": null,
                    "PersonalEvents": null
                }]
            })))
            .mount(&server)
            .await;

        let events = get_calendar_events(&client, "cal-1", &CalendarEventsQuery::default())
            .await
            .unwrap();

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.id, "evt-null-1");
        assert_eq!(event.uid, "uid-null-1");
        assert_eq!(event.calendar_id, "cal-1");
        assert_eq!(event.shared_event_id, "");
        assert_eq!(event.create_time, 0);
        assert_eq!(event.last_edit_time, 0);
        assert_eq!(event.start_time, 0);
        assert_eq!(event.start_timezone, "");
        assert_eq!(event.end_time, 0);
        assert_eq!(event.end_timezone, "");
        assert_eq!(event.full_day, 0);
        assert_eq!(event.author, "");
        assert_eq!(event.permissions, 0);
        assert!(event.attendees.is_empty());
        assert_eq!(event.shared_key_packet, "");
        assert_eq!(event.calendar_key_packet, "");
        assert!(event.shared_events.is_empty());
        assert!(event.calendar_events.is_empty());
        assert!(event.attendees_events.is_empty());
        assert!(event.personal_events.is_empty());
    }

    #[test]
    fn test_sync_event_operation_uses_pascal_case_wire_keys() {
        let payload = SyncMultipleEventsRequest {
            member_id: "member-1".to_string(),
            is_import: Some(0),
            events: vec![
                SyncEventOperation::Create {
                    overwrite: Some(1),
                    event: SyncCalendarEventPayload {
                        permissions: Some(2),
                        shared_key_packet: Some("skp-1".to_string()),
                        ..SyncCalendarEventPayload::default()
                    },
                },
                SyncEventOperation::Delete {
                    id: "evt-3".to_string(),
                    deletion_reason: Some(1),
                },
            ],
        };

        let json = serde_json::to_value(payload).unwrap();
        assert_eq!(json["Events"][0]["Overwrite"], 1);
        assert_eq!(json["Events"][0]["Event"]["Permissions"], 2);
        assert_eq!(json["Events"][0]["Event"]["SharedKeyPacket"], "skp-1");
        assert!(json["Events"][0].get("overwrite").is_none());
        assert!(json["Events"][0].get("event").is_none());

        assert_eq!(json["Events"][1]["ID"], "evt-3");
        assert_eq!(json["Events"][1]["DeletionReason"], 1);
        assert!(json["Events"][1].get("deletion_reason").is_none());
    }

    #[tokio::test]
    async fn test_sync_calendar_events_create_update_delete_contract() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("PUT"))
            .and(path("/calendar/v1/cal-1/events/sync"))
            .and(body_partial_json(serde_json::json!({
                "MemberID": "member-1",
                "IsImport": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Responses": [
                    {
                        "Index": 0,
                        "Response": {
                            "Code": 1000,
                            "Event": {
                                "ID": "evt-1",
                                "UID": "uid-1",
                                "CalendarID": "cal-1",
                                "CreateTime": 1700000000
                            }
                        }
                    },
                    {
                        "Index": 1,
                        "Response": {
                            "Code": 1000,
                            "Event": {
                                "ID": "evt-2",
                                "UID": "uid-2",
                                "CalendarID": "cal-1",
                                "CreateTime": 1700000001
                            }
                        }
                    },
                    {
                        "Index": 2,
                        "Response": {
                            "Code": 1000
                        }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let req = SyncMultipleEventsRequest {
            member_id: "member-1".to_string(),
            is_import: Some(0),
            events: vec![
                SyncEventOperation::Create {
                    overwrite: Some(1),
                    event: SyncCalendarEventPayload {
                        permissions: Some(2),
                        shared_key_packet: Some("skp-1".to_string()),
                        shared_event_content: Some(vec![SyncCalendarEventPart {
                            kind: 1,
                            data: "enc-create".to_string(),
                            signature: None,
                            author: Some("alice@proton.me".to_string()),
                        }]),
                        ..SyncCalendarEventPayload::default()
                    },
                },
                SyncEventOperation::Update {
                    id: "evt-2".to_string(),
                    event: SyncCalendarEventPayload {
                        shared_event_content: Some(vec![SyncCalendarEventPart {
                            kind: 1,
                            data: "enc-update".to_string(),
                            signature: None,
                            author: None,
                        }]),
                        ..SyncCalendarEventPayload::default()
                    },
                },
                SyncEventOperation::Delete {
                    id: "evt-3".to_string(),
                    deletion_reason: Some(1),
                },
            ],
        };

        let resp = sync_calendar_events(&client, "cal-1", &req).await.unwrap();
        assert_eq!(resp.responses.len(), 3);
        assert_eq!(resp.responses[0].index, 0);
        assert_eq!(
            resp.responses[0]
                .response
                .event
                .as_ref()
                .map(|evt| evt.id.as_str()),
            Some("evt-1")
        );
        assert_eq!(resp.responses[1].index, 1);
        assert_eq!(
            resp.responses[1]
                .response
                .event
                .as_ref()
                .map(|evt| evt.id.as_str()),
            Some("evt-2")
        );
        assert_eq!(resp.responses[2].index, 2);
        assert!(resp.responses[2].response.event.is_none());
    }
}
