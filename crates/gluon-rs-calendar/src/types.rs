#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarUpsert {
    pub id: String,
    pub name: String,
    pub description: String,
    pub color: String,
    pub display: i32,
    pub calendar_type: i32,
    pub flags: i64,
    pub raw_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarMemberUpsert {
    pub id: String,
    pub calendar_id: String,
    pub email: String,
    pub color: String,
    pub display: i32,
    pub permissions: i64,
    pub raw_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarKeyUpsert {
    pub id: String,
    pub calendar_id: String,
    pub passphrase_id: String,
    pub private_key: String,
    pub flags: i64,
    pub raw_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarSettingsUpsert {
    pub id: String,
    pub calendar_id: String,
    pub default_event_duration: i64,
    pub default_part_day_notifications_json: String,
    pub default_full_day_notifications_json: String,
    pub raw_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarEventUpsert {
    pub id: String,
    pub calendar_id: String,
    pub uid: String,
    pub shared_event_id: String,
    pub create_time: i64,
    pub last_edit_time: i64,
    pub start_time: i64,
    pub end_time: i64,
    pub start_timezone: String,
    pub end_timezone: String,
    pub full_day: i64,
    pub author: String,
    pub permissions: i64,
    pub attendees_json: String,
    pub shared_key_packet: String,
    pub calendar_key_packet: String,
    pub shared_events_json: String,
    pub calendar_events_json: String,
    pub attendees_events_json: String,
    pub personal_events_json: String,
    pub raw_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCalendar {
    pub id: String,
    pub name: String,
    pub description: String,
    pub color: String,
    pub display: i32,
    pub calendar_type: i32,
    pub flags: i64,
    pub deleted: bool,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCalendarEvent {
    pub id: String,
    pub calendar_id: String,
    pub uid: String,
    pub shared_event_id: String,
    pub start_time: i64,
    pub end_time: i64,
    pub deleted: bool,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CalendarEventRange {
    pub start_time_from: Option<i64>,
    pub start_time_to: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryPage {
    pub limit: usize,
    pub offset: usize,
}

impl Default for QueryPage {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_LIMIT,
            offset: 0,
        }
    }
}

pub const DEFAULT_PAGE_LIMIT: usize = 100;
pub const MAX_PAGE_LIMIT: usize = 500;
