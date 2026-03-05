use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredContact {
    pub id: String,
    pub uid: String,
    pub name: String,
    pub size: i64,
    pub create_time: i64,
    pub modify_time: i64,
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredCalendar {
    pub id: String,
    pub name: String,
    pub description: String,
    pub color: String,
    pub display: i32,
    pub calendar_type: i32,
    pub flags: i64,
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredCalendarEvent {
    pub id: String,
    pub calendar_id: String,
    pub uid: String,
    pub shared_event_id: String,
    pub start_time: i64,
    pub end_time: i64,
    pub deleted: bool,
}
