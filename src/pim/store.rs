use std::path::PathBuf;

use gluon_rs_calendar::CalendarStore;
use gluon_rs_contacts::ContactsStore;
use serde_json::Value;

use crate::api::{calendar, contacts};

use super::convert;
use super::query::{to_calendar_page, CalendarEventRange, QueryPage};
use super::types::{StoredCalendar, StoredCalendarEvent, StoredContact};
use super::Result;

pub struct PimStore {
    contacts: ContactsStore,
    calendar: CalendarStore,
}

impl PimStore {
    pub fn new(contacts_db: PathBuf, calendar_db: PathBuf) -> Result<Self> {
        let contacts = ContactsStore::new(contacts_db)?;
        let calendar = CalendarStore::new(calendar_db)?;
        Ok(Self { contacts, calendar })
    }

    pub fn contacts(&self) -> &ContactsStore {
        &self.contacts
    }

    pub fn calendar(&self) -> &CalendarStore {
        &self.calendar
    }

    // -- Contact mutations --

    pub fn upsert_contact(&self, contact: &contacts::Contact) -> Result<()> {
        let upsert = convert::contact_to_upsert(contact)?;
        self.contacts.upsert_contact(&upsert)?;
        Ok(())
    }

    pub fn soft_delete_contact(&self, contact_id: &str) -> Result<()> {
        self.contacts.soft_delete_contact(contact_id)?;
        Ok(())
    }

    pub fn hard_delete_contact(&self, contact_id: &str) -> Result<()> {
        self.contacts.hard_delete_contact(contact_id)?;
        Ok(())
    }

    // -- Contact queries --

    pub fn list_contacts(
        &self,
        include_deleted: bool,
        page: QueryPage,
    ) -> Result<Vec<StoredContact>> {
        Ok(self.contacts.list_contacts(include_deleted, page)?)
    }

    pub fn get_contact(
        &self,
        contact_id: &str,
        include_deleted: bool,
    ) -> Result<Option<StoredContact>> {
        Ok(self.contacts.get_contact(contact_id, include_deleted)?)
    }

    pub fn get_contact_payload(
        &self,
        contact_id: &str,
        include_deleted: bool,
    ) -> Result<Option<contacts::Contact>> {
        match self
            .contacts
            .get_contact_raw_json(contact_id, include_deleted)?
        {
            Some(raw) => Ok(Some(serde_json::from_str::<contacts::Contact>(&raw)?)),
            None => Ok(None),
        }
    }

    pub fn search_contacts_by_email(
        &self,
        email_like: &str,
        page: QueryPage,
    ) -> Result<Vec<StoredContact>> {
        Ok(self.contacts.search_contacts_by_email(email_like, page)?)
    }

    // -- Calendar mutations --

    pub fn upsert_calendar(&self, cal: &calendar::Calendar) -> Result<()> {
        let upsert = convert::calendar_to_upsert(cal)?;
        self.calendar.upsert_calendar(&upsert)?;
        Ok(())
    }

    pub fn soft_delete_calendar(&self, calendar_id: &str) -> Result<()> {
        self.calendar.soft_delete_calendar(calendar_id)?;
        Ok(())
    }

    pub fn hard_delete_calendar(&self, calendar_id: &str) -> Result<()> {
        self.calendar.hard_delete_calendar(calendar_id)?;
        Ok(())
    }

    pub fn upsert_calendar_member(&self, member: &calendar::CalendarMember) -> Result<()> {
        let upsert = convert::calendar_member_to_upsert(member)?;
        self.calendar.upsert_calendar_member(&upsert)?;
        Ok(())
    }

    pub fn upsert_calendar_key(&self, key: &calendar::CalendarKey) -> Result<()> {
        let upsert = convert::calendar_key_to_upsert(key)?;
        self.calendar.upsert_calendar_key(&upsert)?;
        Ok(())
    }

    pub fn upsert_calendar_settings(&self, settings: &calendar::CalendarSettings) -> Result<()> {
        let upsert = convert::calendar_settings_to_upsert(settings)?;
        self.calendar.upsert_calendar_settings(&upsert)?;
        Ok(())
    }

    pub fn upsert_calendar_event(&self, event: &calendar::CalendarEvent) -> Result<()> {
        let upsert = convert::calendar_event_to_upsert(event)?;
        self.calendar.upsert_calendar_event(&upsert)?;
        Ok(())
    }

    pub fn soft_delete_calendar_event(&self, event_id: &str) -> Result<()> {
        self.calendar.soft_delete_calendar_event(event_id)?;
        Ok(())
    }

    pub fn hard_delete_calendar_event(&self, event_id: &str) -> Result<()> {
        self.calendar.hard_delete_calendar_event(event_id)?;
        Ok(())
    }

    // -- Calendar queries --

    pub fn list_calendars(
        &self,
        include_deleted: bool,
        page: QueryPage,
    ) -> Result<Vec<StoredCalendar>> {
        Ok(self
            .calendar
            .list_calendars(include_deleted, to_calendar_page(page))?)
    }

    pub fn get_calendar(
        &self,
        calendar_id: &str,
        include_deleted: bool,
    ) -> Result<Option<StoredCalendar>> {
        Ok(self.calendar.get_calendar(calendar_id, include_deleted)?)
    }

    pub fn calendar_collection_version(&self, calendar_id: &str) -> Result<i64> {
        Ok(self.calendar.calendar_collection_version(calendar_id)?)
    }

    pub fn list_calendar_events(
        &self,
        calendar_id: &str,
        include_deleted: bool,
        range: CalendarEventRange,
        page: QueryPage,
    ) -> Result<Vec<StoredCalendarEvent>> {
        Ok(self.calendar.list_calendar_events(
            calendar_id,
            include_deleted,
            range,
            to_calendar_page(page),
        )?)
    }

    pub fn get_calendar_event(
        &self,
        event_id: &str,
        include_deleted: bool,
    ) -> Result<Option<StoredCalendarEvent>> {
        Ok(self
            .calendar
            .get_calendar_event(event_id, include_deleted)?)
    }

    pub fn get_calendar_event_payload(
        &self,
        event_id: &str,
        include_deleted: bool,
    ) -> Result<Option<calendar::CalendarEvent>> {
        match self
            .calendar
            .get_calendar_event_raw_json(event_id, include_deleted)?
        {
            Some(raw) => Ok(Some(serde_json::from_str::<calendar::CalendarEvent>(&raw)?)),
            None => Ok(None),
        }
    }

    pub fn get_calendar_event_payload_with_raw(
        &self,
        event_id: &str,
        include_deleted: bool,
    ) -> Result<Option<(calendar::CalendarEvent, Value)>> {
        match self
            .calendar
            .get_calendar_event_raw_json(event_id, include_deleted)?
        {
            Some(raw) => {
                let raw_value: Value = serde_json::from_str(&raw)?;
                let event: calendar::CalendarEvent = serde_json::from_value(raw_value.clone())?;
                Ok(Some((event, raw_value)))
            }
            None => Ok(None),
        }
    }

    // -- Sync state --

    pub fn set_sync_state_text(&self, scope: &str, value: &str) -> Result<()> {
        if is_calendar_scope(scope) {
            self.calendar.set_sync_state_text(scope, value)?;
        } else {
            self.contacts.set_sync_state_text(scope, value)?;
        }
        Ok(())
    }

    pub fn get_sync_state_text(&self, scope: &str) -> Result<Option<String>> {
        if is_calendar_scope(scope) {
            Ok(self.calendar.get_sync_state_text(scope)?)
        } else {
            Ok(self.contacts.get_sync_state_text(scope)?)
        }
    }

    pub fn set_sync_state_int(&self, scope: &str, value: i64) -> Result<()> {
        if is_calendar_scope(scope) {
            self.calendar.set_sync_state_int(scope, value)?;
        } else {
            self.contacts.set_sync_state_int(scope, value)?;
        }
        Ok(())
    }

    pub fn get_sync_state_int(&self, scope: &str) -> Result<Option<i64>> {
        if is_calendar_scope(scope) {
            Ok(self.calendar.get_sync_state_int(scope)?)
        } else {
            Ok(self.contacts.get_sync_state_int(scope)?)
        }
    }
}

fn is_calendar_scope(scope: &str) -> bool {
    scope.starts_with("calendar.") || scope.starts_with("dav.cal.")
}
