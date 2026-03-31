use std::path::PathBuf;

use gluon_rs_calendar::CalendarStore;
use gluon_rs_contacts::ContactsStore;
use serde_json::Value;

use crate::api::{calendar, contacts};

use super::convert;
use super::{
    CalendarEventRange, QueryPage, Result, StoredCalendar, StoredCalendarEvent, StoredContact,
};

fn to_calendar_page(page: QueryPage) -> gluon_rs_calendar::QueryPage {
    gluon_rs_calendar::QueryPage {
        limit: page.limit,
        offset: page.offset,
    }
}

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

    pub fn get_calendar_member_name(&self, calendar_id: &str) -> Option<String> {
        self.calendar
            .get_calendar_member_name(calendar_id)
            .ok()
            .flatten()
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

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::api::calendar::{Calendar, CalendarEvent};
    use crate::api::contacts::{Contact, ContactCard, ContactEmail, ContactMetadata};
    use crate::pim::{CalendarEventRange, QueryPage};

    fn test_store() -> PimStore {
        let tmp = tempdir().unwrap();
        let contacts_db = tmp.path().join("contacts.db");
        let calendar_db = tmp.path().join("calendar.db");
        Box::leak(Box::new(tmp));
        PimStore::new(contacts_db, calendar_db).unwrap()
    }

    fn contact(id: &str, email: &str) -> Contact {
        Contact {
            metadata: ContactMetadata {
                id: id.to_string(),
                name: format!("Name {id}"),
                uid: format!("uid-{id}"),
                size: 1,
                create_time: 1,
                modify_time: 2,
                contact_emails: vec![ContactEmail {
                    id: format!("email-{id}"),
                    email: email.to_string(),
                    name: "Name".to_string(),
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
        }
    }

    fn calendar(id: &str, name: &str) -> Calendar {
        Calendar {
            id: id.to_string(),
            name: name.to_string(),
            description: "".to_string(),
            color: "#00AAFF".to_string(),
            display: 1,
            calendar_type: 0,
            flags: 0,
        }
    }

    fn calendar_event(id: &str, calendar_id: &str, start_time: i64) -> CalendarEvent {
        CalendarEvent {
            id: id.to_string(),
            uid: format!("uid-{id}"),
            calendar_id: calendar_id.to_string(),
            shared_event_id: format!("shared-{id}"),
            create_time: start_time - 5,
            last_edit_time: start_time - 1,
            start_time,
            end_time: start_time + 3600,
            ..CalendarEvent::default()
        }
    }

    #[test]
    fn store_supports_contact_read_write_delete() {
        let store = test_store();
        store
            .upsert_contact(&contact("c1", "alice@proton.me"))
            .unwrap();

        let got = store.get_contact("c1", false).unwrap().unwrap();
        assert_eq!(got.id, "c1");

        let by_email = store
            .search_contacts_by_email(
                "alice@",
                QueryPage {
                    limit: 10,
                    offset: 0,
                },
            )
            .unwrap();
        assert_eq!(by_email.len(), 1);
        assert_eq!(by_email[0].id, "c1");

        store.soft_delete_contact("c1").unwrap();
        assert!(store.get_contact("c1", false).unwrap().is_none());
        assert!(store.get_contact("c1", true).unwrap().is_some());
    }

    #[test]
    fn store_supports_calendar_and_event_read_write_delete() {
        let store = test_store();
        store
            .upsert_calendar(&calendar("cal-1", "Primary"))
            .unwrap();
        store
            .upsert_calendar_event(&calendar_event("evt-1", "cal-1", 100))
            .unwrap();
        store
            .upsert_calendar_event(&calendar_event("evt-2", "cal-1", 200))
            .unwrap();

        let cals = store
            .list_calendars(
                false,
                QueryPage {
                    limit: 10,
                    offset: 0,
                },
            )
            .unwrap();
        assert_eq!(cals.len(), 1);
        assert_eq!(cals[0].id, "cal-1");

        let events = store
            .list_calendar_events(
                "cal-1",
                false,
                CalendarEventRange {
                    start_time_from: Some(50),
                    start_time_to: Some(150),
                },
                QueryPage {
                    limit: 10,
                    offset: 0,
                },
            )
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "evt-1");

        store.soft_delete_calendar_event("evt-1").unwrap();
        assert!(store.get_calendar_event("evt-1", false).unwrap().is_none());
        assert!(store.get_calendar_event("evt-1", true).unwrap().is_some());

        store.hard_delete_calendar("cal-1").unwrap();
        assert!(store.get_calendar("cal-1", true).unwrap().is_none());
    }

    #[test]
    fn store_exposes_sync_state_scopes() {
        let store = test_store();
        store
            .set_sync_state_text("dav.card.token", "ctag-1")
            .unwrap();
        store
            .set_sync_state_int("dav.cal.last_sync_ms", 1700000000000)
            .unwrap();

        assert_eq!(
            store
                .get_sync_state_text("dav.card.token")
                .unwrap()
                .as_deref(),
            Some("ctag-1")
        );
        assert_eq!(
            store.get_sync_state_int("dav.cal.last_sync_ms").unwrap(),
            Some(1700000000000)
        );
    }
}
