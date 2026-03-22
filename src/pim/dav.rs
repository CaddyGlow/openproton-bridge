use std::sync::Arc;

use crate::api::{calendar, contacts};

use super::query::{CalendarEventRange, QueryPage};
use super::store::PimStore;
use super::types::{StoredCalendar, StoredCalendarEvent, StoredContact};
use super::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteMode {
    Soft,
    Hard,
}

pub trait CardDavRepository {
    fn list_contacts(&self, include_deleted: bool, page: QueryPage) -> Result<Vec<StoredContact>>;
    fn get_contact(&self, contact_id: &str, include_deleted: bool)
        -> Result<Option<StoredContact>>;
    fn search_contacts_by_email(
        &self,
        email_like: &str,
        page: QueryPage,
    ) -> Result<Vec<StoredContact>>;
    fn upsert_contact(&self, contact: &contacts::Contact) -> Result<()>;
    fn delete_contact(&self, contact_id: &str, mode: DeleteMode) -> Result<()>;
}

pub trait CalDavRepository {
    fn list_calendars(&self, include_deleted: bool, page: QueryPage)
        -> Result<Vec<StoredCalendar>>;
    fn get_calendar(
        &self,
        calendar_id: &str,
        include_deleted: bool,
    ) -> Result<Option<StoredCalendar>>;
    fn list_calendar_events(
        &self,
        calendar_id: &str,
        include_deleted: bool,
        range: CalendarEventRange,
        page: QueryPage,
    ) -> Result<Vec<StoredCalendarEvent>>;
    fn get_calendar_event(
        &self,
        event_id: &str,
        include_deleted: bool,
    ) -> Result<Option<StoredCalendarEvent>>;
    fn upsert_calendar(&self, calendar: &calendar::Calendar) -> Result<()>;
    fn delete_calendar(&self, calendar_id: &str, mode: DeleteMode) -> Result<()>;
    fn upsert_calendar_event(&self, event: &calendar::CalendarEvent) -> Result<()>;
    fn delete_calendar_event(&self, event_id: &str, mode: DeleteMode) -> Result<()>;
}

pub trait DavSyncStateRepository {
    fn get_sync_state_text(&self, scope: &str) -> Result<Option<String>>;
    fn set_sync_state_text(&self, scope: &str, value: &str) -> Result<()>;
    fn get_sync_state_int(&self, scope: &str) -> Result<Option<i64>>;
    fn set_sync_state_int(&self, scope: &str, value: i64) -> Result<()>;
}

pub trait PimDavRepository: CardDavRepository + CalDavRepository + DavSyncStateRepository {}

impl<T> PimDavRepository for T where T: CardDavRepository + CalDavRepository + DavSyncStateRepository
{}

#[derive(Clone)]
pub struct StoreBackedDavAdapter {
    store: Arc<PimStore>,
}

impl StoreBackedDavAdapter {
    pub fn new(store: Arc<PimStore>) -> Self {
        Self { store }
    }
}

impl CardDavRepository for StoreBackedDavAdapter {
    fn list_contacts(&self, include_deleted: bool, page: QueryPage) -> Result<Vec<StoredContact>> {
        self.store.list_contacts(include_deleted, page)
    }

    fn get_contact(
        &self,
        contact_id: &str,
        include_deleted: bool,
    ) -> Result<Option<StoredContact>> {
        self.store.get_contact(contact_id, include_deleted)
    }

    fn search_contacts_by_email(
        &self,
        email_like: &str,
        page: QueryPage,
    ) -> Result<Vec<StoredContact>> {
        self.store.search_contacts_by_email(email_like, page)
    }

    fn upsert_contact(&self, contact: &contacts::Contact) -> Result<()> {
        self.store.upsert_contact(contact)
    }

    fn delete_contact(&self, contact_id: &str, mode: DeleteMode) -> Result<()> {
        match mode {
            DeleteMode::Soft => self.store.soft_delete_contact(contact_id),
            DeleteMode::Hard => self.store.hard_delete_contact(contact_id),
        }
    }
}

impl CalDavRepository for StoreBackedDavAdapter {
    fn list_calendars(
        &self,
        include_deleted: bool,
        page: QueryPage,
    ) -> Result<Vec<StoredCalendar>> {
        self.store.list_calendars(include_deleted, page)
    }

    fn get_calendar(
        &self,
        calendar_id: &str,
        include_deleted: bool,
    ) -> Result<Option<StoredCalendar>> {
        self.store.get_calendar(calendar_id, include_deleted)
    }

    fn list_calendar_events(
        &self,
        calendar_id: &str,
        include_deleted: bool,
        range: CalendarEventRange,
        page: QueryPage,
    ) -> Result<Vec<StoredCalendarEvent>> {
        self.store
            .list_calendar_events(calendar_id, include_deleted, range, page)
    }

    fn get_calendar_event(
        &self,
        event_id: &str,
        include_deleted: bool,
    ) -> Result<Option<StoredCalendarEvent>> {
        self.store.get_calendar_event(event_id, include_deleted)
    }

    fn upsert_calendar(&self, calendar: &calendar::Calendar) -> Result<()> {
        self.store.upsert_calendar(calendar)
    }

    fn delete_calendar(&self, calendar_id: &str, mode: DeleteMode) -> Result<()> {
        match mode {
            DeleteMode::Soft => self.store.soft_delete_calendar(calendar_id),
            DeleteMode::Hard => self.store.hard_delete_calendar(calendar_id),
        }
    }

    fn upsert_calendar_event(&self, event: &calendar::CalendarEvent) -> Result<()> {
        self.store.upsert_calendar_event(event)
    }

    fn delete_calendar_event(&self, event_id: &str, mode: DeleteMode) -> Result<()> {
        match mode {
            DeleteMode::Soft => self.store.soft_delete_calendar_event(event_id),
            DeleteMode::Hard => self.store.hard_delete_calendar_event(event_id),
        }
    }
}

impl DavSyncStateRepository for StoreBackedDavAdapter {
    fn get_sync_state_text(&self, scope: &str) -> Result<Option<String>> {
        self.store.get_sync_state_text(scope)
    }

    fn set_sync_state_text(&self, scope: &str, value: &str) -> Result<()> {
        self.store.set_sync_state_text(scope, value)
    }

    fn get_sync_state_int(&self, scope: &str) -> Result<Option<i64>> {
        self.store.get_sync_state_int(scope)
    }

    fn set_sync_state_int(&self, scope: &str, value: i64) -> Result<()> {
        self.store.set_sync_state_int(scope, value)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::api::calendar::{Calendar, CalendarEvent};
    use crate::api::contacts::{Contact, ContactCard, ContactEmail, ContactMetadata};

    fn adapter() -> StoreBackedDavAdapter {
        let tmp = tempdir().unwrap();
        let contacts_db = tmp.path().join("contacts.db");
        let calendar_db = tmp.path().join("calendar.db");
        Box::leak(Box::new(tmp));
        let store = Arc::new(PimStore::new(contacts_db, calendar_db).unwrap());
        StoreBackedDavAdapter::new(store)
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
    fn carddav_adapter_supports_contact_read_write_delete() {
        let adapter = adapter();
        adapter
            .upsert_contact(&contact("c1", "alice@proton.me"))
            .unwrap();

        let got = adapter.get_contact("c1", false).unwrap().unwrap();
        assert_eq!(got.id, "c1");

        let by_email = adapter
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

        adapter.delete_contact("c1", DeleteMode::Soft).unwrap();
        assert!(adapter.get_contact("c1", false).unwrap().is_none());
        assert!(adapter.get_contact("c1", true).unwrap().is_some());
    }

    #[test]
    fn caldav_adapter_supports_calendar_and_event_read_write_delete() {
        let adapter = adapter();
        adapter
            .upsert_calendar(&calendar("cal-1", "Primary"))
            .unwrap();
        adapter
            .upsert_calendar_event(&calendar_event("evt-1", "cal-1", 100))
            .unwrap();
        adapter
            .upsert_calendar_event(&calendar_event("evt-2", "cal-1", 200))
            .unwrap();

        let cals = adapter
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

        let events = adapter
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

        adapter
            .delete_calendar_event("evt-1", DeleteMode::Soft)
            .unwrap();
        assert!(adapter
            .get_calendar_event("evt-1", false)
            .unwrap()
            .is_none());
        assert!(adapter.get_calendar_event("evt-1", true).unwrap().is_some());

        adapter.delete_calendar("cal-1", DeleteMode::Hard).unwrap();
        assert!(adapter.get_calendar("cal-1", true).unwrap().is_none());
    }

    #[test]
    fn dav_adapter_exposes_sync_state_scopes() {
        let adapter = adapter();
        adapter
            .set_sync_state_text("dav.card.token", "ctag-1")
            .unwrap();
        adapter
            .set_sync_state_int("dav.cal.last_sync_ms", 1700000000000)
            .unwrap();

        assert_eq!(
            adapter
                .get_sync_state_text("dav.card.token")
                .unwrap()
                .as_deref(),
            Some("ctag-1")
        );
        assert_eq!(
            adapter.get_sync_state_int("dav.cal.last_sync_ms").unwrap(),
            Some(1700000000000)
        );
    }
}
