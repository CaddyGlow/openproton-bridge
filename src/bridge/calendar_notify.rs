use std::sync::Arc;

use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub struct CalendarChangeEvent {
    pub account_id: String,
    pub calendar_id: String,
}

#[derive(Clone)]
pub struct CalendarChangeNotifier {
    tx: broadcast::Sender<CalendarChangeEvent>,
}

impl Default for CalendarChangeNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl CalendarChangeNotifier {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(256);
        Self { tx }
    }

    pub fn notify(&self, account_id: &str, calendar_id: &str) {
        let _ = self.tx.send(CalendarChangeEvent {
            account_id: account_id.to_string(),
            calendar_id: calendar_id.to_string(),
        });
    }

    pub fn notify_account(&self, account_id: &str) {
        self.notify(account_id, "*");
    }

    pub fn subscribe(&self) -> broadcast::Receiver<CalendarChangeEvent> {
        self.tx.subscribe()
    }
}

pub type SharedCalendarChangeNotifier = Arc<CalendarChangeNotifier>;
