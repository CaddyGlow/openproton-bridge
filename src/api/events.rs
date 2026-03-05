use tracing::info;

use super::client::{
    check_api_response, is_transient_http_status, retry_delay_from_headers, send_logged,
    ProtonClient,
};
use super::error::{ApiError, Result};
use super::types::{EventsResponse, TypedEventPayload};

const MAX_TRANSIENT_ATTEMPTS: usize = 2;

/// Fetch incremental user events from Proton.
///
/// If `last_event_id` is empty, Proton returns a baseline cursor from `/latest`.
pub async fn get_events(client: &ProtonClient, last_event_id: &str) -> Result<EventsResponse> {
    info!(last_event_id = %last_event_id, "fetching events");

    let path = if last_event_id.trim().is_empty() {
        "/core/v4/events/latest".to_string()
    } else {
        format!("/core/v4/events/{}", last_event_id)
    };

    for attempt in 0..MAX_TRANSIENT_ATTEMPTS {
        let resp = send_logged(client.get(&path)).await?;
        let status = resp.status();
        let retry_delay = retry_delay_from_headers(resp.headers());
        let json: serde_json::Value = resp.json().await?;

        if !status.is_success()
            && is_transient_http_status(status)
            && attempt + 1 < MAX_TRANSIENT_ATTEMPTS
        {
            tokio::time::sleep(retry_delay).await;
            continue;
        }

        check_api_response(&json)?;
        if status.is_success() {
            let events: EventsResponse = serde_json::from_value(json)?;
            return Ok(events);
        }

        return Err(ApiError::Api {
            code: i64::from(status.as_u16()),
            message: format!("HTTP status {}", status.as_u16()),
            details: Some(json),
        });
    }

    Err(ApiError::Auth("exhausted transient retries".to_string()))
}

pub fn parse_typed_event_payload(value: &serde_json::Value) -> Option<TypedEventPayload> {
    serde_json::from_value(value.clone()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::TypedEventItem;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn find_item<'a>(items: &'a [TypedEventItem], id: &str) -> &'a TypedEventItem {
        items
            .iter()
            .find(|item| item.id == id)
            .expect("missing typed event item")
    }

    #[tokio::test]
    async fn get_events_with_cursor() {
        let server = MockServer::start().await;
        let client = ProtonClient::authenticated(&server.uri(), "uid-1", "token-1").unwrap();

        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-1"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer token-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-2",
                "More": 0,
                "Refresh": 0,
                "Events": [{"ID": "evt-a"}, {"ID": "evt-b"}]
            })))
            .mount(&server)
            .await;

        let resp = get_events(&client, "event-1").await.unwrap();
        assert_eq!(resp.event_id, "event-2");
        assert_eq!(resp.more, 0);
        assert_eq!(resp.refresh, 0);
        assert_eq!(resp.events.len(), 2);
        assert_eq!(resp.events[0]["ID"], "evt-a");
        assert_eq!(resp.events[1]["ID"], "evt-b");
    }

    #[tokio::test]
    async fn get_events_without_cursor() {
        let server = MockServer::start().await;
        let client = ProtonClient::authenticated(&server.uri(), "uid-1", "token-1").unwrap();

        Mock::given(method("GET"))
            .and(path("/core/v4/events/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-1",
                "Events": []
            })))
            .mount(&server)
            .await;

        let resp = get_events(&client, "").await.unwrap();
        assert_eq!(resp.event_id, "event-1");
        assert_eq!(resp.events.len(), 0);
    }

    #[tokio::test]
    async fn get_events_retries_once_on_transient_status() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_task = calls.clone();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await.unwrap();
                let current = calls_task.fetch_add(1, Ordering::SeqCst);
                let body = if current == 0 {
                    serde_json::json!({
                        "Code": 429,
                        "Error": "rate limit"
                    })
                } else {
                    serde_json::json!({
                        "Code": 1000,
                        "EventID": "event-2",
                        "Events": [{"ID": "evt-a"}]
                    })
                };
                let body = body.to_string();
                let status = if current == 0 {
                    "429 Too Many Requests"
                } else {
                    "200 OK"
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nRetry-After: 0\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        let client =
            ProtonClient::authenticated(&format!("http://{}", addr), "uid-1", "token-1").unwrap();
        let resp = get_events(&client, "event-1").await.unwrap();
        assert_eq!(resp.event_id, "event-2");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        server.await.unwrap();
    }

    #[test]
    fn parse_typed_event_payload_supports_canonical_event_shapes() {
        let payload = serde_json::json!({
            "Messages": [{"ID": "msg-1", "Action": 1}],
            "Labels": {"label-1": {"Action": 2}},
            "Addresses": ["addr-1"],
            "Contacts": [{"Action": 1, "Contact": {"ID": "contact-1"}}],
            "ContactEmails": [{"Action": 0, "ContactEmail": {"ID": "contact-email-1"}}],
            "Calendars": [{"Action": 2, "Calendar": {"ID": "calendar-1"}}]
        });

        let parsed = parse_typed_event_payload(&payload).unwrap();
        assert!(parsed.has_recognized_event_fields());
        assert_eq!(parsed.messages.as_ref().map(|v| v.len()), Some(1));
        assert_eq!(parsed.labels.as_ref().map(|v| v.len()), Some(1));
        assert_eq!(parsed.addresses.as_ref().map(|v| v.len()), Some(1));
        assert_eq!(parsed.contacts.as_ref().map(|v| v.len()), Some(1));
        assert_eq!(parsed.contact_emails.as_ref().map(|v| v.len()), Some(1));
        assert_eq!(parsed.calendars.as_ref().map(|v| v.len()), Some(1));
    }

    #[tokio::test]
    async fn get_events_stream_tracks_calendar_contact_changes_across_cursors() {
        let server = MockServer::start().await;
        let client = ProtonClient::authenticated(&server.uri(), "uid-1", "token-1").unwrap();

        Mock::given(method("GET"))
            .and(path("/core/v4/events/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-101",
                "More": 1,
                "Refresh": 0,
                "Events": [{
                    "Contacts": [
                        {"Action": 1, "Contact": {"ID": "contact-1"}}
                    ],
                    "ContactEmails": [
                        {"Action": 2, "ContactEmail": {"ID": "email-1"}}
                    ],
                    "Calendars": [
                        {"Action": 2, "Calendar": {"ID": "cal-1"}}
                    ],
                    "CalendarMembers": [
                        {"Action": 1, "Member": {"ID": "member-1"}}
                    ]
                }]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/core/v4/events/event-101"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "EventID": "event-102",
                "More": 0,
                "Refresh": 0,
                "Events": [{
                    "Contacts": {
                        "contact-1": null,
                        "contact-2": {"Action": 2}
                    },
                    "ContactEmails": {
                        "email-1": null
                    },
                    "Calendars": {
                        "cal-1": {"Action": "0"}
                    },
                    "CalendarMembers": {
                        "member-1": {"Action": 0}
                    }
                }]
            })))
            .mount(&server)
            .await;

        let first = get_events(&client, "").await.unwrap();
        assert_eq!(first.event_id, "event-101");
        assert_eq!(first.more, 1);
        assert_eq!(first.events.len(), 1);

        let first_typed = parse_typed_event_payload(&first.events[0]).unwrap();
        let first_contacts = first_typed.contacts.as_ref().unwrap();
        assert_eq!(first_contacts.len(), 1);
        assert!(find_item(first_contacts, "contact-1").is_create());
        let first_contact_emails = first_typed.contact_emails.as_ref().unwrap();
        assert!(find_item(first_contact_emails, "email-1").is_update());
        let first_calendars = first_typed.calendars.as_ref().unwrap();
        assert!(find_item(first_calendars, "cal-1").is_update());
        let first_members = first_typed.calendar_members.as_ref().unwrap();
        assert!(find_item(first_members, "member-1").is_create());

        let second = get_events(&client, &first.event_id).await.unwrap();
        assert_eq!(second.event_id, "event-102");
        assert_eq!(second.more, 0);
        assert_eq!(second.events.len(), 1);

        let second_typed = parse_typed_event_payload(&second.events[0]).unwrap();
        let second_contacts = second_typed.contacts.as_ref().unwrap();
        assert_eq!(second_contacts.len(), 2);
        assert!(find_item(second_contacts, "contact-1").is_delete());
        assert!(find_item(second_contacts, "contact-2").is_update());
        let second_contact_emails = second_typed.contact_emails.as_ref().unwrap();
        assert!(find_item(second_contact_emails, "email-1").is_delete());
        let second_calendars = second_typed.calendars.as_ref().unwrap();
        assert!(find_item(second_calendars, "cal-1").is_delete());
        let second_members = second_typed.calendar_members.as_ref().unwrap();
        assert!(find_item(second_members, "member-1").is_delete());
    }
}
