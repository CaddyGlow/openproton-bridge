use tracing::info;

use super::client::{check_api_response, ProtonClient};
use super::error::Result;
use super::types::EventsResponse;

/// Fetch incremental user events from Proton.
///
/// If `last_event_id` is empty, Proton returns a baseline cursor.
pub async fn get_events(client: &ProtonClient, last_event_id: &str) -> Result<EventsResponse> {
    info!(last_event_id = %last_event_id, "fetching events");

    let path = if last_event_id.trim().is_empty() {
        "/core/v4/events".to_string()
    } else {
        format!("/core/v4/events/{}", last_event_id)
    };

    let resp = client.get(&path).send().await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let events: EventsResponse = serde_json::from_value(json)?;
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
                "Events": [{"ID": "evt-a"}]
            })))
            .mount(&server)
            .await;

        let resp = get_events(&client, "event-1").await.unwrap();
        assert_eq!(resp.event_id, "event-2");
        assert_eq!(resp.more, 0);
        assert_eq!(resp.refresh, 0);
        assert_eq!(resp.events.len(), 1);
    }

    #[tokio::test]
    async fn get_events_without_cursor() {
        let server = MockServer::start().await;
        let client = ProtonClient::authenticated(&server.uri(), "uid-1", "token-1").unwrap();

        Mock::given(method("GET"))
            .and(path("/core/v4/events"))
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
}
