use tracing::info;

use super::client::{
    check_api_response, is_transient_http_status, retry_delay_from_headers, ProtonClient,
};
use super::error::{ApiError, Result};
use super::types::EventsResponse;

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
        let resp = client.get(&path).send().await?;
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
}
