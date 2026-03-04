use openproton_bridge::api::client::ProtonClient;
use openproton_bridge::api::error::ApiError;
use openproton_bridge::api::{events, messages};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn api_event_accepts_single_event_shape() {
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
            "Event": {"ID": "evt-single"}
        })))
        .mount(&server)
        .await;

    let response = events::get_events(&client, "event-1").await.unwrap();
    assert_eq!(response.event_id, "event-2");
    assert_eq!(response.events.len(), 1);
    assert_eq!(response.events[0]["ID"], "evt-single");
}

#[tokio::test]
async fn api_event_attachment_error_returns_api_error_payload() {
    let server = MockServer::start().await;
    let client = ProtonClient::authenticated(&server.uri(), "uid-1", "token-1").unwrap();

    Mock::given(method("GET"))
        .and(path("/mail/v4/attachments/att-404"))
        .and(header("x-pm-uid", "uid-1"))
        .and(header("Authorization", "Bearer token-1"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "Code": 2501,
            "Error": "Attachment does not exist"
        })))
        .mount(&server)
        .await;

    let err = messages::get_attachment(&client, "att-404")
        .await
        .expect_err("expected API error");
    match err {
        ApiError::Api { code, message, .. } => {
            assert_eq!(code, 2501);
            assert_eq!(message, "Attachment does not exist");
        }
        other => panic!("expected ApiError::Api, got {other:?}"),
    }
}
