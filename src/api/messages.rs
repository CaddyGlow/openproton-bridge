use tracing::info;

use super::client::{check_api_response, ProtonClient};
use super::error::Result;
use super::types::{MessageFilter, MessageResponse, MessagesMetadataResponse};

/// Fetch a full message including encrypted body and attachment metadata.
///
/// Reference: go-proton-api/message.go GetMessage
pub async fn get_message(client: &ProtonClient, message_id: &str) -> Result<MessageResponse> {
    info!(message_id = %message_id, "fetching message");
    let path = format!("/mail/v4/messages/{}", message_id);
    let resp = client.get(&path).send().await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let msg_resp: MessageResponse = serde_json::from_value(json)?;
    Ok(msg_resp)
}

/// Fetch a page of message metadata using POST-as-GET.
///
/// Proton uses POST with X-HTTP-Method-Override: GET because filters can be large.
///
/// Reference: go-proton-api/message.go GetMessageMetadataPage
pub async fn get_message_metadata(
    client: &ProtonClient,
    filter: &MessageFilter,
    page: i32,
    page_size: i32,
) -> Result<MessagesMetadataResponse> {
    info!(
        page = page,
        page_size = page_size,
        "fetching message metadata"
    );

    let body = serde_json::json!({
        "LabelID": filter.label_id,
        "EndID": filter.end_id,
        "Desc": filter.desc,
        "Page": page,
        "PageSize": page_size,
        "Sort": "ID",
    });

    let resp = client
        .post("/mail/v4/messages")
        .header("X-HTTP-Method-Override", "GET")
        .json(&body)
        .send()
        .await?;

    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let meta_resp: MessagesMetadataResponse = serde_json::from_value(json)?;
    Ok(meta_resp)
}

/// Fetch raw encrypted attachment data.
///
/// Reference: go-proton-api/attachment.go GetAttachment
pub async fn get_attachment(client: &ProtonClient, attachment_id: &str) -> Result<Vec<u8>> {
    info!(attachment_id = %attachment_id, "fetching attachment");
    let path = format!("/mail/v4/attachments/{}", attachment_id);
    let resp = client.get(&path).send().await?;
    let bytes = resp.bytes().await?;
    Ok(bytes.to_vec())
}

/// Mark messages as read.
///
/// Reference: go-proton-api/message.go MarkMessagesRead
pub async fn mark_messages_read(client: &ProtonClient, ids: &[&str]) -> Result<()> {
    info!(count = ids.len(), "marking messages read");
    let body = serde_json::json!({ "IDs": ids });
    let resp = client
        .put("/mail/v4/messages/read")
        .json(&body)
        .send()
        .await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    Ok(())
}

/// Mark messages as unread.
///
/// Reference: go-proton-api/message.go MarkMessagesUnread
pub async fn mark_messages_unread(client: &ProtonClient, ids: &[&str]) -> Result<()> {
    info!(count = ids.len(), "marking messages unread");
    let body = serde_json::json!({ "IDs": ids });
    let resp = client
        .put("/mail/v4/messages/unread")
        .json(&body)
        .send()
        .await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    Ok(())
}

/// Add a label to messages.
///
/// Reference: go-proton-api/message.go LabelMessages
pub async fn label_messages(client: &ProtonClient, ids: &[&str], label_id: &str) -> Result<()> {
    info!(count = ids.len(), label_id = %label_id, "labeling messages");
    let body = serde_json::json!({ "LabelID": label_id, "IDs": ids });
    let resp = client
        .put("/mail/v4/messages/label")
        .json(&body)
        .send()
        .await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    Ok(())
}

/// Remove a label from messages.
///
/// Reference: go-proton-api/message.go UnlabelMessages
pub async fn unlabel_messages(client: &ProtonClient, ids: &[&str], label_id: &str) -> Result<()> {
    info!(count = ids.len(), label_id = %label_id, "unlabeling messages");
    let body = serde_json::json!({ "LabelID": label_id, "IDs": ids });
    let resp = client
        .put("/mail/v4/messages/unlabel")
        .json(&body)
        .send()
        .await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup_authenticated_client(server: &MockServer) -> ProtonClient {
        ProtonClient::authenticated(&server.uri(), "test-uid", "test-token").unwrap()
    }

    #[tokio::test]
    async fn test_get_message() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/mail/v4/messages/msg-123"))
            .and(header("x-pm-uid", "test-uid"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Message": {
                    "ID": "msg-123",
                    "AddressID": "addr-1",
                    "LabelIDs": ["0"],
                    "Subject": "Test Email",
                    "Sender": { "Name": "Alice", "Address": "alice@proton.me" },
                    "ToList": [{ "Name": "Bob", "Address": "bob@proton.me" }],
                    "CCList": [],
                    "BCCList": [],
                    "Time": 1700000000,
                    "Size": 1024,
                    "Unread": 1,
                    "NumAttachments": 0,
                    "Header": "From: alice@proton.me\r\n",
                    "Body": "-----BEGIN PGP MESSAGE-----\nencrypted\n-----END PGP MESSAGE-----",
                    "MIMEType": "text/html",
                    "Attachments": []
                }
            })))
            .mount(&server)
            .await;

        let resp = get_message(&client, "msg-123").await.unwrap();
        assert_eq!(resp.message.metadata.id, "msg-123");
        assert_eq!(resp.message.metadata.subject, "Test Email");
        assert_eq!(resp.message.mime_type, "text/html");
    }

    #[tokio::test]
    async fn test_get_message_not_found() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/mail/v4/messages/nonexistent"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 2501,
                "Error": "Message does not exist"
            })))
            .mount(&server)
            .await;

        let err = get_message(&client, "nonexistent").await.unwrap_err();
        assert!(err.to_string().contains("Message does not exist"));
    }

    #[tokio::test]
    async fn test_get_message_metadata() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(header("X-HTTP-Method-Override", "GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 42,
                "Messages": [
                    {
                        "ID": "msg-1",
                        "AddressID": "addr-1",
                        "LabelIDs": ["0"],
                        "Subject": "First",
                        "Sender": { "Name": "Alice", "Address": "alice@proton.me" },
                        "ToList": [],
                        "CCList": [],
                        "BCCList": [],
                        "Time": 1700000000,
                        "Size": 512,
                        "Unread": 1,
                        "NumAttachments": 0
                    },
                    {
                        "ID": "msg-2",
                        "AddressID": "addr-1",
                        "LabelIDs": ["0"],
                        "Subject": "Second",
                        "Sender": { "Name": "Bob", "Address": "bob@proton.me" },
                        "ToList": [],
                        "CCList": [],
                        "BCCList": [],
                        "Time": 1700000001,
                        "Size": 256,
                        "Unread": 0,
                        "NumAttachments": 2
                    }
                ]
            })))
            .mount(&server)
            .await;

        let filter = MessageFilter {
            label_id: Some("0".to_string()),
            desc: 1,
            ..Default::default()
        };

        let resp = get_message_metadata(&client, &filter, 0, 50).await.unwrap();
        assert_eq!(resp.total, 42);
        assert_eq!(resp.messages.len(), 2);
        assert_eq!(resp.messages[0].subject, "First");
        assert_eq!(resp.messages[1].subject, "Second");
    }

    #[tokio::test]
    async fn test_mark_messages_read() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/read"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .mount(&server)
            .await;

        mark_messages_read(&client, &["msg-1", "msg-2"])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_mark_messages_unread() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unread"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .mount(&server)
            .await;

        mark_messages_unread(&client, &["msg-1"]).await.unwrap();
    }

    #[tokio::test]
    async fn test_label_messages() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/label"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .mount(&server)
            .await;

        label_messages(&client, &["msg-1"], "10").await.unwrap();
    }

    #[tokio::test]
    async fn test_unlabel_messages() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/unlabel"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .mount(&server)
            .await;

        unlabel_messages(&client, &["msg-1"], "10").await.unwrap();
    }

    #[tokio::test]
    async fn test_get_attachment() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        let raw_data: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];

        Mock::given(method("GET"))
            .and(path("/mail/v4/attachments/att-456"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(raw_data.clone()))
            .mount(&server)
            .await;

        let bytes = get_attachment(&client, "att-456").await.unwrap();
        assert_eq!(bytes, raw_data);
    }
}
