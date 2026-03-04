use std::time::Instant;

use tracing::info;

use super::client::{
    check_api_response, is_transient_http_status, retry_delay_from_headers, send_logged,
    ProtonClient,
};
use super::error::{ApiError, Result};
use super::types::{
    AttachmentResponse, CreateDraftReq, MessageFilter, MessageResponse, MessagesMetadataResponse,
    SendDraftReq, SendDraftResponse,
};

fn build_message_metadata_body(
    filter: &MessageFilter,
    page: i32,
    page_size: i32,
) -> Result<serde_json::Value> {
    let mut body = match serde_json::to_value(filter)? {
        serde_json::Value::Object(object) => object,
        _ => serde_json::Map::new(),
    };

    body.entry("LabelID".to_string())
        .or_insert(serde_json::Value::Null);
    body.entry("EndID".to_string())
        .or_insert(serde_json::Value::Null);
    body.insert("Page".to_string(), serde_json::json!(page));
    body.insert("PageSize".to_string(), serde_json::json!(page_size));
    body.insert("Sort".to_string(), serde_json::json!("ID"));

    Ok(serde_json::Value::Object(body))
}

/// Fetch a full message including encrypted body and attachment metadata.
///
/// Reference: go-proton-api/message.go GetMessage
pub async fn get_message(client: &ProtonClient, message_id: &str) -> Result<MessageResponse> {
    info!(message_id = %message_id, "fetching message");
    let fetch_started = Instant::now();
    let path = format!("/mail/v4/messages/{}", message_id);
    let resp = send_logged(client.get(&path)).await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let msg_resp: MessageResponse = serde_json::from_value(json)?;
    info!(
        message_id = %message_id,
        duration_ms = fetch_started.elapsed().as_millis() as u64,
        attachment_count = msg_resp.message.attachments.len(),
        "full_message_fetch"
    );
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
    const MAX_TRANSIENT_ATTEMPTS: usize = 2;

    info!(
        page = page,
        page_size = page_size,
        "fetching message metadata"
    );

    let body = build_message_metadata_body(filter, page, page_size)?;

    for attempt in 0..MAX_TRANSIENT_ATTEMPTS {
        let fetch_started = Instant::now();
        let resp = send_logged(
            client
                .post("/mail/v4/messages")
                .header("X-HTTP-Method-Override", "GET")
                .json(&body),
        )
        .await?;

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
            let meta_resp: MessagesMetadataResponse = serde_json::from_value(json)?;
            info!(
                page = page,
                page_size = page_size,
                messages_count = meta_resp.messages.len(),
                total = meta_resp.total,
                attempt = attempt + 1,
                duration_ms = fetch_started.elapsed().as_millis() as u64,
                "metadata_fetch"
            );
            return Ok(meta_resp);
        }

        return Err(ApiError::Api {
            code: i64::from(status.as_u16()),
            message: format!("HTTP status {}", status.as_u16()),
            details: Some(json),
        });
    }

    Err(ApiError::Auth("exhausted transient retries".to_string()))
}

/// Fetch raw encrypted attachment data.
///
/// Reference: go-proton-api/attachment.go GetAttachment
pub async fn get_attachment(client: &ProtonClient, attachment_id: &str) -> Result<Vec<u8>> {
    info!(attachment_id = %attachment_id, "fetching attachment");
    let fetch_started = Instant::now();
    let path = format!("/mail/v4/attachments/{}", attachment_id);
    let resp = send_logged(client.get(&path)).await?;
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let bytes = resp.bytes().await?;

    if !status.is_success() || content_type.contains("json") {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            check_api_response(&json)?;
        } else if !status.is_success() {
            return Err(ApiError::Auth(format!(
                "attachment request failed with HTTP {}",
                status.as_u16()
            )));
        }
    }

    info!(
        attachment_id = %attachment_id,
        bytes = bytes.len(),
        duration_ms = fetch_started.elapsed().as_millis() as u64,
        "attachment_fetch"
    );

    Ok(bytes.to_vec())
}

/// Mark messages as read.
///
/// Reference: go-proton-api/message.go MarkMessagesRead
pub async fn mark_messages_read(client: &ProtonClient, ids: &[&str]) -> Result<()> {
    info!(count = ids.len(), "marking messages read");
    let body = serde_json::json!({ "IDs": ids });
    let resp = send_logged(client.put("/mail/v4/messages/read").json(&body)).await?;
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
    let resp = send_logged(client.put("/mail/v4/messages/unread").json(&body)).await?;
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
    let resp = send_logged(client.put("/mail/v4/messages/label").json(&body)).await?;
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
    let resp = send_logged(client.put("/mail/v4/messages/unlabel").json(&body)).await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    Ok(())
}

/// Create a draft message with an encrypted body.
///
/// Reference: go-proton-api/message_send.go CreateDraft
pub async fn create_draft(client: &ProtonClient, req: &CreateDraftReq) -> Result<MessageResponse> {
    info!("creating draft");
    let resp = send_logged(client.post("/mail/v4/messages").json(req)).await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let msg_resp: MessageResponse = serde_json::from_value(json)?;
    Ok(msg_resp)
}

/// Parameters for uploading an encrypted attachment.
pub struct UploadAttachmentReq {
    pub message_id: String,
    pub filename: String,
    pub mime_type: String,
    pub disposition: String,
    pub content_id: String,
    pub key_packets: Vec<u8>,
    pub data_packet: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Upload an encrypted attachment to a draft message.
///
/// Reference: go-proton-api/attachment.go UploadAttachment
pub async fn upload_attachment(
    client: &ProtonClient,
    req: UploadAttachmentReq,
) -> Result<AttachmentResponse> {
    info!(message_id = %req.message_id, filename = %req.filename, "uploading attachment");

    let form = reqwest::multipart::Form::new()
        .text("MessageID", req.message_id)
        .text("Filename", req.filename)
        .text("MIMEType", req.mime_type)
        .text("Disposition", req.disposition)
        .text("ContentID", req.content_id)
        .part(
            "KeyPackets",
            reqwest::multipart::Part::bytes(req.key_packets)
                .file_name("blob")
                .mime_str("application/octet-stream")
                .unwrap(),
        )
        .part(
            "DataPacket",
            reqwest::multipart::Part::bytes(req.data_packet)
                .file_name("blob")
                .mime_str("application/octet-stream")
                .unwrap(),
        )
        .part(
            "Signature",
            reqwest::multipart::Part::bytes(req.signature)
                .file_name("blob")
                .mime_str("application/octet-stream")
                .unwrap(),
        );

    let resp = send_logged(client.post("/mail/v4/attachments").multipart(form)).await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let att_resp: AttachmentResponse = serde_json::from_value(json)?;
    Ok(att_resp)
}

/// Send a draft message with encryption packages.
///
/// Reference: go-proton-api/message_send.go SendDraft
pub async fn send_draft(
    client: &ProtonClient,
    draft_id: &str,
    req: &SendDraftReq,
) -> Result<SendDraftResponse> {
    info!(draft_id = %draft_id, "sending draft");
    let path = format!("/mail/v4/messages/{}", draft_id);
    let resp = send_logged(client.post(&path).json(req)).await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let send_resp: SendDraftResponse = serde_json::from_value(json)?;
    Ok(send_resp)
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

    #[test]
    fn test_build_message_metadata_body_serializes_extended_filter_fields() {
        let filter = MessageFilter {
            id: Some(vec!["msg-1".to_string()]),
            subject: Some("hello".to_string()),
            address_id: Some("addr-1".to_string()),
            external_id: Some("ext-1".to_string()),
            label_id: Some("0".to_string()),
            end_id: Some("msg-0".to_string()),
            desc: 1,
        };

        let body = build_message_metadata_body(&filter, 3, 25).unwrap();
        assert_eq!(body["ID"], serde_json::json!(["msg-1"]));
        assert_eq!(body["Subject"], "hello");
        assert_eq!(body["AddressID"], "addr-1");
        assert_eq!(body["ExternalID"], "ext-1");
        assert_eq!(body["LabelID"], "0");
        assert_eq!(body["EndID"], "msg-0");
        assert_eq!(body["Desc"], 1);
        assert_eq!(body["Page"], 3);
        assert_eq!(body["PageSize"], 25);
        assert_eq!(body["Sort"], "ID");
    }

    #[test]
    fn test_build_message_metadata_body_preserves_null_end_cursor_compatibility() {
        let filter = MessageFilter {
            label_id: Some("0".to_string()),
            desc: 1,
            ..Default::default()
        };

        let body = build_message_metadata_body(&filter, 0, 50).unwrap();
        assert_eq!(body["LabelID"], "0");
        assert!(body["EndID"].is_null());
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

    #[tokio::test]
    async fn test_create_draft() {
        use super::super::types::{CreateDraftReq, DraftTemplate, EmailAddress};

        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Message": {
                    "ID": "draft-1",
                    "AddressID": "addr-1",
                    "LabelIDs": ["1", "8"],
                    "Subject": "Test Draft",
                    "Sender": { "Name": "Alice", "Address": "alice@proton.me" },
                    "ToList": [{ "Name": "Bob", "Address": "bob@proton.me" }],
                    "CCList": [],
                    "BCCList": [],
                    "Time": 1700000000,
                    "Size": 256,
                    "Unread": 0,
                    "NumAttachments": 0,
                    "Header": "",
                    "Body": "encrypted",
                    "MIMEType": "text/plain",
                    "Attachments": []
                }
            })))
            .mount(&server)
            .await;

        let req = CreateDraftReq {
            message: DraftTemplate {
                subject: "Test Draft".to_string(),
                sender: EmailAddress {
                    name: "Alice".to_string(),
                    address: "alice@proton.me".to_string(),
                },
                to_list: vec![EmailAddress {
                    name: "Bob".to_string(),
                    address: "bob@proton.me".to_string(),
                }],
                cc_list: vec![],
                bcc_list: vec![],
                body: "encrypted body".to_string(),
                mime_type: "text/plain".to_string(),
                unread: 0,
                external_id: None,
            },
            attachment_key_packets: None,
            parent_id: None,
            action: 0,
        };

        let resp = create_draft(&client, &req).await.unwrap();
        assert_eq!(resp.message.metadata.id, "draft-1");
        assert_eq!(resp.message.metadata.subject, "Test Draft");
    }

    #[tokio::test]
    async fn test_create_draft_api_error() {
        use super::super::types::{CreateDraftReq, DraftTemplate, EmailAddress};

        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 2500,
                "Error": "Draft creation failed"
            })))
            .mount(&server)
            .await;

        let req = CreateDraftReq {
            message: DraftTemplate {
                subject: "Bad".to_string(),
                sender: EmailAddress {
                    name: "".to_string(),
                    address: "bad".to_string(),
                },
                to_list: vec![],
                cc_list: vec![],
                bcc_list: vec![],
                body: "".to_string(),
                mime_type: "text/plain".to_string(),
                unread: 0,
                external_id: None,
            },
            attachment_key_packets: None,
            parent_id: None,
            action: 0,
        };

        let err = create_draft(&client, &req).await.unwrap_err();
        assert!(err.to_string().contains("Draft creation failed"));
    }

    #[tokio::test]
    async fn test_send_draft() {
        use super::super::types::SendDraftReq;

        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("POST"))
            .and(path("/mail/v4/messages/draft-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Sent": {
                    "ID": "sent-1",
                    "AddressID": "addr-1",
                    "LabelIDs": ["2", "7"],
                    "Subject": "Sent Email",
                    "Sender": { "Name": "Alice", "Address": "alice@proton.me" },
                    "ToList": [{ "Name": "Bob", "Address": "bob@proton.me" }],
                    "CCList": [],
                    "BCCList": [],
                    "Time": 1700000000,
                    "Size": 512,
                    "Unread": 0,
                    "NumAttachments": 0,
                    "Header": "",
                    "Body": "encrypted",
                    "MIMEType": "text/plain",
                    "Attachments": []
                }
            })))
            .mount(&server)
            .await;

        let req = SendDraftReq { packages: vec![] };

        let resp = send_draft(&client, "draft-1", &req).await.unwrap();
        assert_eq!(resp.sent.metadata.id, "sent-1");
        assert_eq!(resp.sent.metadata.subject, "Sent Email");
    }

    #[tokio::test]
    async fn test_send_draft_api_error() {
        use super::super::types::SendDraftReq;

        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("POST"))
            .and(path("/mail/v4/messages/draft-bad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 2501,
                "Error": "Draft not found"
            })))
            .mount(&server)
            .await;

        let req = SendDraftReq { packages: vec![] };

        let err = send_draft(&client, "draft-bad", &req).await.unwrap_err();
        assert!(err.to_string().contains("Draft not found"));
    }
}
