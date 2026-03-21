use std::time::Instant;

use tokio::task::JoinSet;
use tracing::info;

use super::client::{
    check_api_response, is_transient_http_status, retry_delay_from_headers, send_logged,
    ProtonClient,
};
use super::error::{ApiError, Result};
use super::types::{
    AttachmentResponse, CreateDraftReq, MessageFilter, MessageGroupCount, MessageResponse,
    MessagesMetadataResponse, SendDraftReq, SendDraftResponse, UpdateDraftReq,
};

const API_SUCCESS_CODE: i64 = 1000;
const API_MULTI_CODE: i64 = 1001;
const MAX_MUTATION_BATCH_SIZE: usize = 150;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
struct UndoToken {
    token: String,
    valid_until: i64,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LabelMutationItemResponse {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    details: Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LabelMutationItem {
    #[serde(rename = "ID", default)]
    id: String,
    response: LabelMutationItemResponse,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct LabelMutationResponse {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    responses: Vec<LabelMutationItem>,
    #[serde(default)]
    undo_token: Option<UndoToken>,
}

fn first_label_mutation_failure(
    response: &LabelMutationResponse,
    raw_json: &serde_json::Value,
) -> Option<ApiError> {
    for item in &response.responses {
        if item.response.code != API_SUCCESS_CODE {
            let message = item
                .response
                .error
                .clone()
                .unwrap_or_else(|| format!("label mutation failed for id {}", item.id));
            let details = item
                .response
                .details
                .clone()
                .or_else(|| Some(raw_json.clone()));
            return Some(ApiError::Api {
                code: item.response.code,
                message,
                details,
            });
        }
    }

    None
}

async fn undo_actions(client: &ProtonClient, tokens: &[UndoToken]) -> Result<()> {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    for token in tokens {
        if token.valid_until != 0 && token.valid_until < now_unix {
            return Err(ApiError::Api {
                code: 0,
                message: "undo token expired".to_string(),
                details: Some(serde_json::json!({
                    "Token": token.token,
                    "ValidUntil": token.valid_until
                })),
            });
        }

        let resp = send_logged(client.post("/mail/v4/undoactions").json(token)).await?;
        let json: serde_json::Value = resp.json().await?;
        check_api_response(&json)?;
    }

    Ok(())
}

async fn mutate_labels_with_rollback(
    client: &ProtonClient,
    endpoint: &str,
    ids: &[&str],
    label_id: &str,
    action_name: &str,
) -> Result<()> {
    let mut successful_tokens: Vec<UndoToken> = Vec::new();

    for chunk in ids.chunks(MAX_MUTATION_BATCH_SIZE) {
        let body = serde_json::json!({ "LabelID": label_id, "IDs": chunk });
        let resp = send_logged(client.put(endpoint).json(&body)).await?;
        let json: serde_json::Value = resp.json().await?;

        let parsed: LabelMutationResponse = serde_json::from_value(json.clone())?;

        if parsed.code == API_SUCCESS_CODE && parsed.responses.is_empty() {
            continue;
        }

        if parsed.code == API_MULTI_CODE || !parsed.responses.is_empty() {
            if let Some(err) = first_label_mutation_failure(&parsed, &json) {
                if !successful_tokens.is_empty() {
                    undo_actions(client, &successful_tokens).await.map_err(|undo_err| {
                        ApiError::Api {
                            code: 0,
                            message: format!(
                                "failed to undo previous {action_name} actions after partial failure: {undo_err}"
                            ),
                            details: Some(json.clone()),
                        }
                    })?;
                }
                return Err(err);
            }
        } else {
            check_api_response(&json)?;
        }

        if let Some(token) = parsed.undo_token {
            if !token.token.trim().is_empty() {
                successful_tokens.push(token);
            }
        }
    }

    Ok(())
}

async fn mutate_message_ids_in_chunks(
    client: &ProtonClient,
    endpoint: &str,
    ids: &[&str],
) -> Result<()> {
    for chunk in ids.chunks(MAX_MUTATION_BATCH_SIZE) {
        let body = serde_json::json!({ "IDs": chunk });
        let resp = send_logged(client.put(endpoint).json(&body)).await?;
        let json: serde_json::Value = resp.json().await?;
        check_api_response(&json)?;
    }
    Ok(())
}

async fn delete_message_ids_in_chunks_parallel(client: &ProtonClient, ids: &[&str]) -> Result<()> {
    let chunked_ids: Vec<Vec<String>> = ids
        .chunks(MAX_MUTATION_BATCH_SIZE)
        .map(|chunk| chunk.iter().map(|id| (*id).to_string()).collect())
        .collect();

    if chunked_ids.is_empty() {
        return Ok(());
    }

    let max_parallelism = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    let concurrency = max_parallelism.min(chunked_ids.len()).max(1);

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut join_set = JoinSet::new();

    for chunk in chunked_ids {
        let client = client.clone();
        let semaphore = semaphore.clone();
        join_set.spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .map_err(|err| ApiError::Api {
                    code: 0,
                    message: format!("delete chunk semaphore closed: {err}"),
                    details: None,
                })?;
            let body = serde_json::json!({ "IDs": chunk });
            let resp = send_logged(client.put("/mail/v4/messages/delete").json(&body)).await?;
            let json: serde_json::Value = resp.json().await?;
            check_api_response(&json)?;
            Ok::<(), ApiError>(())
        });
    }

    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                join_set.abort_all();
                while join_set.join_next().await.is_some() {}
                return Err(err);
            }
            Err(err) => {
                join_set.abort_all();
                while join_set.join_next().await.is_some() {}
                return Err(ApiError::Api {
                    code: 0,
                    message: format!("delete chunk task failed: {err}"),
                    details: None,
                });
            }
        }
    }

    Ok(())
}

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

/// Fetch grouped message counts per label.
///
/// Reference: go-proton-api Client.GetGroupedMessageCount
pub async fn get_grouped_message_count(client: &ProtonClient) -> Result<Vec<MessageGroupCount>> {
    let resp = send_logged(client.get("/mail/v4/messages/count")).await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let counts: Vec<MessageGroupCount> = serde_json::from_value(
        json.get("Counts")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![])),
    )?;
    Ok(counts)
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
        label_id = filter.label_id.as_deref().unwrap_or_default(),
        end_id = filter.end_id.as_deref().unwrap_or_default(),
        continuation = filter.end_id.is_some(),
        "fetching message metadata"
    );

    let body = build_message_metadata_body(filter, page, page_size)?;

    let mut stale_round = 0usize;
    'stale_retry: loop {
        stale_round += 1;

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
                if meta_resp.stale != 0 {
                    info!(
                        page = page,
                        page_size = page_size,
                        label_id = filter.label_id.as_deref().unwrap_or_default(),
                        end_id = filter.end_id.as_deref().unwrap_or_default(),
                        continuation = filter.end_id.is_some(),
                        stale_round,
                        attempt = attempt + 1,
                        duration_ms = fetch_started.elapsed().as_millis() as u64,
                        "metadata_fetch_stale_retry"
                    );
                    continue 'stale_retry;
                }

                info!(
                    page = page,
                    page_size = page_size,
                    label_id = filter.label_id.as_deref().unwrap_or_default(),
                    end_id = filter.end_id.as_deref().unwrap_or_default(),
                    continuation = filter.end_id.is_some(),
                    messages_count = meta_resp.messages.len(),
                    total = meta_resp.total,
                    first_message_id = ?meta_resp.messages.first().map(|message| message.id.as_str()),
                    last_message_id = ?meta_resp.messages.last().map(|message| message.id.as_str()),
                    stale_round,
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
        return Err(ApiError::Auth("exhausted transient retries".to_string()));
    }
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
    mutate_message_ids_in_chunks(client, "/mail/v4/messages/read", ids).await
}

/// Mark messages as unread.
///
/// Reference: go-proton-api/message.go MarkMessagesUnread
pub async fn mark_messages_unread(client: &ProtonClient, ids: &[&str]) -> Result<()> {
    info!(count = ids.len(), "marking messages unread");
    mutate_message_ids_in_chunks(client, "/mail/v4/messages/unread", ids).await
}

/// Add a label to messages.
///
/// Reference: go-proton-api/message.go LabelMessages
pub async fn label_messages(client: &ProtonClient, ids: &[&str], label_id: &str) -> Result<()> {
    info!(count = ids.len(), label_id = %label_id, "labeling messages");
    mutate_labels_with_rollback(client, "/mail/v4/messages/label", ids, label_id, "label").await
}

/// Remove a label from messages.
///
/// Reference: go-proton-api/message.go UnlabelMessages
pub async fn unlabel_messages(client: &ProtonClient, ids: &[&str], label_id: &str) -> Result<()> {
    info!(count = ids.len(), label_id = %label_id, "unlabeling messages");
    mutate_labels_with_rollback(
        client,
        "/mail/v4/messages/unlabel",
        ids,
        label_id,
        "unlabel",
    )
    .await
}

/// Permanently delete messages.
///
/// Reference: go-proton-api/message.go DeleteMessage
pub async fn delete_messages(client: &ProtonClient, ids: &[&str]) -> Result<()> {
    info!(count = ids.len(), "permanently deleting messages");
    delete_message_ids_in_chunks_parallel(client, ids).await
}

/// Import an encrypted RFC822 message into Proton.
///
/// The message must be pre-encrypted with `crypto::encrypt::encrypt_rfc822`.
/// Uses multipart POST to `/mail/v4/messages/import`.
///
/// Reference: go-proton-api/message_import.go importMessages
pub async fn import_message(
    client: &ProtonClient,
    metadata: &crate::api::types::ImportMetadata,
    encrypted_rfc822: Vec<u8>,
) -> Result<super::types::ImportRes> {
    use std::collections::HashMap;

    info!("importing message via Proton API");

    let mut meta_map = HashMap::new();
    meta_map.insert("0".to_string(), metadata);
    let meta_json = serde_json::to_vec(&meta_map).map_err(|e| super::error::ApiError::Api {
        code: 0,
        message: format!("serialize metadata: {}", e),
        details: None,
    })?;

    let form = reqwest::multipart::Form::new()
        .part(
            "Metadata",
            reqwest::multipart::Part::bytes(meta_json)
                .mime_str("application/json")
                .unwrap(),
        )
        .part(
            "0",
            reqwest::multipart::Part::bytes(encrypted_rfc822)
                .file_name("0.eml")
                .mime_str("message/rfc822")
                .unwrap(),
        );

    let resp = send_logged(client.post("/mail/v4/messages/import").multipart(form)).await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let import_resp: super::types::ImportResponse = serde_json::from_value(json)?;
    let res = import_resp
        .responses
        .into_iter()
        .find(|r| r.name == "0")
        .map(|r| r.response)
        .ok_or_else(|| super::error::ApiError::Api {
            code: 0,
            message: "no import response for message 0".to_string(),
            details: None,
        })?;
    if res.code != 1000 {
        return Err(super::error::ApiError::Api {
            code: res.code as i64,
            message: format!("import failed with code {}", res.code),
            details: None,
        });
    }
    Ok(res)
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

/// Update an existing draft message.
///
/// Reference: go-proton-api/message_send.go UpdateDraft
pub async fn update_draft(
    client: &ProtonClient,
    draft_id: &str,
    req: &UpdateDraftReq,
) -> Result<MessageResponse> {
    info!(draft_id = %draft_id, "updating draft");
    let path = format!("/mail/v4/messages/{}", draft_id);
    let resp = send_logged(client.put(&path).json(req)).await?;
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

/// Fetch user labels and folders.
///
/// Reference: go-proton-api/label.go ListLabels
pub async fn get_labels(
    client: &ProtonClient,
    label_types: &[i32],
) -> Result<super::types::LabelsResponse> {
    let mut url = String::from("/core/v4/labels");
    for (i, t) in label_types.iter().enumerate() {
        url.push(if i == 0 { '?' } else { '&' });
        url.push_str(&format!("Type={t}"));
    }
    let resp = send_logged(client.get(&url)).await?;
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    let labels_resp: super::types::LabelsResponse = serde_json::from_value(json)?;
    Ok(labels_resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_json, header, method, path};
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
        assert_eq!(resp.stale, 0);
    }

    #[tokio::test]
    async fn test_get_message_metadata_retries_while_stale() {
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
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await.unwrap();
                let current = calls_task.fetch_add(1, Ordering::SeqCst);

                let body = if current == 0 {
                    serde_json::json!({
                        "Code": 1000,
                        "Total": 1,
                        "Stale": 1,
                        "Messages": [{
                            "ID": "msg-stale-1",
                            "AddressID": "addr-1",
                            "LabelIDs": ["0"],
                            "Subject": "Stale First",
                            "Sender": {"Name": "Alice", "Address": "alice@example.com"},
                            "ToList": [],
                            "CCList": [],
                            "BCCList": [],
                            "Time": 1700000000,
                            "Size": 128,
                            "Unread": 1,
                            "NumAttachments": 0
                        }]
                    })
                } else {
                    serde_json::json!({
                        "Code": 1000,
                        "Total": 1,
                        "Stale": 0,
                        "Messages": [{
                            "ID": "msg-stale-2",
                            "AddressID": "addr-1",
                            "LabelIDs": ["0"],
                            "Subject": "Fresh Second",
                            "Sender": {"Name": "Alice", "Address": "alice@example.com"},
                            "ToList": [],
                            "CCList": [],
                            "BCCList": [],
                            "Time": 1700000001,
                            "Size": 128,
                            "Unread": 1,
                            "NumAttachments": 0
                        }]
                    })
                };

                let body = body.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        let client =
            ProtonClient::authenticated(&format!("http://{}", addr), "uid-1", "token-1").unwrap();
        let filter = MessageFilter {
            label_id: Some("0".to_string()),
            desc: 1,
            ..Default::default()
        };
        let resp = get_message_metadata(&client, &filter, 0, 50).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(resp.stale, 0);
        assert_eq!(resp.messages.len(), 1);
        assert_eq!(resp.messages[0].id, "msg-stale-2");
        server.await.unwrap();
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
    async fn test_mark_messages_read_chunks_large_batches() {
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
                let mut buf = [0u8; 16384];
                let _ = stream.read(&mut buf).await.unwrap();
                calls_task.fetch_add(1, Ordering::SeqCst);
                let body = serde_json::json!({ "Code": 1000 }).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        let client =
            ProtonClient::authenticated(&format!("http://{}", addr), "uid-1", "token-1").unwrap();
        let ids_owned: Vec<String> = (0..152).map(|idx| format!("msg-{idx}")).collect();
        let ids: Vec<&str> = ids_owned.iter().map(String::as_str).collect();
        mark_messages_read(&client, &ids).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_mark_messages_unread_chunks_large_batches() {
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
                let mut buf = [0u8; 16384];
                let _ = stream.read(&mut buf).await.unwrap();
                calls_task.fetch_add(1, Ordering::SeqCst);
                let body = serde_json::json!({ "Code": 1000 }).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        let client =
            ProtonClient::authenticated(&format!("http://{}", addr), "uid-1", "token-1").unwrap();
        let ids_owned: Vec<String> = (0..152).map(|idx| format!("msg-{idx}")).collect();
        let ids: Vec<&str> = ids_owned.iter().map(String::as_str).collect();
        mark_messages_unread(&client, &ids).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_delete_messages_chunks_large_batches() {
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
                let mut buf = [0u8; 16384];
                let _ = stream.read(&mut buf).await.unwrap();
                calls_task.fetch_add(1, Ordering::SeqCst);
                let body = serde_json::json!({ "Code": 1000 }).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        let client =
            ProtonClient::authenticated(&format!("http://{}", addr), "uid-1", "token-1").unwrap();
        let ids_owned: Vec<String> = (0..152).map(|idx| format!("msg-{idx}")).collect();
        let ids: Vec<&str> = ids_owned.iter().map(String::as_str).collect();
        delete_messages(&client, &ids).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        server.await.unwrap();
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
    async fn test_label_messages_rolls_back_previous_chunks_on_partial_failure() {
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen_paths: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_paths_task = seen_paths.clone();

        let server = tokio::spawn(async move {
            for idx in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                seen_paths_task.lock().unwrap().push(path.clone());

                let body = match idx {
                    0 => serde_json::json!({
                        "Code": 1000,
                        "Responses": [
                            {"ID": "msg-0", "Response": {"Code": 1000}}
                        ],
                        "UndoToken": {"Token": "undo-a", "ValidUntil": 4102444800_i64}
                    }),
                    1 => serde_json::json!({
                        "Code": 1001,
                        "Responses": [
                            {"ID": "msg-150", "Response": {"Code": 1000}},
                            {"ID": "msg-151", "Response": {"Code": 2500, "Error": "Message does not exist"}}
                        ]
                    }),
                    _ => serde_json::json!({
                        "Code": 1000
                    }),
                }
                .to_string();

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        let client =
            ProtonClient::authenticated(&format!("http://{}", addr), "uid-1", "token-1").unwrap();
        let ids_owned: Vec<String> = (0..152).map(|idx| format!("msg-{idx}")).collect();
        let ids: Vec<&str> = ids_owned.iter().map(String::as_str).collect();

        let err = label_messages(&client, &ids, "10").await.unwrap_err();
        assert!(err.to_string().contains("Message does not exist"));

        server.await.unwrap();
        let observed = seen_paths.lock().unwrap().clone();
        assert_eq!(
            observed,
            vec![
                "/mail/v4/messages/label".to_string(),
                "/mail/v4/messages/label".to_string(),
                "/mail/v4/undoactions".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn test_unlabel_messages_rolls_back_previous_chunks_on_partial_failure() {
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen_paths: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_paths_task = seen_paths.clone();

        let server = tokio::spawn(async move {
            for idx in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                seen_paths_task.lock().unwrap().push(path.clone());

                let body = match idx {
                    0 => serde_json::json!({
                        "Code": 1000,
                        "Responses": [
                            {"ID": "msg-0", "Response": {"Code": 1000}}
                        ],
                        "UndoToken": {"Token": "undo-b", "ValidUntil": 4102444800_i64}
                    }),
                    1 => serde_json::json!({
                        "Code": 1001,
                        "Responses": [
                            {"ID": "msg-150", "Response": {"Code": 1000}},
                            {"ID": "msg-151", "Response": {"Code": 2500, "Error": "Message does not exist"}}
                        ]
                    }),
                    _ => serde_json::json!({
                        "Code": 1000
                    }),
                }
                .to_string();

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });

        let client =
            ProtonClient::authenticated(&format!("http://{}", addr), "uid-1", "token-1").unwrap();
        let ids_owned: Vec<String> = (0..152).map(|idx| format!("msg-{idx}")).collect();
        let ids: Vec<&str> = ids_owned.iter().map(String::as_str).collect();

        let err = unlabel_messages(&client, &ids, "10").await.unwrap_err();
        assert!(err.to_string().contains("Message does not exist"));

        server.await.unwrap();
        let observed = seen_paths.lock().unwrap().clone();
        assert_eq!(
            observed,
            vec![
                "/mail/v4/messages/unlabel".to_string(),
                "/mail/v4/messages/unlabel".to_string(),
                "/mail/v4/undoactions".to_string()
            ]
        );
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
            attachment_key_packets: vec![],
            parent_id: None,
            action: 0,
        };

        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(body_json(serde_json::json!({
                "Message": {
                    "Subject": "Test Draft",
                    "Sender": { "Name": "Alice", "Address": "alice@proton.me" },
                    "ToList": [{ "Name": "Bob", "Address": "bob@proton.me" }],
                    "CCList": [],
                    "BCCList": [],
                    "Body": "encrypted body",
                    "MIMEType": "text/plain",
                    "Unread": 0
                },
                "AttachmentKeyPackets": [],
                "Action": 0
            })))
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

        let resp = create_draft(&client, &req).await.unwrap();
        assert_eq!(resp.message.metadata.id, "draft-1");
        assert_eq!(resp.message.metadata.subject, "Test Draft");
    }

    #[tokio::test]
    async fn test_create_draft_api_error() {
        use super::super::types::{CreateDraftReq, DraftTemplate, EmailAddress};

        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

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
            attachment_key_packets: vec![],
            parent_id: None,
            action: 0,
        };

        Mock::given(method("POST"))
            .and(path("/mail/v4/messages"))
            .and(body_json(serde_json::json!({
                "Message": {
                    "Subject": "Bad",
                    "Sender": { "Name": "", "Address": "bad" },
                    "ToList": [],
                    "CCList": [],
                    "BCCList": [],
                    "Body": "",
                    "MIMEType": "text/plain",
                    "Unread": 0
                },
                "AttachmentKeyPackets": [],
                "Action": 0
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 2500,
                "Error": "Draft creation failed"
            })))
            .mount(&server)
            .await;

        let err = create_draft(&client, &req).await.unwrap_err();
        assert!(err.to_string().contains("Draft creation failed"));
    }

    #[tokio::test]
    async fn test_send_draft() {
        use super::super::types::{MessagePackage, SendDraftReq};

        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        let req = SendDraftReq {
            packages: vec![MessagePackage {
                addresses: std::collections::HashMap::new(),
                mime_type: "text/plain".to_string(),
                package_type: crate::api::types::CLEAR_SCHEME,
                body: "body64".to_string(),
                body_key: None,
                attachment_keys: None,
            }],
        };

        Mock::given(method("POST"))
            .and(path("/mail/v4/messages/draft-1"))
            .and(body_json(serde_json::json!({
                "Packages": [{
                    "Addresses": {},
                    "MIMEType": "text/plain",
                    "Type": crate::api::types::CLEAR_SCHEME,
                    "Body": "body64"
                }]
            })))
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

        let resp = send_draft(&client, "draft-1", &req).await.unwrap();
        assert_eq!(resp.sent.metadata.id, "sent-1");
        assert_eq!(resp.sent.metadata.subject, "Sent Email");
    }

    #[tokio::test]
    async fn test_send_draft_api_error() {
        use super::super::types::{MessagePackage, SendDraftReq};

        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        let req = SendDraftReq {
            packages: vec![MessagePackage {
                addresses: std::collections::HashMap::new(),
                mime_type: "text/plain".to_string(),
                package_type: crate::api::types::CLEAR_SCHEME,
                body: "body64".to_string(),
                body_key: None,
                attachment_keys: None,
            }],
        };

        Mock::given(method("POST"))
            .and(path("/mail/v4/messages/draft-bad"))
            .and(body_json(serde_json::json!({
                "Packages": [{
                    "Addresses": {},
                    "MIMEType": "text/plain",
                    "Type": crate::api::types::CLEAR_SCHEME,
                    "Body": "body64"
                }]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 2501,
                "Error": "Draft not found"
            })))
            .mount(&server)
            .await;

        let err = send_draft(&client, "draft-bad", &req).await.unwrap_err();
        assert!(err.to_string().contains("Draft not found"));
    }

    #[tokio::test]
    async fn test_update_draft() {
        use super::super::types::{DraftTemplate, EmailAddress, UpdateDraftReq};

        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        let req = UpdateDraftReq {
            message: DraftTemplate {
                subject: "Updated Draft".to_string(),
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
                body: "updated encrypted body".to_string(),
                mime_type: "text/plain".to_string(),
                unread: 0,
                external_id: None,
            },
            attachment_key_packets: vec![],
        };

        Mock::given(method("PUT"))
            .and(path("/mail/v4/messages/draft-1"))
            .and(body_json(serde_json::json!({
                "Message": {
                    "Subject": "Updated Draft",
                    "Sender": { "Name": "Alice", "Address": "alice@proton.me" },
                    "ToList": [{ "Name": "Bob", "Address": "bob@proton.me" }],
                    "CCList": [],
                    "BCCList": [],
                    "Body": "updated encrypted body",
                    "MIMEType": "text/plain",
                    "Unread": 0
                },
                "AttachmentKeyPackets": []
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Message": {
                    "ID": "draft-1",
                    "AddressID": "addr-1",
                    "LabelIDs": ["1", "8"],
                    "Subject": "Updated Draft",
                    "Sender": { "Name": "Alice", "Address": "alice@proton.me" },
                    "ToList": [{ "Name": "Bob", "Address": "bob@proton.me" }],
                    "CCList": [],
                    "BCCList": [],
                    "Time": 1700000000,
                    "Size": 256,
                    "Unread": 0,
                    "NumAttachments": 0,
                    "Header": "",
                    "Body": "updated encrypted body",
                    "MIMEType": "text/plain",
                    "Attachments": []
                }
            })))
            .mount(&server)
            .await;

        let resp = update_draft(&client, "draft-1", &req).await.unwrap();
        assert_eq!(resp.message.metadata.id, "draft-1");
        assert_eq!(resp.message.metadata.subject, "Updated Draft");
    }

    #[tokio::test]
    async fn test_import_message_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mail/v4/messages/import"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Responses": [
                    {
                        "Name": "0",
                        "Response": {
                            "Code": 1000,
                            "MessageID": "imported-msg-123"
                        }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let client = ProtonClient::authenticated_with_mode(
            &server.uri(),
            crate::api::types::ApiMode::Bridge,
            "test-uid",
            "test-token",
        )
        .unwrap();

        let metadata = crate::api::types::ImportMetadata {
            address_id: "addr-1".to_string(),
            label_ids: vec!["0".to_string()],
            unread: true,
            flags: 1 | (1 << 9), // RECEIVED | IMPORTED
        };

        let result = import_message(&client, &metadata, b"From: a@b.com\r\n\r\nHello".to_vec())
            .await
            .unwrap();
        assert_eq!(result.message_id, "imported-msg-123");
        assert_eq!(result.code, 1000);
    }

    #[tokio::test]
    async fn test_import_message_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/mail/v4/messages/import"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Responses": [
                    {
                        "Name": "0",
                        "Response": {
                            "Code": 2500,
                            "MessageID": ""
                        }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let client = ProtonClient::authenticated_with_mode(
            &server.uri(),
            crate::api::types::ApiMode::Bridge,
            "test-uid",
            "test-token",
        )
        .unwrap();

        let metadata = crate::api::types::ImportMetadata {
            address_id: "addr-1".to_string(),
            label_ids: vec!["0".to_string()],
            unread: false,
            flags: 1,
        };

        let err = import_message(&client, &metadata, b"From: a@b.com\r\n\r\nHello".to_vec())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("import failed with code 2500"));
    }

    #[test]
    fn test_import_metadata_unread_serializes_as_int() {
        let meta = crate::api::types::ImportMetadata {
            address_id: "addr-1".to_string(),
            label_ids: vec!["0".to_string()],
            unread: true,
            flags: 1,
        };
        let json = serde_json::to_string(&meta).unwrap();
        // Should serialize unread as 1, not true
        assert!(json.contains("\"Unread\":1"), "json={json}");

        let meta_false = crate::api::types::ImportMetadata {
            address_id: "addr-1".to_string(),
            label_ids: vec!["0".to_string()],
            unread: false,
            flags: 1,
        };
        let json = serde_json::to_string(&meta_false).unwrap();
        assert!(json.contains("\"Unread\":0"), "json={json}");
    }
}
