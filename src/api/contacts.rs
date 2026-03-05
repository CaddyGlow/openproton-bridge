use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::client::{check_api_response, send_logged, ProtonClient};
use super::error::{ApiError, Result};

async fn decode_api_json<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
    let json: serde_json::Value = resp.json().await?;
    check_api_response(&json)?;
    serde_json::from_value(json).map_err(ApiError::Json)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ContactEmail {
    #[serde(rename = "ID")]
    pub id: String,
    pub email: String,
    pub name: String,
    #[serde(default)]
    pub kind: Vec<String>,
    #[serde(default)]
    pub defaults: Option<i32>,
    #[serde(default)]
    pub order: Option<i32>,
    #[serde(rename = "ContactID")]
    pub contact_id: String,
    #[serde(default)]
    pub label_ids: Vec<String>,
    #[serde(default)]
    pub last_used_time: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ContactCard {
    #[serde(rename = "Type")]
    pub card_type: i32,
    pub data: String,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ContactMetadata {
    #[serde(rename = "ID")]
    pub id: String,
    pub name: String,
    #[serde(rename = "UID")]
    pub uid: String,
    pub size: i64,
    pub create_time: i64,
    pub modify_time: i64,
    #[serde(default)]
    pub contact_emails: Vec<ContactEmail>,
    #[serde(default)]
    pub label_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Contact {
    #[serde(flatten)]
    pub metadata: ContactMetadata,
    #[serde(default, rename = "Cards")]
    pub cards: Vec<ContactCard>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContactsResponse {
    #[serde(default)]
    contacts: Vec<Contact>,
    total: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContactResponse {
    contact: Contact,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ContactEmailsResponse {
    #[serde(default)]
    contact_emails: Vec<ContactEmail>,
    total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContactCardsPayload {
    pub cards: Vec<ContactCard>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateContactsRequest {
    pub contacts: Vec<ContactCardsPayload>,
    pub overwrite: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateContactRequest {
    pub cards: Vec<ContactCard>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteContactsRequest {
    #[serde(rename = "IDs")]
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateContactResponse {
    pub code: i64,
    #[serde(default)]
    pub contact: Option<Contact>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateContactsResultEntry {
    pub index: i64,
    pub response: CreateContactResponse,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateContactsResponse {
    pub code: i64,
    #[serde(default)]
    pub responses: Vec<CreateContactsResultEntry>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ContactsQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ContactEmailsQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<i32>,
}

pub async fn get_contacts(
    client: &ProtonClient,
    query: &ContactsQuery,
) -> Result<(Vec<Contact>, i64)> {
    let req = client.get("/contacts/v4").query(query);
    let res: ContactsResponse = decode_api_json(send_logged(req).await?).await?;
    Ok((res.contacts, res.total))
}

pub async fn get_contact(client: &ProtonClient, contact_id: &str) -> Result<Contact> {
    let path = format!("/contacts/v4/{contact_id}");
    let res: ContactResponse = decode_api_json(send_logged(client.get(&path)).await?).await?;
    Ok(res.contact)
}

pub async fn get_contact_emails(
    client: &ProtonClient,
    query: &ContactEmailsQuery,
) -> Result<(Vec<ContactEmail>, i64)> {
    let req = client.get("/contacts/v4/emails").query(query);
    let res: ContactEmailsResponse = decode_api_json(send_logged(req).await?).await?;
    Ok((res.contact_emails, res.total))
}

pub async fn count_contacts(client: &ProtonClient) -> Result<i64> {
    let (_contacts, total) = get_contacts(client, &ContactsQuery::default()).await?;
    Ok(total)
}

pub async fn count_contact_emails(client: &ProtonClient, email: Option<&str>) -> Result<i64> {
    let query = ContactEmailsQuery {
        email: email.map(std::string::ToString::to_string),
        ..ContactEmailsQuery::default()
    };
    let (_emails, total) = get_contact_emails(client, &query).await?;
    Ok(total)
}

pub async fn create_contacts(
    client: &ProtonClient,
    req: &CreateContactsRequest,
) -> Result<CreateContactsResponse> {
    decode_api_json(send_logged(client.post("/contacts/v4").json(req)).await?).await
}

pub async fn update_contact(
    client: &ProtonClient,
    contact_id: &str,
    req: &UpdateContactRequest,
) -> Result<Contact> {
    let path = format!("/contacts/v4/{contact_id}");
    let res: ContactResponse =
        decode_api_json(send_logged(client.put(&path).json(req)).await?).await?;
    Ok(res.contact)
}

pub async fn delete_contacts(client: &ProtonClient, req: &DeleteContactsRequest) -> Result<()> {
    let _json: serde_json::Value =
        decode_api_json(send_logged(client.put("/contacts/v4/delete").json(req)).await?).await?;
    Ok(())
}

#[async_trait]
pub trait ContactsApi {
    async fn get_contacts(&self, query: &ContactsQuery) -> Result<(Vec<Contact>, i64)>;
    async fn get_contact(&self, contact_id: &str) -> Result<Contact>;
    async fn get_contact_emails(
        &self,
        query: &ContactEmailsQuery,
    ) -> Result<(Vec<ContactEmail>, i64)>;
    async fn create_contacts(&self, req: &CreateContactsRequest) -> Result<CreateContactsResponse>;
    async fn update_contact(&self, contact_id: &str, req: &UpdateContactRequest)
        -> Result<Contact>;
    async fn delete_contacts(&self, req: &DeleteContactsRequest) -> Result<()>;
}

#[async_trait]
impl ContactsApi for ProtonClient {
    async fn get_contacts(&self, query: &ContactsQuery) -> Result<(Vec<Contact>, i64)> {
        get_contacts(self, query).await
    }

    async fn get_contact(&self, contact_id: &str) -> Result<Contact> {
        get_contact(self, contact_id).await
    }

    async fn get_contact_emails(
        &self,
        query: &ContactEmailsQuery,
    ) -> Result<(Vec<ContactEmail>, i64)> {
        get_contact_emails(self, query).await
    }

    async fn create_contacts(&self, req: &CreateContactsRequest) -> Result<CreateContactsResponse> {
        create_contacts(self, req).await
    }

    async fn update_contact(
        &self,
        contact_id: &str,
        req: &UpdateContactRequest,
    ) -> Result<Contact> {
        update_contact(self, contact_id, req).await
    }

    async fn delete_contacts(&self, req: &DeleteContactsRequest) -> Result<()> {
        delete_contacts(self, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_partial_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup_authenticated_client(server: &MockServer) -> ProtonClient {
        ProtonClient::authenticated(&server.uri(), "test-uid", "test-token").unwrap()
    }

    #[tokio::test]
    async fn test_get_contacts_with_pagination() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/contacts/v4"))
            .and(query_param("Page", "1"))
            .and(query_param("PageSize", "50"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 1,
                "Contacts": [{
                    "ID": "contact-1",
                    "Name": "Alice",
                    "UID": "uid-1",
                    "Size": 10,
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000001,
                    "ContactEmails": [],
                    "LabelIDs": []
                }]
            })))
            .mount(&server)
            .await;

        let (contacts, total) = get_contacts(
            &client,
            &ContactsQuery {
                page: Some(1),
                page_size: Some(50),
            },
        )
        .await
        .unwrap();
        assert_eq!(total, 1);
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].metadata.id, "contact-1");
    }

    #[tokio::test]
    async fn test_get_contact_with_cards() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/contacts/v4/contact-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Contact": {
                    "ID": "contact-1",
                    "Name": "Alice",
                    "UID": "uid-1",
                    "Size": 10,
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000001,
                    "ContactEmails": [],
                    "LabelIDs": [],
                    "Cards": [{
                        "Type": 0,
                        "Data": "BEGIN:VCARD",
                        "Signature": null
                    }]
                }
            })))
            .mount(&server)
            .await;

        let contact = get_contact(&client, "contact-1").await.unwrap();
        assert_eq!(contact.metadata.id, "contact-1");
        assert_eq!(contact.cards.len(), 1);
        assert_eq!(contact.cards[0].card_type, 0);
    }

    #[tokio::test]
    async fn test_get_contact_emails_with_filter_and_pagination() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/contacts/v4/emails"))
            .and(query_param("Email", "alice@proton.me"))
            .and(query_param("Page", "0"))
            .and(query_param("PageSize", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 1,
                "ContactEmails": [{
                    "ID": "email-1",
                    "Email": "alice@proton.me",
                    "Name": "Alice",
                    "Kind": ["home"],
                    "ContactID": "contact-1",
                    "LabelIDs": []
                }]
            })))
            .mount(&server)
            .await;

        let (emails, total) = get_contact_emails(
            &client,
            &ContactEmailsQuery {
                email: Some("alice@proton.me".to_string()),
                page: Some(0),
                page_size: Some(100),
            },
        )
        .await
        .unwrap();

        assert_eq!(total, 1);
        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0].id, "email-1");
        assert_eq!(emails[0].contact_id, "contact-1");
    }

    #[tokio::test]
    async fn test_get_contacts_across_pages_for_sync() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("GET"))
            .and(path("/contacts/v4"))
            .and(query_param("Page", "0"))
            .and(query_param("PageSize", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 3,
                "Contacts": [
                    {
                        "ID": "contact-1",
                        "Name": "Alice",
                        "UID": "uid-1",
                        "Size": 10,
                        "CreateTime": 1700000000,
                        "ModifyTime": 1700000001
                    },
                    {
                        "ID": "contact-2",
                        "Name": "Bob",
                        "UID": "uid-2",
                        "Size": 11,
                        "CreateTime": 1700000002,
                        "ModifyTime": 1700000003
                    }
                ]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/contacts/v4"))
            .and(query_param("Page", "1"))
            .and(query_param("PageSize", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Total": 3,
                "Contacts": [
                    {
                        "ID": "contact-3",
                        "Name": "Charlie",
                        "UID": "uid-3",
                        "Size": 12,
                        "CreateTime": 1700000004,
                        "ModifyTime": 1700000005
                    }
                ]
            })))
            .mount(&server)
            .await;

        let query = ContactsQuery {
            page_size: Some(2),
            ..ContactsQuery::default()
        };
        let (page0, total0) = get_contacts(
            &client,
            &ContactsQuery {
                page: Some(0),
                ..query.clone()
            },
        )
        .await
        .unwrap();
        let (page1, total1) = get_contacts(
            &client,
            &ContactsQuery {
                page: Some(1),
                ..query
            },
        )
        .await
        .unwrap();

        assert_eq!(total0, 3);
        assert_eq!(total1, 3);
        assert_eq!(page0.len() + page1.len(), 3);
        assert_eq!(page0[0].metadata.id, "contact-1");
        assert_eq!(page1[0].metadata.id, "contact-3");
    }

    #[tokio::test]
    async fn test_create_update_delete_contacts() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("POST"))
            .and(path("/contacts/v4"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Responses": [{
                    "Index": 0,
                    "Response": {
                        "Code": 1000,
                        "Contact": {
                            "ID": "contact-1",
                            "Name": "Alice",
                            "UID": "uid-1",
                            "Size": 10,
                            "CreateTime": 1700000000,
                            "ModifyTime": 1700000001,
                            "ContactEmails": [],
                            "LabelIDs": []
                        }
                    }
                }]
            })))
            .mount(&server)
            .await;

        Mock::given(method("PUT"))
            .and(path("/contacts/v4/contact-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Contact": {
                    "ID": "contact-1",
                    "Name": "Alice Updated",
                    "UID": "uid-1",
                    "Size": 10,
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000002,
                    "ContactEmails": [],
                    "LabelIDs": [],
                    "Cards": []
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("PUT"))
            .and(path("/contacts/v4/delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .mount(&server)
            .await;

        let create_resp = create_contacts(
            &client,
            &CreateContactsRequest {
                contacts: vec![ContactCardsPayload { cards: vec![] }],
                overwrite: 0,
                labels: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(create_resp.responses.len(), 1);
        assert_eq!(create_resp.responses[0].index, 0);
        assert!(create_resp.responses[0].response.contact.as_ref().is_some());

        let updated = update_contact(
            &client,
            "contact-1",
            &UpdateContactRequest { cards: vec![] },
        )
        .await
        .unwrap();
        assert_eq!(updated.metadata.name, "Alice Updated");

        delete_contacts(
            &client,
            &DeleteContactsRequest {
                ids: vec!["contact-1".to_string()],
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_create_delete_contacts_payload_contract() {
        let server = MockServer::start().await;
        let client = setup_authenticated_client(&server).await;

        Mock::given(method("POST"))
            .and(path("/contacts/v4"))
            .and(body_partial_json(serde_json::json!({
                "Overwrite": 1,
                "Labels": 1
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000,
                "Responses": [{
                    "Index": 0,
                    "Response": {
                        "Code": 1000,
                        "Contact": {
                            "ID": "contact-1",
                            "Name": "Alice",
                            "UID": "uid-1",
                            "Size": 10,
                            "CreateTime": 1700000000,
                            "ModifyTime": 1700000001
                        }
                    }
                }]
            })))
            .mount(&server)
            .await;

        Mock::given(method("PUT"))
            .and(path("/contacts/v4/delete"))
            .and(body_partial_json(serde_json::json!({
                "IDs": ["contact-1"]
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 1000
            })))
            .mount(&server)
            .await;

        let create = create_contacts(
            &client,
            &CreateContactsRequest {
                contacts: vec![ContactCardsPayload {
                    cards: vec![ContactCard {
                        card_type: 0,
                        data: "BEGIN:VCARD\r\nFN:Alice\r\nEND:VCARD".to_string(),
                        signature: None,
                    }],
                }],
                overwrite: 1,
                labels: Some(1),
            },
        )
        .await
        .unwrap();
        assert_eq!(create.responses.len(), 1);
        assert_eq!(create.responses[0].response.code, 1000);

        delete_contacts(
            &client,
            &DeleteContactsRequest {
                ids: vec!["contact-1".to_string()],
            },
        )
        .await
        .unwrap();
    }
}
