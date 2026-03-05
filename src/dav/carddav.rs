use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::contacts::{Contact, ContactCard, ContactEmail, ContactMetadata};
use crate::bridge::auth_router::AuthRoute;
use crate::pim::dav::{CardDavRepository, DeleteMode, StoreBackedDavAdapter};
use crate::pim::query::QueryPage;
use crate::pim::store::PimStore;

use super::discovery;
use super::error::{DavError, Result};
use super::etag;
use super::http::DavResponse;

pub fn handle_request(
    method: &str,
    raw_path: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
    auth: &AuthRoute,
    store: &Arc<PimStore>,
) -> Result<Option<DavResponse>> {
    let path = normalize_path(raw_path);
    let collection = discovery::default_addressbook_path(&auth.account_id.0);
    let adapter = StoreBackedDavAdapter::new(store.clone());

    if path == collection {
        return match method {
            "GET" | "HEAD" => {
                let count = adapter
                    .list_contacts(false, QueryPage::default())
                    .map_err(|err| DavError::Backend(err.to_string()))?
                    .len();
                let mut response = DavResponse {
                    status: "200 OK",
                    headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
                    body: format!("addressbook contacts={count}\n").into_bytes(),
                };
                if method == "HEAD" {
                    response.body.clear();
                }
                Ok(Some(response))
            }
            _ => Ok(None),
        };
    }

    let Some(contact_id) = parse_contact_resource_id(&collection, &path) else {
        return Ok(None);
    };

    match method {
        "GET" | "HEAD" => {
            let stored = adapter
                .get_contact(&contact_id, false)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            let Some(stored) = stored else {
                return Ok(Some(not_found_response()));
            };
            let payload = store
                .get_contact_payload(&contact_id, false)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            let vcard = payload
                .as_ref()
                .and_then(|contact| contact.cards.first().map(|card| card.data.clone()))
                .unwrap_or_else(|| synthesize_vcard(&stored.uid, &stored.name, None));
            let etag_value = etag::from_updated_ms(&stored.id, stored.updated_at_ms);
            let mut response = DavResponse {
                status: "200 OK",
                headers: vec![
                    ("Content-Type", "text/vcard; charset=utf-8".to_string()),
                    ("ETag", etag_value),
                ],
                body: vcard.into_bytes(),
            };
            if method == "HEAD" {
                response.body.clear();
            }
            Ok(Some(response))
        }
        "PUT" => {
            let existing = adapter
                .get_contact(&contact_id, true)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            let current_etag = existing
                .as_ref()
                .map(|stored| etag::from_updated_ms(&stored.id, stored.updated_at_ms));
            if !etag::if_match_satisfied(headers.get("if-match"), current_etag.as_deref()) {
                return Ok(Some(precondition_failed_response()));
            }
            if !etag::if_none_match_satisfied(headers.get("if-none-match"), current_etag.as_deref())
            {
                return Ok(Some(precondition_failed_response()));
            }

            let payload = std::str::from_utf8(body)
                .map_err(|_| DavError::InvalidRequest("CardDAV PUT body is not utf-8"))?;
            let now = epoch_seconds();
            let create_time = existing
                .as_ref()
                .map(|value| value.create_time)
                .unwrap_or(now);
            let contact = parse_vcard(&contact_id, payload, create_time, now);
            adapter
                .upsert_contact(&contact)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            let stored = adapter
                .get_contact(&contact_id, false)
                .map_err(|err| DavError::Backend(err.to_string()))?
                .ok_or_else(|| DavError::Backend("contact missing after upsert".to_string()))?;
            let status = if existing.is_some() {
                "204 No Content"
            } else {
                "201 Created"
            };
            Ok(Some(DavResponse {
                status,
                headers: vec![(
                    "ETag",
                    etag::from_updated_ms(&stored.id, stored.updated_at_ms),
                )],
                body: Vec::new(),
            }))
        }
        "DELETE" => {
            let existing = adapter
                .get_contact(&contact_id, false)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            let Some(existing) = existing else {
                return Ok(Some(not_found_response()));
            };
            let current_etag = etag::from_updated_ms(&existing.id, existing.updated_at_ms);
            if !etag::if_match_satisfied(headers.get("if-match"), Some(current_etag.as_str())) {
                return Ok(Some(precondition_failed_response()));
            }
            adapter
                .delete_contact(&contact_id, DeleteMode::Soft)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            Ok(Some(DavResponse {
                status: "204 No Content",
                headers: Vec::new(),
                body: Vec::new(),
            }))
        }
        _ => Ok(None),
    }
}

fn parse_contact_resource_id(collection: &str, path: &str) -> Option<String> {
    if !path.starts_with(collection) {
        return None;
    }
    let remainder = path.strip_prefix(collection)?;
    if remainder.is_empty() || remainder.contains('/') || !remainder.ends_with(".vcf") {
        return None;
    }
    let id = remainder.trim_end_matches(".vcf");
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

fn parse_vcard(id: &str, raw: &str, create_time: i64, modify_time: i64) -> Contact {
    let mut uid = None;
    let mut full_name = None;
    let mut email = None;

    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("UID") {
                uid = Some(value.trim().to_string());
                continue;
            }
            if name.eq_ignore_ascii_case("FN") {
                full_name = Some(value.trim().to_string());
                continue;
            }
            if name.to_ascii_uppercase().starts_with("EMAIL") {
                email = Some(value.trim().to_string());
            }
        }
    }

    let uid = uid.unwrap_or_else(|| format!("uid-{id}"));
    let full_name = full_name.unwrap_or_else(|| id.to_string());
    let email = email.unwrap_or_else(|| format!("{id}@invalid"));
    Contact {
        metadata: ContactMetadata {
            id: id.to_string(),
            name: full_name.clone(),
            uid,
            size: raw.len() as i64,
            create_time,
            modify_time,
            contact_emails: vec![ContactEmail {
                id: format!("email-{id}"),
                email,
                name: full_name,
                kind: vec!["OTHER".to_string()],
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
            data: raw.to_string(),
            signature: None,
        }],
    }
}

fn synthesize_vcard(uid: &str, full_name: &str, email: Option<&str>) -> String {
    let email_line = email
        .map(|value| format!("EMAIL:{value}\n"))
        .unwrap_or_default();
    format!("BEGIN:VCARD\nVERSION:3.0\nUID:{uid}\nFN:{full_name}\n{email_line}END:VCARD\n")
}

fn not_found_response() -> DavResponse {
    DavResponse {
        status: "404 Not Found",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"not found\n".to_vec(),
    }
}

fn precondition_failed_response() -> DavResponse {
    DavResponse {
        status: "412 Precondition Failed",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"precondition failed\n".to_vec(),
    }
}

fn normalize_path(path: &str) -> String {
    path.split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(path)
        .to_string()
}

fn epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::parse_vcard;

    #[test]
    fn parses_vcard_fields() {
        let contact = parse_vcard(
            "contact-1",
            "BEGIN:VCARD\nUID:uid-1\nFN:Alice\nEMAIL:alice@proton.me\nEND:VCARD\n",
            1,
            2,
        );
        assert_eq!(contact.metadata.uid, "uid-1");
        assert_eq!(contact.metadata.name, "Alice");
        assert_eq!(contact.metadata.contact_emails[0].email, "alice@proton.me");
    }
}
