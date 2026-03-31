use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use gluon_rs_dav::discovery;
use gluon_rs_dav::etag;
use gluon_rs_dav::http::DavResponse;
use gluon_rs_dav::types::AuthContext;
use gluon_rs_dav::{DavError, Result};

use crate::store::ContactsStore;
use crate::types::{ContactCardUpsert, ContactEmailUpsert, ContactUpsert, QueryPage};

pub fn handle_request(
    method: &str,
    raw_path: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
    auth: &AuthContext,
    store: &ContactsStore,
) -> Result<Option<DavResponse>> {
    let path = normalize_path(raw_path);
    let collection = discovery::default_addressbook_path(&auth.account_id);
    if path == collection {
        return match method {
            "GET" | "HEAD" => {
                let count = store
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
            let stored = store
                .get_contact(&contact_id, false)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            let Some(stored) = stored else {
                return Ok(Some(not_found_response()));
            };
            let vcard = store
                .get_contact_card_data(&contact_id, false)
                .map_err(|err| DavError::Backend(err.to_string()))?
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
            let existing = store
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
            store
                .upsert_contact(&contact)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            let stored = store
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
            let existing = store
                .get_contact(&contact_id, false)
                .map_err(|err| DavError::Backend(err.to_string()))?;
            let Some(existing) = existing else {
                return Ok(Some(not_found_response()));
            };
            let current_etag = etag::from_updated_ms(&existing.id, existing.updated_at_ms);
            if !etag::if_match_satisfied(headers.get("if-match"), Some(current_etag.as_str())) {
                return Ok(Some(precondition_failed_response()));
            }
            store
                .soft_delete_contact(&contact_id)
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

pub fn parse_vcard(id: &str, raw: &str, create_time: i64, modify_time: i64) -> ContactUpsert {
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
    ContactUpsert {
        id: id.to_string(),
        uid,
        name: full_name.clone(),
        size: raw.len() as i64,
        create_time,
        modify_time,
        raw_json: String::new(),
        cards: vec![ContactCardUpsert {
            card_type: 0,
            data: raw.to_string(),
            signature: None,
        }],
        emails: vec![ContactEmailUpsert {
            id: format!("email-{id}"),
            contact_id: id.to_string(),
            email,
            name: full_name,
            kind_json: r#"["OTHER"]"#.to_string(),
            defaults: None,
            order: None,
            label_ids_json: "[]".to_string(),
            last_used_time: None,
            raw_json: String::new(),
        }],
    }
}

pub fn synthesize_vcard(uid: &str, full_name: &str, email: Option<&str>) -> String {
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
        assert_eq!(contact.uid, "uid-1");
        assert_eq!(contact.name, "Alice");
        assert_eq!(contact.emails[0].email, "alice@proton.me");
    }
}
