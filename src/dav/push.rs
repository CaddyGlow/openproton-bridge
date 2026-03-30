use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL;
use base64::Engine;

use super::error::{DavError, Result};
use super::http::DavResponse;

const DEFAULT_SUBSCRIPTION_TTL_SECS: i64 = 7 * 86400; // 7 days
const _MIN_SUBSCRIPTION_TTL_SECS: i64 = 3 * 86400; // 3 days

#[derive(Debug, Clone)]
pub struct PushSubscription {
    pub id: String,
    pub resource_path: String,
    pub push_resource: String,
    pub client_public_key: Vec<u8>,
    pub auth_secret: Vec<u8>,
    pub expires_at: i64,
}

#[derive(Clone)]
pub struct PushSubscriptionStore {
    subscriptions: Arc<RwLock<HashMap<String, Vec<PushSubscription>>>>,
}

impl PushSubscriptionStore {
    pub fn new() -> Self {
        Self {
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add(&self, sub: PushSubscription) {
        let mut subs = self.subscriptions.write().unwrap();
        let list = subs.entry(sub.resource_path.clone()).or_default();

        // Replace existing subscription with same push_resource (resubscribe)
        list.retain(|existing| existing.push_resource != sub.push_resource);
        list.push(sub);
    }

    pub fn remove(&self, subscription_id: &str) -> bool {
        let mut subs = self.subscriptions.write().unwrap();
        let mut found = false;
        for list in subs.values_mut() {
            let before = list.len();
            list.retain(|s| s.id != subscription_id);
            if list.len() < before {
                found = true;
            }
        }
        found
    }

    pub fn remove_by_push_resource(&self, push_resource: &str) {
        let mut subs = self.subscriptions.write().unwrap();
        for list in subs.values_mut() {
            list.retain(|s| s.push_resource != push_resource);
        }
    }

    pub fn get_for_account(&self, account_id: &str) -> Vec<PushSubscription> {
        let now = unix_now();
        let prefix = format!("/dav/{account_id}/");
        let subs = self.subscriptions.read().unwrap();
        subs.iter()
            .filter(|(path, _)| path.starts_with(&prefix))
            .flat_map(|(_, list)| list.iter())
            .filter(|s| s.expires_at > now)
            .cloned()
            .collect()
    }

    pub fn cleanup_expired(&self) {
        let now = unix_now();
        let mut subs = self.subscriptions.write().unwrap();
        for list in subs.values_mut() {
            list.retain(|s| s.expires_at > now);
        }
        subs.retain(|_, list| !list.is_empty());
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub fn handle_push_register(
    raw_path: &str,
    body: &[u8],
    store: &PushSubscriptionStore,
) -> Result<DavResponse> {
    let body_str = std::str::from_utf8(body)
        .map_err(|_| DavError::InvalidRequest("push-register body is not utf-8"))?;

    if !body_str.contains("push-register") {
        return Err(DavError::InvalidRequest("not a push-register request"));
    }

    let push_resource = extract_element_text(body_str, "push-resource")
        .ok_or(DavError::InvalidRequest("missing push-resource"))?;
    let client_pub_b64 = extract_element_text(body_str, "subscription-public-key")
        .ok_or(DavError::InvalidRequest("missing subscription-public-key"))?;
    let auth_secret_b64 = extract_element_text(body_str, "auth-secret")
        .ok_or(DavError::InvalidRequest("missing auth-secret"))?;

    let client_public_key = BASE64URL
        .decode(client_pub_b64.trim())
        .map_err(|_| DavError::InvalidRequest("invalid base64url in subscription-public-key"))?;
    let auth_secret = BASE64URL
        .decode(auth_secret_b64.trim())
        .map_err(|_| DavError::InvalidRequest("invalid base64url in auth-secret"))?;

    if client_public_key.len() != 65 {
        return Err(DavError::InvalidRequest(
            "subscription-public-key must be 65 bytes (uncompressed P-256)",
        ));
    }
    if auth_secret.len() != 16 {
        return Err(DavError::InvalidRequest("auth-secret must be 16 bytes"));
    }

    let now = unix_now();
    let expires_at = now + DEFAULT_SUBSCRIPTION_TTL_SECS;

    let sub_id = uuid::Uuid::new_v4().to_string();
    let resource_path = normalize_path(raw_path);

    let sub = PushSubscription {
        id: sub_id.clone(),
        resource_path: resource_path.clone(),
        push_resource,
        client_public_key,
        auth_secret,
        expires_at,
    };

    tracing::info!(
        subscription_id = %sub_id,
        resource = %resource_path,
        "webdav-push subscription registered"
    );

    store.add(sub);

    let location = format!("{}.push-subscriptions/{sub_id}", resource_path);
    let expires_http = format_http_date(expires_at);

    let response_body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><push-register-response xmlns="https://bitfire.at/webdav-push"><subscription-id>{sub_id}</subscription-id></push-register-response>"#,
    );

    Ok(DavResponse {
        status: "201 Created",
        headers: vec![
            ("Content-Type", "application/xml".to_string()),
            ("Location", location),
            ("Expires", expires_http),
        ],
        body: response_body.into_bytes(),
    })
}

pub fn handle_push_unsubscribe(
    raw_path: &str,
    store: &PushSubscriptionStore,
) -> Result<DavResponse> {
    let path = raw_path.trim_end_matches('/');
    let sub_id = path.rsplit('/').next().unwrap_or("");

    if sub_id.is_empty() {
        return Ok(DavResponse {
            status: "404 Not Found",
            headers: vec![],
            body: Vec::new(),
        });
    }

    if store.remove(sub_id) {
        tracing::info!(subscription_id = %sub_id, "webdav-push subscription removed");
        Ok(DavResponse {
            status: "204 No Content",
            headers: vec![],
            body: Vec::new(),
        })
    } else {
        Ok(DavResponse {
            status: "404 Not Found",
            headers: vec![],
            body: Vec::new(),
        })
    }
}

fn normalize_path(raw_path: &str) -> String {
    let normalized = raw_path.trim_end_matches('/');
    if normalized.is_empty() {
        "/".to_string()
    } else {
        format!("{normalized}/")
    }
}

fn extract_element_text(xml: &str, tag: &str) -> Option<String> {
    // Match with or without namespace prefix: <tag>, <ns:tag>, <prefix:tag>
    let patterns = [format!("<{tag}"), format!("<push:{tag}")];

    for pattern in &patterns {
        if let Some(start_tag) = xml.find(pattern.as_str()) {
            let rest = &xml[start_tag..];
            let content_start = rest.find('>')? + 1;
            let content = &rest[content_start..];
            // Find closing tag with or without prefix
            for close in [format!("</{tag}>"), format!("</push:{tag}>")] {
                if let Some(end) = content.find(&close) {
                    return Some(content[..end].trim().to_string());
                }
            }
        }
    }
    None
}

fn format_http_date(unix_secs: i64) -> String {
    // Simple IMF-fixdate formatting
    let secs_per_day = 86400i64;
    let days = unix_secs / secs_per_day;
    let time_of_day = unix_secs % secs_per_day;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch to date (simplified)
    let (year, month, day, weekday) = days_to_date(days);
    let weekday_str = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][weekday as usize % 7];
    let month_str = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(month - 1) as usize];

    format!("{weekday_str}, {day:02} {month_str} {year} {hours:02}:{minutes:02}:{seconds:02} GMT")
}

fn days_to_date(days_since_epoch: i64) -> (i64, i64, i64, i64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days_since_epoch + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let weekday = (days_since_epoch + 4).rem_euclid(7); // 0=Thu for epoch
    (y, m, d, weekday)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_register_and_lookup() {
        let store = PushSubscriptionStore::new();
        let sub = PushSubscription {
            id: "sub-1".to_string(),
            resource_path: "/dav/uid-1/calendars/cal1/".to_string(),
            push_resource: "https://push.example.com/v1/abc".to_string(),
            client_public_key: vec![0x04; 65],
            auth_secret: vec![0u8; 16],
            expires_at: unix_now() + 86400,
        };
        store.add(sub);

        let found = store.get_for_account("uid-1");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "sub-1");
    }

    #[test]
    fn resubscribe_replaces_existing() {
        let store = PushSubscriptionStore::new();
        let sub1 = PushSubscription {
            id: "sub-1".to_string(),
            resource_path: "/dav/uid-1/calendars/cal1/".to_string(),
            push_resource: "https://push.example.com/v1/abc".to_string(),
            client_public_key: vec![0x04; 65],
            auth_secret: vec![0u8; 16],
            expires_at: unix_now() + 86400,
        };
        store.add(sub1);

        let sub2 = PushSubscription {
            id: "sub-2".to_string(),
            resource_path: "/dav/uid-1/calendars/cal1/".to_string(),
            push_resource: "https://push.example.com/v1/abc".to_string(), // same endpoint
            client_public_key: vec![0x04; 65],
            auth_secret: vec![1u8; 16],
            expires_at: unix_now() + 172800,
        };
        store.add(sub2);

        let found = store.get_for_account("uid-1");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "sub-2");
    }

    #[test]
    fn remove_subscription() {
        let store = PushSubscriptionStore::new();
        let sub = PushSubscription {
            id: "sub-1".to_string(),
            resource_path: "/dav/uid-1/calendars/cal1/".to_string(),
            push_resource: "https://push.example.com/v1/abc".to_string(),
            client_public_key: vec![0x04; 65],
            auth_secret: vec![0u8; 16],
            expires_at: unix_now() + 86400,
        };
        store.add(sub);
        assert!(store.remove("sub-1"));
        assert!(store.get_for_account("uid-1").is_empty());
    }

    #[test]
    fn expired_subscriptions_filtered() {
        let store = PushSubscriptionStore::new();
        let sub = PushSubscription {
            id: "sub-1".to_string(),
            resource_path: "/dav/uid-1/calendars/cal1/".to_string(),
            push_resource: "https://push.example.com/v1/abc".to_string(),
            client_public_key: vec![0x04; 65],
            auth_secret: vec![0u8; 16],
            expires_at: unix_now() - 1, // already expired
        };
        store.add(sub);
        assert!(store.get_for_account("uid-1").is_empty());
    }

    #[test]
    fn extract_element_text_with_namespace() {
        let xml = r#"<push-register xmlns="https://bitfire.at/webdav-push"><subscription><web-push-subscription><push-resource>https://push.example.com/v1/abc</push-resource></web-push-subscription></subscription></push-register>"#;
        assert_eq!(
            extract_element_text(xml, "push-resource"),
            Some("https://push.example.com/v1/abc".to_string())
        );
    }

    #[test]
    fn handle_push_register_creates_subscription() {
        let store = PushSubscriptionStore::new();
        let client_key = BASE64URL.encode(&[0x04u8; 65]);
        let auth = BASE64URL.encode(&[0u8; 16]);
        let body = format!(
            r#"<?xml version="1.0"?><push-register xmlns="https://bitfire.at/webdav-push"><subscription><web-push-subscription><push-resource>https://push.example.com/v1/abc</push-resource><subscription-public-key type="p256dh">{client_key}</subscription-public-key><auth-secret>{auth}</auth-secret></web-push-subscription></subscription></push-register>"#,
        );

        let response =
            handle_push_register("/dav/uid-1/calendars/cal1/", body.as_bytes(), &store).unwrap();

        assert_eq!(response.status, "201 Created");
        assert!(response
            .headers
            .iter()
            .any(|(k, v)| *k == "Location" && v.contains(".push-subscriptions/")));
        assert!(response.headers.iter().any(|(k, _)| *k == "Expires"));

        let subs = store.get_for_account("uid-1");
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].push_resource, "https://push.example.com/v1/abc");
    }

    #[test]
    fn handle_push_unsubscribe_removes_subscription() {
        let store = PushSubscriptionStore::new();
        let sub = PushSubscription {
            id: "test-sub-id".to_string(),
            resource_path: "/dav/uid-1/calendars/cal1/".to_string(),
            push_resource: "https://push.example.com/v1/abc".to_string(),
            client_public_key: vec![0x04; 65],
            auth_secret: vec![0u8; 16],
            expires_at: unix_now() + 86400,
        };
        store.add(sub);

        let response = handle_push_unsubscribe(
            "/dav/uid-1/calendars/cal1/.push-subscriptions/test-sub-id",
            &store,
        )
        .unwrap();
        assert_eq!(response.status, "204 No Content");
        assert!(store.get_for_account("uid-1").is_empty());
    }

    #[test]
    fn format_http_date_works() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        let date = format_http_date(1704067200);
        assert!(date.contains("2024"), "got: {date}");
        assert!(date.contains("Jan"), "got: {date}");
        assert!(date.contains("GMT"), "got: {date}");
    }
}
