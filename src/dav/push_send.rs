use std::sync::Arc;

use tokio::sync::broadcast;

use crate::bridge::calendar_notify::CalendarChangeEvent;

use super::push::PushSubscriptionStore;
use super::push_crypto::{encrypt_push_payload, VapidKeyPair};

pub async fn run_push_sender(
    mut change_rx: broadcast::Receiver<CalendarChangeEvent>,
    subscription_store: PushSubscriptionStore,
    vapid_keys: Arc<VapidKeyPair>,
    http_client: reqwest::Client,
) {
    loop {
        match change_rx.recv().await {
            Ok(event) => {
                send_notifications_for_event(
                    &event,
                    &subscription_store,
                    &vapid_keys,
                    &http_client,
                )
                .await;
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::debug!(lagged = n, "push sender broadcast lagged");
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
    tracing::info!("push sender task stopped");
}

async fn send_notifications_for_event(
    event: &CalendarChangeEvent,
    store: &PushSubscriptionStore,
    vapid_keys: &VapidKeyPair,
    http_client: &reqwest::Client,
) {
    let subscriptions = store.get_for_account(&event.account_id);
    if subscriptions.is_empty() {
        return;
    }

    let topic = format!("{}/{}", event.account_id, event.calendar_id);

    for sub in &subscriptions {
        // Match: wildcard matches all, or specific calendar matches
        if event.calendar_id != "*" && !sub.resource_path.contains(&event.calendar_id) {
            continue;
        }

        let push_xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><push-message xmlns="https://bitfire.at/webdav-push"><topic>{topic}</topic><content-update/></push-message>"#,
        );

        let encrypted = match encrypt_push_payload(
            push_xml.as_bytes(),
            &sub.client_public_key,
            &sub.auth_secret,
        ) {
            Ok((body, _)) => body,
            Err(err) => {
                tracing::warn!(
                    subscription_id = %sub.id,
                    error = %err,
                    "failed to encrypt push payload"
                );
                continue;
            }
        };

        let audience = extract_origin(&sub.push_resource).unwrap_or_default();
        let auth_header = match vapid_keys.sign_vapid_jwt(&audience) {
            Ok(h) => h,
            Err(err) => {
                tracing::warn!(error = %err, "failed to sign VAPID JWT");
                continue;
            }
        };

        let result = http_client
            .post(&sub.push_resource)
            .header("Content-Type", "application/octet-stream")
            .header("Content-Encoding", "aes128gcm")
            .header("Authorization", &auth_header)
            .header("Topic", &topic)
            .header("Urgency", "normal")
            .header("TTL", "86400")
            .body(encrypted)
            .send()
            .await;

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status == 404 || status == 410 {
                    tracing::info!(
                        subscription_id = %sub.id,
                        status,
                        "push endpoint gone, removing subscription"
                    );
                    store.remove_by_push_resource(&sub.push_resource);
                } else if status >= 400 {
                    tracing::warn!(
                        subscription_id = %sub.id,
                        status,
                        "push delivery failed"
                    );
                } else {
                    tracing::debug!(
                        subscription_id = %sub.id,
                        status,
                        "push notification delivered"
                    );
                }
            }
            Err(err) => {
                tracing::warn!(
                    subscription_id = %sub.id,
                    error = %err,
                    "push delivery request failed"
                );
            }
        }
    }
}

fn extract_origin(url: &str) -> Option<String> {
    let after_scheme = url
        .strip_prefix("https://")
        .or(url.strip_prefix("http://"))?;
    let host = after_scheme.split('/').next()?;
    if url.starts_with("https://") {
        Some(format!("https://{host}"))
    } else {
        Some(format!("http://{host}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_origin_works() {
        assert_eq!(
            extract_origin("https://push.example.com/v1/abc"),
            Some("https://push.example.com".to_string())
        );
        assert_eq!(
            extract_origin("http://localhost:8080/push"),
            Some("http://localhost:8080".to_string())
        );
    }
}
