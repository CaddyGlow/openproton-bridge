use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use openproton_bridge::bridge::auth_router::AuthRoute;
use openproton_bridge::bridge::types::AccountId;
use openproton_bridge::dav::caldav::handle_request;
use openproton_bridge::dav::report::handle_report;
use openproton_bridge::pim::store::PimStore;
use tempfile::tempdir;

fn gap_store() -> Arc<PimStore> {
    let tmp = tempdir().unwrap();
    let contacts_db = tmp.path().join("contacts.db");
    let calendar_db = tmp.path().join("calendar.db");
    Box::leak(Box::new(tmp));
    Arc::new(PimStore::new(contacts_db, calendar_db).unwrap())
}

fn gap_auth() -> AuthRoute {
    AuthRoute {
        account_id: AccountId("uid-1".to_string()),
        primary_email: "alice@proton.me".to_string(),
    }
}

fn extract_tag_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let Some((_, rest)) = xml.split_once(&open) else {
        return None;
    };
    let (value, _) = rest.split_once(&close)?;
    Some(value.trim().to_string())
}

fn read_fixture(path: &str) -> String {
    fs::read_to_string(path).expect("read fixture")
}

#[tokio::test]
async fn a1_report_rejects_malformed_addressbook_query_fixture() {
    let store = gap_store();
    let response = handle_report(
        "/dav/uid-1/addressbooks/default/",
        read_fixture("tests/fixtures/rfc-6352-4791/must_fail/addressbook-query-malformed.xml")
            .as_bytes(),
        &gap_auth(),
        &store,
        None,
    )
    .await
    .expect("handler")
    .expect("response");
    assert_eq!(response.status, "400 Bad Request");
}

#[tokio::test]
async fn a1_report_rejects_missing_sync_token_fixture() {
    let store = gap_store();
    let response = handle_report(
        "/dav/uid-1/calendars/default/",
        read_fixture("tests/fixtures/rfc-6352-4791/must_fail/calendar-sync-token-missing.xml").as_bytes(),
        &gap_auth(),
        &store,
        None,
    )
    .await
    .expect("handler")
    .expect("response");
    assert_eq!(response.status, "400 Bad Request");
}

#[tokio::test]
async fn a1_report_rejects_malformed_sync_token_fixture() {
    let store = gap_store();
    let response = handle_report(
        "/dav/uid-1/calendars/default/",
        read_fixture(
            "tests/fixtures/rfc-6352-4791/must_fail/calendar-sync-token-malformed.xml",
        )
        .as_bytes(),
        &gap_auth(),
        &store,
        None,
    )
    .await
    .expect("handler")
    .expect("response");
    assert_eq!(response.status, "400 Bad Request");
}

#[tokio::test]
async fn a1_report_rejects_malformed_calendar_query_time_range_fixture() {
    let store = gap_store();
    let response = handle_report(
        "/dav/uid-1/calendars/default/",
        read_fixture(
            "tests/fixtures/rfc-6352-4791/must_fail/calendar-query-malformed-time-range.xml",
        )
        .as_bytes(),
        &gap_auth(),
        &store,
        None,
    )
    .await
    .expect("handler")
    .expect("response");
    assert_eq!(response.status, "400 Bad Request");
}

#[tokio::test]
async fn a1_report_rejects_empty_calendar_multiget_hrefs_fixture() {
    let store = gap_store();
    let response = handle_report(
        "/dav/uid-1/calendars/default/",
        read_fixture("tests/fixtures/rfc-6352-4791/must_fail/calendar-multiget-empty-hrefs.xml")
            .as_bytes(),
        &gap_auth(),
        &store,
        None,
    )
    .await
    .expect("handler")
    .expect("response");
    assert_eq!(response.status, "400 Bad Request");
}

#[tokio::test]
async fn a1_caldav_put_rejects_if_match_stale_token() {
    let store = gap_store();
    let request = read_fixture("tests/fixtures/rfc-6352-4791/must_fail/calendar-put-stale-if-match.xml");
    let method = extract_tag_text(&request, "method").expect("method");
    let path = extract_tag_text(&request, "path").expect("path");
    let body = extract_tag_text(&request, "body").unwrap_or_default();
    let mut headers = HashMap::new();
    if let Some(value) = extract_tag_text(&request, "if-match") {
        headers.insert("if-match".to_string(), value);
    }

    let response = handle_request(
        &method,
        &path,
        &headers,
        body.as_bytes(),
        &gap_auth(),
        &store,
        None,
    )
    .await
    .expect("handler")
    .expect("response");
    assert_eq!(response.status, "412 Precondition Failed");
}

#[tokio::test]
async fn a1_caldav_put_rejects_if_none_match_when_existing_resource_present() {
    let store = gap_store();
    let request =
        read_fixture("tests/fixtures/rfc-6352-4791/must_fail/calendar-put-if-none-match-existing.xml");
    let path = extract_tag_text(&request, "path").expect("path");
    let body = extract_tag_text(&request, "body").unwrap_or_default();

    let setup = handle_request(
        "PUT",
        &path,
        &HashMap::new(),
        body.as_bytes(),
        &gap_auth(),
        &store,
        None,
    )
    .await
    .expect("handler")
    .expect("response");
    assert!(matches!(setup.status.as_str(), "201 Created" | "204 No Content"));

    let mut headers = HashMap::new();
    if let Some(value) = extract_tag_text(&request, "if-none-match") {
        headers.insert("if-none-match".to_string(), value);
    }
    let response = handle_request(
        "PUT",
        &path,
        &headers,
        body.as_bytes(),
        &gap_auth(),
        &store,
        None,
    )
    .await
    .expect("handler")
    .expect("response");
    assert_eq!(response.status, "412 Precondition Failed");
}
