use std::collections::HashSet;
use std::fs;
use std::path::Path;

use openproton_bridge::bridge::auth_router::AuthRoute;
use openproton_bridge::bridge::types::AccountId;
use openproton_bridge::dav::caldav::handle_request;
use openproton_bridge::dav::report::handle_report;
use openproton_bridge::pim::store::PimStore;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;

#[derive(Debug)]
struct GapRecord {
    phase: String,
    rfc: String,
    section: String,
    requirement: String,
    expected_status: u16,
    owner: String,
    dependency: String,
    acceptance_check: String,
    must_fail_fixture: Option<String>,
}

#[derive(Default)]
struct GapRecordBuilder {
    phase: Option<String>,
    rfc: Option<String>,
    section: Option<String>,
    requirement: Option<String>,
    expected_status: Option<u16>,
    owner: Option<String>,
    dependency: Option<String>,
    acceptance_check: Option<String>,
    must_fail_fixture: Option<String>,
}

impl GapRecordBuilder {
    fn to_record(self) -> Option<GapRecord> {
        Some(GapRecord {
            phase: self.phase?,
            rfc: self.rfc?,
            section: self.section?,
            requirement: self.requirement?,
            expected_status: self.expected_status?,
            owner: self.owner?,
            dependency: self.dependency?,
            acceptance_check: self.acceptance_check?,
            must_fail_fixture: self.must_fail_fixture,
        })
    }
}

fn parse_gap_inventory_rows(raw: &str) -> Vec<GapRecord> {
    let mut records = Vec::new();
    let mut current = None::<GapRecordBuilder>;

    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(line) = line.strip_prefix("- ") {
            if let Some(builder) = current.take() {
                if let Some(record) = builder.to_record() {
                    records.push(record);
                }
            }
            current = Some(GapRecordBuilder {
                phase: Some(trim_yaml_value(line)),
                ..GapRecordBuilder::default()
            });
            continue;
        }

        let Some(builder) = current.as_mut() else {
            continue;
        };

        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = trim_yaml_value(value);

        match key {
            "rfc" => builder.rfc = Some(value.to_string()),
            "section" => builder.section = Some(value.to_string()),
            "requirement" => builder.requirement = Some(value.to_string()),
            "expected_status" => {
                builder.expected_status = value.parse::<u16>().ok();
            }
            "owner" => builder.owner = Some(value.to_string()),
            "dependency" => builder.dependency = Some(value.to_string()),
            "acceptance_check" => builder.acceptance_check = Some(value.to_string()),
            "must_fail_fixture" => builder.must_fail_fixture = Some(value.to_string()),
            _ => {}
        }
    }

    if let Some(builder) = current.take() {
        if let Some(record) = builder.to_record() {
            records.push(record);
        }
    }

    records
}

fn trim_yaml_value(raw: &str) -> String {
    raw.trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn gap_store() -> Arc<PimStore> {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("account.db");
    Box::leak(Box::new(tmp));
    Arc::new(PimStore::new(db_path).unwrap())
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

fn load_fixture(path: &str) -> String {
    fs::read_to_string(path).expect("read fixture")
}

#[test]
fn gap_inventory_manifest_has_complete_contract_metadata() {
    let plan_fixture = Path::new("tests/fixtures/rfc-6352-4791/gaps");
    assert!(plan_fixture.exists(), "gap fixture directory missing: {plan_fixture:?}");

    let mut records = Vec::new();
    for entry in fs::read_dir(plan_fixture).expect("list gap fixtures") {
        let path = entry.expect("list gap fixture entry").path();
        if path.extension().and_then(|value| value.to_str()) != Some("yaml") {
            continue;
        }
        let content = fs::read_to_string(&path).expect("read gap fixture");
        records.extend(parse_gap_inventory_rows(&content));
    }

    assert!(
        !records.is_empty(),
        "at least one gap record is required to freeze RFC coverage"
    );

    let mut section_ids = HashSet::new();
    for record in &records {
        assert_eq!(
            record.phase, "A1",
            "phase A1 inventory must only track baseline phase entries"
        );
        assert!(
            !record.rfc.trim().is_empty(),
            "rfc is required for {}",
            record.section
        );
        assert!(
            !record.section.trim().is_empty(),
            "section is required for dependency {}",
            record.dependency
        );
        assert!(
            !record.requirement.trim().is_empty(),
            "requirement is required for {}",
            record.section
        );
        assert!(
            record.expected_status >= 400,
            "expected_status should be a client error for malformed input: {}",
            record.section
        );
        assert!(
            !record.owner.trim().is_empty(),
            "owner is required for {}",
            record.section
        );
        assert!(
            !record.dependency.trim().is_empty(),
            "dependency is required for {}",
            record.section
        );
        assert!(
            !record.acceptance_check.trim().is_empty(),
            "acceptance_check is required for {}",
            record.section
        );
        assert!(
            section_ids.insert(record.section.clone()),
            "section must be unique in A1 inventory: {}",
            record.section
        );
    }
}

#[test]
fn gap_inventory_references_existing_artifacts() {
    let plan_fixture = Path::new("tests/fixtures/rfc-6352-4791/gaps");
    let mut records = Vec::new();
    for entry in fs::read_dir(plan_fixture).expect("list gap fixtures") {
        let path = entry.expect("list gap fixture entry").path();
        if path.extension().and_then(|value| value.to_str()) != Some("yaml") {
            continue;
        }
        let content = fs::read_to_string(&path).expect("read gap fixture");
        records.extend(parse_gap_inventory_rows(&content));
    }

    for record in records {
        assert!(
            Path::new(&record.acceptance_check).exists(),
            "acceptance_check path missing for {section}: {path}",
            section = record.section,
            path = record.acceptance_check
        );

        if let Some(fixture) = record.must_fail_fixture {
            assert!(
                Path::new(&fixture).exists(),
                "must_fail fixture missing for {section}: {fixture}",
                section = record.section,
                fixture = fixture
            );
        }
    }

    assert!(
        Path::new("tests/fixtures/rfc-6352-4791/must_fail").exists(),
        "must_fail fixture directory must exist"
    );
}

#[tokio::test]
async fn a1_report_rejects_missing_sync_token_fixture() {
    let store = gap_store();
    let response = handle_report(
        "/dav/uid-1/calendars/default/",
        load_fixture("tests/fixtures/rfc-6352-4791/must_fail/calendar-sync-token-missing.xml").as_bytes(),
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
        load_fixture("tests/fixtures/rfc-6352-4791/must_fail/calendar-sync-token-malformed.xml").as_bytes(),
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
    let request = load_fixture("tests/fixtures/rfc-6352-4791/must_fail/calendar-put-stale-if-match.xml");
    let method = extract_tag_text(&request, "method").expect("method");
    let path = extract_tag_text(&request, "path").expect("path");
    let mut headers = HashMap::new();
    if let Some(value) = extract_tag_text(&request, "if-match") {
        headers.insert("if-match".to_string(), value);
    }
    let body = extract_tag_text(&request, "body").unwrap_or_default();
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
    let request = load_fixture("tests/fixtures/rfc-6352-4791/must_fail/calendar-put-if-none-match-existing.xml");
    let path = extract_tag_text(&request, "path").expect("path");
    let body = extract_tag_text(&request, "body").unwrap_or_default();

    let create = handle_request(
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
    assert!(create.status == "201 Created" || create.status == "204 No Content");

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
