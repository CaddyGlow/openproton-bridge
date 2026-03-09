use std::collections::HashSet;
use std::fs;
use std::path::Path;

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
