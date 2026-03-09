# RFC 6352 / RFC 4791 / RFC 5545 Verification & Delivery Plan

Last updated: 2026-03-09

## Objective

1. Verify CardDAV (RFC 6352) and CalDAV (RFC 4791) behavior in current code against the protocol specs.
2. Deliver first full iCalendar (RFC 5545) support for CalDAV with robust protocol conformance.
3. Keep work parallelizable across independent agents and minimize merge conflict.

## Scope

1. In scope:
   - `OPTIONS`, `PROPFIND`, `PROPPATCH`, `REPORT`, `MKCALENDAR`, `GET`, `HEAD`, `PUT`, `DELETE` flows in `src/dav/`.
   - CalDAV REPORT variants and CardDAV query/report flows in `src/dav/report.rs`.
   - iCalendar parsing/serialization in `src/dav/caldav.rs` and `src/dav/calendar_crypto.rs`.
   - Sync/state behavior in `src/pim/dav.rs` and ETag logic in `src/dav/etag.rs`.
2. Out of scope for this phase:
   - Full IMAP/SMTP behavior.
   - Auth/credential architecture changes unless they block RFC conformance.
   - Scheduler extensions that are only meaningful for full server-side scheduling (postponed to later phase).

## Current implementation snapshot (as of 2026-03-09)

### CardDAV (`RFC 6352`) coverage

1. Discovery:
   - `.well-known/carddav` redirection is implemented.
   - Addressbook collection and principal discovery exists, but endpoint capability completeness is partial.
2. Query/report:
   - `addressbook-query` and `sync-collection` request handling exist in REPORT path.
   - Filter and limit parsing is present in parts, but RFC edge-case validation is incomplete.
3. Resource methods:
   - `GET`, `HEAD`, `PUT`, `DELETE` for resources exist.
   - `PROPPATCH` support for addressbook resources is minimal and currently mostly tied to shared DAV paths.
4. Notable gaps:
   - Full `addressbook-data` property mapping and vCard version compatibility matrix.
   - Full `Addressbook-Multiget` and strict `prop` filtering behavior.
   - Missing negative-path status mapping for malformed CardDAV XML payloads.

### CalDAV (`RFC 4791`) coverage

1. Discovery and collection behavior:
   - Calendar collection routing and methods exist (`MKCALENDAR`, `PROPFIND`, etc.).
   - Core collection properties are exposed, but full required response sets are incomplete.
2. REPORT behavior:
   - `calendar-query`, `calendar-multiget`, `sync-collection` are implemented.
   - Parsing strictness and filter coverage are being improved, with recent parser work already present.
3. iCalendar object handling:
   - Current handlers parse and store iCalendar, but full RFC 5545 component/parameter validation is incomplete.
   - Recurrence/time-zone expansions used by query filters are incomplete.
4. State and HTTP metadata:
   - Partial ETag/caching behavior exists, but sync-token lifecycle and conditional request handling need deterministic hardening.

### WebDAV base (`RFC 4918`) coverage

1. Method routing and options headers are implemented.
2. `Depth` and status mapping are present but not fully RFC strict across all endpoints.
3. Need full matrix for multistatus body consistency and 4xx/5xx classification for malformed XML.

## Verification matrix to execute (RFC checklist)

1. RFC 6352 checks:
   - 5.1.1: Principal and addressbook collection discovery responses.
   - 7.6/7.7: `addressbook-query` response status and filter semantics.
   - 11: vCard object PUT/GET behavior for media type and UID handling.
2. RFC 4791 checks:
   - 4: General CalDAV requirements for reporting and synchronization.
   - 5.2: Calendar object resource methods with correct iCalendar payload handling.
   - 7.2: `calendar-query` semantics, including `calendar-data` and optional filters.
   - 7.3: `calendar-multiget` request and error reporting.
   - 8: discovery properties (`calendar-home-set`, supported components, timezone metadata).
3. RFC 5545 checks:
   - Core properties and components (VEVENT, VTODO, VJOURNAL, VTIMEZONE).
   - Parameter escaping, folding/unfolding, line ending normalization.
   - RRULE/RDATE/EXDATE/EXRULE behavior in report-time filtering.

## Failure criteria (must fail before implementation)

1. No endpoint may return 500 for well-formed but unsupported RFC request payloads.
2. Any malformed REPORT/XML/iCalendar input must map to explicit 4xx with deterministic multistatus or XML error body.
3. Round trip iCalendar write/read must preserve unsupported known-ignored properties unless server is not able to safely preserve them.
4. Sync loops must stop reporting unchanged resources as changed after hash-canonicalization stability.
5. Conditional write behavior must reject stale clients using RFC-appropriate `409`/`412` semantics (`If-Match`, `If-None-Match`).

## Progress gate before merge

1. All items in the RFC checklist have failing cases captured as explicit tests.
2. Protocol-level error behavior is deterministic for malformed REPORT/XML/iCalendar payloads.
3. Round-trip iCalendar preservation rules are documented and applied consistently across create/update/delete paths.
4. Sync state changes only for semantic object mutations (create/update/delete) in all test scenarios.

## Execution plan with multi-agent lanes

### Cross-phase constraints

1. Every phase transition must include a named test file/fixture and at least one explicit acceptance check.
2. All protocol errors introduced in this workstream must have deterministic expected body/status coverage in regression tests.
3. No phase is complete without documenting observed behavior in date-stamped notes in `docs/dav-server-operator-and-client-guide.md`.

### Risk and mitigation register

1. RFC-strict parsing may reject payloads used by existing clients.
   - Mitigation: keep a compatibility path for tolerated legacy shape while preserving strict validation for malformed inputs.
2. Sync-state churn can trigger unstable incremental sync behavior.
   - Mitigation: enforce mutation-only sync-token updates and add repeated loop regression tests.
3. Conditional writes (`If-Match` / `If-None-Match`) may return non-standard conflict status.
   - Mitigation: normalize status mapping to RFC-appropriate `412` / `409` and verify through malformed/condition matrix tests.
4. Timezone and recurrence expansion can increase report latency.
   - Mitigation: add targeted benchmarks and fallback path for non-recurring resources; add explicit timeout expectations in tests.
5. Divergent negative-path responses across report and non-report handlers.
   - Mitigation: centralize error classification and validate with a shared fixture set.

### Deliverables by phase (single-screen view)

| Phase | Deliverable | Primary files | Evidence |
|---|---|---|---|
| A1 | RFC gap inventory + failing-case capture | `docs/rfc-6352-4791-full-support-plan.md`, `docs/dav-server-operator-and-client-guide.md` | `tests/dav/rfc_gap_inventory.rs`, `tests/fixtures/rfc-6352-4791/gaps/*.yaml` |
| A2 | RFC 5545 parser/canonicalization + preservation behavior | `src/dav/caldav.rs`, `src/dav/calendar_crypto.rs` | `tests/dav/icalendar_parser.rs`, `tests/dav/calendar_crypto.rs`, `tests/fixtures/rfc-5545/**/*.ics` |
| B1 | REPORT/PROPFIND/OPTIONS protocol hardening | `src/dav/report.rs`, `src/dav/propfind.rs`, `src/dav/xml.rs`, `src/dav/server.rs` | `tests/dav/report_calendaring.rs`, `tests/dav/propfind_xml.rs`, `tests/fixtures/rfc-4791/reports/**/*.xml` |
| B2 | Sync/token/ETag correctness + conditional writes | `src/pim/dav.rs`, `src/dav/etag.rs`, `src/dav/server.rs` | `tests/dav/sync_state.rs`, `tests/dav/etag_headers.rs`, `tests/fixtures/rfc-6578/**/*.json` |
| E1 | CardDAV closure + query/report corrections | `src/dav/carddav.rs`, `src/dav/report.rs`, `tests/**` | `tests/dav/carddav_query.rs`, `tests/dav/carddav_discovery.rs`, `tests/fixtures/rfc-6352/**/*.{xml,vcf}` |
| Z | Interop matrix + release-readiness lock | `tests/**`, `docs/dav-server-operator-and-client-guide.md` | `tests/dav/interop_matrix.rs`, `tests/fixtures/interop/{apple-calendar,thunderbird,evolution}/*` |

### Phase A1 (mandatory first step): RFC gap freeze and harness

1. Owner: Agent A (lead), Agent E (test).
2. Tasks:
   - Generate machine-readable gap list from current behavior against RFC matrix.
   - Add failing fixtures for all "must-fail" cases above.
   - Lock endpoint contract for all new/changed behavior in `docs/dav-server-operator-and-client-guide.md`.
3. Acceptance:
   - Every gap has: RFC section, failing test, expected status, owner, dependency.
4. Exit criteria:
   - Gap register is complete and owned by a single phase.
5. Test mapping:
   - `tests/dav/rfc_gap_inventory.rs`
   - `tests/fixtures/rfc-6352-4791/gaps/*.yaml`
   - `tests/fixtures/rfc-6352-4791/must_fail/*.xml`

#### A1 evidence (baseline snapshot)

- Completed on 2026-03-09 (baseline lockpoint):
  - Added `tests/dav/rfc_gap_inventory.rs`.
    - Validates the A1 inventory manifest shape (required metadata, unique sections, expected client error status).
    - Verifies all acceptance check paths and fixture references resolve.
  - Added `tests/fixtures/rfc-6352-4791/gaps/phase-a1.yaml`.
    - Includes baseline items for RFC 6352 section 5.1.1, RFC 6352 7.6, RFC 4791 7.2, RFC 4791 7.3.
  - Added malformed must-fail payload fixtures under `tests/fixtures/rfc-6352-4791/must_fail/`.
    - `addressbook-query-malformed.xml`
    - `calendar-query-malformed-time-range.xml`
    - `calendar-multiget-empty-hrefs.xml`
  - Added protocol-hardening coverage in implementation:
    - `src/dav/report.rs` now returns deterministic 400 responses for missing/unsupported REPORT bodies.
    - `src/dav/caldav.rs` now validates CALDAV PUT payloads contain an iCalendar envelope before upsert.
- Evidence state:
  - `A1` inventory and malformed must-fail fixtures are now frozen and versioned in git as a baseline.
  - Remaining items are not yet represented as executable tests and are open items below.
- Next A1-to-A2 boundary:
  - Expand this fixture set so every non-governed RFC 6352/4791 must-fail and success-path contract gets an explicit test artifact and acceptance check.
  - Add dedicated fixture rows for sync-token and conditional write negative paths before merging B1/B2 hardening work.

### Phase A2 (parallelizable): Parser and payload correctness

1. Owner: Agent A.
2. Files:
   - `src/dav/caldav.rs`
   - `src/dav/calendar_crypto.rs`
3. Tasks:
   - Implement strict RFC 5545 parser model with lenient passthrough mode.
   - Preserve unknown properties/parameters and property order where safe.
   - Add recurrence and time-zone expansion helpers used by report filters.
   - Add deterministic canonicalization for ETag/hash inputs.
4. Dependencies:
   - Must complete before B2 and before any iCalendar-heavy report changes that rely on semantic filtering.
5. Exit criteria:
   - New parser behavior has regression tests for canonicalization and compatibility mode.
   - Deterministic object hash generation is used by iCal write path.
6. Test mapping:
   - `tests/dav/icalendar_parser.rs`
   - `tests/dav/calendar_crypto.rs`
   - `tests/fixtures/rfc-5545/**/*.ics`

### Phase B1 (parallelizable once A2 starts): CalDAV/CardDAV protocol hardening

1. Owner: Agent B.
2. Files:
   - `src/dav/report.rs`
   - `src/dav/propfind.rs`
   - `src/dav/xml.rs`
   - `src/dav/server.rs`
3. Tasks:
   - Finalize REPORT parsers for calendar-query, calendar-multiget, carddav-query, sync-collection.
   - Add strict request validation and explicit bad-request mappings.
   - Ensure namespace/property matching for all supported report payloads.
   - Tighten `PROPFIND`/`OPTIONS` advertised features to match actual support.
4. Dependencies:
   - A2 needed for reliable component/range filtering.
5. Exit criteria:
   - Malformed report payload paths consistently return 4xx with spec-typed XML error responses.
6. Test mapping:
   - `tests/dav/report_calendaring.rs`
   - `tests/dav/propfind_xml.rs`
   - `tests/fixtures/rfc-4791/reports/**/*.xml`

### Phase B2 (sync + state correctness): state and cache protocol

1. Owner: Agent C.
2. Files:
   - `src/pim/dav.rs`
   - `src/dav/etag.rs`
   - `src/dav/server.rs`
3. Tasks:
   - Deterministic sync token model that changes on create/update/delete only.
   - Implement resource-level conditional headers for write safety (`If-Match`, `If-None-Match`).
   - Validate `Depth` and conflict status for collection state operations.
4. Acceptance:
   - Incremental sync returns only changed resource list across mutations.
5. Exit criteria:
   - Sync token changes are stable and only mutation-driven in repeated mutation/reload loops.
6. Test mapping:
   - `tests/dav/sync_state.rs`
   - `tests/dav/etag_headers.rs`
   - `tests/fixtures/rfc-6578/**/*.json`

### Phase E1 (parallel): CardDAV closure for RFC 6352

1. Owner: Agent E.
2. Files:
   - `src/dav/carddav.rs`
   - `src/dav/report.rs`
   - `tests/**`
3. Tasks:
   - Confirm vCard collection/object property behavior against RFC 6352.
   - Add explicit addressbook-query/addressbook-multiget cases and malformed-input status expectations.
   - Add regression checks for addressbook discovery and response sets.
4. Exit criteria:
   - CardDAV malformed-input status matrix exists and is green in CI.
5. Test mapping:
   - `tests/dav/carddav_query.rs`
   - `tests/dav/carddav_discovery.rs`
   - `tests/fixtures/rfc-6352/**/*.{xml,vcf}`

### Phase Z (all lanes): Validation and interop lock

1. Owner: Agent E.
2. Files:
   - `tests/**`
   - `tests/fixtures/**`
   - `docs/dav-server-operator-and-client-guide.md`
3. Tasks:
   - Run matrix across Apple Calendar, Thunderbird, Evolution, and one CalDAV client CLI path.
   - Add recurring event fixtures with timezone transitions, malformed RFC 5545 tokens, and large datasets.
   - Publish pass/fail with date-stamped results and open issues for each blocker.
4. Exit criteria:
   - All planned clients have at least one successful smoke path through read/write/report/sync.
5. Test mapping:
   - `tests/dav/interop_matrix.rs`
   - `tests/fixtures/interop/apple-calendar/*`
   - `tests/fixtures/interop/thunderbird/*`
   - `tests/fixtures/interop/evolution/*`

## Proposed schedule

1. Week 1:
   - A1 complete + start A2.
2. Week 2:
   - A2 and B1 in parallel.
3. Week 3:
   - B2 and E1 in parallel with remaining B1/B2 merge.
4. Week 4:
   - Full regression + interop matrix (Z) and release candidate decision.

## Definition of done (phase 1)

1. Apple Calendar and Thunderbird can:
   - discover principal/calendar/addressbook correctly,
   - create/read/update/delete VEVENT and VTODO,
   - query/sync with stable tokens and deterministic `ETag`.
2. RFC conformance artifacts exist:
   - each requirement has test and observed status.
3. No behavioral regressions in existing event/message sync flows and credential/crypto paths.

## Immediate implementation ordering for this repo

1. Execute A1 and baseline A2 first.
2. Fork into B1 and B2 as soon as parser foundations are stable.
3. Fold in E1 once `addressbook-query` behavior in REPORT is stable.
4. Run Z lock after all branches merge and run final RFC matrix.
