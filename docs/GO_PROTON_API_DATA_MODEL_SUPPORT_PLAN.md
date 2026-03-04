# go-proton-api Data Model Support Plan

Generated: 2026-03-04

Input baseline:
- Field parity matrix: `docs/GO_PROTON_API_DATA_MODEL_PARITY.md`
- Machine-readable rows: `docs/GO_PROTON_API_DATA_MODEL_PARITY.csv`

Goal:
- Close all `Missing in Rust` model gaps with minimal regression risk.
- Preserve current bridge behavior while progressively enabling richer parity behavior.

Implementation status (2026-03-04):
- Phases 1-3 completed in code.
- `docs/GO_PROTON_API_DATA_MODEL_PARITY.csv` and `.md` updated to reflect closed model gaps.

## Current Gap Snapshot

- Total compared rows: 139
- Missing in Rust: 0
- Rust-only: 0
- Compatible: 94
- Exact: 45

Top missing entities by count:
1. None (all audited `Missing in Rust` rows were closed)

## Execution Strategy

Implement in three tracks:
1. `Schema parity` (safe deserialization/serialization additions, low risk)
2. `Consumer parity` (code paths that should use new fields)
3. `Typed events parity` (largest structural change; isolate last)

Order is optimized for low blast radius and fast measurable wins.

## Phase 1: Schema Parity (Low Risk, High Coverage)

Objective:
- Add missing fields to `src/api/types.rs` using `#[serde(default)]` and `Option<T>` where needed.
- Avoid changing existing call sites unless required.

Target file:
- `src/api/types.rs`

Tasks:
1. Auth and 2FA schema completion
- `AuthInfoResponse`: add `two_factor` (`json:\"2FA\"`, default/optional).
- `AuthResponse`: add `user_id`, add `scope` alongside existing `scopes`.
- `RefreshResponse`: add optional `server_proof`, `scope`, `two_factor`, `password_mode`.
- `Fido2Info`: add `registered_keys` (new nested struct).

2. Key and identity schema completion
- `UserKey`: add optional `token`, `signature`, `primary`, `flags`.
- `Address`: add optional/default `order`.
- `AddressKey`: add optional/default `primary`, `flags`.

3. Message and attachment schema completion
- `MessageMetadata`: add `external_id`, `reply_tos`, `flags`, `is_replied`, `is_replied_all`, `is_forwarded`.
- `Message`: add optional/default `parsed_headers` representation.
- `Attachment`: add `disposition`, `headers`, `signature`.

4. Request model completion
- `MessageFilter`: add `id`, `subject`, `address_id`, `external_id`.
- `DraftTemplate`: add optional `external_id`.
- `CreateDraftReq`: add optional `attachment_key_packets`.

5. Constant parity completion
- Add `ENCRYPTED_OUTSIDE_SCHEME` constant.
- Add `ATTACHED_SIGNATURE` constant.

Acceptance:
- `cargo test` passes.
- New unit tests in `src/api/types.rs` validate parsing of all newly added fields.
- Existing JSON fixtures still deserialize (backward compatibility preserved).

## Phase 2: Consumer Parity (Behavioral Use Of New Fields)

Objective:
- Ensure newly modeled fields are actually used where parity matters.

Primary files:
- `src/api/messages.rs`
- `src/bridge/events.rs`
- `src/imap/mailbox.rs`
- `src/smtp/send.rs`
- `src/main.rs` (CLI fetch/filter flows)

Tasks:
1. Filter propagation
- Extend `get_message_metadata` request body in `src/api/messages.rs` to send new `MessageFilter` fields when present (`ID`, `Subject`, `AddressID`, `ExternalID`).

2. Draft request propagation
- Ensure `CreateDraftReq.attachment_key_packets` can be supplied by send path when available.
- Keep optional default (`None`) so current behavior does not regress.

3. Metadata-driven mailbox behavior
- Review `imap` flag derivation to optionally use `flags`, `is_replied`, `is_forwarded` where meaningful.
- Keep current unread/label behavior as fallback.

4. Key handling readiness
- Audit key unlock flow (`src/crypto/keys.rs`) for compatibility with new optional key fields (`primary`, `flags`).
- No behavior change required in first pass; ensure no assumptions are violated.

Acceptance:
- Existing integration tests pass.
- Add targeted tests for request serialization (`MessageFilter`, `CreateDraftReq`).
- No regression in IMAP listing/sync tests.

## Phase 3: Typed Events Parity (High Impact, Isolated)

Objective:
- Replace/augment untyped `Vec<Value>` event payload handling with typed event models aligned to go-proton-api semantics.

Primary files:
- `src/api/types.rs`
- `src/api/events.rs`
- `src/bridge/events.rs`

Tasks:
1. Introduce typed event payload structs/enums
- Model `Event`-like shape: user/mail settings/messages/labels/addresses/notifications/used space.
- Keep raw payload preservation for unknown fields (`#[serde(flatten)]` + fallback).

2. Dual parse strategy
- Parse into typed model first.
- Fall back to current heuristic parsing for unknown/legacy payloads.

3. Worker integration
- Update delta extraction in `src/bridge/events.rs` to consume typed events where available.
- Keep existing heuristic as safety net during transition.

Acceptance:
- Add parity tests for create/update/delete action handling and refresh semantics.
- Event worker tests confirm identical behavior for existing fixtures.

## Milestone Plan (PR Slices)

1. `DM-001` Add missing fields in `src/api/types.rs` + tests.
2. `DM-002` Add missing constants + tests.
3. `DM-003` Propagate `MessageFilter` fields in `src/api/messages.rs` + tests.
4. `DM-004` Wire `CreateDraftReq.attachment_key_packets` through send path.
5. `DM-005` Add optional metadata flag consumption in IMAP/mailbox logic.
6. `DM-006` Introduce typed event structs (non-breaking, unused first).
7. `DM-007` Switch `bridge/events` to typed-first parsing with fallback.
8. `DM-008` Clean up and document final parity status (update parity CSV/MD).

## Risk Controls

1. Backward compatibility safety
- Default every new deserialized field with `Option<T>` or `#[serde(default)]`.
- Avoid changing field types already used by runtime paths unless necessary.

2. Test-first change policy
- For each `DM-*` task: add failing test first, then implement.

3. Rollout guard
- Land Phase 1 and Phase 2 before typed events.
- Keep event fallback path until parity fixtures prove typed model robustness.

## Definition Of Done

1. All rows marked `Missing in Rust` in `docs/GO_PROTON_API_DATA_MODEL_PARITY.csv` are closed or explicitly deferred with rationale.
2. `docs/GO_PROTON_API_DATA_MODEL_PARITY.md` updated with final statuses.
3. Test suite remains green (`cargo test`), including new parity-focused tests.
