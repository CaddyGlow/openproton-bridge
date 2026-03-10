# Event Loop Parity (OpenProton vs go-proton-api vs proton-bridge)

## Scope

This document compares event fetch and sync-loop semantics for:

- `openproton-bridge` Rust worker path
- `go-proton-api` event contracts
- `proton-bridge` IMAP sync/event handlers built on GPA

Primary files:

- `src/api/events.rs`
- `src/api/types.rs`
- `src/bridge/events.rs`
- `../go-proton-api/event.go`
- `../go-proton-api/event_types.go`
- `../proton-bridge/internal/services/imapservice/service_sync_events.go`
- `../proton-bridge/internal/services/imapservice/service_message_events.go`

## Implementation status (2026-03-10)

- Done: aligned per-poll `More` safety cap with GPA collection cap (`50`) in `src/bridge/events.rs`.
- Done: aligned refresh handling with upstream `RefreshMail` bit semantics (`refresh & 1 != 0`).
- Done: added regressions:
  - `poll_account_once_non_mail_refresh_bit_does_not_trigger_resync`
  - `poll_account_once_more_chain_honors_upstream_page_limit`
- Done: fixture-driven typed-vs-heuristic payload matrix coverage:
  - `tests/parity/fixtures/events_delta_matrix.json`
  - `parse_event_deltas_matches_fixture_matrix_cases`
- Done: non-mail refresh bit fixture coverage broadened:
  - `tests/parity/fixtures/events_refresh_bits.json`
  - `poll_account_once_multiple_non_mail_refresh_bits_do_not_trigger_resync`
- Done: transient fetch retry budget increased to `3` attempts with regression coverage.
  - `get_events_retries_twice_before_success`
- Done (intentional deviation): stale-cursor telemetry parity reviewed.
  - Upstream emits user bad-event signals via dedicated event bus.
  - OpenProton records `cursor_reset_resync` checkpoint state and account health transitions.
  - Decision: keep current Rust runtime/account-health model; do not add a parallel bad-event bus.

## Current findings

### 1) `More` pagination cap mismatch (resolved)

Observed:

- GPA aggregates up to `maxCollectedEvents = 50` in one `GetEvent` call chain.
- OpenProton now aligns with this cap (`MAX_EVENT_PAGES_PER_POLL = 50`).

Risk:

- Residual risk is low and mostly operational (still bounded in one poll cycle by design).

Validation tasks:

- Keep long-chain `More` parity coverage in fixtures/tests.

### 2) Refresh flag semantics simplified to non-zero (resolved)

Observed:

- GPA defines `RefreshFlag` bitmask (`RefreshMail`, `RefreshAll`).
- OpenProton now applies bit semantics for mail refresh (`refresh & 1 != 0`).

Risk:

- Residual risk is low for mail-path behavior; non-mail refresh values remain fixture-covered.

Validation tasks:

- Keep refresh-bit fixture matrix updated as additional upstream bits appear.

### 3) Cursor reset flow diverges from upstream style (medium)

Observed:

- OpenProton catches invalid cursor, runs bounded resync, clears cursor, refetches `/events/latest`.
- Upstream bridge handles bad events via user-level bad-event/deauth handling paths.

Risk:

- Different operator/user-visible behavior and potentially different telemetry around event-loop recovery.

Validation tasks:

- Force stale cursor errors and compare resulting state transitions/events emitted in both implementations.

### 4) Typed + heuristic event delta parsing (medium)

Observed:

- OpenProton supports typed deserialization and fallback heuristics (`Action`, `Deleted`, string/int shapes).
- GPA uses strict typed event models.

Risk:

- Heuristics may incorrectly classify corner payloads; strict typing may reject payload drift.

Validation tasks:

- Build fixture matrix for mixed payload shapes and compare message/label/address deltas produced.

### 5) Transient retry policy (resolved, still intentionally bounded)

Observed:

- OpenProton `get_events` retries transient failures with `MAX_TRANSIENT_ATTEMPTS = 3`.
- Upstream behavior is primarily stream-driven and may smooth retries differently in higher layers.

Risk:

- Residual risk is low; retries remain intentionally bounded per poll cycle.

Validation tasks:

- Keep burst simulations (`429/5xx`) in API event tests and runtime e2e scenarios.

## Proposed implementation plan (step 3 execution)

1. Add parity fixtures for long `More` chains, refresh bit variants, stale cursor recovery, and mixed event payload shapes.
2. Add focused tests in `tests/parity/` asserting cursor advancement, checkpoint `sync_state`, and applied mailbox/message deltas.
3. Decide and document intentional deviations:
   - page cap `32` vs `50`
   - coarse `refresh != 0` resync behavior
4. If deviations are not intentional, patch:
   - page cap behavior
   - refresh bitmask interpretation
   - stale cursor recovery telemetry parity
5. Re-run `cargo test --locked` plus targeted parity tests and update `06-gap-backlog.md`.

## Acceptance gates for event-loop parity

- No event loss under `More` chains exceeding both cap values.
- Deterministic cursor/checkpoint progression across restart/recovery cases.
- Explicitly documented handling for each observed refresh bit.
- Matching behavior for message create/update/delete delta application on shared fixtures.
