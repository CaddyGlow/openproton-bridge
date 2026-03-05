# Calendar/Contact Cache Option 2 - Execution Plan

## Goal

Implement calendar/contact caching in the existing per-account Gluon SQLite DB (`backend/db/<storage_user_id>.db`) with production-safe sync semantics similar to the mail runtime model.

## Guardrails

1. Do not regress mail cache behavior.
2. Core event checkpoint must not advance when PIM apply fails.
3. Calendar model-event cursors must advance atomically with row updates.
4. One account worker remains the single writer for that account state.

## Milestone and PR Breakdown

## PR1 - PIM Storage Foundation

### Scope

- Add schema migration + storage abstraction for contacts/calendar.
- No event-worker integration yet.

### Files

- New: `src/pim/mod.rs`
- New: `src/pim/schema.rs`
- New: `src/pim/types.rs`
- New: `src/pim/store.rs`
- Update: `src/lib.rs` (module export)
- New tests in `src/pim/store.rs` and `src/pim/schema.rs`

### Tickets

1. `PIM-001` create schema migration framework
- Add migration table `openproton_schema_migrations`.
- Add `component='pim_cache'` versioning.
- Implement idempotent migrate entrypoint.

2. `PIM-002` add contacts tables
- `pim_contacts`
- `pim_contact_cards`
- `pim_contact_emails`
- add indexes on `modify_time`, `email`, `contact_id`.

3. `PIM-003` add calendar tables
- `pim_calendars`
- `pim_calendar_members`
- `pim_calendar_keys`
- `pim_calendar_settings`
- `pim_calendar_events`
- add indexes on `calendar_id`, `uid`, `start_time/end_time`.

4. `PIM-004` add sync-state table
- `pim_sync_state(scope, value_text, value_int, updated_at_ms)`.
- helper APIs: `get_text`, `set_text`, `get_int`, `set_int`.

5. `PIM-005` implement `PimStore` CRUD
- contact upsert/delete with child replacement.
- calendar/event upsert/delete.
- transactional APIs for cursor + data commit.

### Test gate

- unit tests:
  - migration idempotency
  - upsert overwrite semantics
  - cascade delete behavior
  - sync-state read/write
- command:
  - `cargo test --locked --lib pim::`

### Exit criteria

- schema exists and migrates cleanly on empty/existing DB.
- all store operations pass tests with restart continuity.

## PR2 - Contacts Bootstrap Sync

### Scope

- Add contacts bootstrap job that fills `pim_contacts/*`.
- Keep runtime wiring behind explicit call path (not yet core event-driven).

### Files

- New: `src/pim/sync_contacts.rs`
- Update: `src/pim/mod.rs`
- Update: `src/api/contacts.rs` (only if helper gaps needed)
- New integration tests: `src/pim/sync_contacts.rs` test module

### Tickets

1. `PIM-101` implement paginated contacts fetch
- page through `/contacts/v4`.
- for each id fetch full `/contacts/v4/{id}`.

2. `PIM-102` implement bootstrap transaction flow
- per-contact upsert in single transaction.
- maintain in-memory seen set.
- soft-delete local contacts not seen in full run.

3. `PIM-103` persist contacts bootstrap state
- write `contacts.last_full_sync_ms`.
- optional: `contacts.bootstrap_version`.

4. `PIM-104` retry and rate-limit handling
- bounded retry for transient HTTP failures.

### Test gate

- wiremock tests:
  - multi-page bootstrap
  - full detail fetch per contact
  - removal reconciliation
  - restart idempotency
- command:
  - `cargo test --locked --lib pim::sync_contacts::tests`

### Exit criteria

- cold bootstrap yields stable, queryable contacts cache.

## PR3 - Calendar Bootstrap Sync

### Scope

- Add calendar bootstrap job for metadata + initial event window + model-event baseline cursor.

### Files

- New: `src/pim/sync_calendar.rs`
- Update: `src/pim/mod.rs`
- Update: `src/api/calendar.rs` (only missing helpers if needed)
- New integration tests in `src/pim/sync_calendar.rs`

### Tickets

1. `PIM-201` fetch and cache calendars
- `/calendar/v1` into `pim_calendars`.

2. `PIM-202` fetch per-calendar resources
- members, keys, settings upsert.

3. `PIM-203` set model-event baseline cursor
- `/calendar/v1/{id}/modelevents/latest`.
- persist `calendar.<id>.model_event_id`.

4. `PIM-204` seed event horizon
- `/calendar/v1/{id}/events` with configured window.
- upsert into `pim_calendar_events`.

5. `PIM-205` reconcile removed calendars/events
- soft-delete missing entities from prior local state.

### Test gate

- wiremock tests:
  - multi-calendar bootstrap
  - cursor initialization
  - event horizon load and dedupe
  - removed calendar soft-delete
- command:
  - `cargo test --locked --lib pim::sync_calendar::tests`

### Exit criteria

- calendar metadata/events present with per-calendar model cursors initialized.

## PR4 - Incremental Sync Integration (Core Event Worker)

### Scope

- Integrate PIM incremental updates into account event polling.
- Cursor safety and failure behavior included.

### Files

- Update: `src/bridge/events.rs`
- Update: `src/bridge/mail_runtime.rs`
- New: `src/pim/incremental.rs`
- Update: `src/pim/mod.rs`
- Add tests in `src/bridge/events.rs` and `src/pim/incremental.rs`

### Tickets

1. `PIM-301` wire `PimStore` into runtime context
- initialize once per runtime, same account mapping as mail store.
- pass through `EventWorkerConfig`.

2. `PIM-302` extend typed delta handling
- consume `Contacts`, `ContactEmails`, `Calendars`, `CalendarMembers`.
- map deltas to PIM incremental operations.

3. `PIM-303` contact incremental apply
- on create/update: refresh full contact and upsert.
- on delete: soft-delete row.

4. `PIM-304` calendar model-event incremental apply
- for affected calendars (or bounded sweep), read stored cursor.
- apply `/modelevents/{cursor}` changes.
- fetch/upsert/delete events as required.

5. `PIM-305` checkpoint ordering guarantees
- apply mail + PIM mutations first.
- commit account checkpoint only after both succeed.

6. `PIM-306` partial failure policy
- if one calendar fails model-event apply:
  - keep its cursor unchanged
  - do not advance core event checkpoint for that poll
  - emit warning/health signal

### Test gate

- integration tests:
  - core events with contact create/update/delete
  - calendar model-event create/update/delete
  - replay safety after injected failure
  - checkpoint does not advance on PIM failure
- command:
  - `cargo test --locked --lib bridge::events::tests pim::incremental::tests`

### Exit criteria

- incremental PIM cache stays consistent across restarts and failures.

## PR5 - Reconciliation and Health

### Scope

- Add periodic safety reconciliations and health observability.

### Files

- Update: `src/pim/sync_contacts.rs`
- Update: `src/pim/sync_calendar.rs`
- Update: `src/bridge/events.rs`
- Update: `src/bridge/accounts.rs` (health surface if needed)
- Update: `src/main.rs` or settings source for config knobs

### Tickets

1. `PIM-401` periodic contacts full reconciliation
- default every 24h.

2. `PIM-402` periodic calendar metadata reconciliation
- default every 24h.

3. `PIM-403` calendar event horizon refresh
- default every 12h.

4. `PIM-404` degraded-state tracking
- surface per-account PIM sync warnings/errors.

5. `PIM-405` metrics/log instrumentation
- lag, apply counts, error counts, duration.

### Test gate

- deterministic interval tests with mocked clock where feasible.
- degraded-state transitions tested.

### Exit criteria

- stale or missed deltas recover automatically with bounded overhead.

## PR6 - Read API Surface for Next Consumers

### Scope

- Expose internal read APIs for future WebDAV/CalDAV/CardDAV and gRPC.
- No DAV server implementation yet.

### Files

- New: `src/pim/query.rs`
- Update: `src/pim/mod.rs`
- Optional: `src/frontend/grpc/*` if read RPCs are added now

### Tickets

1. `PIM-501` query APIs
- contacts list/get/search by email.
- calendars list/get.
- calendar events by calendar and time range.

2. `PIM-502` pagination and ordering contracts
- deterministic sorting and stable paging.

3. `PIM-503` read-path tests
- query correctness with mixed deleted/non-deleted rows.

### Exit criteria

- clean internal API available for DAV layer implementation.

## Cross-PR Non-Functional Requirements

1. Performance
- keep incremental poll cost bounded.
- avoid full-table rewrites on single-item updates.

2. SQLite safety
- use transactions for all multi-row mutations.
- avoid long write transactions in hot loops.

3. Compatibility
- never modify or drop `openproton_mailbox_index`.
- keep mail cache code paths unchanged unless explicitly required.

4. Security
- do not log sensitive card/event payload data.
- keep existing auth/session handling untouched.

## Execution Order and Ownership

1. PR1
2. PR2 and PR3 in parallel after PR1 merge
3. PR4
4. PR5
5. PR6

Suggested ownership:

- Engineer A: PR1 + PR2
- Engineer B: PR3
- Engineer C: PR4 + PR5
- Engineer D: PR6 and integration polish

## Parallel Agent Matrix (Ticket-Level)

This matrix is the execution contract for parallel implementation.

### Global file-lock rules

1. Single-owner files per wave:
- `src/pim/schema.rs`
- `src/pim/store.rs`
- `src/pim/mod.rs`
- `src/bridge/events.rs`
- `src/bridge/mail_runtime.rs`

2. Branch hygiene:
- One branch per ticket range.
- Rebase before merge, never merge stale branches directly.

3. Ownership precedence:
- If two agents need the same file, one agent owns it and the other delivers changes via handoff notes, not code edits.

### Wave 0 (PR1 baseline, serial)

| Agent | Tickets | Write Set | Parallel | Output |
|---|---|---|---|---|
| Agent A | `PIM-001`..`PIM-005` | `src/pim/schema.rs`, `src/pim/store.rs`, `src/pim/types.rs`, `src/pim/mod.rs`, `src/lib.rs` | No | PR1 merged foundation |

Reason: PR1 has heavy overlap in schema/store core files and must remain single-owner.

### Wave 1 (parallel bootstraps after PR1)

| Agent | Tickets | Write Set | Parallel With | Blocked By | Output |
|---|---|---|---|---|---|
| Agent B | `PIM-101`..`PIM-104` | `src/pim/sync_contacts.rs`, tests in same file | Agent C | PR1 | PR2 contacts bootstrap |
| Agent C | `PIM-201`..`PIM-205` | `src/pim/sync_calendar.rs`, tests in same file | Agent B | PR1 | PR3 calendar bootstrap |

Wave 1 conflict rule:
- `src/pim/mod.rs` is updated in a tiny integration commit after both branches are rebased.

### Wave 2 (parallel incremental implementation)

| Agent | Tickets | Write Set | Parallel With | Blocked By | Output |
|---|---|---|---|---|---|
| Agent D | `PIM-303`, data-logic part of `PIM-304` | `src/pim/incremental.rs`, tests in same file | Agent E | PR2 + PR3 | Incremental PIM apply module |
| Agent E | `PIM-301`, `PIM-302`, `PIM-305`, `PIM-306` | `src/bridge/events.rs`, `src/bridge/mail_runtime.rs` | Agent D | PR2 + PR3 | Event worker wiring + checkpoint safety |

Wave 2 conflict rules:
- Agent D does not edit bridge files.
- Agent E does not add core business logic into `src/pim/incremental.rs`; only integration glue and calls.

Wave 2 merge order:
1. Merge Agent D.
2. Rebase Agent E on top.
3. Merge Agent E.

### Wave 3 (parallel hardening + query API)

| Agent | Tickets | Write Set | Parallel With | Blocked By | Output |
|---|---|---|---|---|---|
| Agent F | `PIM-401`..`PIM-405` | `src/pim/sync_contacts.rs`, `src/pim/sync_calendar.rs`, `src/bridge/events.rs`, optional `src/bridge/accounts.rs` | Agent G (limited) | PR4 | Reconciliation + health |
| Agent G | `PIM-501`..`PIM-503` | `src/pim/query.rs`, tests, optional `src/frontend/grpc/*` | Agent F (if no shared-file edits) | PR4 | Query/read API |

Wave 3 conflict rule:
- If Agent G needs `src/pim/mod.rs`, merge Agent F first, then Agent G rebases and updates `mod.rs`.

### Required handoff template (every agent)

1. Tickets completed.
2. Exact files changed.
3. Commands run and test results.
4. Known risks or TODOs.
5. Migration impact summary (if schema touched).

### Recommended branch names

- `pim/pim-001-005-storage-foundation`
- `pim/pim-101-104-contacts-bootstrap`
- `pim/pim-201-205-calendar-bootstrap`
- `pim/pim-301-306-incremental-integration`
- `pim/pim-401-405-reconcile-health`
- `pim/pim-501-503-query-api`

## Validation Matrix

Run on each PR:

1. `cargo fmt --all --check`
2. `cargo clippy --workspace --all-targets`
3. targeted test suites for touched modules
4. full `cargo test --locked` before merge

Before PR4 merge, run an end-to-end scenario:

1. start with empty DB
2. bootstrap contacts/calendar
3. process incremental events
4. restart bridge
5. verify no duplicate rows and cursors continue from persisted state

## Risks and Mitigations

1. Core events may not include enough detail for all contact-email mutations
- Mitigation: refresh full contact by id and schedule periodic reconciliation.

2. Calendar model-event volume spikes
- Mitigation: `max_calendar_model_pages_per_poll` and deferred catch-up.

3. Cursor corruption or invalidation
- Mitigation: domain-scoped reset + bounded bootstrap/reconcile.

4. Write contention with mail operations
- Mitigation: keep one account worker writer model and short transactions.

## Done Definition (Program-Level)

- Contacts and calendars are durable in per-account DB.
- Incremental changes converge after restart/failures.
- Core checkpoint and model-event cursors are replay-safe.
- Mail cache behavior remains unchanged.
- Read APIs are ready for DAV-facing work.
