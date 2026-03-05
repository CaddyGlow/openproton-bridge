# Calendar/Contact Cache Plan (Option 2)

## Decision

Use the existing per-account Gluon SQLite database file and add dedicated SQL tables for calendar/contact cache data.

This keeps storage colocated with current bridge account data while avoiding the scalability limits of stuffing PIM state into the JSON mailbox index payload.

## Why Option 2

- Reuses existing per-account DB path and lifecycle:
  - `RuntimePaths::gluon_paths(...).account_db_path(storage_user_id)`
- Keeps one account = one DB artifact, which fits current runtime and backup/debug habits.
- Enables indexed reads and incremental updates for calendars/contacts.
- Avoids the write amplification and query limitations of JSON-only index payloads.

## Scope

### In scope

- Local cache for contacts and calendar metadata/events.
- Bootstrap sync + incremental sync from Proton events/model-events.
- Per-account cursors/state in SQL.
- Cache correctness and restart continuity.

### Out of scope (for this phase)

- WebDAV/CalDAV/CardDAV serving layer.
- Full offline write queue and conflict UX.
- Multi-device merge beyond server-last-write semantics.
- Advanced search ranking beyond SQL filtering.

## Existing Baseline (Mail)

- Mail data is cached in Gluon store with:
  - blob files under `backend/store/<storage_user_id>/`
  - SQLite index table `openproton_mailbox_index` in `backend/db/<storage_user_id>.db`
- Event checkpointing is handled in bridge event worker.

We will mirror the same runtime model for PIM:

- same per-account DB file
- account-scoped worker updates cache
- persisted sync cursors for restart continuity

## Target Architecture

### Components

1. `PimStore` (new module)
- Owns schema migration and SQL access for contacts/calendar.
- Exposes upsert/delete/query methods.
- Persists sync cursors and reconciliation metadata.

2. `PimSyncEngine` (new module)
- Orchestrates bootstrap and incremental sync.
- Uses existing Proton API modules:
  - contacts: `/contacts/v4`
  - calendar: `/calendar/v1/...` including model-events
  - core events: `/core/v4/events/...`

3. Event worker integration
- Extend account event loop to trigger PIM sync steps.
- Keep ordering guarantees per account.

### Runtime model

- One account worker updates:
  - mail cache
  - PIM cache
  - account checkpoint/cursors
- Per-account serial writes prevent cross-thread SQLite write contention.

## SQL Schema (Proposed)

All tables live in the existing account DB (`<storage_user_id>.db`).

### Migration/meta

```sql
CREATE TABLE IF NOT EXISTS openproton_schema_migrations (
    component TEXT NOT NULL,
    version   INTEGER NOT NULL,
    applied_at_ms INTEGER NOT NULL,
    PRIMARY KEY (component, version)
);
```

Component for this feature: `pim_cache`.

### Contacts

```sql
CREATE TABLE IF NOT EXISTS pim_contacts (
    id TEXT PRIMARY KEY,
    uid TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    create_time INTEGER NOT NULL DEFAULT 0,
    modify_time INTEGER NOT NULL DEFAULT 0,
    raw_json TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pim_contacts_modify_time
    ON pim_contacts(modify_time DESC);
```

```sql
CREATE TABLE IF NOT EXISTS pim_contact_cards (
    contact_id TEXT NOT NULL,
    card_index INTEGER NOT NULL,
    card_type INTEGER NOT NULL,
    data TEXT NOT NULL,
    signature TEXT,
    PRIMARY KEY (contact_id, card_index),
    FOREIGN KEY (contact_id) REFERENCES pim_contacts(id) ON DELETE CASCADE
);
```

```sql
CREATE TABLE IF NOT EXISTS pim_contact_emails (
    id TEXT PRIMARY KEY,
    contact_id TEXT NOT NULL,
    email TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    kind_json TEXT NOT NULL DEFAULT '[]',
    defaults_value INTEGER,
    order_value INTEGER,
    label_ids_json TEXT NOT NULL DEFAULT '[]',
    last_used_time INTEGER,
    raw_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (contact_id) REFERENCES pim_contacts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_pim_contact_emails_email
    ON pim_contact_emails(email);
CREATE INDEX IF NOT EXISTS idx_pim_contact_emails_contact
    ON pim_contact_emails(contact_id);
```

### Calendar

```sql
CREATE TABLE IF NOT EXISTS pim_calendars (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    color TEXT NOT NULL DEFAULT '',
    display INTEGER NOT NULL DEFAULT 0,
    calendar_type INTEGER NOT NULL DEFAULT 0,
    flags INTEGER NOT NULL DEFAULT 0,
    raw_json TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);
```

```sql
CREATE TABLE IF NOT EXISTS pim_calendar_members (
    id TEXT PRIMARY KEY,
    calendar_id TEXT NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    color TEXT NOT NULL DEFAULT '',
    display INTEGER NOT NULL DEFAULT 0,
    permissions INTEGER NOT NULL DEFAULT 0,
    raw_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (calendar_id) REFERENCES pim_calendars(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_pim_calendar_members_calendar
    ON pim_calendar_members(calendar_id);
```

```sql
CREATE TABLE IF NOT EXISTS pim_calendar_keys (
    id TEXT PRIMARY KEY,
    calendar_id TEXT NOT NULL,
    passphrase_id TEXT NOT NULL DEFAULT '',
    private_key TEXT NOT NULL DEFAULT '',
    flags INTEGER NOT NULL DEFAULT 0,
    raw_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (calendar_id) REFERENCES pim_calendars(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_pim_calendar_keys_calendar
    ON pim_calendar_keys(calendar_id);
```

```sql
CREATE TABLE IF NOT EXISTS pim_calendar_settings (
    id TEXT PRIMARY KEY,
    calendar_id TEXT NOT NULL,
    default_event_duration INTEGER NOT NULL DEFAULT 0,
    default_part_day_notifications_json TEXT NOT NULL DEFAULT '[]',
    default_full_day_notifications_json TEXT NOT NULL DEFAULT '[]',
    raw_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (calendar_id) REFERENCES pim_calendars(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_pim_calendar_settings_calendar
    ON pim_calendar_settings(calendar_id);
```

```sql
CREATE TABLE IF NOT EXISTS pim_calendar_events (
    id TEXT PRIMARY KEY,
    calendar_id TEXT NOT NULL,
    uid TEXT NOT NULL DEFAULT '',
    shared_event_id TEXT NOT NULL DEFAULT '',
    create_time INTEGER NOT NULL DEFAULT 0,
    last_edit_time INTEGER NOT NULL DEFAULT 0,
    start_time INTEGER NOT NULL DEFAULT 0,
    end_time INTEGER NOT NULL DEFAULT 0,
    start_timezone TEXT NOT NULL DEFAULT '',
    end_timezone TEXT NOT NULL DEFAULT '',
    full_day INTEGER NOT NULL DEFAULT 0,
    author TEXT NOT NULL DEFAULT '',
    permissions INTEGER NOT NULL DEFAULT 0,
    attendees_json TEXT NOT NULL DEFAULT '[]',
    shared_key_packet TEXT NOT NULL DEFAULT '',
    calendar_key_packet TEXT NOT NULL DEFAULT '',
    shared_events_json TEXT NOT NULL DEFAULT '[]',
    calendar_events_json TEXT NOT NULL DEFAULT '[]',
    attendees_events_json TEXT NOT NULL DEFAULT '[]',
    personal_events_json TEXT NOT NULL DEFAULT '[]',
    raw_json TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL,
    FOREIGN KEY (calendar_id) REFERENCES pim_calendars(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_pim_calendar_events_calendar_time
    ON pim_calendar_events(calendar_id, start_time, end_time);
CREATE INDEX IF NOT EXISTS idx_pim_calendar_events_uid
    ON pim_calendar_events(uid);
CREATE INDEX IF NOT EXISTS idx_pim_calendar_events_edit_time
    ON pim_calendar_events(last_edit_time DESC);
```

### Sync state

```sql
CREATE TABLE IF NOT EXISTS pim_sync_state (
    scope TEXT PRIMARY KEY,
    value_text TEXT NOT NULL DEFAULT '',
    value_int INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);
```

Reserved scopes:

- `contacts.core_event_id`
- `contacts.last_full_sync_ms`
- `calendar.last_full_sync_ms`
- `calendar.active_list_hash`
- `calendar.<calendar_id>.model_event_id`

This generic KV avoids schema churn for cursor evolution.

## Cursor and Checkpoint Model

Use two levels:

1. Core account event cursor (already persisted by event worker).
2. Per-calendar model-event cursor in `pim_sync_state`.

Rules:

- Core cursor advances only after mail + PIM event handling completes.
- Per-calendar model-event cursor advances only after affected rows commit.
- On partial failures:
  - do not advance failed cursor
  - keep checkpoint unchanged for replay safety

## Sync Flows

### 1) Bootstrap sync

#### Contacts bootstrap

1. Page through `/contacts/v4` (`Page`, `PageSize`).
2. For each contact ID, fetch full record via `/contacts/v4/{id}`.
3. Upsert `pim_contacts`, replace child cards/emails in one transaction per contact.
4. Mark missing contacts as deleted after full scan comparison.
5. Store `contacts.last_full_sync_ms`.

#### Calendar bootstrap

1. Fetch calendars via `/calendar/v1`; upsert into `pim_calendars`.
2. For each calendar:
  - fetch members, keys, settings and upsert.
  - fetch `modelevents/latest`; store baseline cursor.
  - seed event window via `/calendar/v1/{calendar_id}/events` (configurable lookback/lookahead, default: -180d/+365d).
3. Mark removed calendars/events as deleted after reconciliation.
4. Store `calendar.last_full_sync_ms`.

### 2) Incremental sync

#### From core events stream

Use typed payload fields already parsed:

- `Contacts`
- `ContactEmails`
- `Calendars`
- `CalendarMembers`

Handling:

- Contact create/update:
  - `GET /contacts/v4/{id}` then upsert full contact graph.
- Contact delete:
  - soft delete contact row and cascade delete children.
- Contact email change:
  - if `ContactID` available from payload extra, refresh that contact.
  - otherwise schedule short delayed reconciliation pass (`contacts mini-resync`).
- Calendar/calendar-member change:
  - refresh calendar metadata (calendar, members, keys, settings).

#### Calendar event-level changes (model-events)

Core events do not reliably carry all event-level mutations. Model-events are authoritative.

Loop per active calendar:

1. load cursor `calendar.<id>.model_event_id`.
2. call `/calendar/v1/{id}/modelevents/{cursor}`.
3. parse buckets and apply by action:
  - event create/update: fetch event details and upsert.
  - event delete: mark event deleted.
  - key/member/settings updates: refresh corresponding resources.
4. update cursor to response `CalendarModelEventID`.
5. repeat while server indicates more changes (if applicable by API behavior), else stop.

### 3) Periodic reconciliation

Run low-frequency safety jobs:

- Contacts full reconciliation every 24h.
- Calendar metadata reconciliation every 24h.
- Calendar event horizon refresh every 12h.

Purpose:

- recover from missed deltas
- correct edge cases around event payload incompleteness

## Transaction Boundaries

For correctness and replay safety:

- One SQL transaction per logical unit:
  - one contact graph upsert
  - one calendar event apply
  - one metadata refresh set
- Cursor update in same transaction as corresponding data mutation.
- Core event cursor checkpoint commit after all mutations in batch succeed.

## Deletion Policy

Use soft delete flags (`deleted=1`) first, with periodic hard-prune.

Prune job:

- contacts/events deleted older than configurable TTL (default 30 days).
- keeps short rollback/debug window.

## Module/File Plan

### New modules

- `src/pim/mod.rs`
- `src/pim/store.rs`
- `src/pim/schema.rs`
- `src/pim/sync.rs`
- `src/pim/types.rs`

### Integration changes

- `src/bridge/mail_runtime.rs`
  - initialize `PimStore` alongside `MessageStore`
  - pass into event worker config
- `src/bridge/events.rs`
  - extend delta handling pipeline with PIM sync hooks
  - ensure checkpoint commit order includes PIM success
- `src/lib.rs` and `src/main.rs`
  - module wiring/config flags

## Config and Tuning

Add settings with safe defaults:

- `pim.contacts_page_size` default `100`
- `pim.bootstrap_event_lookback_days` default `180`
- `pim.bootstrap_event_lookahead_days` default `365`
- `pim.reconcile_contacts_interval_sec` default `86400`
- `pim.reconcile_calendar_interval_sec` default `86400`
- `pim.max_calendar_model_pages_per_poll` default `10`

## Observability

Metrics/logs per account:

- cache row counts by table
- bootstrap duration and item counts
- incremental apply latency
- cursor lag:
  - core event lag
  - per-calendar model-event lag
- reconciliation result counts
- error rate by endpoint and operation

Add structured log fields:

- `account_id`
- `calendar_id` (when relevant)
- `cursor_before`, `cursor_after`
- `upsert_count`, `delete_count`

## Error Handling and Recovery

- Retry transient API errors with bounded backoff.
- On persistent per-calendar model-event failures:
  - freeze that calendar cursor
  - continue others
  - emit degraded-state health signal
- On DB corruption:
  - recreate PIM tables only (not mail index table)
  - run full bootstrap for PIM domain
- On invalid cursor:
  - reset specific domain cursor
  - run bounded reconciliation

## Testing Strategy

### Unit tests

- schema migration idempotency
- upsert and delete semantics
- cursor read/write behavior
- transaction rollback on injected errors

### Integration tests (wiremock)

- contacts bootstrap pagination + restart continuity
- calendar bootstrap with multiple calendars
- model-events create/update/delete event application
- core-event + model-event combined flow
- stale cursor reset and recovery
- partial failure replay safety (checkpoint not advanced)

### Regression tests

- ensure mail cache behavior unchanged
- startup/shutdown with mixed mail+PIM sync load

## Delivery Plan

### Milestone 1: Storage foundation

- Implement schema/migrations and `PimStore`.
- Add CRUD unit tests for all tables.

### Milestone 2: Bootstrap sync

- Contacts + calendar bootstrap.
- Persist cursors and row-count verification.

### Milestone 3: Incremental sync

- Core event-driven contact/calendar metadata updates.
- Per-calendar model-event event sync.

### Milestone 4: Recovery and reconciliation

- periodic reconciliation jobs
- cursor reset paths
- degraded-state reporting

### Milestone 5: Hardening

- performance tuning
- backpressure controls
- operational dashboards/log checks

## Acceptance Criteria

- Restart continuity: no duplicate IDs or missing rows after restart.
- Eventual consistency: cache converges after transient failures.
- Core cursor safety: no cursor advance on failed PIM apply.
- Model-event safety: per-calendar cursor advances atomically with data writes.
- Performance target: incremental poll applies under 2s for typical small batches.

## Open Questions

- Exact retention window for soft-deleted rows.
- Preferred bootstrap event horizon defaults per product expectations.
- Whether to expose PIM cache via gRPC before DAV layer.
- Whether to add a dedicated `pim_state` status in account health summary.
