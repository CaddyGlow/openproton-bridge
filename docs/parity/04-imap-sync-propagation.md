# IMAP Sync Propagation Parity

## Scope

This document compares how upstream API events propagate into IMAP-visible state in OpenProton versus upstream `proton-bridge`.

Primary files:

- `src/bridge/events.rs`
- `src/imap/store.rs`
- `src/imap/session.rs`
- `../proton-bridge/internal/services/imapservice/service_message_events.go`
- `../proton-bridge/internal/services/imapservice/service_sync_events.go`
- `../proton-bridge/internal/services/imapservice/service_label_events.go`

## Implementation status (2026-03-10)

- Done: IDLE/NOOP selected-mailbox updates now emit granular deltas from snapshot diffs:
  - `EXPUNGE` for removed sequence positions
  - `FETCH (FLAGS (...))` for flag-only changes
  - `EXISTS` when message count changes
- Done: label-topology reconciliation on label-change events:
  - rename/path changes migrate mailbox state by label ID
  - deleted labels clear stale mailbox state
  - user-label naming is now conflict-safe (case-insensitive dedupe)
- Done: regressions added:
  - `test_idle_emits_expunge_and_exists_on_delete`
  - `test_idle_emits_flag_fetch_on_flag_only_change`
  - `poll_account_once_label_event_reconciles_renamed_mailbox_state`
  - `poll_account_once_label_event_clears_deleted_mailbox_state`
  - `test_labels_to_mailboxes_deduplicates_case_insensitive_collisions`

## Current findings

### 1) Propagation architecture differs (state-store vs push-update channels) (medium)

Observed:

- OpenProton applies event deltas into `MessageStore` and notifies IMAP sessions via `watch` change sequence + mailbox snapshots.
- Upstream Bridge constructs Gluon `imap.Update` objects and publishes them via connector channels (`publishUpdate`/`waitOnIMAPUpdates`).

Risk:

- Same final state may be reached, but timing/ordering of client-visible updates can differ, especially under concurrent operations.

Validation tasks:

- Record and compare IMAP wire traces for identical event sequences (EXISTS/EXPUNGE/FLAGS timing).

### 2) IDLE update model is now granular (resolved)

Observed:

- OpenProton `cmd_idle` reacts to store changes and emits `EXPUNGE`/`FETCH FLAGS`/`EXISTS` based on selected-mailbox diffs.
- Upstream uses granular Gluon updates for message/flag/mailbox changes.

Risk:

- Residual risk is low and mostly timing/order differences vs upstream channel-driven updates.

Validation tasks:

- Keep parity tests for flag-only/delete/topology-driven transitions during IDLE.

### 3) Update fallback behavior exists in both, but with different mechanics (low)

Observed:

- Upstream explicitly falls back update->create when Gluon reports `NoSuchMessage`.
- OpenProton checks whether message exists in local store and applies create/update semantics through metadata projection.

Risk:

- Mostly equivalent intent, but edge differences may appear when events race with local deletion or label topology changes.

Validation tasks:

- Reproduce race fixtures: update on missing message, delete+update in close sequence, draft/sent transitions.

### 4) Label topology handling differences narrowed (medium, narrowed)

Observed:

- OpenProton refreshes user labels and reconciles mailbox topology state (rename migration + delete cleanup).
- Upstream has dedicated label conflict resolution and mailbox created/updated/deleted update generation.

Risk:

- Remaining differences are mostly execution-model differences (connector update pipeline vs store-reconcile model).

Validation tasks:

- Keep rename/path/delete fixtures and verify IMAP LIST/LSUB/selectability transitions without restart.

### 5) Store durability and change signaling are robust but not parity-proven (low)

Observed:

- OpenProton GluonStore persists index/message blobs transactionally and emits change notifications on mutations.
- Upstream parity expectation is behaviorally equivalent client view, not identical storage internals.

Risk:

- Crash/restart windows could expose divergence in what IDLE/SELECT sees immediately after recovery.

Validation tasks:

- Crash-recovery replay tests with pending event checkpoints and store repairs.

## Proposed implementation plan (step 5 execution)

1. Create event-replay parity tests that inject known event streams and capture IMAP wire outputs.
2. Add focused IDLE coverage for:
   - message create (EXISTS increase)
   - message delete (EXPUNGE visibility)
   - flag-only changes
   - label-to-mailbox reassignment effects
3. Verify selected mailbox `mod_seq` and snapshot progression on each mutation class.
4. Decide whether to add more granular untagged updates during IDLE or document current behavior as intentional.
5. Add comparison report table mapping each event type to observed client-visible IMAP responses.

## Acceptance gates for IMAP propagation parity

- Identical final mailbox state for shared fixtures.
- No missed visibility of create/delete events under IDLE.
- Defined behavior for flag-only and label-topology changes during active sessions.
- Restart recovery preserves consistent SELECT/STATUS/IDLE-visible counts.
