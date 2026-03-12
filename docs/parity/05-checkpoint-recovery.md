# Checkpoint and Recovery Parity

## Scope

This document compares event checkpoint persistence and recovery behavior.

Primary files:

- `src/bridge/types.rs`
- `src/bridge/events.rs`
- `src/vault.rs`
- `../proton-bridge/internal/services/imapservice/sync_state_provider.go`
- `../proton-bridge/internal/bridge/user_events.go`

## Current findings

### Implemented Gluon recovery/corruption behaviors

Observed:

- Startup replays pending Gluon transaction journals before loading account state.
- Unrecoverable pending journal artifacts fail startup with a `GluonCorruption` error rooted at `.gluon-txn`.
- Missing blob references are repaired deterministically by pruning stale UID/blob mappings, persisting the repaired sqlite index, and bumping `uid_validity` so IMAP clients drop stale caches.
- Readable but partial sqlite state falls back to blob discovery instead of surfacing mixed partial metadata.
- Cache moves with unresolved staged transaction paths fail until the original root is restored and recovery can complete against the staged paths.

Primary regression coverage:

- `tests/gluon_recovery_integration.rs`
- `tests/gluon_corruption.rs`
- `tests/gluon_store_read.rs`

### 1) Checkpoint model differs from upstream sync-state model (medium)

Observed:

- OpenProton persists `EventCheckpoint { last_event_id, last_event_ts, sync_state }` (vault/file/in-memory backends).
- Upstream sync provider persists richer sync status fields (labels/messages/message count/failed IDs).

Risk:

- Recovery diagnostics and partially-failed message tracking may differ.

Validation tasks:

- Map required operator-visible recovery signals and ensure OpenProton exposes equivalents.

### 2) Cursor-reset recovery path is implemented and test-covered (low)

Observed:

- OpenProton handles stale cursor errors by bounded resync + baseline reset, persisting `sync_state = cursor_reset_resync`.
- Tests in `src/bridge/events.rs` already assert this path.

Risk:

- Low functional risk; parity question is mostly around telemetry/event emission consistency with upstream.

Validation tasks:

- Compare user-facing/runtime event emissions during stale-cursor recovery.

### 3) Sync-state semantics are now typed in OpenProton (resolved)

Observed:

- OpenProton now uses a strict internal enum (`CheckpointSyncState`) for checkpoint state transitions.
- Upstream uses structured status fields and explicit state transitions.

Risk:

- Residual risk is low for state-shape drift; unknown states are now rejected by design.

Validation tasks:

- Keep transition coverage in event worker tests and recovery replay scenarios.

### 4) Startup resync gating appears robust but parity needs scenario replay (low)

Observed:

- OpenProton event worker applies startup resync logic with generation checks and failure backoff.
- Upstream uses user bad-event/deauth handling and resync verification hooks.

Risk:

- Edge differences on restart with mixed account health states.

Validation tasks:

- Multi-account recovery replay with one degraded account and one healthy account.

### 5) Checked-in sanitized sqlite artifacts remain placeholder-only (non-blocking)

Observed:

- The checked-in sanitized fixture intentionally contains placeholder sqlite/deferred-delete artifacts for file-family coverage.
- This is documented in `tests/fixtures/gluon_fixture_manifest.json` and enforced by fixture tests.

Risk:

- The checked-in fixture alone does not prove upstream cache-open parity.
- `BE-029` is covered instead by the private local official-Bridge gate in `tests/gluon_real_fixture.rs`, which opens a real upstream cache outside the repo.

Validation tasks:

- Optionally capture and pin a real sanitized upstream cache set whose sqlite artifacts remain openable by the compatibility store.

## Proposed implementation plan (step 6 execution)

1. Define a normalized checkpoint state machine document and validate all existing `sync_state` writes against it.
2. Add cross-restart fixtures for:
   - empty cursor bootstrap
   - stale cursor reset
   - refresh-triggered resync
   - repeated transient failures
3. Add parity assertions that checkpoint progression is monotonic and restart-safe.
4. Expand recovery/restart fixtures to validate enum-state progression under mixed failure modes.
5. Optionally replace placeholder sanitized sqlite artifacts with a real cache-open fixture set later; this is no longer required to close `BE-029`.

## Acceptance gates for checkpoint/recovery parity

- Restart never regresses cursor to an older committed event.
- Recovery from stale cursor is deterministic and idempotent.
- Sync-state progression is explicit, validated, and documented.
- Multi-account restart isolation is demonstrated in tests.
