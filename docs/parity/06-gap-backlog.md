# Parity Gap Backlog (Ranked)

## Critical

- None currently identified from static comparison.

## High

1. Metadata stale-page handling parity
   - Area: message metadata fetch/resync
   - Status: resolved in current pass (`Stale` modeled and retried until fresh page).
   - Target files: `src/api/types.rs`, `src/api/messages.rs`, `src/bridge/events.rs`

2. Label/unlabel partial-failure semantics
   - Area: mutation atomicity
   - Status: resolved in current pass (chunked per-item validation + rollback via `/mail/v4/undoactions`).
   - Target files: `src/api/messages.rs`, IMAP mutation callers in `src/imap/session.rs`

3. Refresh bitmask semantics audit
   - Area: event loop resync trigger
   - Status: resolved in current pass for mail refresh handling (`RefreshMail` bit semantics).
   - Remaining: broaden fixture coverage for non-mail refresh values.
   - Target files: `src/bridge/events.rs`, `src/api/types.rs`

## Medium

1. `More` pagination cap divergence (`32` vs GPA collection cap `50`)
   - Status: resolved in current pass (event-loop page cap aligned to `50` with regression coverage).
   - Target files: `src/bridge/events.rs`, `docs/parity/02-event-loop-parity.md`
2. IDLE granularity differences (EXISTS-focused vs granular update stream)
   - Status: resolved in current pass (`EXPUNGE`/`FETCH FLAGS`/`EXISTS` diff emission for selected mailbox).
   - Target files: `src/imap/session.rs`, `docs/parity/04-imap-sync-propagation.md`
3. Label topology conflict-resolution path differences
   - Status: resolved in current pass (label rename/delete reconciliation + collision-safe label mailbox naming).
   - Target files: `src/bridge/events.rs`, `src/imap/mailbox.rs`, `docs/parity/04-imap-sync-propagation.md`
4. Checkpoint state representation as free-form strings
5. Large batch mutation chunking behavior
   - Status: resolved in current pass (`150` chunking across label/unlabel/read/unread/delete + parallel delete chunks).
   - Target files: `src/api/messages.rs`, `docs/parity/03-message-mutation-parity.md`

## Low

1. Transient retry strategy differences in event fetch path
2. Recovery telemetry/event-emission shape differences (intentional runtime-model divergence)

## Suggested execution order

1. High-1 (`Stale` handling)
2. High-2 (label/unlabel partial failure)
3. High-3 (refresh bit semantics)
4. Medium-1 (`More` cap and backlog convergence)
5. Medium-2 (IDLE granularity parity)
6. Remaining medium/low items
