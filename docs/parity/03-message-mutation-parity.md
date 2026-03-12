# Message Mutation Parity (IMAP -> API)

## Scope

This document compares IMAP-triggered remote mutations in OpenProton against `go-proton-api` and upstream `proton-bridge` behavior.

Primary files:

- `src/imap/session.rs`
- `src/api/messages.rs`
- `src/api/types.rs`
- `../go-proton-api/message.go`
- `../go-proton-api/message_types.go`

## Implementation status (2026-03-10)

- Done: metadata page `Stale` parity handling implemented.
  - `MessagesMetadataResponse` now models `Stale`.
  - `get_message_metadata` now retries while `Stale != 0` (upstream-compatible behavior).
- Done: stale-value compatibility widened to bool-like payloads (`0/1`, booleans, numeric strings).
- Done: regressions added:
  - `test_get_message_metadata_retries_while_stale`
  - `test_messages_metadata_response_deserializes_stale_boolish_values`
- Done: label/unlabel partial-failure rollback semantics implemented (GPA-style previous-chunk undo).
- Done: label/unlabel chunking parity implemented (`150` IDs per chunk) with rollback tests.
- Done: broader mutation chunking implemented for read/unread/delete (`150` IDs per chunk).
- Done: delete mutation now executes chunk pages in parallel (bounded by available parallelism) to match GPA throughput model.
- Done: regressions added:
  - `test_mark_messages_read_chunks_large_batches`
  - `test_mark_messages_unread_chunks_large_batches`
  - `test_delete_messages_chunks_large_batches`
- Done: draft/send endpoint contract parity pass completed.
  - `CreateDraftReq.AttachmentKeyPackets` now always serializes (including empty list), matching GPA request shape.
  - Added `UpdateDraftReq` + `update_draft` endpoint wrapper (GPA parity for draft update flow).
  - Added wire-level request-body assertions for `create_draft`, `update_draft`, and `send_draft`.

## Current findings

### 1) Label/unlabel partial failure rollback mismatch (high)

Observed:

- GPA `LabelMessages` / `UnlabelMessages` validates per-message responses and invokes `UndoActions` on partial failure.
- OpenProton now chunks requests (`150` IDs), inspects per-item responses, and calls `/mail/v4/undoactions`
  for prior successful chunks when a later chunk fails.

Risk:

- Residual risk is low; rollback now matches upstream intent for prior successful chunks.

Validation tasks:

- Add wiremock fixtures returning mixed per-item responses for label/unlabel.
- Verify local store and remote outcome alignment in compat and strict modes.

### 2) Metadata page stale handling gap (high)

Observed:

- GPA `GetMessageMetadataPage` loops while response `Stale == true`.
- OpenProton now models `Stale` and retries until a non-stale page is returned.

Risk:

- Residual risk is low and mostly around pathological repeated stale responses.

Validation tasks:

- Add API fixture with `Stale=true` then `Stale=false` for same request.
- Confirm resync path (`src/bridge/events.rs`) retries until non-stale page.

### 3) Chunking and throughput behavior parity (resolved)

Observed:

- GPA chunks most mutation calls by `maxPageSize` (150) and parallelizes delete pages.
- OpenProton now enforces chunking (`150`) for label/unlabel/read/unread/delete, and parallelizes delete chunks.

Risk:

- Residual risk is low and mainly operational (burstier outbound delete requests under large batches).

Validation tasks:

- Keep stress tests for >150 IDs in parity suite.
- Monitor rate-limit behavior under large delete bursts.

### 4) Mutation failures now follow Proton Bridge parity

Observed:

- OpenProton now fails IMAP mutation commands when the upstream Proton mutation fails.
- This matches Proton Bridge command-level mutation behavior.
- Tests exist for failure propagation on `COPY`, `MOVE`, `EXPUNGE`, and `UID EXPUNGE`.

Risk:

- Any future attempt to reintroduce local-success-on-upstream-failure behavior would be a parity regression.

Validation tasks:

- Document command-by-command policy and expected client-visible responses.

### 5) Draft/send endpoint-contract parity (resolved)

Observed:

- OpenProton now has `create_draft`, `update_draft`, and `send_draft` wrappers with GPA-aligned request field shapes.
- Request body tests now validate serialized draft/send payloads against expected API contracts.

Risk:

- Residual risk is low and mostly limited to higher-level package assembly choices in SMTP flow.

Validation tasks:

- Keep fixture coverage for package edge cases (mixed internal/external recipients + attachments).

## Proposed implementation plan (step 4 execution)

1. Extend `src/api/types.rs` and `src/api/messages.rs` to model and handle `Stale` for metadata page calls.
2. Add robust result validation for label/unlabel responses; decide whether to implement undo semantics directly or document intentional non-rollback.
3. Introduce chunk helpers for message ID mutations (or enforce at call-sites) and test with >150 IDs.
4. Add targeted tests under `src/api/messages.rs` and `tests/parity/` for:
   - partial label/unlabel failures
   - stale metadata pages
   - large mutation batches
5. Keep docs and fixture matrix in sync with any future mutation-contract changes.

## Acceptance gates for message mutation parity

- No stale metadata accepted without retry.
- Label/unlabel behavior is either rollback-safe or explicitly documented as intentional non-atomic behavior.
- Large batch mutation behavior is deterministic and tested.
- IMAP command responses under strict/compat modes are fully specified and covered.
