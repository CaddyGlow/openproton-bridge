# Multi-User + Split-Address + Event-Stream Plan

## Goal
Implement true multi-account support in one daemon process, including:
1. Split-address mode (authenticate per address, not only primary account email).
2. Incremental event-stream sync (near-real-time updates without full re-fetch loops).
3. Isolation between accounts so deauth/failures in one account do not break others.

## Current Implementation Status (2026-02-28)
Completed:
1. Multi-account vault + CLI account targeting/default selection.
2. Runtime account registry + split-address IMAP/SMTP auth routing.
3. Account-scoped IMAP store keys and isolation tests.
4. Per-account event workers with checkpoint persistence, bounded refresh resync, and address-index refresh.
5. IMAP change visibility via `NOOP` and baseline `IDLE`.
6. Per-account health transitions, failure classification, retry backoff/jitter, and structured worker observability counters.
7. Graceful worker group shutdown/join and restart continuity tests using vault-backed checkpoints.
8. Phase 8 parity hardening pass: corrected Proton numeric event-action mapping (`delete=0`) and added fallback parsing for parent-scoped `Message` payloads.
9. Phase 8 parser compatibility pass: added support for scalar/null map-style `Messages` entries (including null-as-delete handling).
10. Phase 8 performance hardening pass: added bounded deterministic startup poll staggering per account to avoid event worker thundering-herd bursts.
11. Phase 8 label parity pass: label events now trigger bounded account resync with checkpoint state `label_resync`.
12. Performance pass: system mailbox definitions are now static to eliminate repeated allocation in IMAP/session/event paths.
13. Phase 8 parser compatibility pass: scalar `Messages` arrays now parse with parent `Action` fallback (including delete handling).
14. Performance tuning pass: widened deterministic startup poll staggering (2s cap) and added high-account spread guard tests.
15. Test hardening pass: restart continuity assertions now wait for checkpoint conditions, avoiding fixed-sleep flakiness under staggered startup.

Remaining:
1. Phase 8 hardening/parity gaps discovered in real-world event payloads.
2. High-account-count profiling/benchmarking to tune poll cadence and bounded resync behavior with measured data.

This plan follows architecture patterns used in `../proton-bridge` and auth/session behavior from `../go-proton-api`, adapted to this Rust codebase.

## Why This Is a Full Refactor
Current runtime is single-account in critical paths:
1. Protocol auth compares against one preloaded session email/password in `imap::SessionConfig` and `smtp::SmtpSessionConfig`.
2. `serve` loads only one session and prints only one credential pair.
3. IMAP in-memory store is mailbox-scoped, not account-scoped.
4. Token refresh is CLI-startup-centric, not per-account runtime managed.

Split-address + events cannot be safely layered on top of this shape without first adding a per-account runtime coordinator.

## Scope
In scope:
1. Multi-account vault semantics and CLI account targeting.
2. Runtime account registry with per-account token lifecycle.
3. Split-address auth routing for IMAP and SMTP.
4. Store namespacing by account (and address where needed).
5. Event polling, checkpointing, incremental application, and recovery.
6. End-to-end tests with two accounts active simultaneously.

Out of scope for this wave:
1. GUI workflows.
2. Persistent SQL store migration (keep in-memory unless separate task is opened).
3. Full parity with every official bridge event type on first pass.

## Target Architecture

### 1. Durable State (vault)
Add explicit multi-account operations and metadata:
1. `list_sessions() -> Vec<Session>`
2. `load_session_by_email(email)`
3. `save_session(session)` upsert by normalized email
4. `remove_session_by_email(email)`
5. `set_default_email(email)` / `get_default_email()`
6. Per-account sync checkpoint fields:
   `last_event_id`, `last_event_ts`, `sync_state`
7. Optional per-account mode field:
   `address_mode: Combined | Split`

### 2. Runtime State (new bridge coordinator)
Create `src/bridge/accounts.rs` with:
1. `AccountRegistry` (`HashMap<AccountId, AccountState>`) protected by `RwLock`.
2. `AccountState`:
   `session`, `bridge_password`, `primary_email`, `address_index`,
   `refresh_lock`, `event_handle`, `health_state`.
3. Fast lookup indexes:
   `email -> account_id`,
   `address_email -> (account_id, address_id)`.

### 3. Auth Router
Replace fixed config checks with dynamic resolution:
1. IMAP `LOGIN user pass`:
   resolve `user` via address index,
   constant-time compare with matched account bridge password,
   attach session context `(account_id, address_id?)`.
2. SMTP `AUTH PLAIN`:
   same resolution and password verification,
   maintain `(account_id, auth_address_id)` for sender validation and send path.
3. Preserve current security constraints:
   constant-time password compare,
   no account existence leaks in error text.

### 4. Store Partitioning
Make cache keys account-aware:
1. IMAP store key changes:
   from `mailbox` to `(account_id, mailbox)` (and optionally `address_id` namespace for split mode behavior).
2. UID mappings and RFC822 caches become account-scoped.
3. Prevent cross-account collisions for label names (`INBOX`, `Sent`, etc.).

### 5. Event Engine
Add `src/bridge/events.rs` with per-account worker:
1. Poll events endpoint using account tokens.
2. Persist checkpoint (`last_event_id`) after successful apply batch.
3. Apply handlers:
   message created/updated/deleted,
   label updates,
   unread/flag changes,
   address changes (for split routing refresh).
4. Gap recovery strategy:
   if checkpoint invalid/stale, schedule bounded resync for that account only.
5. Backoff policy with jitter per account.

### 6. Deauth/Refresh Behavior
Per-account lifecycle, inspired by `go-proton-api` client semantics:
1. On 401/expired token, refresh once under account refresh lock.
2. Persist rotated tokens immediately.
3. Retry original API call once.
4. If refresh fails with deauth class errors, mark only that account unavailable and continue serving others.

## Phased Execution Plan

## Phase 0: Contracts + Skeleton
Deliverables:
1. Add `bridge` modules:
   `accounts.rs`, `auth_router.rs`, `events.rs`, `types.rs`.
2. Define traits:
   `SessionProvider`, `AccountResolver`, `EventCheckpointStore`.
3. Wire from `main.rs` without behavior change yet.

Exit criteria:
1. Build passes.
2. No protocol behavior changes.

## Phase 1: Vault Multi-Account Semantics
Deliverables:
1. Implement vault APIs listed above.
2. Add default account persistence and migration:
   if existing single-user vault, set that user as default.
3. Add targeted removal and keep `remove_session` as full wipe.

Tests:
1. Save two sessions, list both, load by email.
2. Remove one session keeps other intact.
3. Default account reads/writes correctly.
4. Backward compatibility with current vault format.

Exit criteria:
1. `cargo test` passes vault suite.

## Phase 2: CLI Multi-Account Commands
Deliverables:
1. `login` upserts account instead of global overwrite.
2. `status` lists all accounts and marks default.
3. `logout --email <addr>` removes one.
4. `logout --all` wipes vault.
5. Add `accounts list` and `accounts use <email>`.

Tests:
1. CLI parser tests for new flags/commands.
2. Functional tests against temp vault directory.

Exit criteria:
1. Multi-account management works before server changes.

## Phase 3: Runtime Account Registry
Deliverables:
1. Load all vault accounts at `serve` startup.
2. Build lookup indexes for primary and enabled addresses.
3. Add per-account refresh lock and helper `with_valid_access_token(account_id)`.

Tests:
1. Registry resolves by primary and alias addresses.
2. Concurrent refresh attempts collapse to one refresh call per account.

Exit criteria:
1. `serve` starts with 2+ accounts loaded in memory.

## Phase 4: IMAP/SMTP Split-Address Auth Routing
Deliverables:
1. Refactor IMAP session to resolve account at LOGIN time.
2. Refactor SMTP AUTH PLAIN similarly.
3. Attach authenticated account context to session state.
4. Validate MAIL FROM against authenticated account addresses only.

Tests:
1. Two accounts, same server port, both can auth concurrently.
2. Wrong password for valid address fails.
3. Valid password but wrong account address fails.
4. Alias address auth succeeds in split mode.

Exit criteria:
1. No single fixed `SessionConfig.session` dependency in auth path.

## Phase 5: Account-Scoped Store
Deliverables:
1. Add `account_id` to store APIs and data keys.
2. Update IMAP select/fetch/store flows accordingly.
3. Ensure UID validity is account-local.

Tests:
1. Same mailbox names across two accounts do not cross-read.
2. Metadata and cached bodies remain isolated.

Exit criteria:
1. Isolation regression tests pass.

## Phase 6: Event-Stream Sync Engine
Deliverables:
1. Start one event worker per active account on `serve`.
2. Persist checkpoint after successful apply.
3. Apply message and label deltas into account-scoped store.
4. Rebuild address index on address-change events.
5. Emit IMAP notifications for changed mailboxes (initially via NOOP-visible state change; IDLE push can follow).

Tests:
1. Event apply unit tests per type.
2. Checkpoint persistence/restart continuity tests.
3. Gap-recovery test path falls back to bounded resync.

Exit criteria:
1. New messages and flag changes appear without full mailbox refetch.

## Phase 7: Robustness + Observability
Deliverables:
1. Per-account health state and structured logs with `account_id`.
2. Error classification:
   transient, refreshable auth, deauth.
3. Restart-safe worker lifecycle (`start/stop/join`).

Tests:
1. One account deauths while second continues serving.
2. Worker restart after transient network failure.

Exit criteria:
1. Failure isolation confirmed.

## Phase 8: Hardening and Parity Gaps
Deliverables:
1. Fill unsupported event types discovered during testing.
2. Performance pass for high mailbox counts.
3. Documentation updates (`README`, command examples).

Exit criteria:
1. Stable two-account manual run with split addresses and live sync.

## File-Level Change Plan
Primary files to modify:
1. `src/vault.rs`
2. `src/main.rs`
3. `src/imap/session.rs`
4. `src/smtp/session.rs`
5. `src/imap/store.rs`
6. `src/bridge/mod.rs` and new `src/bridge/*.rs`
7. `src/api/auth.rs` (refresh helpers, error classification if needed)
8. `tests/*` new integration coverage

## Test Matrix
Minimum matrix before merge:
1. Single-account regression:
   login, serve, IMAP login, SMTP send.
2. Multi-account combined mode:
   two primaries authenticate and fetch/send independently.
3. Split-address mode:
   alias auth and MAIL FROM validation.
4. Event updates:
   message create/update/delete reflected in store.
5. Deauth isolation:
   one account invalidated, second remains functional.
6. Restart continuity:
   checkpoint resumes from last processed event.

## Risks and Mitigations
1. Risk: race conditions during token refresh.
   Mitigation: per-account mutex and refresh deduplication.
2. Risk: stale address indexes after alias changes.
   Mitigation: full index rebuild on relevant event classes.
3. Risk: event gaps or out-of-order delivery.
   Mitigation: checkpoint validation + bounded resync path.
4. Risk: accidental cross-account cache reads.
   Mitigation: account id required in store API signature.
5. Risk: regressions in legacy single-user flow.
   Mitigation: keep regression tests and default-account compatibility behavior.

## Merge Strategy
Use small, reviewable commits:
1. `feat(vault): multi-account session operations + default account`
2. `feat(cli): account selection and management commands`
3. `feat(bridge): account registry and token lifecycle`
4. `refactor(imap): account-resolved login and account-scoped state`
5. `refactor(smtp): account-resolved auth and sender routing`
6. `feat(imap): account-scoped store keys`
7. `feat(sync): per-account event worker + checkpoints`
8. `test: multi-account split-address and event-stream integration suite`

## Definition of Done
1. Two Proton accounts can stay logged in simultaneously.
2. IMAP/SMTP auth works for primary and allowed alias addresses in split mode.
3. Incremental events update state without full mailbox refresh loops.
4. Token refresh and deauth are isolated per account.
5. Existing single-account users can upgrade without manual vault migration.
6. `cargo test`, `cargo fmt --check`, and clippy pass.
