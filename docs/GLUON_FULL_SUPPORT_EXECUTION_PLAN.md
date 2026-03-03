# Gluon Full Support Execution Plan (Hard Cut, No Migration)

Updated: 2026-03-03

## Scope
- Objective: implement full support for Proton Bridge Gluon on-disk data files as the production IMAP cache backend.
- Constraint: no migration from current openproton JSON cache format.
- Constraint: no dual-format runtime compatibility mode.
- Source of truth: `proton-bridge` behavior and the pinned `github.com/ProtonMail/gluon` version used by upstream.

## Non-Goals
- No JSON-cache importer.
- No fallback to the current `PersistentStore` JSON format in production.
- No temporary shim layer that rewrites Gluon files into internal JSON.

## Definition Of Done
- Existing Proton-style profile data with Gluon artifacts is loaded directly.
- Read/write/update/delete flows operate against Gluon files with restart continuity.
- Locking, atomicity, and corruption behavior match upstream expectations.
- gRPC and CLI flows continue to work with unchanged external contract.
- CI has mandatory Gluon parity tests and recovery tests.

## BE-016 Frozen Gluon Compatibility Target
- Machine-readable target: `tests/fixtures/gluon_compatibility_target.json`.
- Freeze date: `2026-03-03`.
- Pinned upstream reference (`proton-bridge`): `92305960372cbe7a7e7acf3debb3c19c5e82bfb1` (`master`).
- Pinned upstream Gluon commit required by upstream `go.mod`: `2046c95ca7455812254eaef2f77da0aaaee3fae1` (`github.com/ProtonMail/gluon v0.17.1-0.20260112123503-2046c95ca745`).

### Required File Families
- `gluon_message_store_files`: `<gluon_cache_root>/backend/store/<gluon_user_id>/<internal_message_id>`.
- `gluon_sqlite_primary_db`: `<gluon_cache_root>/backend/db/<gluon_user_id>.db`.
- `gluon_sqlite_wal_sidecars`: `<gluon_cache_root>/backend/db/<gluon_user_id>.db-wal` and `.db-shm`.
- `gluon_deferred_delete_pool`: `<gluon_cache_root>/backend/db/deferred_delete/*`.
- `imap_sync_state_files`: `<settings_root>/sync-<user_id>` and `.tmp` sidecar.

### Compatibility Matrix (Frozen)
| Family | OpenProton Target | Status | Notes |
| --- | --- | --- | --- |
| `gluon_message_store_files` | Required (Read/Write/Delete) | Planned | No JSON projection/migration allowed in hard-cut mode. |
| `gluon_sqlite_primary_db` | Required (Read/Write) | Planned | Open per-user sqlite metadata DB directly. |
| `gluon_sqlite_wal_sidecars` | Required (Read/Write/Recovery) | Planned | WAL files are mandatory due to `journal_mode=WAL`. |
| `gluon_deferred_delete_pool` | Required (Delete/Recovery) | Planned | Preserve deferred-delete semantics for locked sqlite files. |
| `imap_sync_state_files` | Required (Startup/Recovery) | Planned | Preserve sync resume and bad-event recovery behavior. |

## Ticket Backlog (Test-First)

1. `BE-016` Freeze Gluon compatibility target.
- Deliverables: pinned upstream commit hashes, explicit list of required Gluon file families, and compatibility matrix.
- Files: `docs/GLUON_FULL_SUPPORT_EXECUTION_PLAN.md`, `docs/BACKEND_PARITY_LEDGER.md`.
- Tests first: add a failing compatibility assertion test that checks pinned version metadata.
- Depends on: none.

2. `BE-017` Build fixture capture tooling.
- Deliverables: script to generate sanitized Proton profile fixtures with Gluon data.
- Files: `scripts/` (new fixture tool), `tests/fixtures/` manifest.
- Tests first: fixture manifest validator test fails when required files are missing.
- Depends on: `BE-016`.

3. `BE-018` Add fixture manifest and invariants.
- Deliverables: machine-readable fixture manifest with mailbox/user invariants.
- Files: `tests/fixtures/gluon_manifest.*`, `tests/`.
- Tests first: failing invariant-check test over sample fixture.
- Depends on: `BE-017`.

4. `BE-019` Implement Gluon path resolver and account-scoped layout.
- Deliverables: canonical Gluon storage path resolver wired to runtime paths + account scope.
- Files: `src/paths.rs`, `src/main.rs`, `src/frontend/grpc/mod.rs`.
- Tests first: path-resolution tests for Linux/macOS/Windows-style roots.
- Depends on: `BE-016`.

5. `BE-020` Implement Gluon key/ID binding layer.
- Deliverables: reliable use of `GluonKey`, `GluonIDs`, `GluonDir` vault fields in store bootstrap.
- Files: `src/vault.rs`, `src/main.rs`, `src/frontend/grpc/mod.rs`.
- Tests first: failing tests for missing/invalid key and mismatched ID bindings.
- Depends on: `BE-016`.

6. `BE-021` Implement low-level Gluon file codec module.
- Deliverables: parser/writer for all required Gluon file families discovered in `BE-016`.
- Files: `src/imap/gluon_codec.rs` (new), `src/imap/mod.rs`.
- Tests first: fixture decode tests fail on unsupported family.
- Depends on: `BE-016`, `BE-018`.

7. `BE-022` Implement Gluon lock manager and single-writer guarantees.
- Deliverables: advisory/process lock semantics equivalent to target behavior.
- Files: `src/imap/gluon_lock.rs` (new), `src/imap/`.
- Tests first: concurrent writer tests must fail before lock implementation.
- Depends on: `BE-021`.

8. `BE-023` Implement atomic commit and recovery journal semantics.
- Deliverables: temp-file + commit marker + recovery-on-start behavior for interrupted writes.
- Files: `src/imap/gluon_txn.rs` (new), `src/imap/`.
- Tests first: crash-injection tests for half-written operations.
- Depends on: `BE-021`, `BE-022`.

9. `BE-024` Implement `GluonStore` read path under `MessageStore`.
- Deliverables: mailbox load, UID maps, metadata, flags, and RFC822 reads.
- Files: `src/imap/store.rs`, `src/imap/`.
- Tests first: golden read tests from captured fixtures.
- Depends on: `BE-021`.

10. `BE-025` Implement `GluonStore` mutation path under `MessageStore`.
- Deliverables: insert/update/delete, UID assignment continuity, flag mutation.
- Files: `src/imap/store.rs`, `src/imap/session.rs`.
- Tests first: mutation parity tests against fixture expectations.
- Depends on: `BE-023`, `BE-024`.

11. `BE-026` Cut runtime over to Gluon backend only.
- Deliverables: production wiring uses `GluonStore`; JSON backend no longer used in runtime path.
- Files: `src/main.rs`, `src/frontend/grpc/mod.rs`, `src/imap/store.rs`.
- Tests first: failing integration test that asserts Gluon files are produced/updated in runtime.
- Depends on: `BE-024`, `BE-025`.

12. `BE-027` Align disk-cache move flow with Gluon store semantics.
- Deliverables: move/switch/cleanup works with live Gluon files and restart continuity.
- Files: `src/frontend/grpc/rpc.rs`, `src/frontend/grpc/mod.rs`, `src/main.rs`.
- Tests first: existing disk-cache tests adapted to assert Gluon artifacts.
- Depends on: `BE-026`.

13. `BE-028` Remove production JSON store paths and dead code.
- Deliverables: remove legacy runtime references to JSON `PersistentStore`; keep test utilities only if needed.
- Files: `src/imap/store.rs`, `src/main.rs`, `src/frontend/grpc/mod.rs`.
- Tests first: compile-fail or lint gate proving no production call sites remain.
- Depends on: `BE-026`.

14. `BE-029` Add corruption detection and deterministic repair behavior.
- Deliverables: explicit handling for corrupt/missing Gluon artifacts with expected errors/events.
- Files: `src/imap/`, `src/frontend/grpc/service.rs`.
- Tests first: corruption fixtures must fail with expected typed error path.
- Depends on: `BE-023`, `BE-026`.

15. `BE-030` Add multi-account isolation and contention parity tests.
- Deliverables: prove no cross-account data leakage and lock contention isolation.
- Files: `tests/`, `src/bridge/accounts.rs`, `src/imap/`.
- Tests first: two-account conflict tests fail before isolation fixes.
- Depends on: `BE-026`.

16. `BE-031` Add full Gluon parity integration suite.
- Deliverables: end-to-end startup, sync, restart, delete, cache-move, and event parity tests.
- Files: `tests/`, `src/frontend/grpc/mod.rs`.
- Tests first: red suite scaffold in CI.
- Depends on: `BE-027`, `BE-029`, `BE-030`.

17. `BE-032` Add CI gate for Gluon parity + recovery suite.
- Deliverables: mandatory CI job; merge blocked on suite failure.
- Files: CI workflow files, test docs.
- Tests first: pipeline check expects missing job and fails.
- Depends on: `BE-031`.

18. `BE-033` Deployment and rollback runbook (format hard cut).
- Deliverables: operator docs for release, known limitations, and rollback procedure (binary rollback only; no data migration support).
- Files: `README.md`, `docs/`.
- Tests first: n/a (documentation ticket).
- Depends on: `BE-032`.

## Multi-Agent Parallel Distribution

## Lane A: Spec + Fixtures
- Tickets: `BE-016`, `BE-017`, `BE-018`.
- Ownership: `docs/`, fixture scripts, fixture manifests.
- Notes: unblocks all codec work; prioritize completion first.

## Lane B: Core Gluon Codec
- Tickets: `BE-021`.
- Ownership: `src/imap/gluon_codec.rs`, codec tests.
- Depends on: Lane A outputs.

## Lane C: Concurrency + Atomicity
- Tickets: `BE-022`, `BE-023`.
- Ownership: `src/imap/gluon_lock.rs`, `src/imap/gluon_txn.rs`, recovery tests.
- Depends on: `BE-021`.

## Lane D: Runtime Integration
- Tickets: `BE-019`, `BE-020`, `BE-024`, `BE-025`, `BE-026`, `BE-027`, `BE-028`.
- Ownership: `src/main.rs`, `src/vault.rs`, `src/frontend/grpc/*`, `src/imap/store.rs`, `src/imap/session.rs`.
- Depends on: Lane A for paths/keys and Lane B/C for storage internals.

## Lane E: Parity + CI
- Tickets: `BE-029`, `BE-030`, `BE-031`, `BE-032`, `BE-033`.
- Ownership: `tests/`, CI workflow, operator docs.
- Depends on: Lane D runtime cutover.

## Main Agent Operating Instructions

1. Create branch and enforce ownership boundaries.
- Assign each lane explicit file ownership and forbid cross-lane edits except by main agent.

2. Spawn workers in parallel after seed tasks.
- Start Lane A immediately.
- Start Lane D partial work (`BE-019`, `BE-020`) in parallel with Lane A.
- Start Lane B only after fixture manifest is available.
- Start Lane C after Lane B first green commit.
- Start Lane E test scaffolding early, then finalize after Lane D cutover.

3. Enforce ticket protocol per lane.
- Every ticket must follow `Red -> Green -> Refactor`.
- Reject worker handoff without failing test first and passing test after.

4. Integrate in strict merge order.
- Merge order: A -> B -> C -> D -> E.
- Rebase workers daily on latest integrated mainline.
- Main agent resolves conflicts; workers do not touch foreign-lane files.

5. Continuous verification gates.
- After each merged ticket, run targeted tests for changed modules.
- After each lane completion, run full parity suite.
- Before release candidate, run full CI including stress/recovery scenarios.

6. Cutover and deploy.
- Deploy only after `BE-032` gate is green.
- Publish release notes with explicit hard-cut statement: no JSON-cache compatibility/migration.
- Keep previous binary available for rollback.

## Main Agent Tasking Template (for worker kickoff)

Use this message template when assigning a ticket:

```text
You own ticket <BE-XXX>.
Scope: <one paragraph>.
Owned files: <explicit file list>.
Non-owned files: do not edit.
Required workflow: Red -> Green -> Refactor.
Deliverables:
1) failing test commit
2) implementation commit
3) optional refactor commit
Verification: run <exact test commands>.
Handoff: include risks, assumptions, and any follow-up needed by main agent.
```

## Risks And Controls
- Risk: partial format support causes silent data divergence.
- Control: fixture manifest + golden parity tests must cover every required file family from `BE-016`.
- Risk: concurrency regressions under multi-account load.
- Control: lock contention tests and stress suite in `BE-030`/`BE-031`.
- Risk: deployment confusion due to hard cut.
- Control: explicit release note + runbook language in `BE-033`.
