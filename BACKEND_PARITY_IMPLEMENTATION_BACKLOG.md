# Backend Parity Plan And Concrete Backlog (No Backward Compatibility)

## Scope
- Objective: make `openproton-bridge` backend behavior and storage layout match Proton Bridge parity target.
- Constraint: no backward compatibility with old `openproton-bridge` paths/format branches.
- Source of truth: `proton-bridge` gRPC contract and runtime behavior.

## Non-Goals
- No migration from legacy `~/.config/openproton-bridge`.
- No dual path support mode.
- No temporary compatibility shims once parity implementation lands.

## Mandatory Development Rules
- Test-driven development is required for every ticket.
- Execution model for every backlog item: `Red -> Green -> Refactor`.
- `Red`: add or adapt failing parity test first.
- `Green`: implement minimum code needed to pass.
- `Refactor`: clean structure with tests still green.
- Do not merge implementation-only changes without corresponding tests.

## Proton Reference Tests To Follow
- Treat Proton Bridge tests as behavior specification and mirror their expectations in Rust tests.
- Primary backend parity references:
- `proton-bridge/internal/bridge/sync_test.go`
- `proton-bridge/internal/bridge/settings_test.go`
- `proton-bridge/internal/bridge/user_event_test.go`
- `proton-bridge/internal/bridge/bridge_test.go`
- `proton-bridge/internal/vault/vault_test.go`
- `proton-bridge/internal/vault/settings_test.go`
- `proton-bridge/internal/vault/certs_test.go`
- `proton-bridge/internal/vault/user_test.go`
- `proton-bridge/internal/services/imapservice/sync_build_test.go`
- `proton-bridge/internal/services/imapservice/sync_state_provider_test.go`
- `proton-bridge/internal/services/imapservice/conflicts_test.go`
- `proton-bridge/internal/locations/locations_test.go`
- For each implemented feature, add an explicit mapping note in PR/task log:
- `Proton test reference -> openproton equivalent test`.

## Definition Of Done (Backend)
- gRPC proto and RPC/event behavior match parity checklist.
- Runtime storage layout uses Proton-style directories and files only.
- Vault/keychain interop works with existing Proton Bridge account data.
- Disk cache move flow is real (copy/switch/cleanup/events), not a setting-only update.
- Sync progress events are emitted from real sync pipeline (`SyncStarted`, `SyncProgress`, `SyncFinished`).
- Contract and integration tests pass for parity-critical flows.

## Milestones

## M1 - Contract Freeze And Gap Ledger
### Tasks
1. Freeze backend proto at [`proto/bridge.proto`](proto/bridge.proto) to parity target.
2. Build RPC/event gap ledger from implementation in [`src/frontend/grpc.rs`](src/frontend/grpc.rs).
3. Mark every RPC/event as `Exact`, `Partial`, `Missing`, `Behavior Mismatch`.

### Deliverables
- Updated parity ledger (table) in this file or linked parity table.
- Explicit list of blocking mismatches for M2-M5.

### Acceptance
- No unknown parity status remains for any RPC/event in proto.

## M2 - Filesystem Layout Hard-Cut To Proton Model
### Tasks
1. Replace default session/settings directory resolution in [`src/main.rs`](src/main.rs) with Proton-style location model.
2. Centralize path resolver module (settings/data/cache/logs/imap-sync/tls/grpc config).
3. Ensure gRPC config (`grpcServerConfig.json`) is emitted at Proton-style settings path.
4. Remove old openproton path fallback and conditional branches.

### Deliverables
- Single path resolver used by daemon startup and gRPC frontend.
- Deterministic OS-specific path rules documented in code comments.

### Acceptance
- Fresh run never writes under `~/.config/openproton-bridge` unless explicitly overridden by flag.
- All runtime files resolve through unified path resolver.

## M3 - Vault And Keychain Interop (Proton-Only Semantics)
### Tasks
1. Keep vault envelope/data format aligned with Proton vault expectations in [`src/vault.rs`](src/vault.rs).
2. Ensure keychain service/account naming remains Proton-compatible.
3. Validate vault read/write against real Proton profile fixture.
4. Remove/avoid branches that preserve legacy local-only vault behavior where it diverges from parity target.

### Deliverables
- Vault/keychain interop test fixtures.
- Clear failure behavior when keychain entry is unavailable.

### Acceptance
- Existing Proton profile can be loaded without manual conversion scripts.
- Session/account selection and refresh token reuse work from parity paths.

## M4 - Real Disk Cache Semantics
### Tasks
1. Replace setting-only `SetDiskCachePath` logic in [`src/frontend/grpc.rs`](src/frontend/grpc.rs) with real cache move workflow:
- Validate target path.
- Copy/move cache payload.
- Switch active runtime cache path.
- Best-effort cleanup old path.
2. Preserve expected event sequence:
- `DiskCachePathChanged` on success with effective new path.
- `DiskCachePathChangeFinished` always at operation end.
- `DiskCacheError(CANT_MOVE_DISK_CACHE_ERROR)` on failure.
3. Make `DiskCachePath` return runtime-effective location, not stale config.

### Deliverables
- Cache move service module with robust error handling.
- Unit + integration tests for success/failure paths.

### Acceptance
- Cache move survives restart.
- Error paths emit expected event semantics.

## M5 - Persistent Message Cache And UID Mapping
### Tasks
1. Replace production use of in-memory IMAP store (currently in [`src/imap/store.rs`](src/imap/store.rs)) with persistent on-disk backend.
2. Persist per-account:
- Proton ID <-> UID mapping.
- RFC822 message body cache.
- Flags and mailbox ordering metadata.
3. Wire backend storage path to selected disk cache location.
4. Ensure restart continuity and account isolation.

### Deliverables
- On-disk message store implementation and tests.
- Cache integrity checks for missing/corrupted artifacts.

### Acceptance
- Restart does not lose cached message bodies/UID mappings.
- Multi-account data does not cross-contaminate.

## M6 - Sync Progress Event Parity
### Tasks
1. Instrument sync pipeline to emit:
- `SyncStarted`
- periodic `SyncProgress` with `progress`, `elapsedMs`, `remainingMs`
- `SyncFinished`
2. Ensure progress is tied to actual download/build pipeline stages.
3. Define behavior for cancellation/restart/failure transitions.

### Deliverables
- Event emission hooks in sync worker path.
- Tests covering initial sync and incremental sync.

### Acceptance
- UI can render stable synchronizing percentages from backend stream only.

## M7 - Full RPC/Event Parity Completion
### Tasks
1. Resolve all `Partial`/`Missing` items from M1 ledger.
2. Align error types/messages where contract-visible.
3. Verify timing/order-sensitive event flows (repair, keychain, cache, updates, user state).

### Deliverables
- Updated parity table with no unresolved blockers.

### Acceptance
- All contract tests pass with exact expected stream payloads and ordering.

## M8 - Verification, CI Gates, Release Readiness
### Tasks
1. Add parity contract tests for unary RPCs and event stream.
2. Add integration scenario suite:
- login/logout
- startup/shutdown/restart
- sync with progress
- disk cache move
- account reuse from Proton layout
3. Add CI gate requiring parity suite green before merge.

### Deliverables
- CI jobs and test docs.
- Release checklist for backend parity cutover.

### Acceptance
- CI green on parity test matrix.
- Backend declared parity-ready for frontend integration.

## Concrete Backlog (Execution Order)
Note: every `BE-*` item must start by adding a failing test derived from Proton behavior references.

1. `BE-001` Freeze proto and publish RPC/event gap ledger.
2. `BE-002` Implement unified Proton path resolver module.
3. `BE-003` Replace default runtime path wiring with resolver.
4. `BE-004` Remove legacy openproton default-path fallback code.
5. `BE-005` Add vault/keychain interop fixture tests.
6. `BE-006` Harden keychain failure behavior and telemetry.
7. `BE-007` Implement disk cache move service (copy/switch/cleanup).
8. `BE-008` Wire gRPC cache RPCs/events to move service.
9. `BE-009` Build persistent message store backend (UID/proton-id/rfc822/flags).
10. `BE-010` Switch IMAP session/store wiring to persistent backend.
11. `BE-011` Implement sync progress emission hooks.
12. `BE-012` Add sync progress contract tests.
13. `BE-013` Close remaining RPC/event parity gaps.
14. `BE-014` Add end-to-end parity integration suite.
15. `BE-015` Enable CI parity gate and document release criteria.

## M9 - Gluon Full File Support Hard-Cut (No Migration)
- Detailed ticket plan and parallel lane allocation: [`docs/GLUON_FULL_SUPPORT_EXECUTION_PLAN.md`](docs/GLUON_FULL_SUPPORT_EXECUTION_PLAN.md)
- Ticket range reserved for this stream: `BE-016` to `BE-033`.

## Parallel Multi-Agent Execution Plan
## Lane A - Contract And Event Semantics
- Scope: `BE-001`, `BE-013`.
- Files: `proto/bridge.proto`, `src/frontend/grpc.rs`, parity tables.
- Dependency: none at start; feeds all other lanes.

## Lane B - Paths, Vault, Keychain
- Scope: `BE-002` to `BE-006`.
- Files: `src/main.rs`, `src/vault.rs`, path resolver module, tests.
- Dependency: starts after lane A contract freeze (`BE-001`).

## Lane C - Cache And Persistent Store
- Scope: `BE-007` to `BE-010`.
- Files: `src/frontend/grpc.rs`, `src/imap/*`, cache move/storage modules.
- Dependency: starts after `BE-002` path resolver contracts are merged.

## Lane D - Sync Progress + Verification + CI
- Scope: `BE-011`, `BE-012`, `BE-014`, `BE-015`.
- Files: sync pipeline, tests, CI workflows.
- Dependency: `BE-011` can start once lane A stable; full lane completion depends on B/C merge.

## Parallelization Guardrails
- Keep each lane on disjoint file ownership where possible.
- Merge cadence: small slices with tests green per slice.
- Use a daily integration window to rebase all lanes and run full parity suite.
- Block frontend start until backend milestone `BE-013` is complete and validated.

## Ownership And Sequencing
- Backend core: `src/main.rs`, `src/frontend/grpc.rs`, `src/vault.rs`.
- IMAP/cache: `src/imap/*`, sync/event worker pipeline.
- Tests/CI: `tests/*`, CI workflow files.
- Frontend starts only after `BE-013` and stable event semantics.

## Risks And Controls
- Risk: subtle vault/keychain mismatch causes account load failures.
- Control: fixture-based tests against Proton-style profile directories.
- Risk: cache move race conditions.
- Control: serialized move operation + atomic switch marker + event completion guarantees.
- Risk: progress percentages unstable.
- Control: derive progress from deterministic stage counters, not ad-hoc timers.
