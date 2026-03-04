# Runtime Supervisor PR1 Checklist (Bridge Core Only)

## Goal
Introduce a single bridge-core lifecycle API (`RuntimeSupervisor`) that can own mail runtime transitions in later PRs, without changing current CLI or gRPC behavior in this PR.

## Scope (PR1)
- Add new bridge-core module and tests only.
- No migration of `src/main.rs` or `src/frontend/grpc/*` ownership logic yet.

## Non-Goals (PR1)
- No change to command UX/flags (`serve`, `grpc`, interactive shell).
- No change to gRPC startup/settings/repair/reset/logout transition behavior.
- No sync-owner redesign in gRPC.

## Current Ownership Map (Baseline)
- Mail runtime constructor/engine:
  - `src/bridge/mail_runtime.rs:120` (`start`)
  - `src/bridge/mail_runtime.rs:387` (`run_runtime`)
  - `src/bridge/mail_runtime.rs:88` (`MailRuntimeHandle` lifecycle)
- Event worker group lifecycle:
  - `src/bridge/events.rs:1842`
  - `src/bridge/events.rs:231`
- gRPC-owned runtime transitions (defer migration):
  - `src/frontend/grpc/service.rs`
  - `src/frontend/grpc/rpc.rs`
  - `src/frontend/grpc/runtime.rs`
- CLI/interactive startup surface (do not touch in PR1):
  - `src/main.rs`

## File-by-File Implementation Checklist

1. `src/bridge/runtime_supervisor.rs` (new)
- [ ] Add `RuntimeSupervisor` with ownership fields:
  - `runtime_paths: RuntimePaths`
  - `handle: tokio::sync::Mutex<Option<MailRuntimeHandle>>`
  - `transition_lock: tokio::sync::Mutex<()>`
- [ ] Add constructor:
  - `pub fn new(runtime_paths: RuntimePaths) -> Self`
- [ ] Add lifecycle methods (async):
  - `start(config, transition, notify_tx) -> Result<(), MailRuntimeStartError>`
  - `stop(reason) -> anyhow::Result<()>`
  - `restart(config, transition, notify_tx) -> Result<(), MailRuntimeStartError>`
  - `is_running() -> bool`
- [ ] Implement methods strictly via existing primitives:
  - `mail_runtime::start(...)`
  - `MailRuntimeHandle::stop()`
- [ ] Ensure transitions are serialized with `transition_lock`.
- [ ] Add concise tracing fields for transition reason/start-stop outcomes.

2. `src/bridge/mod.rs`
- [ ] Export module: `pub mod runtime_supervisor;`

3. `src/bridge/runtime_supervisor.rs` tests
- [ ] Add focused unit tests for control-flow/state:
  - start when stopped stores running handle
  - start when already running is idempotent or controlled error (choose one and document)
  - stop when running clears handle
  - stop when already stopped is no-op
  - restart performs stop+start under serialized lock
  - concurrent start/stop calls do not race state mutation
- [ ] Keep tests independent from gRPC and CLI wiring.

## Explicitly Untouched in PR1

1. `src/main.rs`
- Keep command parsing/dispatch unchanged.
- Keep non-interactive `cmd_serve` and `cmd_grpc` behavior unchanged.
- Keep interactive `serve` / `grpc` command behavior unchanged.

2. `src/frontend/grpc/service.rs`
- Keep current startup/start/stop/settings-change lifecycle logic unchanged.
- Keep rollback semantics on settings failure unchanged.
- Keep `refresh_sync_workers*` behavior unchanged.

3. `src/frontend/grpc/rpc.rs`
- Keep restart/reset/quit hard-stop behavior unchanged.
- Keep repair/reset/logout/settings transition calls unchanged.

4. `src/frontend/grpc/runtime.rs`
- Keep startup-before-serve and shutdown ordering unchanged.

## Test Gates (PR1)

1. Core compile/tests
- [ ] `cargo test --locked` passes.
- [ ] New supervisor tests pass.

2. Regression guardrails (must remain unchanged)
- [ ] Existing `src/main.rs` parser/interactive tests remain green.
- [ ] Existing gRPC tests around startup port conflict/settings transitions remain green.

## Exit Criteria
- New `RuntimeSupervisor` module exists, exported, and tested.
- No functional behavior difference in CLI/gRPC startup paths.
- PR ready as a pure bridge-core foundation for migration PRs.

## Follow-up PR Boundaries
- PR2: migrate gRPC ownership to `RuntimeSupervisor` (including settings and transition calls).
- PR3: migrate CLI/interactive ownership and enforce single runtime owner at entrypoints.
