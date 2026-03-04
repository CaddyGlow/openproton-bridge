# gRPC Mail Runtime + Parity Plan

## Objective
Make gRPC mode start and manage IMAP/SMTP listeners with behavior and observability parity to Proton Bridge, while preserving existing `serve` behavior and minimizing code duplication.

## Scope
- In scope:
  - Shared mail runtime lifecycle for `serve` and `grpc`.
  - gRPC startup starts IMAP/SMTP.
  - gRPC settings updates apply live to IMAP/SMTP.
  - Startup/change failure events for mail settings parity.
  - Log message and field parity for lifecycle transitions.
- Out of scope:
  - Protocol-level IMAP/SMTP feature changes.
  - API/auth flow redesign.
  - UI redesign.

## Source-of-Truth Parity References
- Proton Bridge frontend selection:
  - `../proton-bridge/internal/app/frontend.go`
- Proton Bridge bridge initialization and server manager wiring:
  - `../proton-bridge/internal/bridge/bridge.go`
- Proton Bridge IMAP/SMTP server lifecycle behavior and logs:
  - `../proton-bridge/internal/services/imapsmtpserver/service.go`
- OpenProton current split lifecycle:
  - `src/main.rs` (`cmd_serve`, `prepare_serve_runtime`, `run_serve_runtime`, `cmd_grpc`)
  - `src/frontend/grpc/runtime.rs`
  - `src/frontend/grpc/rpc.rs`

## Current Gap
- `serve` starts IMAP/SMTP and event workers.
- `grpc` starts gRPC + sync workers only.
- `set_mail_server_settings` in gRPC persists settings and emits events but does not rebind IMAP/SMTP listeners.

## Target Behavior
- Starting gRPC runtime should also start IMAP and SMTP listeners using persisted gRPC mail settings.
- Changing mail settings through gRPC should reconfigure live listeners safely.
- On startup bind failure, gRPC remains available and emits startup error events.
- On change failure, existing listeners remain active and `*_CHANGE_ERROR` is emitted.
- `serve` behavior remains functionally unchanged.

## Architecture Plan

### 1) Extract shared mail runtime orchestration
- Create a reusable runtime module under `src/bridge/` (example: `src/bridge/mail_runtime.rs`).
- Move shared logic from `main.rs`:
  - account/session bootstrap
  - auth router setup
  - store bootstrap
  - IMAP/SMTP config creation
  - event worker lifecycle
  - IMAP/SMTP task lifecycle
- Define explicit handle API:
  - `start(config) -> MailRuntimeHandle`
  - `stop(handle) -> Result<()>`
  - `restart(handle, config) -> Result<MailRuntimeHandle>`

### 2) Refactor serve mode onto shared runtime
- Replace direct `main.rs` lifecycle code with the new shared runtime calls.
- Keep CLI output semantics and runtime stop behavior stable.

### 3) Integrate shared runtime into gRPC mode
- Extend gRPC state with mail runtime handle and lifecycle lock.
- In `run_server`:
  - load persisted mail settings
  - attempt to start mail runtime
  - if startup fails, emit startup error events and continue running gRPC
- Ensure `quit`, `restart`, and shutdown path stop mail runtime first, then close gRPC server.

### 4) Apply settings changes live in gRPC
- Update `set_mail_server_settings` flow:
  - validate request
  - persist settings
  - attempt runtime restart with new settings
  - on success emit `MailServerSettingsChanged` then `ChangeMailServerSettingsFinished`
  - on failure emit `IMAP_PORT_CHANGE_ERROR` or `SMTP_PORT_CHANGE_ERROR` and keep previous runtime handle active

### 5) Stabilize transition semantics
- Add transition guard to prevent concurrent runtime restarts from:
  - settings updates
  - repair/reset paths
  - shutdown path
- Ensure runtime restart and sync worker refresh ordering is deterministic and logged.

## Logging and Field Parity Contract

### Canonical lifecycle messages to preserve
- `Starting IMAP server`
- `Starting SMTP server`
- `Failed to start IMAP server on bridge start`
- `Failed to start SMTP server on bridge start`
- `Restarting IMAP server`
- `Restarting SMTP server`
- Listener stop/close messages for both protocols

### Canonical fields to preserve
- `port`
- `ssl`
- Existing package/transition fields where already used (`pkg`, `transition`).

### Logging implementation approach
- Add central logging helpers in shared runtime so `serve` and `grpc` use identical message text and fields.
- Emit one start attempt and one outcome per protocol per transition:
  - `startup`
  - `settings_change`
  - `shutdown`
- Keep existing gRPC transition logs unchanged:
  - `pkg=grpc/bridge`
  - `pkg=grpc/sync`

## Event Parity Contract
- Startup failures in gRPC runtime:
  - emit `IMAP_PORT_STARTUP_ERROR` and/or `SMTP_PORT_STARTUP_ERROR`.
- Settings-change failures:
  - emit `IMAP_PORT_CHANGE_ERROR` and/or `SMTP_PORT_CHANGE_ERROR`.
- Success path:
  - emit settings changed payload followed by finished event in stable order.

## Detailed Execution Phases

### Phase 0: Baseline and safety net
- Add/adjust tests that currently define gRPC event ordering and settings behavior to avoid regressions.
- Capture current log expectations in `tests/golden_log_validation.rs`.

### Phase 1: Shared runtime extraction
- Introduce new runtime module and types.
- Move non-CLI-specific serve startup/shutdown logic from `main.rs`.
- Keep `main.rs` adapter thin.

### Phase 2: Serve migration
- Update `cmd_serve` and interactive serve runtime start/stop to use shared runtime.
- Confirm existing serve tests still pass.

### Phase 3: gRPC runtime start integration
- Add `mail_runtime` handle into `GrpcState`.
- Start runtime in `run_server` with loaded `StoredMailSettings`.
- Emit startup error events and parity logs on bind failure.

### Phase 4: gRPC live settings apply
- Implement restart-on-settings-change in RPC handler.
- Add rollback behavior to keep previous listeners on restart failure.
- Keep event ordering stable and tested.

### Phase 5: Unified shutdown behavior
- Ensure all exit paths stop runtime cleanly:
  - gRPC `quit`
  - gRPC `restart`
  - Ctrl-C path
  - server loop termination

### Phase 6: Log/message parity hardening
- Normalize runtime logs through helper APIs.
- Add golden log assertions for message text + field presence.

### Phase 7: Verification and cleanup
- Remove dead/duplicate lifecycle code from `main.rs`.
- Ensure no stale paths start IMAP/SMTP directly outside shared runtime.

## Testing Plan
- Unit tests:
  - runtime start/stop/restart state machine.
  - settings apply success/failure and rollback behavior.
- Integration tests:
  - gRPC startup creates IMAP/SMTP listeners.
  - gRPC settings change rebinds listeners.
  - startup port conflict emits startup error and gRPC remains reachable.
  - change-time port conflict emits change error and old listeners remain alive.
- Event wire tests:
  - `MailServerSettingsChanged` then `ChangeMailServerSettingsFinished` ordering.
  - startup/change error event emission.
- Log tests:
  - message parity strings and required fields (`port`, `ssl`, `pkg`, `transition` where applicable).

## Risks and Mitigations
- Risk: introducing lifecycle races between gRPC transitions and runtime restart.
  - Mitigation: single runtime lifecycle lock and explicit transition sequencing.
- Risk: settings persistence diverges from active runtime on restart failure.
  - Mitigation: atomic restart attempt with previous-handle retention and explicit error event.
- Risk: log parity drift over time.
  - Mitigation: centralized log helper + golden log tests.

## Definition of Done
- gRPC mode starts IMAP/SMTP automatically.
- Live mail settings updates rebind listeners safely.
- Startup/change failure events are emitted with parity semantics.
- Log messages/fields match defined parity contract.
- `serve` behavior remains unchanged from user perspective.
- Test suite additions for runtime, event, and log parity pass.
