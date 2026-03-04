# gRPC Parity Implementation Plan

## Goal
Implement the same frontend gRPC contract used by Proton Bridge in `openproton-bridge`, based on:

- `proton-bridge/internal/frontend/grpc/bridge.proto`
- `proton-bridge/internal/focus/proto/focus.proto` (optional second phase)

This plan targets practical delivery in phases, starting with a usable MVP and then expanding to full API parity.

## Scope Clarification

### Primary parity target
- GUI-facing `Bridge` gRPC service (`bridge.proto`) from `proton-bridge`.

### Secondary reference
- `go-proton-api/server/proto/server.proto` is a smaller test utility service and **not** the parity target.

## Current Rust Baseline
- IMAP/SMTP server runtime already exists (`src/imap`, `src/smtp`).
- Multi-account runtime and auth routing exist (`src/bridge/accounts.rs`, `src/bridge/auth_router.rs`).
- Event polling/checkpoints exist (`src/bridge/events.rs`).
- CLI lifecycle exists (`src/main.rs`).
- No gRPC server/client module exists yet.

## Architecture Plan

### 1) Add gRPC contract and code generation
- Add `proto/bridge.proto` (copied from upstream parity target).
- Add build-time codegen via `tonic-build`/`prost-build` in `build.rs`.
- Generate server + message types into a dedicated module (e.g. `src/frontend/grpc/pb.rs`).
- Keep a checked-in parity table documenting RPC implementation status.

### 2) Introduce gRPC frontend module
Create:
- `src/frontend/mod.rs`
- `src/frontend/grpc/mod.rs`
- `src/frontend/grpc/service.rs` (bootstrap, transport, interceptors, shutdown)
- `src/frontend/grpc/state.rs` (shared runtime state)
- `src/frontend/grpc/methods_app.rs`
- `src/frontend/grpc/methods_login.rs`
- `src/frontend/grpc/methods_user.rs`
- `src/frontend/grpc/methods_mail.rs`
- `src/frontend/grpc/methods_cert.rs`
- `src/frontend/grpc/stream.rs` (event stream server)

### 3) Transport and handshake parity
Implement server startup semantics compatible with upstream:
- Listen on random localhost TCP port first (unix socket later).
- Generate ephemeral TLS cert for gRPC transport.
- Generate random auth token.
- Write `grpcServerConfig.json` with:
  - `port`
  - `cert`
  - `token`
  - `fileSocketPath` (empty in initial phase)
- Enforce token auth via unary + stream interceptors using `server-token` metadata key.

### 4) Runtime supervisor extraction
Refactor serve lifecycle from `src/main.rs` into a reusable supervisor so gRPC RPCs can:
- Start/stop protocol servers.
- Read and mutate server settings.
- Trigger controlled restarts.
- Expose runtime/account health data.

### 5) Event stream integration
Implement server-push stream semantics:
- Internal broadcast channel for `StreamEvent`.
- `RunEventStream` with single active stream policy.
- `StopEventStream` to terminate stream cleanly.
- Event mapping from existing runtime signals (login, account changes, sync status, settings changes, repair actions).

## Delivery Phases

## Phase 0: Foundation
- Add proto + codegen + module skeleton.
- Add gRPC config writer/loader structs compatible with JSON shape.
- Add token interceptors and TLS bootstrap.

Acceptance:
- gRPC server starts.
- `grpcServerConfig.json` is written.
- A client can connect with TLS + token metadata.

## Phase 1: MVP RPC set (usable external control plane)
Implement:
- `CheckTokens`
- `RunEventStream`
- `StopEventStream`
- `Version`
- `GoOs`
- `Quit`
- `Login`
- `Login2FA`
- `Login2Passwords`
- `LoginAbort`
- `GetUserList`
- `GetUser`
- `LogoutUser`
- `RemoveUser`
- `MailServerSettings`
- `SetMailServerSettings`
- `Hostname`
- `IsPortFree`
- `IsTLSCertificateInstalled`
- `InstallTLSCertificate`
- `ExportTLSCertificates`

Acceptance:
- Login flow works entirely through gRPC.
- User/account listing and removal work via gRPC.
- Mail server settings can be read/updated via gRPC.
- Event stream emits meaningful lifecycle events.

## Phase 2: Extended app/settings parity
Implement app/system endpoints:
- `GuiReady`, `Restart`, `TriggerRepair`
- telemetry/beta/autostart toggles
- disk cache path endpoints
- DoH toggles
- color scheme + misc app metadata endpoints

Acceptance:
- Major settings APIs from upstream proto return functional results (not stubs).

## Phase 3: Long-tail parity
Implement or explicitly mark unsupported:
- update RPCs (`CheckUpdate`, `InstallUpdate`, automatic updates toggles)
- keychain management RPCs
- launcher/reporting/KB suggestion APIs
- FIDO-specific paths where applicable

Acceptance:
- Every RPC in `bridge.proto` is either:
  - implemented, or
  - returns a deliberate `UNIMPLEMENTED` with rationale in parity table.

## Testing Plan

### Unit tests
- Token interceptor behavior (missing/invalid/valid metadata).
- gRPC config serialization compatibility.
- Event mapping utilities.

### Integration tests
- Start gRPC service, read config JSON, connect with TLS + token.
- Validate RPC happy paths for Phase 1.
- Validate stream lifecycle (`RunEventStream`/`StopEventStream`).
- Validate login and account operations over gRPC.

### Compatibility checks
- Ensure message field names/types match upstream `bridge.proto`.
- Ensure status code behavior is deterministic and documented.

## Risks and Mitigations
- Broad API surface in `bridge.proto`.
  - Mitigation: phased rollout + parity matrix + explicit stubs.
- Runtime restart semantics may require deeper refactors.
  - Mitigation: introduce supervisor abstraction before adding many mutating RPCs.
- Event model mismatch between current Rust runtime and upstream stream events.
  - Mitigation: ship minimal meaningful events first, then expand.

## Concrete Task Checklist
1. Add protobuf toolchain deps and `build.rs`.
2. Import `bridge.proto` and generate Rust bindings.
3. Add `frontend/grpc` module skeleton and server bootstrap.
4. Implement TLS + token + config-file handshake.
5. Extract server supervisor from CLI `serve`.
6. Implement Phase 1 RPCs.
7. Implement event stream and event mapping.
8. Add integration tests for connection + auth + stream + core RPCs.
9. Implement Phase 2 and Phase 3 RPCs incrementally.
10. Maintain parity table until all RPCs are resolved.

## Done Definition
- gRPC service can fully drive core account/login/mail-server workflows without CLI interaction.
- Config/TLS/token handshake is client-compatible.
- Phase 1 tests pass in CI.
- Remaining RPCs are implemented or intentionally documented as unsupported.
