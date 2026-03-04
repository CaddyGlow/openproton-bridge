# gRPC UI Plan (Tauri + Svelte)

## Goal
Build a desktop UI for `openproton-bridge` using **Tauri v2 + Svelte**, with Bridge-like behavior (system tray, startup behavior, notifications) and control entirely via the `bridge.proto` gRPC contract.

This plan complements backend parity work in `GRPC_PARITY_IMPLEMENTATION_PLAN.md`.

## Architecture

### High-level components
- **openproton-bridge daemon (Rust):** exposes gRPC service (`bridge.proto`), writes `grpcServerConfig.json`.
- **Tauri shell (Rust):** desktop lifecycle, tray/menu, autostart, native notifications, secure bridge process handling.
- **gRPC adapter (Rust, inside Tauri):**
  - Reads `grpcServerConfig.json` (`port`, `cert`, `token`, `fileSocketPath`).
  - Connects to local gRPC over TLS.
  - Injects `server-token` metadata for all unary and stream calls.
  - Owns and supervises one `RunEventStream` reader.
- **Svelte UI (TypeScript):** renders screens, sends commands to Tauri (`invoke`), subscribes to pushed events (`listen`).

### Why this split
- Keep security-sensitive handshake/token logic in Rust.
- Keep UI thin and event-driven.
- Avoid direct gRPC-web/browser transport complexity.

## Repository Layout (proposed)
- `apps/bridge-ui/`
- `apps/bridge-ui/src/` (Svelte app)
- `apps/bridge-ui/src/lib/stores/` (UI state stores)
- `apps/bridge-ui/src/lib/api/` (typed frontend commands/events wrappers)
- `apps/bridge-ui/src-tauri/src/main.rs` (Tauri bootstrap)
- `apps/bridge-ui/src-tauri/src/grpc/` (generated client + adapter)
- `apps/bridge-ui/src-tauri/src/tray.rs` (tray and menu handling)
- `apps/bridge-ui/src-tauri/src/state.rs` (app runtime state, stream status)

## UX Scope

### Phase 1 (MVP)
- Splash/connection status.
- Login wizard:
  - username/password
  - 2FA
  - mailbox password
  - abort flow
- Accounts list + account detail:
  - sign in/out
  - remove account
  - split mode toggle
- Mail server settings:
  - IMAP/SMTP ports
  - SSL vs STARTTLS
  - hostname
  - local port availability checks
- TLS settings:
  - install cert
  - export cert/key
- Tray features:
  - show/hide main window
  - quit
  - unread/error style badge state driven by events

### Phase 2
- General settings parity:
  - autostart
  - beta channel
  - telemetry
  - DoH
  - disk cache path
  - keychain selector
  - color scheme
- Repair/reset flows.
- Update flows (`CheckUpdate`, `InstallUpdate`, auto update toggle).
- Better onboarding/client config wizard parity.

### Phase 3
- Long-tail parity endpoints:
  - launcher/reporting/KB suggestion endpoints
  - advanced platform-specific UX parity
  - remaining RPCs marked as implemented or explicitly unsupported

## gRPC Contract Usage

### Startup / session
- `CheckTokens`
- `Version`
- `GoOs`
- `GuiReady`
- `RunEventStream`
- `StopEventStream`

### Login
- `Login`
- `Login2FA`
- `Login2Passwords`
- `LoginAbort`
- (optional later) `LoginFido`, `FidoAssertionAbort`

### Accounts
- `GetUserList`
- `GetUser`
- `SetUserSplitMode`
- `LogoutUser`
- `RemoveUser`
- `SendBadEventUserFeedback`

### Mail settings
- `MailServerSettings`
- `SetMailServerSettings`
- `Hostname`
- `IsPortFree`
- `SetIsAllMailVisible`
- `IsAllMailVisible`

### TLS
- `IsTLSCertificateInstalled`
- `InstallTLSCertificate`
- `ExportTLSCertificates`

### App/system settings
- `SetIsAutostartOn`, `IsAutostartOn`
- `SetIsBetaEnabled`, `IsBetaEnabled`
- `SetIsTelemetryDisabled`, `IsTelemetryDisabled`
- `SetIsDoHEnabled`, `IsDoHEnabled`
- `DiskCachePath`, `SetDiskCachePath`
- `AvailableKeychains`, `CurrentKeychain`, `SetCurrentKeychain`
- `SetColorSchemeName`, `ColorSchemeName`
- `Quit`, `Restart`, `TriggerRepair`, `TriggerReset`

## Event Stream Model

### Transport policy
- Single active stream in adapter.
- Auto-reconnect with backoff on stream errors.
- Emit adapter-level health events (`stream_connecting`, `stream_up`, `stream_down`).

### UI state handling
- Map `StreamEvent` into domain actions:
  - `app`
  - `login`
  - `update`
  - `cache`
  - `mailServerSettings`
  - `keychain`
  - `mail`
  - `user`
  - `genericError`
- Prefer stream events over optimistic local mutation for final state.

### Critical event-driven flows
- Login screens switch on login events (`tfaRequested`, `twoPasswordRequested`, `finished`, `error`).
- Settings save buttons complete on `*Finished` events.
- Notifications/toasts sourced from `genericError`, user events, repair/update events.

## Desktop Behavior (Tauri)

### System tray
- Tray menu entries:
  - Show/Hide window
  - Settings
  - Quit Bridge
- Left-click behavior:
  - Windows/Linux: toggle main window.
  - macOS: prefer menu-first behavior, configurable.

### Window lifecycle
- Close button hides to tray by default (configurable).
- Explicit Quit terminates UI and calls backend `Quit` (or detaches if attach-mode is chosen later).

### Startup
- Support launch-on-login via Tauri plugin or OS integration.
- Sync UI setting with gRPC `IsAutostartOn` / `SetIsAutostartOn`.

### Notifications
- Use native notification APIs for:
  - login failures
  - sync/repair completion
  - account issues (`userBadEvent`, `imapLoginFailed`)

## Security Requirements
- Never expose gRPC token to browser JS if avoidable.
  - Preferred: Svelte calls only Tauri commands; Rust adapter owns token and gRPC client.
- Certificate pinning behavior:
  - Trust only cert content from `grpcServerConfig.json`.
- Validate config path ownership/permissions before reading if platform allows checks.

## Implementation Phases

1. **Foundation**
- Scaffold Tauri + Svelte app.
- Add Rust gRPC client generation for `bridge.proto`.
- Implement config loader + TLS/token interceptors.
- Implement minimal stream supervisor and diagnostics.

2. **MVP UI + Core RPCs**
- Implement login wizard and account list.
- Implement mail settings + TLS settings views.
- Add tray with show/hide/quit.
- Add event-to-store mapping and notifications.

3. **Settings Parity**
- Implement general + advanced settings pages and associated RPCs.
- Implement disk cache, keychain, update, repair/reset flows.

4. **Parity Closure**
- Fill remaining RPC gaps.
- Add explicit unsupported behavior list when needed.
- Stabilize UX and platform behavior edge cases.

## Testing Plan

### Rust adapter tests
- Token metadata interceptor on unary/stream calls.
- Config parsing/validation for TCP and file-socket modes.
- Stream reconnect logic and dedup behavior.

### Integration tests
- Start bridge, load config, connect successfully.
- Validate end-to-end login flow over RPC + stream events.
- Validate settings update produces expected `*Finished` or error events.

### UI tests
- Component tests for each wizard/settings state.
- E2E smoke:
  - connect
  - login
  - open settings
  - change IMAP/SMTP
  - logout/remove user

## Milestones / Exit Criteria
- **M1:** App launches, connects via TLS/token, stream alive.
- **M2:** Full login + account operations via UI.
- **M3:** Mail settings + TLS workflows complete.
- **M4:** Tray/autostart/notifications parity.
- **M5:** Remaining RPCs resolved (implemented or explicitly unsupported).
