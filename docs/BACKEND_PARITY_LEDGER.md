# Backend RPC/Event Parity Ledger

Updated: 2026-03-02

Scope:
- Proto: `proto/bridge.proto`
- Implementation: `src/frontend/grpc.rs`
- Status vocabulary: `Exact`, `Partial`, `Missing`, `Behavior Mismatch`

Notes:
- `Exact` means implemented with contract-consistent behavior for current backend scope.
- `Partial` means callable but intentionally reduced behavior (known parity gap).
- `Behavior Mismatch` means implemented but visible semantics still diverge from Proton Bridge.
- `Missing` means not implemented (none currently for declared RPCs).

## RPC Ledger

| RPC | Status | Notes |
| --- | --- | --- |
| `CheckTokens` | Exact | Reads client config JSON and returns token. |
| `AddLogEntry` | Exact | Maps gRPC log levels to `tracing` levels. |
| `GuiReady` | Exact | Emits show-main-window and returns splash flag. |
| `Restart` | Exact | Signals controlled shutdown. |
| `TriggerRepair` | Partial | Emits repair event only; no full repair workflow. |
| `TriggerReset` | Exact | Clears session/settings artifacts and emits `resetFinished`. |
| `ShowOnStartup` | Exact | Returns persisted app setting. |
| `SetIsAutostartOn` | Exact | Persists app setting. |
| `IsAutostartOn` | Exact | Returns persisted app setting. |
| `SetIsBetaEnabled` | Exact | Persists app setting. |
| `IsBetaEnabled` | Exact | Returns persisted app setting. |
| `SetIsAllMailVisible` | Exact | Persists app setting. |
| `IsAllMailVisible` | Exact | Returns persisted app setting. |
| `SetIsTelemetryDisabled` | Exact | Persists app setting. |
| `IsTelemetryDisabled` | Exact | Returns persisted app setting. |
| `GoOs` | Exact | Returns runtime OS constant. |
| `Version` | Exact | Returns crate version. |
| `LogsPath` | Exact | Returns runtime resolver logs path. |
| `LicensePath` | Partial | Placeholder path only; no packaged-license resolution parity. |
| `ReleaseNotesPageLink` | Exact | Returns Proton Bridge releases URL. |
| `DependencyLicensesLink` | Exact | Returns upstream dependency licenses URL. |
| `LandingPageLink` | Exact | Returns Proton Bridge landing URL. |
| `SetColorSchemeName` | Exact | Validates and persists app setting. |
| `ColorSchemeName` | Exact | Returns persisted app setting. |
| `CurrentEmailClient` | Behavior Mismatch | Static `openproton-bridge` value. |
| `ReportBug` | Partial | Logs metadata and emits `reportBugSuccess` + `reportBugFinished`; no upstream submission flow. |
| `ForceLauncher` | Exact | Persists launcher setting. |
| `SetMainExecutable` | Exact | Persists executable setting. |
| `RequestKnowledgeBaseSuggestions` | Partial | Emits `knowledgeBaseSuggestions` with derived support-search suggestion; no upstream KB backend. |
| `Login` | Exact | Full auth flow + vault session persistence. |
| `Login2FA` | Exact | Completes pending 2FA flow. |
| `LoginFido` | Exact | Completes pending auth via FIDO assertion payload. |
| `Login2Passwords` | Exact | Alias to primary login flow. |
| `LoginAbort` | Exact | Cancels pending login and emits error event. |
| `FidoAssertionAbort` | Partial | No-op success; no dedicated active FIDO flow state. |
| `CheckUpdate` | Partial | Placeholder success; no updater integration. |
| `InstallUpdate` | Partial | Shutdown handoff placeholder only. |
| `SetIsAutomaticUpdateOn` | Exact | Persists app setting. |
| `IsAutomaticUpdateOn` | Exact | Returns persisted app setting. |
| `DiskCachePath` | Exact | Returns runtime-effective active cache path. |
| `SetDiskCachePath` | Exact | Real copy/switch/cleanup flow + error/finish events. |
| `SetIsDoHEnabled` | Exact | Persists app setting. |
| `IsDoHEnabled` | Exact | Returns persisted app setting. |
| `MailServerSettings` | Exact | Returns persisted IMAP/SMTP settings. |
| `SetMailServerSettings` | Exact | Validates, persists, and emits change/finish/error events. |
| `Hostname` | Exact | Returns configured bind host. |
| `IsPortFree` | Exact | Checks local bind availability. |
| `AvailableKeychains` | Partial | Static keychain list (`keyring`, `file`). |
| `SetCurrentKeychain` | Exact | Persists selected keychain setting. |
| `CurrentKeychain` | Exact | Returns selected keychain setting. |
| `GetUserList` | Exact | Lists persisted sessions as users. |
| `GetUser` | Exact | Resolves by account id or email. |
| `SetUserSplitMode` | Exact | Persists split mode and emits user-changed. |
| `SendBadEventUserFeedback` | Partial | Accepts/logs feedback only. |
| `LogoutUser` | Exact | Removes account session and emits disconnected event. |
| `RemoveUser` | Exact | Alias to remove/logout path. |
| `ConfigureUserAppleMail` | Partial | Logs request only; no OS automation. |
| `IsTLSCertificateInstalled` | Exact | Checks TLS cert/key presence. |
| `InstallTLSCertificate` | Exact | Generates cert/key if missing. |
| `ExportTLSCertificates` | Exact | Exports cert/key to target directory. |
| `RunEventStream` | Exact | Single-active stream, backlog replay, sync event contract tests. |
| `StopEventStream` | Exact | Stops active stream, `NotFound` when inactive. |
| `Quit` | Exact | Signals graceful shutdown. |

## Event Ledger (Stream Surface)

| Event Surface | Status | Notes |
| --- | --- | --- |
| `DiskCache.PathChanged` | Exact | Emitted on successful path switch. |
| `DiskCache.PathChangeFinished` | Exact | Emitted at end of set path operation, including failures. |
| `DiskCache.Error(CANT_MOVE_DISK_CACHE_ERROR)` | Exact | Emitted on move/persist failures. |
| `User.SyncStartedEvent` | Exact | Emitted from real event-worker resync lifecycle. |
| `User.SyncProgressEvent` | Exact | Emitted with `progress`, `elapsedMs`, `remainingMs`. |
| `User.SyncFinishedEvent` | Exact | Emitted when resync lifecycle completes. |
| `RunEventStream replay semantics` | Exact | Replays buffered pre-stream events in order. |
| `RunEventStream stop semantics` | Exact | Stream terminates after `StopEventStream`; late events not delivered. |
| `App.ReportBugSuccess` | Exact | Emitted on `ReportBug` request handling path. |
| `App.ReportBugFinished` | Exact | Emitted after `App.ReportBugSuccess`. |
| `App.KnowledgeBaseSuggestions` | Exact | Emitted by `RequestKnowledgeBaseSuggestions` with suggestion payload. |
| `App.ResetFinished` | Exact | Emitted after `TriggerReset` completes state cleanup. |

## Current Blockers Toward Full Exact Parity

- Updater workflow RPCs (`CheckUpdate`, `InstallUpdate`) are placeholders.
- Bug reporting, KB suggestions, Apple Mail config, and bad-event feedback are currently reduced stubs.
- Keychain surface is static list rather than full backend parity behavior.
