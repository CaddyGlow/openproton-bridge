# gRPC Bridge Parity Table

Updated: 2026-03-01

Legend:
- `Implemented`: functional in `src/frontend/grpc.rs`
- `Partial`: callable but intentionally simplified (no full upstream side effects yet)
- `Unsupported`: returns `UNIMPLEMENTED` with explicit reason

| RPC | Status | Notes |
| --- | --- | --- |
| `CheckTokens` | Implemented | Reads client config JSON and returns token. |
| `AddLogEntry` | Implemented | Maps gRPC log levels to `tracing` levels. |
| `GuiReady` | Implemented | Emits show-main-window event and returns splash flag. |
| `Restart` | Implemented | Signals shutdown for controlled restart path. |
| `TriggerRepair` | Partial | Emits app event only; no deep repair workflow yet. |
| `TriggerReset` | Implemented | Clears sessions and persisted gRPC settings files. |
| `ShowOnStartup` | Implemented | Returns persisted app setting. |
| `SetIsAutostartOn` | Implemented | Persists app setting. |
| `IsAutostartOn` | Implemented | Returns persisted app setting. |
| `SetIsBetaEnabled` | Implemented | Persists app setting. |
| `IsBetaEnabled` | Implemented | Returns persisted app setting. |
| `SetIsAllMailVisible` | Implemented | Persists app setting. |
| `IsAllMailVisible` | Implemented | Returns persisted app setting. |
| `SetIsTelemetryDisabled` | Implemented | Persists app setting. |
| `IsTelemetryDisabled` | Implemented | Returns persisted app setting. |
| `DiskCachePath` | Implemented | Returns persisted app setting. |
| `SetDiskCachePath` | Implemented | Validates/creates path and persists setting. |
| `SetIsDoHEnabled` | Implemented | Persists app setting. |
| `IsDoHEnabled` | Implemented | Returns persisted app setting. |
| `SetColorSchemeName` | Implemented | Validates and persists setting. |
| `ColorSchemeName` | Implemented | Returns persisted app setting. |
| `CurrentEmailClient` | Implemented | Returns `openproton-bridge`. |
| `LogsPath` | Implemented | Ensures and returns logs directory path. |
| `LicensePath` | Partial | Returns vault-local path placeholder. |
| `ReleaseNotesPageLink` | Implemented | Returns Proton Bridge releases URL. |
| `DependencyLicensesLink` | Implemented | Returns upstream dependency licenses URL. |
| `LandingPageLink` | Implemented | Returns Proton Bridge landing URL. |
| `ReportBug` | Partial | Accepts payload and logs metadata only. |
| `ForceLauncher` | Implemented | Persists forced launcher setting. |
| `SetMainExecutable` | Implemented | Persists executable path setting. |
| `RequestKnowledgeBaseSuggestions` | Partial | Logs request only; no suggestion backend yet. |
| `Login` | Implemented | Full auth flow including persisted session creation. |
| `Login2FA` | Implemented | Completes pending 2FA flow and finalizes session. |
| `LoginFido` | Implemented | Completes pending auth by submitting FIDO2 assertion payload to `/auth/v4/2fa`. |
| `Login2Passwords` | Implemented | Alias to primary login flow. |
| `LoginAbort` | Implemented | Cancels pending login and emits login error event. |
| `FidoAssertionAbort` | Partial | No-op success; no active FIDO flow exists yet. |
| `GetUserList` | Implemented | Lists persisted sessions as users. |
| `GetUser` | Implemented | Looks up user by id or email. |
| `SetUserSplitMode` | Implemented | Persists per-account split mode in vault and emits user-changed event. |
| `SendBadEventUserFeedback` | Partial | Accepts feedback and logs intent only. |
| `LogoutUser` | Implemented | Removes session and emits disconnect event. |
| `RemoveUser` | Implemented | Alias to logout/remove path. |
| `ConfigureUserAppleMail` | Partial | Accepts request and logs intent; no OS-level Apple Mail automation yet. |
| `CheckUpdate` | Partial | Returns success placeholder; no updater integration yet. |
| `InstallUpdate` | Partial | Triggers controlled shutdown as a restart/update handoff placeholder. |
| `SetIsAutomaticUpdateOn` | Implemented | Persists automatic update flag. |
| `IsAutomaticUpdateOn` | Implemented | Returns persisted automatic update flag. |
| `AvailableKeychains` | Partial | Returns static list (`keyring`, `file`). |
| `SetCurrentKeychain` | Implemented | Persists selected keychain name. |
| `CurrentKeychain` | Implemented | Returns persisted selected keychain name. |
| `MailServerSettings` | Implemented | Returns persisted IMAP/SMTP settings. |
| `SetMailServerSettings` | Implemented | Validates ports, checks availability, persists and emits events. |
| `Hostname` | Implemented | Returns configured bind host. |
| `IsPortFree` | Implemented | Checks local port bind availability. |
| `IsTLSCertificateInstalled` | Implemented | Checks presence of mail TLS cert/key pair. |
| `InstallTLSCertificate` | Implemented | Generates cert/key if missing. |
| `ExportTLSCertificates` | Implemented | Exports cert/key to requested directory. |
| `RunEventStream` | Implemented | Single-active stream with stop signaling. |
| `StopEventStream` | Implemented | Stops active stream or returns not-found. |
| `Version` | Implemented | Returns crate version. |
| `GoOs` | Implemented | Returns runtime OS constant. |
| `Quit` | Implemented | Signals graceful shutdown. |
