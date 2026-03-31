# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Rust implementation of a Proton Mail bridge. Exposes local IMAP/SMTP servers to let standard email clients access Proton Mail (including free accounts). Single-crate project, single developer, test-driven.

## Build and Test Commands

```bash
cargo build                          # build
cargo fmt                            # format (always run before finishing work)
cargo clippy                         # lint (always run before finishing work)
cargo test                           # run all tests
cargo test <test_name>               # run a single test by name
cargo test --test <file_stem>        # run one integration test file, e.g. cargo test --test gluon_integration
cargo test -- --nocapture             # run tests with stdout visible
cargo run -- serve --imap-port 1143 --smtp-port 1025  # start local mail services
```

For headless/no-keyring environments: `OPENPROTON_CREDENTIAL_STORE=file cargo test --locked`.

The project uses `build.rs` to compile `proto/bridge.proto` via `tonic-build` with vendored `protoc`. No manual protobuf toolchain setup is needed.

## Architecture

### Module Dependency Flow

```
grpc (gRPC/Tauri) -> bridge -> imap, smtp, dav, api, crypto
                                bridge -> pim (calendar/contacts sync)
                                api and crypto are standalone
                                imap, smtp, and dav must never cross-depend
```

### Core Modules

- **`api/`** -- Proton REST API client. Submodules: `auth` (SRP login, 2FA, token refresh), `client` (ProtonClient with reqwest, retry logic, two ApiMode variants: Bridge and Webmail), `srp` (SRP-6a implementation), `events` (event polling), `messages`, `keys`, `users`, `contacts`, `calendar`, `types` (API response structs with PascalCase serde).
- **`crypto/`** -- PGP operations via `sequoia-openpgp`. `keys` (key parsing/unlocking), `encrypt`, `decrypt`. Standalone; no IMAP/SMTP/bridge imports.
- **`imap/`** -- Custom IMAP4rev1 server built directly on tokio TCP + tokio-rustls (no IMAP library). `server` (connection accept loop), `session` (per-connection state machine), `command` (IMAP command parsing), `response` (IMAP response formatting), `mailbox` (label-to-mailbox mapping), `store` (MessageStore trait + GluonStore SQLite impl + InMemoryStore for tests), `gluon_*` (Go-bridge-compatible on-disk message store: codec, locking, transactions).
- **`smtp/`** -- Custom SMTP server on tokio TCP + tokio-rustls. `server`, `session` (SMTP state machine), `send` (message submission to Proton API).
- **`bridge/`** -- Orchestration layer. `accounts` (AccountRegistry, RuntimeAccountRegistry with health tracking and token refresh), `auth_router` (maps IMAP/SMTP/DAV login credentials to Proton sessions via bridge passwords), `events` (event loop syncing Proton server events to local store), `session_manager` (centralized session lifecycle), `runtime_supervisor` (multi-account runtime with health tracking), `mail_runtime` (orchestrates IMAP/SMTP/DAV servers with event workers), `types` (AccountId newtype, EventCheckpointStore trait).
- **`vault`** -- Go-bridge-compatible encrypted vault (AES-256-GCM + MessagePack). Reads/writes `vault.enc` with keys from OS keychain (`keyring`), `pass`, or file-based credential stores. Stores per-account sessions, settings, gluon encryption keys.
- **`grpc/`** -- gRPC control service (`proto/bridge.proto`) exposing login, account management, settings, and event streaming to GUI clients (Tauri app in `apps/bridge-ui/`).
- **`paths`** -- RuntimePaths: resolves config/data/cache directories matching Go bridge layout (XDG on Linux, Library on macOS, AppData on Windows).
- **`dav/`** -- CardDAV/CalDAV server on tokio TCP + tokio-rustls. `server`, `auth`, `discovery` (well-known/principal routing), `propfind`/`report` (WebDAV XML request handling), `carddav`/`caldav` (resource-specific handlers), `calendar_crypto` (encrypted calendar event handling), `push` (WebDAV-Push subscriptions, VAPID/RFC 8291 encryption, notification sender).
- **`pim/`** -- Personal Information Management sync engine. `sync_contacts`/`sync_calendar` (incremental sync from Proton events), `store` (local PIM persistence with SQLite via gluon_rs_contacts/gluon_rs_calendar). Re-exports `QueryPage`, `CalendarEventRange`, `StoredContact`, `StoredCalendar`, `StoredCalendarEvent` from its root. Drives DAV server content.
- **`observability`** -- Tracing setup with rotating session logs, crash reports, and support bundles.

### Key Trait Boundaries

- `MessageStore` (`imap::store`) -- abstracts message persistence. `GluonStore` (SQLite + on-disk) for production, `InMemoryStore` for tests.
- `EventCheckpointStore` (`bridge::types`) -- abstraction for event checkpoint persistence (3 impls: InMemory, File, Vault).
- No `ProtonApi` trait yet; `ProtonClient` is used directly (via free functions in `api::auth`, `api::messages`, etc.).

### Data Flow: Email Client -> Proton

1. Email client connects to local IMAP/SMTP on 127.0.0.1
2. `AuthRouter` maps the bridge password to a Proton `Session`
3. IMAP reads from `GluonStore` (populated by event sync worker)
4. SMTP encrypts outgoing mail via `crypto` and submits via `api::messages`
5. DAV serves contacts/calendars from `pim` store (populated by PIM sync workers)

### CLI Subcommands (clap)

`login`, `fido-assert`, `status`, `logout`, `accounts`, `fetch`, `serve` (IMAP+SMTP+DAV), `grpc` (frontend service), `cli` (interactive shell), `vault-dump`, `mutt-config`, `optimize-cache`.

## Key Conventions

### Rust Style
- Use `thiserror` for error enums in library code. Use `anyhow` only in `main.rs` / CLI layer.
- Use newtypes for identifiers: `MessageId(String)`, `LabelId(String)`, `AddressId(String)`, etc.
- Use `async/await` for all I/O. Never block the tokio runtime with synchronous calls.
- Use `tracing` for logging, not `println!` or `log`.
- Prefer `&str` over `String` in function parameters where ownership is not needed.
- Use builder pattern for complex request structs.

### Testing
- Write tests first when implementing new functionality.
- Unit tests go in `#[cfg(test)]` blocks within each module.
- Integration tests go in `tests/` directory. Major test suites: `gluon_*` (store behavior, concurrency, corruption recovery, codec), `smtp_integration`, `imap_smtp_tls_integration`, `grpc_wire_contract`, `runtime_events_e2e`, `observability_runtime`, `dav/` (CardDAV/CalDAV integration), `parity/` (event loop, message mutation, checkpoint recovery, sync propagation).
- No network calls in unit tests. Use trait mocks instead.
- Use `wiremock` for API integration tests, `async-imap` for IMAP integration tests, `lettre` for SMTP integration tests.

### Git
- Use conventional commits: `feat:`, `fix:`, `test:`, `refactor:`, `docs:`, `chore:`.
- Keep commits focused. One logical change per commit.
- Do not force push to main.

### What Not to Do
- Do not add features beyond what is currently being worked on.
- Do not add comments explaining obvious code.
- Do not add type annotations where the compiler can infer them.
- Do not create utility/helper modules for one-off functions.
- Do not introduce `unsafe` without explicit discussion.
- No emoji in code, comments, commit messages, or documentation.
- Do not introduce cross-dependencies between `imap`, `smtp`, and `dav` modules.
- Keep `api/` and `crypto/` free of any IMAP/SMTP/DAV concerns.

## Reference Code

SRP authentication is adapted from `../proton-vpn-rst/tunmux/src/proton/api/srp.rs`. The Go bridge at `../proton-bridge/` is the architecture reference.
