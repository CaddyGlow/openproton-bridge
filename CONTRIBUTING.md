# Contributing to openproton-bridge

## Development Setup

### With Nix (recommended)

A `flake.nix` is provided that supplies Rust, protoc, bun, and all Linux UI
libraries (GTK3, WebKitGTK, libsoup, cairo, pango, appindicator):

```bash
nix develop
cargo build
cargo test
```

### Without Nix

1. Install Rust 1.75+ via [rustup](https://rustup.rs/)
2. Install system dependencies for the Tauri frontend:
   - **Linux:** `libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-3.0-dev libayatana-appindicator3-dev`
   - **macOS/Windows:** no extra system packages needed
3. Install [bun](https://bun.sh/) for the frontend JS tooling
4. Clone the repository
5. `cargo build` to verify the toolchain works
6. `cargo test` to run the test suite

### Build Targets

| Target | Command | Description |
|--------|---------|-------------|
| Backend binary | `cargo build --release` | Standalone IMAP/SMTP/gRPC server |
| Frontend binary | `cd apps/bridge-ui && bun install && bun run tauri:build` | Standalone Tauri GUI (connects via gRPC) |
| Combined binary | `cd apps/bridge-ui/src-tauri && cargo build --release --features embed-backend` | GUI with embedded backend in one process |

The `embed-backend` feature adds `openproton-bridge` as a dependency of the
Tauri crate. The embedded backend acquires the instance lock on startup, so it
cannot run alongside a standalone `openproton-bridge grpc` process.

## Code Style

- Run `cargo fmt` before committing. No exceptions.
- Run `cargo clippy` and fix all warnings before committing.
- Follow standard Rust naming conventions (snake_case for functions/variables, CamelCase for types/traits).

## Commit Messages

Use conventional commits:

```
feat: add IMAP IDLE support
fix: handle expired refresh tokens gracefully
test: add SRP proof test vectors from Go reference
refactor: extract mailbox label mapping into its own module
docs: update README with SMTP configuration
```

Keep the subject line under 72 characters. Use the body for context on *why*, not *what*.

## Testing

This project follows test-driven development. The expectation is:

1. **Write the test first.** Define what the function should do before implementing it.
2. **Unit tests live next to the code** in `#[cfg(test)]` blocks within each module.
3. **Integration tests live in `tests/`** and exercise multiple modules together.
4. **No network in unit tests.** All external dependencies (HTTP, filesystem) are behind traits. Tests use in-process mocks.
5. **Every code path that can fail has a test.** No numeric coverage target, but error paths matter as much as happy paths.

### Running tests

```
# All tests
cargo test
# opt in to real system keychain access in tests
OPENPROTON_TEST_ENABLE_SYSTEM_KEYCHAIN=1 cargo test

# Single module
cargo test api::srp

# Integration tests only
cargo test --test auth_integration

# With output
cargo test -- --nocapture
```

Credential-store test default:

- Test binaries force credential backend `auto/system` to file mode to avoid macOS/OS keychain authorization prompts.
- Set `OPENPROTON_TEST_ENABLE_SYSTEM_KEYCHAIN=1` when you explicitly want keychain-backed test behavior.
- The runtime keychain integration is behind the Cargo feature `system-keychain` (enabled by default). Use `--no-default-features` to disable it.

### Test dependencies

- `wiremock` -- mock HTTP server for API tests
- `async-imap` -- IMAP client for IMAP server integration tests
- `lettre` -- SMTP client for SMTP server integration tests
- `tempfile` -- temporary directories for storage tests
- `assert_matches` -- pattern matching assertions

## Project Structure

```
src/
  api/          Proton REST API client
  crypto/       PGP operations (sequoia-openpgp)
  imap/         Local IMAP server
  smtp/         Local SMTP server
  bridge/       Daemon orchestration, config, sync
tests/          Integration tests
```

Each module has a clear responsibility. Cross-module dependencies flow downward:

```
bridge -> imap, smtp, api, crypto
imap   -> api (trait), crypto (trait)
smtp   -> api (trait), crypto (trait)
api    -> (standalone, no internal deps)
crypto -> (standalone, no internal deps)
```

## Design Principles

- **Trait boundaries for testability.** `ProtonApi`, `CryptoProvider`, and `MessageStore` traits allow mocking in tests without network or external services.
- **Newtypes for IDs.** `MessageId(String)`, `LabelId(String)`, etc. prevent mixing up string identifiers.
- **No over-abstraction.** If a function is used once, do not extract it into a helper. Extract only on actual reuse.
- **Async throughout.** All I/O uses tokio async/await. No blocking calls on the async runtime.
- **Errors as enums.** Use `thiserror` for typed error enums. Reserve `anyhow` for the top-level CLI only.

## Pull Requests

- Keep PRs focused on a single concern.
- Include tests for new functionality.
- Update PLAN.md if the change affects the roadmap.
- Ensure `cargo test`, `cargo fmt --check`, and `cargo clippy` all pass.
