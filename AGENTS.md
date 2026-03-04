# Repository Guidelines

## Project Structure & Module Organization
- `src/` contains the Rust bridge backend.
- `src/api/` handles Proton REST calls (auth, users, keys, messages, events).
- `src/crypto/` handles key unlock/decrypt/encrypt logic.
- `src/imap/` and `src/smtp/` implement local mail protocols and store integration.
- `src/bridge/` coordinates runtime account/session orchestration.
- `src/vault.rs` implements encrypted vault + credential store/keychain backend logic.
- `src/frontend/grpc/` implements the gRPC control surface used by desktop UI/runtime clients.
- `src/main.rs` defines the CLI entrypoint; `src/lib.rs` exposes modules for integration tests.
- `tests/` contains a broad integration/parity suite (IMAP/SMTP, gRPC wire contract, vault/gluon fixtures, observability).
- `apps/bridge-ui/` contains the Tauri + Svelte desktop UI (`src-tauri/` + frontend app).
- `docs/` contains runbooks and release/deployment docs.
- CI workflows live in `.github/workflows/`:
  - `ci-release.yml` for backend tests + release artifact pipeline.
  - `bridge-ui-desktop-build.yml` for desktop UI build/typecheck/test coverage.
- Reference implementation context lives in sibling `../proton-bridge` for behavior/parity checks.

## Build, Test, and Development Commands
- `cargo build` builds debug binaries.
- `cargo build --release` builds optimized binaries.
- `cargo test --locked` runs the Rust test suite (same baseline as CI).
- `cargo test api::srp` runs a focused backend target.
- `OPENPROTON_CREDENTIAL_STORE=file cargo test --locked` forces file credential store (useful in headless/no-keyring environments).
- `cargo fmt --check` verifies formatting.
- `cargo clippy --all-targets --all-features -D warnings` enforces lint cleanliness.
- `cargo run -- serve --imap-port 1143 --smtp-port 1025` starts local mail services.
- UI workflow (from `apps/bridge-ui/`):
  - `bun install`
  - `bun run check`
  - `bun run test:run`
  - `bun run tauri:build --debug --no-bundle --ci`

## Coding Style & Naming Conventions
- Rust edition: 2021; use idiomatic Rust with 4-space indentation.
- Naming: `snake_case` for functions/variables/modules, `CamelCase` for types/traits, `SCREAMING_SNAKE_CASE` for constants.
- Prefer `thiserror` enums in library code; keep `anyhow` at CLI boundaries.
- Use `tracing` for logs; avoid blocking operations on the Tokio runtime.

## Testing Guidelines
- Add/extend unit tests alongside code (`#[cfg(test)] mod tests`).
- Put cross-module behavior tests in `tests/` with descriptive names (IMAP/SMTP, gRPC, vault/gluon, runtime events).
- Reuse fixture assets in `tests/fixtures/` and `tests/parity/fixtures/` where possible.
- Cover both success and failure paths; mock external HTTP with `wiremock`.
- Run `cargo test --locked`, `cargo fmt --check`, and clippy before opening a PR.
- For CI/headless environments without OS keyring, use file credential store (`OPENPROTON_CREDENTIAL_STORE=file`).

## Commit & Pull Request Guidelines
- Follow Conventional Commits (`feat:`, `fix:`, `test:`, `refactor:`, `docs:`, `chore:`), subject line under 72 chars.
- Keep PRs scoped to one concern and explain the behavioral change.
- Include or update tests with code changes.
- Update related docs/runbooks in `docs/` and `README.md` when behavior, CI, or operator workflows change.
