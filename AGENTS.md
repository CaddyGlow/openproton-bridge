# Repository Guidelines

## Project Structure & Module Organization
- `src/` contains the Rust bridge implementation.
- `src/api/` handles Proton REST calls (auth, users, messages).
- `src/crypto/` handles key unlock/decrypt logic.
- `src/imap/` and `src/smtp/` implement local mail protocols.
- `src/bridge/` and `src/vault.rs` coordinate session/config state.
- `src/main.rs` defines the CLI; `src/lib.rs` exposes modules for testing.
- `tests/` is reserved for Rust integration tests (currently minimal); most tests are inline in module files under `#[cfg(test)]`.
- Reference implementation context lives in the sibling directory `../proton-bridge` (outside this repo) for behavior/parity checks.

## Build, Test, and Development Commands
- `cargo build` builds debug binaries.
- `cargo build --release` builds optimized binaries.
- `cargo test` runs the Rust test suite.
- `cargo test api::srp` runs a focused test target.
- `cargo fmt --check` verifies formatting.
- `cargo clippy --all-targets --all-features -D warnings` enforces lint cleanliness.
- `cargo run -- serve --imap-port 1143` starts the local IMAP service.

## Coding Style & Naming Conventions
- Rust edition: 2021; use idiomatic Rust with 4-space indentation.
- Naming: `snake_case` for functions/variables/modules, `CamelCase` for types/traits, `SCREAMING_SNAKE_CASE` for constants.
- Prefer `thiserror` enums in library code; keep `anyhow` at CLI boundaries.
- Use `tracing` for logs; avoid blocking operations on the Tokio runtime.

## Testing Guidelines
- Add/extend unit tests alongside code (`#[cfg(test)] mod tests`).
- Put cross-module behavior tests in `tests/` with descriptive names (example: `auth_integration.rs`).
- Cover both success and failure paths; mock external HTTP with `wiremock`.
- Run `cargo test`, `cargo fmt --check`, and clippy before opening a PR.

## Commit & Pull Request Guidelines
- Follow Conventional Commits (`feat:`, `fix:`, `test:`, `refactor:`, `docs:`, `chore:`), subject line under 72 chars.
- Keep PRs scoped to one concern and explain the behavioral change.
- Include or update tests with code changes.
- Update `PLAN.md` when roadmap/phase status is affected.
