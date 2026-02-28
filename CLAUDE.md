# Claude Code Instructions for openproton-bridge

## Project Overview

Rust implementation of a Proton Mail bridge. Exposes local IMAP/SMTP servers to let standard email clients access Proton Mail (including free accounts). Single-crate project, single developer, test-driven.

## Key Conventions

### Rust Style
- Always run `cargo fmt` and `cargo clippy` before finishing work.
- Use `thiserror` for error enums in library code. Use `anyhow` only in `main.rs` / CLI layer.
- Use newtypes for identifiers: `MessageId(String)`, `LabelId(String)`, `AddressId(String)`, etc.
- Use `async/await` for all I/O. Never block the tokio runtime with synchronous calls.
- Use `tracing` for logging, not `println!` or `log`.
- Prefer `&str` over `String` in function parameters where ownership is not needed.
- Use builder pattern for complex request structs.

### Testing
- Write tests first when implementing new functionality.
- Unit tests go in `#[cfg(test)]` blocks within each module.
- Integration tests go in `tests/` directory.
- No network calls in unit tests. Use trait mocks instead.
- Use `wiremock` for API integration tests, `async-imap` for IMAP integration tests, `lettre` for SMTP integration tests.
- Test every error path, not just happy paths.

### Architecture
- External dependencies (HTTP, PGP, storage) sit behind traits (`ProtonApi`, `CryptoProvider`, `MessageStore`).
- Module dependency flow: `bridge -> imap, smtp, api, crypto`. `api` and `crypto` are standalone.
- Do not introduce cross-dependencies between `imap` and `smtp` modules.
- Keep `api/` and `crypto/` free of any IMAP/SMTP concerns.

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

## Reference Code

SRP authentication is adapted from `../proton-vpn-rst/tunmux/src/proton/api/srp.rs`. The Go bridge at `../proton-bridge/` is the architecture reference. See `PLAN.md` for the full implementation plan and phase breakdown.

## File Layout

```
src/
  main.rs         CLI entry point (clap)
  lib.rs          Re-exports for integration tests
  api/            Proton REST API client (auth, messages, labels, events)
  crypto/         PGP key management, encrypt/decrypt (sequoia-openpgp)
  imap/           Local IMAP4rev1 server
  smtp/           Local SMTP server
  bridge/         Config, vault, sync engine, user management
tests/            Integration tests
```
