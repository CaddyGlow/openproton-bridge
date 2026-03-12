# Backend Parity Ledger

## Gluon Compatibility Freeze (BE-016)

- Fixture: `tests/fixtures/gluon_compatibility_target.json`
- Frozen on: `2026-03-03`
- Proton Bridge commit: `92305960372cbe7a7e7acf3debb3c19c5e82bfb1`
- Gluon commit: `2046c95ca7455812254eaef2f77da0aaaee3fae1`
- Scope: This ledger tracks the frozen upstream compatibility target that later Gluon parity tickets validate against.

## Current Cutover State

- `BE-017` through `BE-028`: landed in repo
- `BE-029`: partial because sanitized sqlite fixture artifacts are placeholders, so real upstream cache-open parity remains open; a manual private profile/archive gate with optional real blob-decode verification now exists in `tests/gluon_real_fixture.rs`
- `BE-030`: in progress with IMAP, IDLE, and event-worker parity coverage on the Gluon backend
- `BE-031`: in progress with recovery/corruption tests and behavior docs landed; remaining gap is broader cutover confidence rather than missing recovery semantics documentation
- `BE-032`: pending default cutover and CI gate tightening
