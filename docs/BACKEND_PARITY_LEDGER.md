# Backend Parity Ledger

## Gluon Compatibility Freeze (BE-016)

- Fixture: `tests/fixtures/gluon_compatibility_target.json`
- Frozen on: `2026-03-03`
- Proton Bridge commit: `92305960372cbe7a7e7acf3debb3c19c5e82bfb1`
- Gluon commit: `2046c95ca7455812254eaef2f77da0aaaee3fae1`
- Scope: This ledger tracks the frozen upstream compatibility target that later Gluon parity tickets validate against.

## Current Cutover State

- `BE-017` through `BE-028`: landed in repo
- `BE-029`: complete under the current acceptance rule via `tests/gluon_real_fixture.rs`, which validates a private local official-Bridge profile/archive and optionally derives real blob keys from `vault.enc`; the checked-in sanitized fixture remains placeholder-only for file-family coverage
- `BE-030`: in progress with IMAP, IDLE, event-worker parity coverage, explicit compat-helper naming, and a live mail-runtime IMAP probe on the Gluon backend that now covers startup, offline `LOGIN`, authenticated `LIST`/`SELECT`/`FETCH`/`SEARCH`, authenticated `COPY`/`MOVE`/`STORE`/`EXPUNGE` upstream sync, direct connector-driven `IDLE` flag updates, event-worker-driven create/delete updates, and refresh-resync updates surfaced through real IMAP `IDLE`/`NOOP`
- `BE-031`: in progress with recovery/corruption tests and behavior docs landed; the remaining gap is broader cutover confidence rather than missing recovery semantics documentation
- `BE-032`: in progress; IMAP runtime defaults now point at Gluon, legacy `"compat"` settings deserialize as Gluon aliases instead of selecting a separate runtime path, and CI exercises the Gluon parity suites. Remaining work is the final release-candidate checklist and operator-facing cutover docs.
