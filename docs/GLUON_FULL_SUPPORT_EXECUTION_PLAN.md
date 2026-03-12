# Gluon Full Support Execution Plan

## Goal

Replace the custom Rust mail store/runtime path with a Gluon-native architecture that:

- hard-cuts to Gluon-compatible storage semantics
- does not support migration or a dual-format runtime mode
- produces a reusable `gluon-rs-core` foundation for future CardDAV and CalDAV engines
- keeps mail-specific behavior in `gluon-rs-mail`
- converges the bridge onto a Gluon-native IMAP/update model instead of indefinitely extending the current custom IMAP stack

This document is the execution plan for tickets `BE-016` through `BE-033`.

## Non-Negotiable Constraints

- No JSON cache migration path.
- No runtime dual-format mode.
- One ticket is the unit of delivery unless the user explicitly batches tickets.
- Every ticket follows `Red -> Green -> Refactor`.
- Parallel workers must keep owned-file boundaries strict.
- Runtime event publication must use one shared connector instance per runtime.
- `gluon-rs-core` must remain domain-neutral. Mailbox/message semantics live in `gluon-rs-mail`.

## BE-016 Frozen Gluon Compatibility Target

- Fixture: `tests/fixtures/gluon_compatibility_target.json`
- Frozen on: `2026-03-03`
- Proton Bridge commit: `92305960372cbe7a7e7acf3debb3c19c5e82bfb1`
- Gluon commit: `2046c95ca7455812254eaef2f77da0aaaee3fae1`
- Current fixture limitation: `tests/fixtures/proton_profile_gluon_sanitized` still contains placeholder sqlite artifacts for file-family coverage, but `BE-029` is now satisfied by the private local official-Bridge fixture gate in `tests/gluon_real_fixture.rs`.

## Target Architecture

### `crates/gluon-rs-core`

Owns generic local-engine infrastructure:

- encrypted blob storage
- sqlite lifecycle/open modes
- transactional journal and recovery
- lock management
- account/bootstrap/key handling
- generic watcher/update bus primitives
- shared path/layout helpers that are not mail-specific

Must not own:

- mailbox schemas
- UID/mod-seq logic
- IMAP command/state logic
- CardDAV or CalDAV resource models

### `crates/gluon-rs-mail`

Owns the mail domain:

- Gluon-compatible mail schema/store semantics
- mailbox/message read and mutation APIs
- Gluon-style update model
- bridge adapter surface for current IMAP/event runtime
- future Gluon-native mail engine

### Future DAV Domain Crates

Planned after mail cutover:

- `gluon-rs-contacts`
- `gluon-rs-calendar`

These reuse `gluon-rs-core` infra only, not mail semantics.

## Ticket Map

| Ticket | Scope | Depends On | Lane |
|---|---|---|---|
| `BE-016` | crate split design and execution doc | none | A |
| `BE-017` | extract `gluon-rs-core` shared modules | `BE-016` | A |
| `BE-018` | fixture manifest, upstream capture scripts, plan/backlog sync | `BE-016` | A |
| `BE-019` | runtime bootstrap passes full Gluon bootstrap and keys | `BE-016` | D |
| `BE-020` | shared runtime connector/update bus wiring | `BE-016` | D |
| `BE-021` | strict blob codec module and codec tests in core | `BE-017`, `BE-018` | B |
| `BE-022` | lock manager parity and cross-process safety | `BE-017`, `BE-021` | C |
| `BE-023` | atomicity/recovery parity and staged sqlite commit model | `BE-017`, `BE-021`, `BE-022` | C |
| `BE-024` | `gluon-rs-mail` read adapter for bridge interfaces | `BE-017`, `BE-019`, `BE-020` | D |
| `BE-025` | `gluon-rs-mail` mutation adapter for bridge interfaces | `BE-024` | D |
| `BE-026` | event worker integration on mail adapter and shared connector | `BE-020`, `BE-025` | D |
| `BE-027` | IMAP read-path cutover to `gluon-rs-mail` backend | `BE-024` | D |
| `BE-028` | IMAP mutation-path cutover and backend flag | `BE-025`, `BE-027` | D |
| `BE-029` | upstream fixture validation and cache-open parity suite | `BE-018`, `BE-021`, `BE-023`, `BE-028` | E |
| `BE-030` | IMAP/IDLE/update parity suite on new backend | `BE-026`, `BE-028` | E |
| `BE-031` | crash/recovery/corruption suite on new backend | `BE-023`, `BE-028` | E |
| `BE-032` | CI gate and default cutover readiness | `BE-029`, `BE-030`, `BE-031` | E |
| `BE-033` | release notes, rollback guidance, operator docs | `BE-032` | E |

## Current Status As Of 2026-03-12

- `BE-017` through `BE-028` are effectively implemented in the repo. The Gluon-backed read, mutation, connector, runtime selection, and event-worker paths exist and are covered by focused tests.
- `BE-029` is complete under the current acceptance rule. File-family capture, manifest checks, schema assertions, and unsupported-case documentation remain in place for the checked-in sanitized fixture, and `tests/gluon_real_fixture.rs` now proves cache-open parity plus real blob decode against a private local official Bridge fixture.
- The private-fixture parity harness accepts either `OPENPROTON_REAL_GLUON_PROFILE=/path/to/bridge-v3` or `OPENPROTON_REAL_GLUON_ARCHIVE=/path/to/profile.tar`, and it can also take `OPENPROTON_REAL_VAULT_KEY` (or legacy alias `OPENPROTON_REAL_GLUON_KEY`) to decrypt `vault.enc`, derive real per-account `gluon_key` bindings, and verify real blob decryption without checking secrets or fixture payloads into the repo.
- `BE-030` is in progress. IMAP read/mutation/IDLE parity and multiple event-worker Gluon paths are covered, compat-only IMAP helpers are explicitly named, and there is now a live mail-runtime IMAP probe on the Gluon defaults that exercises startup, offline `LOGIN`, authenticated `LIST`/`SELECT`/`FETCH`/`SEARCH`, authenticated `COPY`/`MOVE`/`STORE`/`EXPUNGE` upstream sync, direct connector-driven `IDLE` flag updates, event-worker-driven create/delete updates, and refresh-resync updates surfaced through real IMAP `IDLE`/`NOOP`. The remaining gap is narrower release/cutover confidence rather than missing core runtime protocol coverage.
- `BE-031` is in progress. Recovery and corruption suites cover interrupted transaction replay, cache-move rollback recovery, missing-blob repair, partial-sqlite fallback, and the corresponding corruption behavior docs are landed. The remaining gap is broader cutover confidence rather than missing recovery documentation.
- `BE-032` is in progress. CI coverage exists for the Gluon backend and the runtime now defaults IMAP read and mutation backends to Gluon, but release-candidate cutover criteria and compat-path retirement are not complete.

## Lane Ownership

### Lane A: foundation and docs

Owned files:

- `docs/GLUON_FULL_SUPPORT_EXECUTION_PLAN.md`
- `docs/parity/*` when touched for Gluon cutover
- fixture scripts and manifests
- crate manifests for `crates/gluon-rs-core` and `crates/gluon-rs-mail`
- module moves from current `crates/gluon-rs` into the split crates

Must not edit:

- `src/imap/session.rs`
- `src/bridge/events.rs`
- `src/bridge/mail_runtime.rs`

### Lane B: codec

Owned files:

- `crates/gluon-rs-core/src/blob.rs`
- codec-focused tests

Must not edit:

- bridge runtime files
- IMAP session files
- event worker files

### Lane C: locking, atomicity, recovery

Owned files:

- `crates/gluon-rs-core/src/txn.rs`
- `crates/gluon-rs-core/src/lock.rs`
- `src/imap/gluon_txn.rs` only until old store is retired
- recovery-focused tests

Must not edit:

- IMAP session logic
- connector/update translation logic

### Lane D: runtime integration

Owned files:

- `src/bridge/mail_runtime.rs`
- `src/bridge/events.rs`
- `src/imap/gluon_connector.rs`
- `src/imap/mailbox_view.rs`
- `src/imap/mailbox_mutation.rs`
- `src/imap/mailbox_catalog.rs`
- new adapter modules bridging current runtime to `gluon-rs-mail`

Must not edit:

- codec internals
- fixture capture scripts
- CI/release docs except when explicitly needed for the current ticket

### Lane E: parity, CI, release

Owned files:

- `tests/gluon_*`
- `tests/runtime_events_e2e.rs`
- IMAP parity tests
- `.github/workflows/*` only for cutover gates
- release/operator docs

Must not edit:

- core codec and recovery code unless a bug fix is handed back to the owning lane

## Recommended Parallel Waves

### Wave 0

- `BE-016` Lane A
- `BE-019` Lane D
- `BE-020` Lane D

Objective:

- lock architecture and bootstrap/update boundaries before lower-level work branches

### Wave 1

- `BE-017` Lane A
- `BE-018` Lane A

Objective:

- split current `gluon-rs` into core and mail crates
- freeze fixture and upstream reference inputs

### Wave 2

- `BE-021` Lane B
- `BE-022` Lane C

Objective:

- finish core blob and lock semantics on the split crate layout

### Wave 3

- `BE-023` Lane C
- `BE-024` Lane D

Objective:

- finish recovery model
- land first read-only bridge adapter

### Wave 4

- `BE-025` Lane D
- `BE-026` Lane D
- `BE-027` Lane D

Objective:

- make the mail adapter write-capable and runtime-driven

### Wave 5

- `BE-028` Lane D
- `BE-029` Lane E
- `BE-030` Lane E
- `BE-031` Lane E

Objective:

- complete backend switch
- prove parity and failure behavior

### Wave 6

- `BE-032` Lane E
- `BE-033` Lane E

Objective:

- CI and release readiness

## Detailed Ticket Definitions

### `BE-016` Define split and package boundaries

Outcome:

- repo-level design for `gluon-rs-core` and `gluon-rs-mail`
- explicit module move list from current `crates/gluon-rs`
- documented bridge integration boundary

Deliverables:

- this plan file updated and accepted
- crate/module map
- ownership notes for all later tickets

Required tests:

- none beyond doc consistency checks

### `BE-017` Extract `gluon-rs-core`

Outcome:

- move generic infra out of current monolithic `gluon-rs`

Target modules:

- blob codec
- txn/deferred delete
- locking
- bootstrap/key helpers
- generic path/layout helpers

Deliverables:

- `crates/gluon-rs-core`
- `crates/gluon-rs-mail` depending on core
- tests moved with code ownership

Required tests:

- `cargo test --manifest-path crates/gluon-rs-core/Cargo.toml`
- `cargo test --manifest-path crates/gluon-rs-mail/Cargo.toml`

### `BE-018` Fixture and reference baseline

Outcome:

- frozen upstream compatibility target and reproducible fixture generation

Deliverables:

- fixture manifest
- capture scripts
- reference docs for which upstream commit and Proton Bridge artifact set are canonical

Required tests:

- fixture manifest validation tests

### `BE-019` Runtime bootstrap uses full Gluon bootstrap

Outcome:

- runtime no longer initializes mail backend with storage IDs alone

Deliverables:

- full account bootstrap handed from vault/runtime into backend init
- keys available where blob/store code actually needs them

Required tests:

- runtime bootstrap tests
- account/key binding tests

### `BE-020` Shared connector/update bus contract

Outcome:

- one connector instance per runtime
- IMAP, event workers, and future JMAP watch the same update stream

Deliverables:

- no duplicated authored-update buses
- explicit runtime wiring test

Required tests:

- connector tests
- IDLE/update notification tests

### `BE-021` Strict blob codec in core

Outcome:

- production codec lives in `gluon-rs-core`
- clear error semantics on corruption

Deliverables:

- encode/decode implementation
- corruption/truncation tests
- interop statement in docs if format intentionally diverges from old drafts

Required tests:

- core blob tests

### `BE-022` Lock parity

Outcome:

- safe cross-process writer/read coordination

Deliverables:

- lock manager in core
- contention tests
- stale-lock handling policy

Required tests:

- lock and contention suites

### `BE-023` Recovery and atomicity parity

Outcome:

- staged writes and exact deletes recover as one unit
- sqlite snapshot and blob writes commit together

Deliverables:

- recovery journal model in core
- store integration on the bridge side until old store is removed
- corruption detection behavior

Required tests:

- txn tests
- recovery integration tests
- corruption tests

### `BE-024` Read-only bridge adapter

Outcome:

- current IMAP-facing read abstractions can read from `gluon-rs-mail`

Deliverables:

- adapter implementing mailbox catalog/view traits
- runtime can start in read-only adapter mode behind a flag

Required tests:

- mailbox view tests
- select/status/fetch/search coverage on adapter backend

### `BE-025` Mutation bridge adapter

Outcome:

- current IMAP-facing mutation abstractions can write through `gluon-rs-mail`

Deliverables:

- adapter implementing mutation trait surface
- copy/move/expunge/store/append parity on adapter backend

Required tests:

- mutation tests
- copy/move/expunge targeted suites

### `BE-026` Event worker integration on mail adapter

Outcome:

- Proton event loop mutates the `gluon-rs-mail` backend and publishes updates on the shared connector

Deliverables:

- event worker path no longer depends on legacy store-specific assumptions
- empty-label topology changes still notify IMAP/JMAP watchers

Required tests:

- event worker tests
- label topology update tests
- IDLE refresh coverage

### `BE-027` IMAP read-path cutover

Outcome:

- read-heavy IMAP operations run on the new backend

Deliverables:

- select/examine/status/fetch/search read via adapter

Required tests:

- IMAP read suites
- store-read parity suites

### `BE-028` IMAP mutation-path cutover

Outcome:

- mutation-heavy IMAP operations run on the new backend
- runtime feature/config switch exists

Deliverables:

- append/store/copy/move/expunge use adapter
- Gluon is the default runtime backend, with compat retained only as rollback wiring

Required tests:

- IMAP mutation suites
- runtime integration tests

### `BE-029` Upstream fixture parity

Outcome:

- `gluon-rs-mail` can open and validate real upstream fixture sets used as the compatibility target

Deliverables:

- fixture-open tests
- schema/version assertions
- documented unsupported cases if any remain
- manual private-profile/archive gate over an official Bridge fixture kept outside the repo

Required tests:

- `tests/gluon_*`

### `BE-030` Protocol/update parity gate

Outcome:

- IDLE and update propagation semantics are proven on the new backend

Deliverables:

- parity tests covering message and mailbox topology changes
- no split connector paths

Required tests:

- IDLE/event/runtime suites

### `BE-031` Recovery/corruption gate

Outcome:

- crashes and corrupted artifacts fail or recover in controlled, tested ways

Deliverables:

- recovery matrix coverage
- corruption behavior docs

Required tests:

- recovery and corruption suites

### `BE-032` CI cutover gate

Outcome:

- new backend is green in CI and default cutover can be defended with explicit rollback guidance

Deliverables:

- CI jobs/gates updated
- release-candidate acceptance checklist complete

Required tests:

- full backend suite
- parity suite
- targeted runtime integration suite

### `BE-033` Release and rollback docs

Outcome:

- operator-facing release notes and rollback guidance exist for the hard cut

Deliverables:

- release notes
- explicit no-migration statement
- rollback guidance says rollback binary only

Required tests:

- docs review

## Worker Assignment Template

Use this exact format when spawning a worker:

```text
You own ticket <BE-XXX>.
Scope: <one paragraph>.
Owned files: <explicit list>.
Non-owned files: do not edit.
Required workflow: Red -> Green -> Refactor.
Deliverables:
1) failing test commit
2) implementation commit
3) optional refactor commit
Verification: run <exact test commands>.
Handoff: include risks, assumptions, and follow-up needed by main agent.
```

## Exit Criteria Per Ticket

- failing test existed first or the handoff explains why an existing failing test already covered the gap
- implementation is minimal and passes targeted tests
- no foreign-lane files edited
- no hidden runtime dual-format logic added
- handoff includes:
  - user-visible behavior
  - risks
  - assumptions
  - follow-up ticket if scope was intentionally narrowed

## Cutover Readiness Gate

Keep compat rollback wiring available until all are true:

- `BE-029` green
- `BE-030` green
- `BE-031` green
- no known connector split-brain paths remain
- no legacy JSON store writes remain in the runtime path

## Post-Cutover Follow-Up

After `BE-033`, open a new plan for:

- `gluon-rs-mail` native IMAP engine replacing the transitional custom IMAP runtime
- `gluon-rs-contacts`
- `gluon-rs-calendar`
- DAV adapters over shared `gluon-rs-core`
