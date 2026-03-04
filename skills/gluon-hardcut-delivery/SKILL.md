---
name: gluon-hardcut-delivery
description: Implement and ship full Gluon on-disk file support in openproton-bridge using a hard-cut strategy with no migration. Use when executing BE-016 to BE-033, coordinating parallel worker lanes, enforcing Red-Green-Refactor per ticket, and driving Gluon backend cutover through CI and release gates.
---

# Gluon Hard-Cut Delivery

## Overview
Use this skill to execute the Gluon file-format hard cut in `openproton-bridge` with strict ticket sequencing, test-first delivery, and controlled multi-agent parallelization.

## Load Context
1. Open `docs/GLUON_FULL_SUPPORT_EXECUTION_PLAN.md`.
2. Open `BACKEND_PARITY_IMPLEMENTATION_BACKLOG.md`.
3. Confirm the ticket range in scope is `BE-016` to `BE-033`.
4. Confirm the constraints remain: no migration and no dual-format runtime mode.

If the Gluon plan document is missing, create it before writing code.

## Mandatory Constraints
- Keep Gluon hard cut semantics: no JSON cache migration path.
- Keep one ticket as the unit of delivery unless the user explicitly batches tickets.
- Enforce `Red -> Green -> Refactor` for every ticket.
- Keep lane file ownership strict; do not allow workers to edit foreign-lane files.

## Ticket Execution Workflow
1. Select one ticket with all dependencies satisfied.
2. Write or adapt a failing test that proves the missing behavior.
3. Implement the minimum code to pass the test.
4. Refactor for clarity and maintainability while tests stay green.
5. Run targeted tests for changed modules.
6. Record handoff notes: risks, assumptions, follow-up tickets.

Use `references/checklists.md` for exit criteria.

## Parallel Lane Orchestration
Use these ownership boundaries when running workers in parallel:
- Lane A: `BE-016` to `BE-018` (`docs/`, fixture scripts, fixture manifests)
- Lane B: `BE-021` (codec module + codec tests)
- Lane C: `BE-022` to `BE-023` (locking, atomicity, recovery)
- Lane D: `BE-019`, `BE-020`, `BE-024` to `BE-028` (runtime integration)
- Lane E: `BE-029` to `BE-033` (parity tests, CI gates, release docs)

Follow this start order:
1. Start Lane A immediately.
2. Start Lane D seed work (`BE-019`, `BE-020`) in parallel.
3. Start Lane B after fixture manifest is ready.
4. Start Lane C after codec baseline is green.
5. Finalize Lane E after runtime cutover lands.

## Worker Assignment Template
Use this template when assigning work:

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

## Verification Strategy
Run fast, scoped checks per ticket, then full gates by lane:
1. Run targeted tests for modified modules first.
2. Run full backend parity and Gluon suites at lane boundaries.
3. Run full CI gate before release candidate.

Prefer explicit commands with manifest path:
- `cargo test --manifest-path openproton-bridge/Cargo.toml <target>`
- `cargo test --manifest-path openproton-bridge/Cargo.toml`

## Deployment And Cutover
1. Ship only after `BE-032` CI gate is green.
2. Publish release notes that explicitly state hard cut and no migration support.
3. Keep previous binary available for rollback.
4. If rollback is needed, roll back binary only; do not introduce format migration work in the rollback path.
