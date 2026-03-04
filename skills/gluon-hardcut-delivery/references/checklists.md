# Checklists

## Per-Ticket Exit Checklist
- Dependency tickets are complete.
- Failing test exists before implementation.
- Implementation makes the failing test pass.
- Refactor keeps tests green.
- Targeted tests for changed files pass.
- Handoff notes include risks and follow-ups.

## Lane Exit Checklist
- All lane tickets are merged in dependency order.
- Cross-lane integration tests pass.
- No lane violates file ownership boundaries.
- Open risks are tracked as explicit follow-up tickets.

## Release Candidate Checklist
- `BE-032` CI gate is green.
- Gluon parity and recovery suites pass.
- Release notes state hard-cut/no-migration behavior.
- Rollback procedure references binary rollback only.
