# Bridge UI Parity Merge Checklist (FE-013)

Use this checklist before merging parity-impacting `apps/bridge-ui` changes.

## Scope and mapping
- [ ] Updated `docs/workflows/bridge-ui-parity-matrix.md` if any screen/state/trigger changed.
- [ ] Every changed UI state has a parity ID (`PM-UI-*`) and test mapping entry.
- [ ] New parity-critical behavior includes deterministic fixture query params in `src/visual/VisualScenarios.svelte`.

## Test gates
- [ ] `bun run check` passes.
- [ ] `bun run test:run` passes.
- [ ] `bun run test:parity` passes.
- [ ] `bun run test:visual` passes without unexpected diffs.

## Snapshot policy
- [ ] Snapshot updates are only from deterministic fixture routes (`/__visual__?...`).
- [ ] Snapshot diffs were reviewed against parity targets in `UI/`.
- [ ] If snapshot changes are intentional, matrix rows were updated and reason noted in PR description.

## CI and PR hygiene
- [ ] `.github/workflows/bridge-ui-parity.yml` remains green on the branch.
- [ ] PR description includes parity IDs touched and command output summary.
- [ ] No edits to `apps/bridge-ui/src/App.svelte` for fixture/harness-only parity tasks.
