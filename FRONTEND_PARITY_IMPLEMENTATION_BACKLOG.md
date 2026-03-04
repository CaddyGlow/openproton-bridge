# Frontend Parity Plan And Concrete Backlog (No Backward Compatibility)

## Scope
- Objective: make `apps/bridge-ui` behavior and visual flows match Proton Bridge UI parity target.
- Constraint: no compatibility UI modes for legacy dashboard/state model.
- Dependency: backend parity event semantics are source of truth.

## Non-Goals
- No support for old dashboard-style UI as alternate experience.
- No UI fallback for missing backend parity events; missing events are backend bugs.

## Mandatory Development Rules
- Test-driven development is required for every ticket.
- Execution model for every backlog item: `Red -> Green -> Refactor`.
- `Red`: add failing UI/state/e2e test first.
- `Green`: implement the smallest change to pass.
- `Refactor`: clean up with all tests still passing.
- Do not merge UI changes without test coverage for new/changed behavior.

## Proton Reference Tests And Specs To Follow
- Treat original Proton UI tests and QML behavior as parity specification.
- Primary parity references:
- `proton-bridge/tests/e2e/ui_tests/windows_os/Tests/SettingsMenuTests.cs`
- `proton-bridge/tests/e2e/ui_tests/windows_os/Tests/ZeroPercentUpdateTest.cs`
- `proton-bridge/tests/e2e/ui_tests/windows_os/Windows/SettingsMenuWindow.cs`
- `proton-bridge/internal/frontend/bridge-gui/bridge-gui/qml/AccountDelegate.qml`
- `proton-bridge/internal/frontend/bridge-gui/bridge-gui/qml/LocalCacheSettings.qml`
- `proton-bridge/internal/frontend/bridge-gui/bridge-gui/qml/SetupWizard/SetupWizard.qml`
- `proton-bridge/internal/frontend/bridge-gui/bridge-gui/qml/SetupWizard/ClientConfigSelector.qml`
- `proton-bridge/internal/frontend/bridge-gui/bridge-gui/qml/SetupWizard/ClientConfigParameters.qml`
- `proton-bridge/internal/frontend/bridge-gui/bridge-gui/qml/SetupWizard/ClientConfigAppleMail.qml`
- `proton-bridge/internal/frontend/bridge-gui/bridge-gui/qml/Notifications/Notifications.qml`
- For each feature, record `reference test/spec -> bridge-ui test` mapping in task/PR notes.

## Definition Of Done (Frontend)
- Screens and flows match reference screenshots in `UI/`.
- UI state is driven by gRPC contract/events, not ad-hoc polling/manual assumptions.
- Sync progress, cache move, and auth flows (2FA/FIDO/HV) work end-to-end.
- Frontend tests and screenshot regressions pass in CI.

## Milestones

## F1 - Parity UX Spec Lock
### Tasks
1. Build explicit screen/state inventory from `UI/` references.
2. Map each visual state to gRPC data/event dependencies.
3. Define acceptance snapshots and interaction scripts per flow.

### Deliverables
- UI parity matrix: screen, state, trigger, expected output.

### Acceptance
- Every required screen/state has defined source-of-truth data and acceptance criteria.

## F2 - Frontend State Architecture Refactor
### Tasks
1. Replace current dashboard-oriented state wiring with event-driven domain store:
- app state
- account/user state
- sync state
- cache/settings operation state
2. Ensure one-way event application from stream to UI state reducers.
3. Remove redundant local state that can diverge from backend.

### Deliverables
- Typed store model and reducer/event mapping docs in code comments.

### Acceptance
- UI remains consistent after reconnect/restart and event replay.

## F3 - Core Navigation And Layout Parity
### Tasks
1. Rebuild primary layout to match target shell:
- account pane
- settings and menu affordances
- wizard/flow transitions
2. Implement responsive behavior for desktop/mobile constraints used by app window.
3. Eliminate placeholder/dev-only surfaces.

### Deliverables
- Final shell/layout components replacing temporary scaffolding.

### Acceptance
- Main app frame and navigation match parity references visually and behaviorally.

## F4 - Authentication Flow Parity
### Tasks
1. Implement complete login journey:
- standard credentials
- two-factor
- FIDO flow
- human verification flow
2. Ensure error and retry states map to gRPC error types.
3. Add explicit loading and cancellation states.

### Deliverables
- Production auth flow components and state machine.

### Acceptance
- All auth branches complete successfully against real backend.

## F5 - Account View And Sync Progress Parity
### Tasks
1. Implement account cards/list states matching reference.
2. Wire sync event handling:
- `SyncStarted` -> syncing state visible
- `SyncProgress` -> percent/progress UI update
- `SyncFinished` -> steady connected state
3. Handle disconnected/error/recovering states from user events.

### Deliverables
- Account screen parity implementation.

### Acceptance
- “Synchronizing (n%)” and transitions behave identically to expected UX timing.

## F6 - Settings And Cache UX Parity
### Tasks
1. Implement settings pages/components for parity options:
- autostart
- telemetry
- DoH
- keychain
- disk cache location
2. Implement disk cache location change UX:
- folder selection
- in-flight loading state
- success/failure notifications from stream events
3. Reflect runtime-effective values after backend operations.

### Deliverables
- Settings parity screens and notifications.

### Acceptance
- Cache move UX mirrors backend async event sequence and error handling.

## F7 - Client Configuration Wizard Parity
### Tasks
1. Implement setup wizard views:
- client selector
- parameter configuration
- end state confirmations
2. Align copy/labels/actions with parity target.
3. Support platform-specific client configuration branches where needed.

### Deliverables
- Wizard flow integrated into main app navigation.

### Acceptance
- Full first-run and per-account client-config flows pass scripted tests.

## F8 - QA, Snapshot, And E2E Parity Gates
### Tasks
1. Add unit tests for state reducers/event mappers.
2. Add integration tests for auth/sync/cache/settings flows.
3. Add screenshot regression baseline aligned with `UI/` references.
4. Add CI gates requiring parity suite pass.

### Deliverables
- Test suites and CI rules.

### Acceptance
- Frontend parity checks pass consistently in CI and local reproducible runs.

## Concrete Backlog (Execution Order)
Note: every `FE-*` item must start by adding failing tests based on Proton references and then implementing to green.

1. `FE-001` Build and commit UI parity matrix from `UI/` screenshots.
2. `FE-002` Define and implement central event-driven store schema.
3. `FE-003` Refactor stream subscription to reducer-based state updates.
4. `FE-004` Replace current app shell/layout with parity shell.
5. `FE-005` Implement login/2FA/FIDO/HV state machine and views.
6. `FE-006` Implement account list/cards with sync progress rendering.
7. `FE-007` Implement settings expanded/collapsed parity components.
8. `FE-008` Implement disk cache settings flow with event-based notifications.
9. `FE-009` Implement client config wizard pages and transitions.
10. `FE-010` Add state reducer unit tests.
11. `FE-011` Add e2e tests for auth, sync progress, and cache move.
12. `FE-012` Add screenshot regression harness and baseline captures.
13. `FE-013` Add CI parity gates and merge checklist.

## Parallel Multi-Agent Execution Plan
## Lane A - State Core And gRPC Mapping
- Scope: `FE-002`, `FE-003`, `FE-010`.
- Files: `apps/bridge-ui/src/lib/*`, `apps/bridge-ui/src-tauri/src/grpc/*`.
- Dependency: backend event schema stable from `BE-001`.

## Lane B - Authentication Flows
- Scope: `FE-005`.
- Files: auth views/state/actions.
- Dependency: lane A base store contracts available.

## Lane C - Account And Sync Progress UI
- Scope: `FE-006`.
- Files: account list/card components, sync progress presentation.
- Dependency: lane A reducers for user/sync events.

## Lane D - Settings And Disk Cache UX
- Scope: `FE-007`, `FE-008`.
- Files: settings components, cache dialogs, notifications wiring.
- Dependency: backend cache event parity (`BE-007`, `BE-008`) available.

## Lane E - Wizard, Visual Parity, And QA
- Scope: `FE-001`, `FE-004`, `FE-009`, `FE-011`, `FE-012`, `FE-013`.
- Files: shell/wizard/visual regression/e2e harness/CI.
- Dependency: can start with `FE-001` immediately; remaining tasks integrate as lanes A-D merge.

## Parallelization Guardrails
- Use file ownership per lane to reduce merge conflicts.
- Require each lane PR to include tests and parity reference mapping.
- Run shared integration branch daily for full e2e + screenshot diff.
- Freeze visual copy/spacing tokens once screenshot baseline is approved to avoid churn.

## Ownership And Sequencing
- Frontend app: `apps/bridge-ui/src/*`.
- Tauri bridge/grpc adapter: `apps/bridge-ui/src-tauri/src/grpc/*`.
- Proto bindings/state typing: `apps/bridge-ui/src/lib/api/*`.
- Start F5/F6 only after backend milestones `BE-011` and `BE-007/BE-008` are stable.

## Risks And Controls
- Risk: UI diverges from backend truth due to optimistic local state.
- Control: reducer-first architecture and stream-driven authoritative state.
- Risk: parity visuals drift over iterations.
- Control: screenshot diff gate tied to approved references.
- Risk: auth edge cases (FIDO/HV) regress.
- Control: dedicated e2e flows for each auth branch.
