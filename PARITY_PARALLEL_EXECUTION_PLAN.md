# OpenProton 1:1 Parity Execution Plan (Parallel Worker Ready)

## Objective
- Deliver 1:1 parity with `go-proton-api` and `proton-bridge` for:
- Store data compatibility (read/write interoperability).
- Runtime interfaces (IMAP/SMTP/gRPC behavior and wire compatibility).
- Event and API semantics.
- Debuggability (logs, crash pipeline, telemetry parity level).

## Scope Priority
- This plan follows the "implement top blockers now" path.
- P0 blockers must land first before broad feature parity.

## Non-Negotiable Acceptance Gates
- Existing Proton Bridge profile data loads and works without manual conversion.
- IMAP/SMTP auth + TLS behavior matches Proton Bridge client expectations.
- gRPC login + event stream are wire-compatible with Proton Bridge frontend expectations.
- Core API/event semantics match `go-proton-api` behavior (including auth refresh and event shape).
- Logs support parity-grade support/debug workflows (sessionized logs, rotation, crash capture path).

## Delivery Strategy
- Use short sequential "waves" with explicit parallel lanes.
- Each lane has strict file ownership to reduce merge conflicts.
- Every task uses `Red -> Green -> Refactor` with parity tests first.

---

## Wave 0 (Sequential, 1-2 days): Safety Rails + Parity Test Harness

### W0.1 Build parity fixtures and test matrix
- Add fixtures for:
- Proton vault samples (v2.3/v2.4/current).
- Event payload variants (`Event` single object and `Events[]` forms).
- gRPC login payload samples (base64 password, 2-password flow).
- IMAP/SMTP TLS handshake scripts.
- Files:
- `tests/parity/fixtures/*`
- `tests/parity_matrix.rs` (new)

### W0.2 Define CI parity gates (soft fail initially)
- Add dedicated commands:
- `cargo test parity_store_interop`
- `cargo test parity_api_event`
- `cargo test parity_grpc_wire`
- `cargo test parity_imap_smtp_tls`
- `cargo test parity_observability`

### Exit criteria
- Failing tests exist for all current P0/P1 blockers.
- Baseline report stored as artifact.

---

## Wave 1 (Parallel, highest priority): Store + Protocol Hard Breaks

### Lane A (Worker A): Vault/store compatibility core
Owner files:
- `src/vault.rs`
- `src/paths.rs` (only if needed for vault path parity)
- `tests/parity_store_interop.rs` (new)

Tasks:
1. Implement vault version migration pipeline compatible with Proton versions.
2. Fix bridge password binary handling (`Vec<u8>` semantics, no lossy UTF-8 path).
3. Align keychain/file-key precedence and insecure fallback behavior with Proton model.
4. Align `migrated` lifecycle handling.
5. Align cookie persistence behavior through vault lifecycle.
6. Align cert persistence model or add compatibility bridge layer.
7. Align password archive behavior on account delete/re-add.

Validation:
- Read Proton-created vaults.
- Write vault and reopen in Proton Bridge compatibility test harness.

### Lane B (Worker B): IMAP/SMTP TLS and auth protocol parity
Owner files:
- `src/imap/server.rs`
- `src/imap/session.rs`
- `src/smtp/server.rs`
- `src/smtp/session.rs`
- `tests/parity_imap_smtp_tls.rs` (new)

Tasks:
1. Implement real IMAP STARTTLS upgrade flow (socket -> TLS stream swap).
2. Implement SMTP STARTTLS or equivalent TLS listener mode parity as Proton expects.
3. Ensure runtime actually consumes TLS settings (not loaded-only).
4. Add SMTP SASL `LOGIN` parity alongside `PLAIN`.
5. Validate capability advertisement reflects actual enabled features.

Validation:
- Scripted STARTTLS negotiation tests.
- Real client compatibility smoke tests.

### Lane C (Worker C): gRPC login wire compatibility
Owner files:
- `proto/bridge.proto`
- `src/frontend/grpc/rpc.rs`
- `src/frontend/grpc/service.rs`
- `tests/parity_grpc_wire.rs` (new)

Tasks:
1. Align password encoding behavior (base64 decode path parity).
2. Implement proper 2-password login stage (not aliasing to single login).
3. Align emitted login event sequencing and payloads.
4. Reconcile proto drift fields with upstream compatibility policy.

Validation:
- Wire-level request/response conformance tests using protobuf fixtures.

### Wave 1 integration order
1. Lane A merges first (store format is foundational).
2. Lane B and C can merge in parallel after rebasing to latest main.

### Wave 1 exit criteria
- No failing P0 tests in store/TLS/login wire categories.

---

## Wave 2 (Parallel): API/Event Semantics and Runtime Behavior

### Lane D (Worker D): API client semantics parity (`go-proton-api`)
Owner files:
- `src/api/client.rs`
- `src/api/types.rs`
- `src/api/messages.rs`
- `src/api/mod.rs`
- `src/crypto/keys.rs`
- `tests/parity_api_event.rs` (extend)

Tasks:
1. Support both event payload shapes (`Event` and `Events[]`) safely.
2. Add HTTP 401 refresh/retry semantics parity.
3. Add `PasswordMode` and related auth flow data model.
4. Fix attachment fetch error handling (status + API error parse path).
5. Add stale-aware metadata paging behavior.
6. Add missing endpoint support used by Proton Bridge (`AuthDelete`, labels, org data, data event).
7. Add transient retry policy parity (including rate-limit behavior).
8. Add token signature verification parity in key unlock flow.

### Lane E (Worker E): Runtime settings + event stream parity
Owner files:
- `src/frontend/grpc/rpc.rs`
- `src/frontend/grpc/service.rs`
- `src/main.rs`
- `src/bridge/events.rs`
- `tests/parity_runtime_events.rs` (new)

Tasks:
1. Ensure `SetMailServerSettings` applies live runtime restart behavior.
2. Expand gRPC event mapping to parity set (connection/update/tls/all-users-loaded/etc.).
3. Fill missing runtime operations (`CheckUpdate`, Apple Mail config behavior or explicit compatibility handling).
4. Ensure event ordering and terminal notifications match Proton behavior.

### Wave 2 integration order
1. Lane D and E merge independently.
2. Final pass resolves overlaps in `src/frontend/grpc/rpc.rs`.

### Wave 2 exit criteria
- API/event parity tests green for all previously identified high blockers.

---

## Wave 3 (Parallel): Observability and Debuggability Parity

### Lane F (Worker F): Logging lifecycle + sensitive logging controls
Owner files:
- `src/main.rs`
- `src/paths.rs`
- `src/imap/session.rs`
- `src/smtp/session.rs`
- `src/api/client.rs`
- `tests/parity_observability.rs` (new)

Tasks:
1. Implement sessionized log files with rotation/pruning parity.
2. Add support log bundle generation path compatibility.
3. Add sensitive logging controls with explicit opt-in and redaction defaults.
4. Add per-session/per-connection correlation IDs and structured spans.

### Lane G (Worker G): Crash + telemetry + debug commands
Owner files:
- `src/main.rs`
- `src/frontend/grpc/rpc.rs`
- `src/frontend/grpc/service.rs`
- `tests/parity_observability.rs` (extend)

Tasks:
1. Add crash capture pipeline parity (panic hooks, artifacts, report path).
2. Add parity-grade telemetry hooks (heartbeat/repair signals where required).
3. Implement `debug mailbox-state` parity diagnostics.
4. Add instrumentation for event stream drops and critical error transitions.

### Wave 3 exit criteria
- Support/debug workflows produce equivalent actionable diagnostics.

---

## Worker Instructions Template (Copy/Paste For Each Parallel Worker)

Use this instruction block when spawning workers:

1. You own only the listed files for your lane.
2. You are not alone in the codebase; ignore unrelated edits by other workers and do not revert them.
3. Start by writing/adjusting failing parity tests for your lane (`Red`).
4. Implement minimal fix to pass (`Green`), then cleanup (`Refactor`).
5. Do not change protobuf or shared contracts outside your lane unless explicitly listed.
6. Report:
- Files changed.
- Tests added.
- Commands run + pass/fail.
- Remaining known gaps.

---

## Merge and Conflict Policy
- Merge per lane in small PR-sized commits.
- If conflicts hit shared files:
- Prefer rebasing onto latest main.
- Preserve behavior parity over local style preferences.
- Never drop existing tests; adapt them.

---

## Command Checklist Per Lane
- `cargo fmt --all --check`
- `cargo test <lane-specific-tests>`
- `cargo test` (before merge)
- `cargo clippy --workspace --all-targets --all-features -D warnings` (before merge wave completion)

---

## Milestone Definition of Done

### M1 (after Wave 1)
- Store interop + TLS/login wire blockers closed.

### M2 (after Wave 2)
- API/client/event/runtime behavior parity closed for all high severity gaps.

### M3 (after Wave 3)
- Observability/debug parity close enough for support-level troubleshooting equivalence.

### Final parity sign-off
- Full parity matrix green.
- Manual interoperability smoke:
- Proton-created profile works in OpenProton.
- OpenProton-created/updated profile is accepted by Proton Bridge compatibility harness.
- IMAP, SMTP, gRPC client smoke tests pass with expected event sequences.

---

## Immediate Next Execution Slice (Start Here)
- Start with Wave 1 lanes A, B, C in parallel.
- First merge target: Lane A (vault/store compatibility), because other lanes depend on stable auth/store semantics.
