# Gluon Hard-Cut Release Checklist (BE-033)

## Policy

This release train is **hard-cut only**:

- No live data migration job is provided.
- No dual-write bridge path is supported.
- No compatibility shim for mixed runtime layouts is supported.

Every deployment is an all-or-nothing binary cutover plus runtime artifact backup/restore.

## Pre-cut requirements

1. CI is green, including `Gluon Parity Recovery Gate` and `CI and Release` test jobs.
2. Operator has verified backups for:
   - the current bridge binary/artifact package,
   - vault/settings directory,
   - active disk-cache root (including `.gluon-txn` and `backend/store/*`).
3. Rollback artifact is available and checksum-verified before rollout.

## Cutover procedure

1. Stop bridge processes on the target host.
2. Snapshot runtime state directories and copy the current binary artifact to a rollback location.
3. Install the new binary artifact.
4. Start the service and run smoke checks:
   - `openproton-bridge status`
   - gRPC user list and disk-cache path checks (if gRPC mode is enabled)
   - account sync/read smoke via IMAP client.
5. Monitor startup logs for Gluon recovery errors and account worker health.

## Abort criteria

Rollback immediately if any of the following appear:

- startup reports `GluonCorruption`,
- accounts fail to load after restart,
- cache-path relocation produces unresolved `.gluon-txn` journal errors,
- parity smoke checks diverge from expected user/session state.
