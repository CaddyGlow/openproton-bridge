# Gluon Deployment and Rollback Runbook (BE-033)

## Hard-cut statement

This rollout is a **hard cut with no migration path**.

- Do not perform in-place schema/data migration between old and new binaries.
- Do not run old and new binaries in parallel against the same live cache.
- Do not move an unresolved cache root that still has pending `.gluon-txn` transactions.

## Deployment steps

1. Stop all running `openproton-bridge` processes.
2. Capture backups:
   - active executable(s),
   - vault/settings directory,
   - active disk cache root.
3. Deploy the new binary.
4. Start the service.
5. Verify:
   - account list loads,
   - IMAP store reads succeed,
   - event checkpoint and split-mode settings still load,
   - disk-cache path matches expected runtime configuration.

## Rollback steps

1. Stop all running `openproton-bridge` processes.
2. Restore the previous binary artifact.
3. Restore the pre-cut backup of vault/settings and disk-cache directories.
4. Start the previous binary.
5. Re-run smoke checks:
   - `openproton-bridge status`
   - one account IMAP read flow
   - checkpoint/sync continuity in logs.

## Cache-move failure recovery

If startup fails after relocating a cache root with a pending `.gluon-txn` journal:

1. Stop the service.
2. Move the cache root back to the original absolute path.
3. Start the service once to allow pending transaction recovery.
4. Confirm `.gluon-txn/<scope>` is cleared.
5. Retry cache relocation only after recovery is complete.
