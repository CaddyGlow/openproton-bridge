# Vault-Dir And Credential Store Plan

## Goal

Keep runtime configuration simple:

1. Keep `--vault-dir` as the main way to isolate openproton-bridge from official Proton Bridge.
2. Add explicit credential-store backend forcing: `system`, `pass`, `file`.
3. Allow backend-specific settings so side-by-side operation is reliable.

## Scope Change

This simplifies the previous multi-folder mode proposal:

- No separate `--settings-dir` / `--data-dir` / `--cache-dir`.
- No required runtime mode switch for path handling.
- Isolation is primarily done through `--vault-dir` + credential-store settings.

## Current State

- `--vault-dir` already exists and remaps runtime storage root.
- Vault key lookup backend is currently auto/probing with constants in `src/vault.rs`.
- Keychain namespace/secret are hard-coded (`bridge-v3`, `bridge-vault-key`).

## Proposed CLI

Global flags:

- `--vault-dir <PATH>`
- `--credential-store <auto|system|pass|file>` (default `auto`)
- `--credential-store-namespace <STRING>` (default `bridge-v3`)
- `--credential-store-secret <STRING>` (default `bridge-vault-key`)

Optional backend-specific flags:

- `--credential-store-system-service <STRING>` (advanced override for system backend service name)
- `--credential-store-pass-entry <STRING>` (advanced override for pass entry path)
- `--credential-store-file-path <PATH>` (advanced override for key file path, default `<vault-dir>/vault.key`)

Compatibility note:

- Existing `--vault-dir` behavior is preserved.
- Default behavior with no new flags remains Proton-compatible.

## Environment Variables

Support ENV equivalents for runtime/operator usage:

- `OPENPROTON_VAULT_DIR`
- `OPENPROTON_CREDENTIAL_STORE` (`auto|system|pass|file`)
- `OPENPROTON_CREDENTIAL_STORE_NAMESPACE`
- `OPENPROTON_CREDENTIAL_STORE_SECRET`
- `OPENPROTON_CREDENTIAL_STORE_SYSTEM_SERVICE`
- `OPENPROTON_CREDENTIAL_STORE_PASS_ENTRY`
- `OPENPROTON_CREDENTIAL_STORE_FILE_PATH`

ENV values map 1:1 to the corresponding CLI options.

## Optional Config File (Minimal)

Optional file for persistent operator settings:

- Path: `<vault-dir>/credential_store.toml`

Schema:

```toml
backend = "auto" # auto | system | pass | file
namespace = "bridge-v3"
secret = "bridge-vault-key"

[system]
service = "protonmail/bridge-v3/users"

[pass]
entry = "protonmail/bridge-v3/users/bridge-vault-key"

[file]
path = "vault.key"
```

Precedence:

1. CLI flags
2. Environment variables
3. `credential_store.toml`
4. Built-in defaults

## Backend Behavior

### `auto`

- Keep current probe/fallback behavior.
- Use namespace/secret values when building service/account names.

### `system`

- Force keyring/native keystore only.
- Do not fallback to `pass` when forced.
- Use:
  - service from `system.service` or derived from namespace.
  - account/secret from configured `secret`.

### `pass`

- Force `pass` backend only.
- Use:
  - pass entry from `pass.entry` or derived from namespace + secret.

### `file`

- Force file backend only.
- Use:
  - path from `file.path` or default `vault.key` under vault dir.

## Side-By-Side Operation Guidance

To run official Proton Bridge and openproton-bridge at the same time:

1. Start openproton-bridge with a dedicated `--vault-dir`.
2. Use either:
   - `--credential-store file` (most isolated), or
   - `--credential-store system/pass` with custom namespace/secret.
3. Use distinct IMAP/SMTP ports if both daemons run simultaneously.

## Implementation Plan

1. Add `CredentialStoreConfig` model (`src/vault.rs` or `src/bridge/types.rs`) with:
   - backend
   - namespace
   - secret
   - optional backend-specific overrides
2. Add CLI parsing in `src/main.rs` and resolve effective config.
3. Add ENV parsing (same fields as CLI) in `src/main.rs`.
4. Refactor vault key access helpers to derive names/entries from effective config instead of hard-coded constants.
5. Wire config into:
   - read/write/delete key flows
   - backend probes
   - helper persistence where relevant
6. Keep current defaults untouched when no new flags/config/env are provided.

## Test Plan

Unit tests:

- CLI parsing for `--credential-store` and overrides.
- Effective config precedence (CLI > ENV > file > defaults).
- ENV parsing/validation for every supported variable.
- Name derivation for each backend.
- Forced backend semantics:
  - `system` never uses pass fallback.
  - `pass` never uses system fallback.
  - `file` never hits keychain code path.

Integration tests:

- `--vault-dir A` and `--vault-dir B` are isolated.
- `file` backend in isolated vault dir does not read official keychain entries.
- `system/pass` with custom namespace/secret do not collide with default Proton namespace.
- Default mode still loads existing Proton fixture data.

## Risks And Mitigations

Risks:

- Regressing default key lookup behavior.
- Forced backend paths not handled consistently across code paths.

Mitigations:

- Preserve current default constants as defaults.
- Add regression tests for default namespace/service/secret.
- Add explicit tests for each forced backend mode.
