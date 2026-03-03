# openproton-bridge

A Rust implementation of a Proton Mail bridge that exposes local IMAP and SMTP servers, allowing standard email clients (Thunderbird, etc.) to access Proton Mail accounts -- including free accounts.

## What it does

openproton-bridge runs as a local daemon and:

1. Authenticates with Proton Mail servers using SRP-6a
2. Fetches and decrypts your encrypted mail using PGP
3. Serves it over a local IMAP server on `localhost:1143`
4. Accepts outgoing mail over a local SMTP server on `localhost:1025`, encrypts it, and sends it through Proton

Your email client connects to these local servers as if they were any other mail provider.

## Why

The official Proton Mail Bridge requires a paid Proton account. This project provides the same functionality for free-tier accounts.

## Status

Active development. Core bridge flows are implemented, including multi-account runtime support, per-account event workers, and IMAP `IDLE`/`NOOP` visibility for mailbox changes. See [PLAN.md](PLAN.md) for roadmap and detailed phase tracking.

## Requirements

- Rust 1.75+ (uses async/await, impl trait in return position)
- A Proton Mail account (free or paid)

## Building

```
cargo build --release
```

## Usage

```
# Log in to your Proton account
openproton-bridge login

# Optional: select API mode for this account (defaults to bridge)
openproton-bridge login --api-mode webmail

# Add another account (optional, repeat login)
openproton-bridge login --username other@proton.me

# List accounts and active/default account
openproton-bridge status
openproton-bridge accounts list

# Set default account used by fetch/status
openproton-bridge accounts use other@proton.me

# Start the bridge daemon (IMAP on 1143, SMTP on 1025)
openproton-bridge serve

# Start interactive shell (account and runtime commands)
openproton-bridge cli

# In interactive shell:
#   serve            # start IMAP/SMTP in background
#   serve-status     # inspect runtime state
#   grpc            # start gRPC control service in background
#   grpc-status     # inspect gRPC runtime state
#   stop            # stop all background runtimes

# Optional: tune per-account event poll interval
openproton-bridge serve --event-poll-secs 10

# Run with isolated vault directory + file credential store
openproton-bridge --vault-dir ~/.config/protonmail/openproton-bridge \
  --credential-store file serve

# Force system keychain namespace/secret (side-by-side with official Bridge)
openproton-bridge --credential-store system \
  --credential-store-namespace openproton-bridge \
  --credential-store-secret openproton-vault-key serve

# Check status
openproton-bridge status

# Log out
openproton-bridge logout --email other@proton.me
openproton-bridge logout --all
```

Then configure your email client:

- **IMAP server:** `localhost:1143`
- **SMTP server:** `localhost:1025`
- **Username:** any enabled address for the target account (primary or alias)
- **Password:** the bridge password printed during login for that account
- **Security:** STARTTLS by default (`--no-tls` is restricted to loopback bind addresses)

## Runtime Behavior

- `serve` loads all saved accounts from vault and starts one event worker per account.
- Event poll interval defaults to 30s and can be changed with `--event-poll-secs`.
- Event workers apply incremental updates to account-scoped IMAP store data.
- Checkpoints and sync state are persisted in encrypted vault records, so workers resume from the saved cursor after restart.
- Label topology events trigger bounded account resync and persist checkpoint state as `label_resync`.
- Failures are isolated per account; one unavailable account does not stop healthy accounts.
- Workers expose structured health/failure logs (`auth`/`transient`/`permanent`) with retry backoff + jitter.
- Worker startup polls are deterministically staggered per account (bounded) to reduce burst load on large account sets.

## Operator Runbook

### Common operations

1. Add or refresh one account credentials:

```
openproton-bridge login --username user@proton.me
# or force webmail mode for that account
openproton-bridge login --username user@proton.me --api-mode webmail
```

2. Keep one account active while removing another:

```
openproton-bridge logout --email old-user@proton.me
```

3. Reduce API polling load for many accounts:

```
openproton-bridge serve --event-poll-secs 60
```

4. Faster near-real-time polling for testing:

```
openproton-bridge serve --event-poll-secs 10
```

### Troubleshooting quick checks

1. Confirm all accounts loaded and default account selection:

```
openproton-bridge status
```

2. If one account shows repeated auth failures in logs, re-run `login` for that account; other accounts continue serving.
3. After account list changes (`login`, `logout --email`, `logout --all`), restart `serve` so runtime workers match vault state.

### Credential Store Options

Global options:

- `--credential-store <auto|system|pass|file>`
- `--credential-store-namespace <name>`
- `--credential-store-secret <name>`
- `--credential-store-system-service <service>`
- `--credential-store-pass-entry <entry>`
- `--credential-store-file-path <path>`

Environment variable equivalents:

- `OPENPROTON_VAULT_DIR`
- `OPENPROTON_CREDENTIAL_STORE`
- `OPENPROTON_CREDENTIAL_STORE_NAMESPACE`
- `OPENPROTON_CREDENTIAL_STORE_SECRET`
- `OPENPROTON_CREDENTIAL_STORE_SYSTEM_SERVICE`
- `OPENPROTON_CREDENTIAL_STORE_PASS_ENTRY`
- `OPENPROTON_CREDENTIAL_STORE_FILE_PATH`

Precedence:

1. CLI flags
2. Environment variables
3. `<vault-dir>/credential_store.toml`
4. Built-in defaults

## Configuration

Config file location: `~/.config/openproton-bridge/config.toml`

```toml
[imap]
host = "127.0.0.1"
port = 1143

[smtp]
host = "127.0.0.1"
port = 1025

[logging]
level = "info"
```

## Testing

```
cargo test
```

Integration tests use `wiremock` for HTTP mocking and do not require network access or a Proton account.

## Architecture

Single-crate Rust project organized into modules:

- `api/` -- Proton REST API client (SRP auth, messages, labels, events)
- `crypto/` -- PGP key management, message encryption/decryption (sequoia-openpgp)
- `imap/` -- Local IMAP4rev1 server
- `smtp/` -- Local SMTP server
- `bridge/` -- Daemon orchestration, config, credential vault, sync engine

See [PLAN.md](PLAN.md) for detailed architecture and design decisions.

## References

- [proton-bridge](https://github.com/ProtonMail/proton-bridge) -- Official Go implementation (architecture reference)
- [Eppie-App](https://github.com/nicknsy/eppie-app) -- C# mail client with direct Proton API access

## License

MIT
