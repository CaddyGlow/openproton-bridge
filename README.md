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

Early development. See [PLAN.md](PLAN.md) for the implementation roadmap and current phase.

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

# Start the bridge daemon (IMAP on 1143, SMTP on 1025)
openproton-bridge start

# Check status
openproton-bridge status

# Log out
openproton-bridge logout
```

Then configure your email client:

- **IMAP server:** `localhost:1143`
- **SMTP server:** `localhost:1025`
- **Username:** your Proton email address
- **Password:** the bridge password printed during login

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
