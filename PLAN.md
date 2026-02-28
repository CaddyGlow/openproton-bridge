# OpenProton Bridge -- Rust Implementation Plan

## Context

Proton Mail Bridge is a Go application that exposes local IMAP/SMTP servers, allowing standard email clients to access Proton Mail. The official bridge requires a paid account. This project reimplements the bridge in Rust as a headless CLI daemon that supports free Proton accounts.

Key references:
- **proton-bridge/** (Go) -- official bridge; architecture reference
- **proton-vpn-rst/tunmux/src/proton/** (Rust) -- working SRP-6a auth + HTTP client to adapt directly
- **Eppie-App/** (C#) -- proves free-account API access works

---

## Design Principles

- **Single crate, module tree** -- no workspace overhead for one developer. Modules provide clean boundaries without the friction of cross-crate dependency management.
- **Trait-based boundaries** -- every external dependency (HTTP, PGP, storage) sits behind a trait. Production code uses real implementations; tests use in-process mocks. No test servers, no network in unit tests.
- **Test-first** -- write the test, then the implementation. Each module has a `tests` submodule. Integration tests live in `tests/`.
- **Modern Rust** -- async/await throughout, `thiserror` for error enums, newtypes for IDs (`MessageId(String)`, `LabelId(String)`), builder pattern for complex requests, `tracing` for structured logging.
- **No over-abstraction** -- if a function is used once, inline it. Extract only when there is actual reuse.

---

## Project Structure

```
openproton-bridge/
  Cargo.toml
  src/
    main.rs                     # CLI entry point (clap)
    lib.rs                      # Re-exports for integration tests
    api/
      mod.rs
      client.rs                 # ProtonClient: HTTP client with auth headers
      srp.rs                    # SRP-6a math (adapted from tunmux)
      auth.rs                   # Login, 2FA, refresh flows
      messages.rs               # Message CRUD, metadata pagination
      labels.rs                 # Label CRUD
      events.rs                 # Event polling, event types
      users.rs                  # User info, addresses, key salts
      types.rs                  # API request/response structs (serde)
      error.rs                  # ApiError enum
    crypto/
      mod.rs
      keys.rs                   # Key parsing, unlock, keyring management
      decrypt.rs                # Message + attachment decryption
      encrypt.rs                # Outgoing message encryption + signing
    imap/
      mod.rs
      server.rs                 # Tokio TCP listener, TLS, session dispatch
      session.rs                # Per-connection IMAP state machine
      mailbox.rs                # Mailbox abstraction (label mapping)
      store.rs                  # SQLite message store (trait + impl)
    smtp/
      mod.rs
      server.rs                 # Tokio TCP listener, TLS
      session.rs                # Per-connection SMTP state machine
      send.rs                   # RFC 822 parse -> encrypt -> API send
    bridge/
      mod.rs
      config.rs                 # Config loading (TOML)
      vault.rs                  # Encrypted credential storage
      sync.rs                   # Full + incremental sync engine
      user.rs                   # Per-user state: keys, services
  tests/
    auth_integration.rs         # Login against mock HTTP server
    crypto_integration.rs       # Decrypt known test vectors
    imap_integration.rs         # IMAP client against running server
    smtp_integration.rs         # SMTP client against running server
```

---

## Trait Boundaries (for testability)

```rust
// API layer -- mock HTTP responses in tests
#[async_trait]
trait ProtonApi: Send + Sync {
    async fn login(&self, username: &str, password: &str) -> Result<Session>;
    async fn get_user(&self) -> Result<User>;
    async fn get_messages(&self, filter: MessageFilter) -> Result<Vec<MessageMetadata>>;
    async fn get_full_message(&self, id: &MessageId) -> Result<FullMessage>;
    async fn send_message(&self, req: SendRequest) -> Result<()>;
    async fn get_events(&self, last_event_id: &str) -> Result<EventResponse>;
    // ...
}

// Crypto layer -- test with known PGP key pairs
trait CryptoProvider: Send + Sync {
    fn unlock_keys(&self, keys: &[ArmoredKey], passphrase: &[u8]) -> Result<Keyring>;
    fn decrypt_message(&self, keyring: &Keyring, armored_body: &str) -> Result<Vec<u8>>;
    fn encrypt_message(&self, keyring: &Keyring, recipient_key: &PublicKey, body: &[u8]) -> Result<Vec<u8>>;
}

// Storage layer -- test with in-memory SQLite
trait MessageStore: Send + Sync {
    async fn store_message(&self, mailbox: &str, msg: &StoredMessage) -> Result<Uid>;
    async fn fetch_message(&self, mailbox: &str, uid: Uid) -> Result<StoredMessage>;
    async fn list_mailboxes(&self) -> Result<Vec<MailboxInfo>>;
    // ...
}
```

---

## Testing Strategy

**Unit tests** (in each module's `#[cfg(test)]` block):
- `api::srp` -- test vectors: known password + salt + modulus -> expected proof. Validate expandHash, password hashing, client proof against Go reference output.
- `api::auth` -- mock HTTP responses (serde_json fixtures), verify login flow state machine.
- `api::types` -- round-trip serde for every API struct.
- `crypto::keys` -- unlock test PGP keys, verify keyring construction.
- `crypto::decrypt` -- decrypt test messages encrypted with known keys.
- `crypto::encrypt` -- encrypt then decrypt round-trip.
- `imap::session` -- feed raw IMAP commands, assert responses. No network.
- `imap::mailbox` -- label-to-mailbox mapping logic.
- `smtp::session` -- feed raw SMTP commands, assert responses.
- `bridge::config` -- parse valid/invalid TOML configs.
- `bridge::vault` -- encrypt/decrypt round-trip.

**Integration tests** (`tests/` directory):
- `auth_integration` -- full login flow against a `wiremock` HTTP server returning scripted JSON responses.
- `crypto_integration` -- decrypt actual Proton-format PGP message fixtures.
- `imap_integration` -- start real IMAP server on random port, connect with `async-imap` crate as client, exercise LOGIN/LIST/SELECT/FETCH.
- `smtp_integration` -- start real SMTP server on random port, connect with `lettre` as client, send a message, verify it reaches the mock API.

**Test deps:** `wiremock` (HTTP mocking), `async-imap` (IMAP client for tests), `lettre` (SMTP client for tests), `tempfile`, `assert_matches`.

**Coverage target:** all trait methods, all error paths in SRP, all IMAP command handlers, all SMTP command handlers. No coverage percentage goal -- just "every code path that can fail has a test."

---

## Dependencies

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "cookies"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
thiserror = "2"
anyhow = "1"

# SRP + crypto
num-bigint = "0.4"
num-traits = "0.2"
num-integer = "0.1"
sha2 = "0.10"
bcrypt = "0.16"
base64 = "0.22"
rand = "0.8"
aes-gcm = "0.10"

# PGP
sequoia-openpgp = "1"

# IMAP/SMTP protocol
imap-codec = "2"
mailparse = "0.15"

# Storage + config
rusqlite = { version = "0.31", features = ["bundled"] }
toml = "0.8"
dirs = "5"

# TLS
rustls = "0.23"
rustls-pemfile = "2"
rcgen = "0.13"
tokio-rustls = "0.26"

# Async trait
async-trait = "0.1"

[dev-dependencies]
wiremock = "0.6"
async-imap = "0.10"
lettre = "0.11"
tempfile = "3"
assert_matches = "1"
tokio-test = "0.4"
```

---

## Implementation Phases

### Phase 1: Scaffold + SRP auth + tests
1. `cargo init`, set up module tree with empty `mod.rs` files
2. Copy `srp.rs` from tunmux, adapt to standalone module. Write unit tests for expandHash, password hashing, and full SRP proof using test vectors extracted from the Go reference.
3. Implement `ProtonClient` (HTTP wrapper with auth headers). Adapt from tunmux `http.rs`.
4. Implement `auth.rs` login flow. Write tests against wiremock with fixture JSON.
5. Implement `api::types` -- `User`, `Address`, `Salt`, `Session` structs. Test serde round-trips.
6. Implement `api::users` -- get user, get addresses, get salts. Test against wiremock.
7. Implement session file persistence.
8. Wire up CLI: `openproton-bridge login`
9. **Manual verify:** login with a free Proton account, print user info.

### Phase 2: PGP crypto + message fetching + tests
1. Implement `crypto::keys` -- parse armored PGP keys, unlock with passphrase, build keyring. Test with generated test keypairs.
2. Implement `crypto::decrypt` -- decrypt PGP message body, decrypt attachments. Test with known-key encrypted fixtures.
3. Implement `api::messages` -- metadata pagination, full message fetch, attachment fetch. Test against wiremock.
4. Wire these together: fetch encrypted messages from API, decrypt with keyring.
5. CLI: `openproton-bridge fetch` (dump decrypted subjects + snippet)
6. **Manual verify:** fetch and read messages from a free account.

### Phase 3: IMAP server + tests
1. Implement `imap::store` -- SQLite-backed message store with trait. Test with in-memory SQLite.
2. Implement `imap::mailbox` -- Proton label -> IMAP folder mapping. Unit test all system label mappings.
3. Implement `imap::session` -- IMAP command handler state machine. Test by feeding raw command bytes and asserting response bytes. Start with: CAPABILITY, LOGIN, LIST, SELECT, FETCH (ENVELOPE, FLAGS, BODY), STORE, CLOSE, LOGOUT.
4. Implement `imap::server` -- tokio TCP acceptor + TLS. Integration test with `async-imap` client.
5. Add SEARCH, COPY, MOVE, EXPUNGE, NOOP.
6. **Manual verify:** Thunderbird connects to `localhost:1143`, browses inbox.

### Phase 4: SMTP server + sending + tests
1. Implement `smtp::session` -- SMTP command handler (EHLO, AUTH PLAIN, MAIL FROM, RCPT TO, DATA, QUIT). Test by feeding raw command bytes.
2. Implement `smtp::send` -- parse RFC 822, validate sender, encrypt body, create draft, send via API. Test with wiremock + test PGP keys.
3. Implement `crypto::encrypt` -- encrypt message body to recipient public key. Round-trip test with `crypto::decrypt`.
4. Implement `smtp::server` -- tokio TCP acceptor + TLS. Integration test with `lettre`.
5. **Manual verify:** Thunderbird sends email through `localhost:1025`.

### Phase 5: Sync + events + daemon
1. Implement `api::events` -- poll events, parse event types. Test with wiremock fixtures.
2. Implement `bridge::sync` -- initial full sync (paginate all messages, decrypt, store). Test with mock API + in-memory store.
3. Implement incremental sync (apply message/label/flag events to store).
4. Implement IMAP IDLE (notify clients when sync inserts new messages).
5. Implement `api::auth` token refresh. Test refresh flow with wiremock.
6. Implement `bridge::vault` -- AES-GCM encrypted credential file. Round-trip test.
7. Implement `bridge::config` -- TOML config parsing. Test valid/invalid configs.
8. CLI: `openproton-bridge start` (foreground daemon), `status`, `logout`.
9. **Manual verify:** full end-to-end with Thunderbird. Receive mail via IDLE, send mail, manage folders.

---

## Key Files to Adapt From

| Source | Target | Action |
|--------|--------|--------|
| `tunmux/src/proton/api/srp.rs` | `src/api/srp.rs` | Copy, add test vectors |
| `tunmux/src/proton/api/auth.rs` | `src/api/auth.rs` | Copy, extend for mail |
| `tunmux/src/proton/api/http.rs` | `src/api/client.rs` | Copy, extend |
| `tunmux/src/proton/models/session.rs` | `src/api/types.rs` | Simplify for mail |
| `tunmux/src/error.rs` | `src/api/error.rs` | Adapt pattern |
| `proton-bridge/pkg/message/decrypt.go` | `src/crypto/decrypt.rs` | Rewrite |
| `proton-bridge/internal/services/smtp/smtp_packages.go` | `src/crypto/encrypt.rs` | Rewrite |
| `proton-bridge/internal/services/userevents/event_source.go` | `src/api/events.rs` | Rewrite |
| `proton-bridge/internal/services/imapservice/connector.go` | `src/imap/mailbox.rs` | Logic reference |

---

## Verification

- **Phase 1:** `cargo test` passes all SRP + auth tests. `openproton-bridge login` works with free Proton account.
- **Phase 2:** `cargo test` passes crypto + message tests. `openproton-bridge fetch` prints decrypted messages.
- **Phase 3:** `cargo test` passes IMAP tests. Thunderbird browses inbox on `localhost:1143`.
- **Phase 4:** `cargo test` passes SMTP tests. Thunderbird sends mail through `localhost:1025`.
- **Phase 5:** `cargo test` passes all tests. Full daemon runs, receives new mail via IDLE, sends mail.
