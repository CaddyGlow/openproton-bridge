# gluon-rs

`gluon-rs` is a Rust draft crate for byte- and format-compatible access to
Proton Gluon's on-disk cache.

This crate is intentionally not a wrapper around the current OpenProton
`openproton_*` schema. Its API is shaped around the upstream cache layout:

- `backend/store/<user-id>/...` message blobs
- `backend/db/<user-id>.db{,-wal,-shm}` SQLite state
- `backend/db/deferred_delete/*` deferred-delete pool

Current scope in this draft:

- Compatibility-oriented cache layout API
- Redacted key/passphrase wrapper
- SQLite schema probe for upstream-vs-custom layouts
- Transaction path naming helpers
- Store bootstrap surface for future read/write implementation

Out of scope in this draft:

- Blob crypto
- Upstream SQL execution
- Recovery replay
- IMAP-facing message mutation logic
