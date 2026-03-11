# gluon-rs-core

`gluon-rs-core` owns Gluon cache infrastructure that is shared across domains.

Current scope:

- encrypted blob encode/decode
- cache path and account layout helpers
- Gluon key bootstrap primitives
- transaction and deferred-delete path management

Out of scope:

- mailbox and message schemas
- compatibility target pinning
- mail-specific read and mutation APIs
