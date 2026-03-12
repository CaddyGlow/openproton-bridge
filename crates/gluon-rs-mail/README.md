# gluon-rs-mail

`gluon-rs-mail` owns the Gluon mail-domain schema and store semantics.

Current scope:

- upstream-compatible mail schema probing
- compatibility target metadata for the mail cache
- mailbox and message read/write APIs over Gluon storage

It depends on `gluon-rs-core` for shared blob, layout, key, and transaction
infrastructure.
