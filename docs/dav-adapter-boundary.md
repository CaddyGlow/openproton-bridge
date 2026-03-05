# DAV Adapter Boundary (Prep for CalDAV/CardDAV/WebDAV)

## Goal

Define a stable boundary between transport/server code (future DAV layer) and existing PIM cache/query/write logic, so implementation can proceed in parallel without reworking core storage.

## Code Boundary

Implemented in:

- `src/pim/dav.rs`

Main pieces:

- `CardDavRepository`
- `CalDavRepository`
- `DavSyncStateRepository`
- `PimDavRepository` (trait union)
- `StoreBackedDavAdapter` (production adapter over `PimStore`)

Delete semantics are explicit through `DeleteMode::{Soft, Hard}`.

## Method Mapping

CardDAV-facing operations:

- list/get/search contacts
- upsert contact
- soft/hard delete contact

CalDAV-facing operations:

- list/get calendars
- list/get calendar events by time range
- upsert calendar
- upsert calendar event
- soft/hard delete calendar
- soft/hard delete calendar event

Sync-token/state operations:

- get/set text scope
- get/set int scope

These are backed by existing `pim_sync_state` rows so DAV sync tokens can be stored without new tables.

## Parallel Work Split

Track A (server/protocol team):

- Build CalDAV/CardDAV request handlers and serializers.
- Depend only on `PimDavRepository` traits.
- No direct `PimStore` access.

Track B (cache/data team):

- Extend adapter implementation if richer data is needed (for example raw VCARD/ICS payload views).
- Keep trait shape stable where possible.

Track C (integration team):

- Wire adapter instance creation from account runtime context.
- Map account-scoped DAV auth/session to the correct per-account adapter.

## Next Minimal Integration Steps

1. Add a DAV runtime module that receives `Arc<dyn PimDavRepository + Send + Sync>`.
2. Thread account selection (`uid/email`) to adapter resolution (same mapping model as gRPC PIM endpoints).
3. Add protocol-level tests against the trait with an in-memory fixture adapter and one end-to-end test using `StoreBackedDavAdapter`.
