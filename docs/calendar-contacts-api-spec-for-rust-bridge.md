# Calendar + Contacts API Spec for Rust Bridge

## Goal
Provide a practical API contract for implementing Proton Calendar and Contacts support in OpenProton Bridge (Rust), using official ProtonMail client implementations as reference.

## Sources (official)
- `ProtonMail/go-proton-api` (active): canonical read paths and contact CRUD used by Proton Bridge ecosystem.
- `ProtonMail/android-calendar` (active): calendar write flow and payloads (`events/sync`, participation, personal part, etc.).
- `ProtonMail/ios-calendar` (active): confirms write flow and sync action model (create/update/delete over `events/sync`).
- `ProtonMail/proton-shared` (archived): explicit endpoint builders and TypeScript interfaces with field names.

## Scope
- Transport/auth token acquisition is out of scope.
- This spec focuses on endpoint paths, params, payload fields, and response shapes needed by a Rust HTTP client.

## Naming and serialization rules
- API JSON uses `PascalCase` field names.
- Most IDs are strings.
- Time values are Unix timestamps (seconds) in most endpoints.
- Some booleans are encoded as `0|1` integers.

## Calendar API

### Endpoint matrix

| Method | Path | Purpose | Params | Body |
|---|---|---|---|---|
| `GET` | `/calendar/v1` | List calendars | optional pagination in some clients | - |
| `GET` | `/calendar/v1/{calendarID}` | Get calendar | - | - |
| `POST` | `/calendar/v1` | Create calendar | - | `CalendarCreateArguments` |
| `PUT` | `/calendar/v1/{calendarID}` | Update calendar metadata | - | partial `CalendarCreateData` |
| `DELETE` | `/calendar/v1/{calendarID}` | Delete calendar | - | - |
| `GET` | `/calendar/v1/{calendarID}/bootstrap` | Full bootstrap (keys, passphrase, members, settings) | - | - |
| `GET` | `/calendar/v1/{calendarID}/keys` | Active keys | - | - |
| `GET` | `/calendar/v1/{calendarID}/keys/all` | All keys | - | - |
| `POST` | `/calendar/v1/{calendarID}/keys` | Setup calendar key | - | `CalendarSetupData` |
| `PUT` | `/calendar/v1/{calendarID}/keys/{keyID}` | Reactivate key | - | `{ "PrivateKey": string }` |
| `GET` | `/calendar/v1/keys/reset` | Key reset info | - | - |
| `POST` | `/calendar/v1/keys/reset` | Reset calendar keys | - | `{ "CalendarKeys": { ... } }` |
| `GET` | `/calendar/v1/{calendarID}/members` | Calendar members | optional pagination | - |
| `GET` | `/calendar/v1/{calendarID}/members/all` | All members | - | - |
| `PUT` | `/calendar/v1/{calendarID}/members/{memberID}` | Update member/display | - | member payload |
| `DELETE` | `/calendar/v1/{calendarID}/members/{memberID}` | Remove member / leave shared calendar | - | - |
| `GET` | `/calendar/v1/{calendarID}/passphrase` | Active passphrase | - | - |
| `GET` | `/calendar/v1/{calendarID}/passphrases` | All passphrases | - | - |
| `GET` | `/calendar/v1/{calendarID}/settings` | Calendar settings | - | - |
| `PUT` | `/calendar/v1/{calendarID}/settings` | Update settings | - | partial settings |
| `GET` | `/calendar/v1/{calendarID}/events` | Query events | `Start`, `End`, `Timezone`, `Type`, `Page`, `PageSize` | - |
| `GET` | `/calendar/v1/{calendarID}/events/count` | Count events | - | - |
| `GET` | `/calendar/v1/{calendarID}/events/{eventID}` | Get one event | - | - |
| `GET` | `/calendar/v1/events` | Query by UID | `UID`, `RecurrenceID?`, `Page?`, `PageSize?` | - |
| `GET` | `/calendar/v1/{calendarID}/events/{eventID}/attendees` | List attendees | `Page?` | - |
| `PUT` | `/calendar/v1/{calendarID}/events/sync` | Main write endpoint (create/update/delete) | - | `SyncMultipleEventsData` |
| `POST` | `/calendar/v1/{calendarID}/events` | Legacy direct create event path | - | `CreateSingleCalendarEventData` |
| `PUT` | `/calendar/v1/{calendarID}/events/{eventID}` | Legacy direct update event path | - | `CreateSingleCalendarEventData` |
| `DELETE` | `/calendar/v1/{calendarID}/events/{eventID}` | Legacy direct delete event path | - | - |
| `PUT` | `/calendar/v1/{calendarID}/events/{eventID}/attendees/{attendeeID}` | Update participation status | - | `UpdateParticipationStatus` |
| `PUT` | `/calendar/v1/{calendarID}/events/{eventID}/personal` | Update personal part | - | `CreateSinglePersonalEventData` |
| `PUT` | `/calendar/v1/{calendarID}/events/{eventID}/upgrade` | Upgrade invitation/event key packet | - | `{ "SharedKeyPacket": string }` |
| `GET` | `/calendar/v1/{calendarID}/alarms` | List alarms | `Start`, `End`, `PageSize` | - |
| `GET` | `/calendar/v1/{calendarID}/alarms/{alarmID}` | Get one alarm | - | - |
| `GET` | `/calendar/v1/vtimezones` | Resolve VTIMEZONE blocks | `Timezones[]=...` | - |

### Calendar query parameters

| Name | Type | Required | Notes |
|---|---|---|---|
| `Start` | `int64` | for event-window queries | window start (unix seconds) |
| `End` | `int64` | for event-window queries | window end (unix seconds) |
| `Timezone` | `string` | for event-window queries | e.g. `Europe/Paris` |
| `Type` | `int` | for event-window queries | enum below |
| `Page` | `int` | optional | pagination index |
| `PageSize` | `int` | optional | page size |
| `UID` | `string` | for UID lookup | iCal UID |
| `RecurrenceID` | `int64` | optional | recurrence instance |

`Type` (from official TS interfaces):
- `0`: PartDayInsideWindow
- `1`: PartDayBeforeWindow
- `2`: FullDayInsideWindow
- `3`: FullDayBeforeWindow

### Core calendar models (response)

#### Calendar

| Field | Type |
|---|---|
| `ID` | `string` |
| `Name` | `string` |
| `Description` | `string` |
| `Color` | `string` |
| `Display` | `0|1` or bool-like |
| `Type` | `int` (`0` personal, `1` subscribed) |
| `Flags` | bitmask `int64` |

Known calendar flags:
- `1`: active
- `2`: update passphrase
- `4`: reset needed
- `8`: incomplete setup
- `16`: lost access

#### CalendarKey

| Field | Type |
|---|---|
| `ID` | `string` |
| `CalendarID` | `string` |
| `PassphraseID` | `string` |
| `PrivateKey` | armored `string` |
| `Flags` | bitmask |

#### CalendarMember

| Field | Type |
|---|---|
| `ID` | `string` |
| `CalendarID` | `string` |
| `Email` | `string` |
| `Color` | `string` |
| `Display` | `0|1` |
| `Permissions` | `int` |

#### CalendarPassphrase

| Field | Type |
|---|---|
| `ID` | `string` |
| `Flags` | `int64` |
| `MemberPassphrases[]` | array |

`MemberPassphrase` fields:
- `MemberID: string`
- `Passphrase: string` (armored encrypted payload)
- `Signature: string` (armored signature)

#### CalendarEvent

| Field | Type |
|---|---|
| `ID` | `string` |
| `UID` | `string` |
| `CalendarID` | `string` |
| `SharedEventID` | `string` |
| `CreateTime` | `int64` |
| `LastEditTime` | `int64` |
| `StartTime` | `int64` |
| `StartTimezone` | `string` |
| `EndTime` | `int64` |
| `EndTimezone` | `string` |
| `FullDay` | `0|1` |
| `Author` | `string` |
| `Permissions` | `int` |
| `Attendees[]` | array |
| `SharedKeyPacket` | `string` |
| `CalendarKeyPacket` | `string` |
| `SharedEvents[]` | `CalendarEventPart[]` |
| `CalendarEvents[]` | `CalendarEventPart[]` |
| `AttendeesEvents[]` | `CalendarEventPart[]` |
| `PersonalEvents[]` | `CalendarEventPart[]` |

`CalendarEventPart` fields:
- `MemberID: string`
- `Type: int` (`0` clear, `1` encrypted, `2` signed)
- `Data: string`
- `Signature: string`
- `Author: string`

### Calendar write payloads

#### `POST /calendar/v1` body (`CalendarCreateArguments`)

| Field | Type | Required |
|---|---|---|
| `AddressID` | `string` | yes |
| `Name` | `string` | yes |
| `Description` | `string` | yes |
| `Color` | `string` | yes |
| `Display` | `0|1` | yes |
| `URL` | `string` | optional (subscription/import cases) |

#### `POST /calendar/v1/{calendarID}/keys` body (`CalendarSetupData`)

| Field | Type | Required |
|---|---|---|
| `AddressID` | `string` | yes |
| `Signature` | `string` | yes |
| `PrivateKey` | `string` | yes |
| `Passphrase.DataPacket` | `string` | yes |
| `Passphrase.KeyPackets` | `string` | yes |

#### `PUT /calendar/v1/{calendarID}/events/sync` body (`SyncMultipleEventsData`)

Top-level fields:

| Field | Type | Required |
|---|---|---|
| `MemberID` | `string` | yes |
| `IsImport` | `0|1` | optional |
| `Events` | array | yes |

`Events[]` is a union. Implement as untagged Rust enum.

Create variant:

| Field | Type | Required |
|---|---|---|
| `Overwrite` | `0|1` | optional |
| `Event` | `CreateCalendarEventData` | yes |

Update variant:

| Field | Type | Required |
|---|---|---|
| `ID` | `string` | yes |
| `Event` | partial event data | optional/yes by flow |

Delete variant:

| Field | Type | Required |
|---|---|---|
| `ID` | `string` | yes |
| `DeletionReason` | `int` | optional but supported by Android |

Linked-create variant:

| Field | Type | Required |
|---|---|---|
| `Overwrite` | `0|1` | optional |
| `Event.UID` | `string` | yes |
| `Event.SharedEventID` | `string` | yes |
| `Event.SharedKeyPacket` | `string` | yes |

`CreateCalendarEventData` fields:

| Field | Type | Required |
|---|---|---|
| `Permissions` | `int` | yes |
| `IsOrganizer` | `0|1` | optional |
| `RemovedAttendeeAddresses` | `string[]` | optional |
| `CalendarKeyPacket` | `string` | optional |
| `CalendarEventContent` | `CalendarEventData[]` | optional |
| `SharedKeyPacket` | `string` | required in create paths |
| `SharedEventContent` | `CalendarEventData[]` | required in create paths |
| `PersonalEventContent` | `CalendarEventData` | optional |
| `AttendeesEventContent` | `CalendarEventData[]` | optional |
| `Attendees` | attendee list | optional |

`CalendarEventData` fields:

| Field | Type |
|---|---|
| `Type` | `int` |
| `Data` | `string` |
| `Signature` | `string|null` |
| `Author` | `string` |

#### `PUT /calendar/v1/{calendarID}/events/{eventID}/attendees/{attendeeID}` body

| Field | Type | Required |
|---|---|---|
| `Status` | `int` | yes |
| `UpdateTime` | `int64` | yes |

#### `PUT /calendar/v1/{calendarID}/events/{eventID}/personal` body

| Field | Type | Required |
|---|---|---|
| `MemberID` | `string` | yes |
| `PersonalEventContent` | `CalendarEventData` | optional |

### Calendar implementation recommendation
- Implement reads from `go-proton-api` parity first.
- Implement writes through `PUT /calendar/v1/{calendarID}/events/sync` first (this is the active path in iOS/Android clients).
- Keep direct single-event CRUD (`POST/PUT/DELETE /events`) behind feature flag until confirmed against real server behavior.

## Contacts API

### Endpoint matrix (v4)

| Method | Path | Purpose | Params | Body |
|---|---|---|---|---|
| `GET` | `/contacts/v4` | List contacts and total | `Page`, `PageSize` | - |
| `GET` | `/contacts/v4/{contactID}` | Get one contact | - | - |
| `GET` | `/contacts/v4/emails` | List contact emails and total | `Email`, `Page`, `PageSize` | - |
| `POST` | `/contacts/v4` | Create contacts | - | `CreateContactsReq` |
| `PUT` | `/contacts/v4/{contactID}` | Update contact cards | - | `UpdateContactReq` |
| `PUT` | `/contacts/v4/delete` | Bulk delete contacts | - | `DeleteContactsReq` |

### Contact query parameters

| Name | Type | Required | Notes |
|---|---|---|---|
| `Page` | `int` | optional | zero-based pagination |
| `PageSize` | `int` | optional | max page size is server-limited |
| `Email` | `string` | optional | filter in `/contacts/v4/emails` |

### Contact models

#### ContactMetadata

| Field | Type |
|---|---|
| `ID` | `string` |
| `Name` | `string` |
| `UID` | `string` |
| `Size` | `int64` |
| `CreateTime` | `int64` |
| `ModifyTime` | `int64` |
| `ContactEmails` | `ContactEmail[]` |
| `LabelIDs` | `string[]` |

#### ContactEmail

| Field | Type |
|---|---|
| `ID` | `string` |
| `Name` | `string` |
| `Email` | `string` |
| `Type` | `string[]` |
| `ContactID` | `string` |
| `LabelIDs` | `string[]` |

Optional fields seen in web clients (deserialize as `Option`):
- `Defaults: int`
- `Order: int`
- `LastUsedTime: int64`

#### ContactCard

| Field | Type | Notes |
|---|---|---|
| `Type` | `int` | `0=clear`, `1=encrypted`, `2=signed` |
| `Data` | `string` | vCard payload (raw/armored depending on type) |
| `Signature` | `string|null` | used with signed cards |

#### Contact

Contact object = `ContactMetadata` fields plus:
- `Cards: ContactCard[]`

### Contact write payloads

#### `POST /contacts/v4` (`CreateContactsReq`)

| Field | Type | Required |
|---|---|---|
| `Contacts` | array of `{ Cards: ContactCard[] }` | yes |
| `Overwrite` | `0|1` | yes |
| `Labels` | `int` | optional |

Response shape:
- `Responses[]`
- each item has `Index` and `Response` with `Code`, optional `Contact`, optional `Error`.

#### `PUT /contacts/v4/{contactID}` (`UpdateContactReq`)

| Field | Type | Required |
|---|---|---|
| `Cards` | `ContactCard[]` | yes |

#### `PUT /contacts/v4/delete` (`DeleteContactsReq`)

| Field | Type | Required |
|---|---|---|
| `IDs` | `string[]` | yes |

### Contact vCard settings fields
When parsing/updating crypto preferences inside contact cards, these vCard custom fields are used:
- `X-PM-SCHEME` (`pgp-inline` / `pgp-mime`)
- `X-PM-SIGN` (`true|false`)
- `X-PM-ENCRYPT` (`true|false`)
- `X-PM-ENCRYPT-UNTRUSTED` (`true|false`)
- `X-PM-MIMETYPE`
- `KEY` (`base64,...`)

## Rust modeling guidance

### Serde conventions
- Prefer `#[serde(rename_all = "PascalCase")]` on structs.
- Use explicit `#[serde(rename = "...")]` for path-specific mismatches.
- Use `Option<T>` for fields that vary by client/server version.

### Calendar sync event enum
Use an untagged enum for `Events[]` payload items because variants are shape-based.

Suggested discriminator logic:
- create: has `Event`, no `ID`
- update: has `ID` and `Event`
- delete: has `ID` and no `Event` (possibly `DeletionReason`)

### Numeric wrappers
- Keep `Permissions`, `Flags`, and attendee status as integer newtypes/enums in Rust.
- Keep timestamps as `i64`.
- Keep bool-like ints as `u8` or custom enum when server expects `0|1` exactly.

## Proposed implementation order in Bridge
1. Calendar read endpoints + bootstrap + event query.
2. Contacts list/get/create/update/delete.
3. Calendar event writes via `events/sync`.
4. Participation/personal-part update endpoints.
5. Optional legacy/supplemental endpoints behind feature flags.

## Compatibility notes
- `go-proton-api` currently exposes calendar read methods but not full write helpers.
- Active Proton mobile clients rely on `events/sync` for create/update/delete behavior.
- Archived web/shared code includes direct single-event CRUD builders; treat as secondary reference.
