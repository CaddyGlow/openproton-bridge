# go-proton-api vs openproton-bridge Data Model Parity

Generated: 2026-03-04

Scope:
- `go-proton-api` model structs from `manager_auth_types.go`, `user_types.go`, `address_types.go`, `keyring.go`, `message_types.go`, `attachment_types.go`, `message_draft_types.go`, `message_send_types.go`, `keys_types.go`, `event_types.go`.
- `openproton-bridge` model structs from `src/api/types.rs`.

Status legend:
- `Exact`: same field semantics and representation.
- `Compatible`: same semantics, different type or naming.
- `Missing in Rust`: present in `go-proton-api`, absent in `openproton-bridge` model.
- `Rust-only`: present in `openproton-bridge` model, absent in corresponding `go-proton-api` model.

## AuthInfo (`AuthInfo` vs `AuthInfoResponse`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `Version` | `Version int` | `version i32` | Compatible | Numeric width differs only. |
| `Modulus` | `Modulus string` | `modulus String` | Exact | |
| `ServerEphemeral` | `ServerEphemeral string` | `server_ephemeral String` | Exact | |
| `Salt` | `Salt string` | `salt String` | Exact | |
| `SRPSession` | `SRPSession string` | `srp_session String` | Exact | |
| `2FA` | `TwoFA TwoFAInfo` | `two_factor Option<TwoFactorInfo>` | Compatible | Rust models 2FA metadata as optional. |

## Login Auth Response (`Auth` vs `AuthResponse`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `UserID` | `UserID string` | `user_id Option<String>` | Compatible | |
| `UID` | `UID string` | `uid String` | Exact | |
| `AccessToken` | `AccessToken string` | `access_token String` | Exact | |
| `RefreshToken` | `RefreshToken string` | `refresh_token String` | Exact | |
| `ServerProof` | `ServerProof string` | `server_proof String` | Exact | |
| `Scope` | `Scope string` | `scope Option<String>` | Compatible | |
| `2FA` | `TwoFA TwoFAInfo` | `two_factor TwoFactorInfo` | Compatible | Same concept, different nested shape. |
| `PasswordMode` | `PasswordMode PasswordMode` | `password_mode i32` | Compatible | Rust uses raw integer, Go typed enum. |

## Refresh Auth Response (`Auth` vs `RefreshResponse`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `UID` | `UID string` | `uid String` | Exact | Rust defaults/fills if missing. |
| `AccessToken` | `AccessToken string` | `access_token String` | Exact | |
| `RefreshToken` | `RefreshToken string` | `refresh_token String` | Exact | |
| `ServerProof` | `ServerProof string` | `server_proof Option<String>` | Compatible | |
| `Scope` | `Scope string` | `scope Option<String>` | Compatible | |
| `2FA` | `TwoFA TwoFAInfo` | `two_factor Option<TwoFactorInfo>` | Compatible | |
| `PasswordMode` | `PasswordMode PasswordMode` | `password_mode Option<i32>` | Compatible | Enum vs optional raw int. |

## 2FA Metadata (`TwoFAInfo` vs `TwoFactorInfo`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `Enabled` | `Enabled TwoFAStatus` | `enabled i32` | Compatible | Rust uses raw integer bit flags. |
| `FIDO2` | `FIDO2 FIDO2Info` | `fido2 Option<Fido2Info>` | Compatible | Rust optional, Go non-optional struct. |

## FIDO2 Metadata (`FIDO2Info` vs `Fido2Info`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `AuthenticationOptions` | `AuthenticationOptions any` | `authentication_options Value` | Compatible | |
| `RegisteredKeys` | `RegisteredKeys []RegisteredKey` | `registered_keys Vec<RegisteredKey>` | Compatible | |

## User (`User` vs `User`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `ID` | `ID string` | `id String` | Exact | |
| `Name` | `Name string` | `name String` | Exact | |
| `DisplayName` | `DisplayName string` | `display_name String` | Exact | |
| `Email` | `Email string` | `email String` | Exact | |
| `Keys` | `Keys Keys` | `keys Vec<UserKey>` | Compatible | Different key struct representation. |
| `UsedSpace` | `UsedSpace uint64` | `used_space i64` | Compatible | Signed vs unsigned. |
| `MaxSpace` | `MaxSpace uint64` | `max_space i64` | Compatible | Signed vs unsigned. |
| `MaxUpload` | `MaxUpload uint64` | `max_upload i64` | Compatible | Signed vs unsigned. |
| `Credit` | `Credit int` | `credit i64` | Compatible | |
| `Currency` | `Currency string` | `currency String` | Exact | |
| `ProductUsedSpace` | `ProductUsedSpace ProductUsedSpace` | `product_used_space ProductUsedSpace` | Exact | |

## User Key (`Key` subset vs `UserKey`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `ID` | `ID string` | `id String` | Exact | |
| `PrivateKey` | `PrivateKey []byte` (armored JSON I/O via custom marshal) | `private_key String` | Compatible | Rust stores armored string directly. |
| `Active` | `Active Bool` | `active i32` | Compatible | Bool wrapper vs API-int. |
| `Token` | `Token string` | `token Option<String>` | Compatible | |
| `Signature` | `Signature string` | `signature Option<String>` | Compatible | |
| `Primary` | `Primary Bool` | `primary Option<i32>` | Compatible | Bool wrapper vs API-int. |
| `Flags` | `Flags KeyState` | `flags Option<i32>` | Compatible | Enum vs raw int. |

## ProductUsedSpace (`ProductUsedSpace` vs `ProductUsedSpace`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `Calendar` | `Calendar uint64` | `calendar i64` | Compatible | |
| `Contact` | `Contact uint64` | `contact i64` | Compatible | |
| `Drive` | `Drive uint64` | `drive i64` | Compatible | |
| `Mail` | `Mail uint64` | `mail i64` | Compatible | |
| `Pass` | `Pass uint64` | `pass i64` | Compatible | |

## Address (`Address` vs `Address`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `ID` | `ID string` | `id String` | Exact | |
| `Email` | `Email string` | `email String` | Exact | |
| `Send` | `Send Bool` | `send i32` | Compatible | Bool wrapper vs API-int. |
| `Receive` | `Receive Bool` | `receive i32` | Compatible | Bool wrapper vs API-int. |
| `Status` | `Status AddressStatus` | `status i32` | Compatible | Enum vs raw int. |
| `Type` | `Type AddressType` | `address_type i32` | Compatible | Enum vs raw int. |
| `Order` | `Order int` | `order i32` | Compatible | Defaults to `0` when absent. |
| `DisplayName` | `DisplayName string` | `display_name String` | Exact | |
| `Keys` | `Keys Keys` | `keys Vec<AddressKey>` | Compatible | Different key struct representation. |

## Address Key (`Key` subset vs `AddressKey`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `ID` | `ID string` | `id String` | Exact | |
| `PrivateKey` | `PrivateKey []byte` (armored JSON I/O via custom marshal) | `private_key String` | Compatible | Rust stores armored string directly. |
| `Token` | `Token string` | `token Option<String>` | Compatible | Rust allows null/missing. |
| `Signature` | `Signature string` | `signature Option<String>` | Compatible | Rust allows null/missing. |
| `Active` | `Active Bool` | `active i32` | Compatible | |
| `Primary` | `Primary Bool` | `primary Option<i32>` | Compatible | Bool wrapper vs API-int. |
| `Flags` | `Flags KeyState` | `flags Option<i32>` | Compatible | Enum vs raw int. |

## MessageMetadata (`MessageMetadata` vs `MessageMetadata`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `ID` | `ID string` | `id String` | Exact | |
| `AddressID` | `AddressID string` | `address_id String` | Exact | |
| `LabelIDs` | `LabelIDs []string` | `label_ids Vec<String>` | Exact | |
| `ExternalID` | `ExternalID string` | `external_id Option<String>` | Compatible | |
| `Subject` | `Subject string` | `subject String` | Exact | |
| `Sender` | `Sender *mail.Address` | `sender EmailAddress` | Compatible | Pointer/mail.Address vs owned struct. |
| `ToList` | `ToList []*mail.Address` | `to_list Vec<EmailAddress>` | Compatible | |
| `CCList` | `CCList []*mail.Address` | `cc_list Vec<EmailAddress>` | Compatible | |
| `BCCList` | `BCCList []*mail.Address` | `bcc_list Vec<EmailAddress>` | Compatible | |
| `ReplyTos` | `ReplyTos []*mail.Address` | `reply_tos Vec<EmailAddress>` | Compatible | |
| `Flags` | `Flags MessageFlag` | `flags i64` | Compatible | Bitmask width differs. |
| `Time` | `Time int64` | `time i64` | Exact | |
| `Size` | `Size int` | `size i64` | Compatible | Width difference. |
| `Unread` | `Unread Bool` | `unread i32` | Compatible | Bool wrapper vs API-int. |
| `IsReplied` | `IsReplied Bool` | `is_replied i32` | Compatible | Bool wrapper vs API-int. |
| `IsRepliedAll` | `IsRepliedAll Bool` | `is_replied_all i32` | Compatible | Bool wrapper vs API-int. |
| `IsForwarded` | `IsForwarded Bool` | `is_forwarded i32` | Compatible | Bool wrapper vs API-int. |
| `NumAttachments` | `NumAttachments int` | `num_attachments i32` | Compatible | |

## Message (`Message` vs `Message`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `MessageMetadata` fields | Embedded `MessageMetadata` | `metadata` (flattened) | Exact | Same payload flattening at JSON boundary. |
| `Header` | `Header string` | `header String` | Exact | |
| `ParsedHeaders` | `ParsedHeaders Headers` | `parsed_headers Option<Value>` | Compatible | |
| `Body` | `Body string` | `body String` | Exact | |
| `MIMEType` | `MIMEType rfc822.MIMEType` | `mime_type String` | Compatible | Typed alias vs plain string. |
| `Attachments` | `Attachments []Attachment` | `attachments Vec<Attachment>` | Exact | |

## Attachment (`Attachment` vs `Attachment`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `ID` | `ID string` | `id String` | Exact | |
| `Name` | `Name string` | `name String` | Exact | |
| `Size` | `Size int64` | `size i64` | Exact | |
| `MIMEType` | `MIMEType rfc822.MIMEType` | `mime_type String` | Compatible | Typed alias vs plain string. |
| `Disposition` | `Disposition Disposition` | `disposition Option<String>` | Compatible | |
| `Headers` | `Headers Headers` | `headers Option<Value>` | Compatible | |
| `KeyPackets` | `KeyPackets string` | `key_packets String` | Exact | |
| `Signature` | `Signature string` | `signature Option<String>` | Compatible | |

## MessageFilter (`MessageFilter` vs `MessageFilter`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `ID` | `ID []string` | `id Option<Vec<String>>` | Compatible | |
| `Subject` | `Subject string` | `subject Option<String>` | Compatible | |
| `AddressID` | `AddressID string` | `address_id Option<String>` | Compatible | |
| `ExternalID` | `ExternalID string` | `external_id Option<String>` | Compatible | |
| `LabelID` | `LabelID string` | `label_id Option<String>` | Compatible | Optional in Rust. |
| `EndID` | `EndID string` | `end_id Option<String>` | Compatible | Optional in Rust. |
| `Desc` | `Desc Bool` | `desc i32` | Compatible | Bool wrapper vs API-int. |

## DraftTemplate (`DraftTemplate` vs `DraftTemplate`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `Subject` | `Subject string` | `subject String` | Exact | |
| `Sender` | `Sender *mail.Address` | `sender EmailAddress` | Compatible | |
| `ToList` | `ToList []*mail.Address` | `to_list Vec<EmailAddress>` | Compatible | |
| `CCList` | `CCList []*mail.Address` | `cc_list Vec<EmailAddress>` | Compatible | |
| `BCCList` | `BCCList []*mail.Address` | `bcc_list Vec<EmailAddress>` | Compatible | |
| `Body` | `Body string` | `body String` | Exact | |
| `MIMEType` | `MIMEType rfc822.MIMEType` | `mime_type String` | Compatible | |
| `Unread` | `Unread Bool` | `unread i32` | Compatible | |
| `ExternalID` | `ExternalID string` | `external_id Option<String>` | Compatible | |

## CreateDraftReq (`CreateDraftReq` vs `CreateDraftReq`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `Message` | `Message DraftTemplate` | `message DraftTemplate` | Exact | |
| `AttachmentKeyPackets` | `AttachmentKeyPackets []string` | `attachment_key_packets Option<Vec<String>>` | Compatible | |
| `ParentID` | `ParentID string` | `parent_id Option<String>` | Compatible | |
| `Action` | `Action CreateDraftAction` | `action i32` | Compatible | Enum vs raw int. |

## MessageRecipient (`MessageRecipient` vs `MessageRecipient`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `Type` | `Type EncryptionScheme` | `recipient_type i32` (`Type`) | Compatible | Enum vs raw int. |
| `Signature` | `Signature SignatureType` | `signature i32` | Compatible | Enum vs raw int. |
| `BodyKeyPacket` | `BodyKeyPacket string` | `body_key_packet Option<String>` | Compatible | Optional modeling in Rust. |
| `AttachmentKeyPackets` | `AttachmentKeyPackets map[string]string` | `attachment_key_packets Option<HashMap<String,String>>` | Compatible | Optional modeling in Rust. |

## MessagePackage (`MessagePackage` vs `MessagePackage`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `Addresses` | `Addresses map[string]*MessageRecipient` | `addresses HashMap<String, MessageRecipient>` | Compatible | Pointer values vs owned values. |
| `MIMEType` | `MIMEType rfc822.MIMEType` | `mime_type String` | Compatible | |
| `Type` | `Type EncryptionScheme` | `package_type i32` (`Type`) | Compatible | Enum vs raw int. |
| `Body` | `Body string` | `body String` | Exact | |
| `BodyKey` | `BodyKey *SessionKey` | `body_key Option<SessionKeyInfo>` | Compatible | |
| `AttachmentKeys` | `AttachmentKeys map[string]*SessionKey` | `attachment_keys Option<HashMap<String, SessionKeyInfo>>` | Compatible | |

## SessionKey (`SessionKey` vs `SessionKeyInfo`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `Key` | `Key string` | `key String` | Exact | |
| `Algorithm` | `Algorithm string` | `algorithm String` | Exact | |

## SendDraftReq (`SendDraftReq` vs `SendDraftReq`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `Packages` | `Packages []*MessagePackage` | `packages Vec<MessagePackage>` | Compatible | Pointer slice vs owned vec. |

## PublicKey (`PublicKey` vs `PublicKeyInfo`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `Flags` | `Flags KeyState` | `flags i32` | Compatible | Enum vs raw int. |
| `PublicKey` | `PublicKey string` | `public_key String` | Exact | |

## Public Keys Envelope (anonymous Go response vs `PublicKeysResponse`)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `Keys` | `[]PublicKey` (anonymous response struct in `keys.go`) | `keys Vec<PublicKeyInfo>` | Compatible | |
| `RecipientType` | `RecipientType RecipientType` | `recipient_type i32` | Compatible | Enum vs raw int. |

## Events Envelope (typed `Event` vs `EventsResponse` + untyped payloads)

| JSON key | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| `EventID` | `EventID string` | `event_id String` | Exact | |
| `More` | separate envelope bool in `getEvent` response | `more i32` | Compatible | Bool-ish/int-ish API convention. |
| `Refresh` | `Refresh RefreshFlag` | `refresh i32` | Compatible | Bitflag enum vs raw int. |
| event payload | typed fields on `Event` (`User`, `Messages`, `Labels`, `Addresses`, etc.) | `events Vec<Value>` + `TypedEventPayload` | Compatible | Typed models are parsed first with raw JSON fallback for unknown payloads. |

## Constant-Level Differences (send/signature schemes)

| Concept | go-proton-api | openproton-bridge | Status | Notes |
|---|---|---|---|---|
| Encryption scheme values | `Internal, EncryptedOutside, Clear, PGPInline, PGPMIME, ClearMIME` | `INTERNAL, ENCRYPTED_OUTSIDE, CLEAR, PGP_INLINE, PGP_MIME, CLEAR_MIME` | Exact | |
| Signature types | `NoSignature, DetachedSignature, AttachedSignature` | `NO_SIGNATURE, DETACHED_SIGNATURE, ATTACHED_SIGNATURE` | Exact | |

## Summary

- Core model parity gaps from the 2026-03-04 audit are now implemented.
- Remaining differences are mostly representation choices (`Option<T>`, raw ints vs enums, and dual typed/raw event handling).
