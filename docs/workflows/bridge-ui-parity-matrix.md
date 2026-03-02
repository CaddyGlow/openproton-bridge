# Bridge UI Parity Matrix (FE-001)

This matrix is built from screenshot references in `UI/` captured on **March 2, 2026**.

## Matrix
| Parity ID | Source screenshot | bridge-ui fixture URL | Screen | State | Trigger | Expected output | Test mapping placeholders |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PM-UI-001 | `Screenshot 2026-03-02 at 06.15.19.png` | `/__visual__?screen=login&state=welcome` | Login wizard | Welcome/start setup | App starts with no authenticated user | Left pane welcome copy and right pane `Step 1`, `Step 2`, `Start setup` CTA visible | `visual`: `e2e/visual.spec.ts` -> `login-welcome snapshot`; `e2e`: `parity.runtime.spec.ts` -> `auth wizard opens in credentials welcome state` |
| PM-UI-002 | `Screenshot 2026-03-02 at 06.16.22.png` | `/__visual__?screen=login&state=security-key` | Login wizard | Security key auth | Auth flow enters FIDO/security-key branch | `Security key authentication` title, `Authenticate`, `Cancel`, and fallback link shown | `visual`: `login-security-key snapshot`; `e2e`: `parity.spec.ts` -> `auth flow fixture renders security key state` |
| PM-UI-003 | `Screenshot 2026-03-02 at 06.16.49.png` | `/__visual__?screen=login&state=client-selector` | Setup wizard | Client selection | Proton account connected; setup proceeds to client chooser | `Select your email client` with Apple Mail, Outlook, Thunderbird, Other, and `Setup later` | `visual`: `login-client-selector snapshot`; `e2e`: `parity.runtime.spec.ts` -> `client config wizard progresses through selector and configuration steps` |
| PM-UI-004 | `Screenshot 2026-03-02 at 06.16.57.png` | `/__visual__?screen=login&state=client-config` | Setup wizard | Client configuration details | User picks an email client | IMAP/SMTP cards with host/port/username/password/security and `Continue` CTA | `visual`: `login-client-config snapshot`; `e2e`: `parity.runtime.spec.ts` -> `client config wizard progresses through selector and configuration steps` |
| PM-UI-005 | `Screenshot 2026-03-02 at 06.17.14.png` | `/__visual__?screen=accounts&state=sync-progress&progress=4` | Accounts | Sync progress active | `SyncStarted` + `SyncProgress` events received | Account row and main panel show `Synchronizing (n%)` state while mailbox cards remain visible | `visual`: `accounts-sync-progress snapshot`; `e2e`: `parity.spec.ts` -> `account flow fixture renders sync progress state` |
| PM-UI-006 | `Screenshot 2026-03-02 at 06.17.32.png` | `/__visual__?screen=settings&state=general` | Settings | General section | User opens settings root | General toggles (updates/startup/beta) with advanced settings entry point visible | `visual`: `settings-general snapshot`; `e2e`: `parity.runtime.spec.ts` -> `settings sections and maintenance controls progress through parity states` |
| PM-UI-007 | `Screenshot 2026-03-02 at 06.17.43.png` | `/__visual__?screen=settings&state=advanced` | Settings | Advanced section expanded | User opens advanced settings | Advanced toggles plus actions for default ports, connection mode, and local cache | `visual`: `settings-advanced snapshot`; `e2e`: `parity.runtime.spec.ts` -> `settings sections and maintenance controls progress through parity states` |
| PM-UI-008 | `Screenshot 2026-03-02 at 06.17.52.png` | `/__visual__?screen=settings&state=maintenance` | Settings | Maintenance actions visible | User scrolls deeper into advanced settings | Local cache/export/repair/reset actions visible with account still in syncing state | `visual`: `settings-maintenance snapshot`; `e2e`: `parity.runtime.spec.ts` -> `settings sections and maintenance controls progress through parity states` |
| PM-UI-009 | `Screenshot 2026-03-02 at 06.18.03.png` | `/__visual__?screen=settings&state=menu-open&progress=6` | Settings | Overflow menu open | User opens top-right overflow (`...`) | Context menu with `Close window` and `Quit Bridge` displayed over settings page | `visual`: `settings-menu-open snapshot`; `e2e`: `parity.runtime.spec.ts` -> `settings overflow menu opens with runtime window actions` |

## Additional parity fixture state (not in screenshot set)
| Parity ID | bridge-ui fixture URL | Screen | State | Trigger | Expected output | Test mapping |
| --- | --- | --- | --- | --- | --- | --- |
| PM-UI-010 | `/__visual__?screen=settings&state=cache-move&cacheState=moving&cacheProgress=42` | Settings | Local cache move in-flight | User starts cache relocation | `Move status` shows deterministic in-flight progress text | `visual`: `settings-cache-move snapshot`; `e2e`: `parity.spec.ts` -> `settings flow fixture renders cache move states` |

## Coverage bookkeeping
- FE-011 scope covered by runtime parity e2e for auth/client-config/settings/overflow plus fixture assertions for security-key auth (`PM-UI-002`), sync progress (`PM-UI-005`), and cache move (`PM-UI-010`).
- FE-012 scope covered by snapshot harness entries for all screenshot-derived states (`PM-UI-001` through `PM-UI-009`) plus cache move regression capture (`PM-UI-010`).
