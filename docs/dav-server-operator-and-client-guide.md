# DAV Server Operator and Client Guide

This guide covers local CardDAV and CalDAV operation in OpenProton Bridge.

## Scope and status

- Feature: local DAV server (CardDAV + CalDAV)
- Runtime: same process as IMAP/SMTP serve runtime
- Auth model: existing account email + bridge password (Basic auth)
- Default state: disabled (`dav_enable = false`)

## Operator configuration (DAV-501)

### Runtime config knobs

These settings are part of the serve runtime configuration:

- `dav_enable` (bool)
- `dav_port` (u16)
- `dav_tls_mode` (`none` or `starttls`)

Current defaults:

- `dav_enable = false`
- `dav_port = 8080`
- `dav_tls_mode = none`

### CLI flags

Serve-time overrides:

- `--dav-enable`
- `--dav-disable`
- `--dav-port <port>`
- `--dav-tls-mode <none|starttls>`

Example:

```bash
openproton-bridge serve --dav-enable --dav-port 8080 --dav-tls-mode none
```

### Interactive runtime changes

Supported interactive `change` targets include:

- `change dav-enable <on|off|true|false|1|0>`
- `change dav-port <port>`
- `change dav-tls-mode <none|starttls>`

### Ports and bind host

- DAV listens on `<bind_host>:<dav_port>`.
- Keep `bind_host` local (`127.0.0.1`) unless you explicitly need LAN exposure.
- If DAV is exposed off-host, place TLS/auth network controls in front of it.

### TLS mode notes

- `none`: plaintext HTTP transport.
- `starttls`: STARTTLS mode is configurable in runtime settings; use client-side validation and network controls consistent with your environment.

### Migration notes

- DAV is additive: enabling DAV does not replace IMAP/SMTP behavior.
- Existing account/session storage and bridge password auth remain the same.
- PIM data is served from the local cache/store used by existing PIM sync flows.

## Client setup (DAV-502)

Use account email as username and bridge password as password.

Discovery endpoints:

- CardDAV: `http://127.0.0.1:<dav_port>/.well-known/carddav`
- CalDAV: `http://127.0.0.1:<dav_port>/.well-known/caldav`

### Apple Contacts (CardDAV)

1. Open `Contacts` -> `Settings` -> `Accounts` -> `Add Account` -> `Other Contacts Account` -> `Add CardDAV Account`.
2. Choose manual setup.
3. Server: `127.0.0.1` (or your configured bind host).
4. Username: Proton account email.
5. Password: bridge password.
6. Port: configured `dav_port` (default `8080`).
7. If prompted for a URL, use `/.well-known/carddav` on the configured host/port.

### Apple Calendar (CalDAV)

1. Open `Calendar` -> `Settings` -> `Accounts` -> `Add Account` -> `Other CalDAV Account`.
2. Choose manual setup.
3. Server: `127.0.0.1`.
4. Username/password: email + bridge password.
5. Port: configured `dav_port`.
6. If URL is requested directly, use `/.well-known/caldav`.

### Thunderbird + CardBook

1. In Thunderbird, install/enable CardBook if needed for contacts.
2. Add CardDAV account in CardBook with discovery URL:
   - `http://127.0.0.1:<dav_port>/.well-known/carddav`
3. Add CalDAV calendar in Thunderbird Calendar with:
   - `http://127.0.0.1:<dav_port>/.well-known/caldav`
4. Authenticate with email + bridge password.
5. If your environment enforces secure transport only, place DAV behind TLS termination and use the terminated endpoint URL.

## Rollout controls (DAV-503)

### Guardrails

- Keep `dav_enable=false` by default for baseline installs.
- Enable DAV only for staged cohorts.
- Keep `dav_port` non-conflicting with local services.
- Prefer local bind during early rollout.

### Recommended staged rollout

1. Stage 0: disabled everywhere (`dav_enable=false`).
2. Stage 1: single-operator lab with one account and one CardDAV client.
3. Stage 2: add one CalDAV client, validate recurring sync loops.
4. Stage 3: small internal cohort (multiple OS/client mixes).
5. Stage 4: broader enablement with ongoing telemetry review.

### What to monitor during rollout

- Request latency and failure ratios from DAV runtime logs.
- Auth failures (`401`) spikes after client onboarding.
- Client-specific sync behavior on repeated refresh cycles.
- Store availability errors (`503`) and malformed request rates (`400`).

## Quick smoke checklist

1. Start runtime with DAV enabled.
2. Verify discovery endpoints return redirects.
3. Verify authenticated `PROPFIND` returns `207 Multi-Status`.
4. Verify one contact create/read/delete via CardDAV client.
5. Verify one event create/read/delete via CalDAV client.
