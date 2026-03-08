use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use crate::api::calendar::{self, CalendarBootstrap, CalendarEvent, CalendarEventPart};
use crate::api::client::ProtonClient;
use crate::api::types::Address;
use crate::bridge::accounts::RuntimeAccountRegistry;
use crate::bridge::types::AccountId;
use crate::crypto::decrypt;
use crate::crypto::keys::{self, Keyring};

pub struct CalendarDecryptContext {
    keyring: Keyring,
}

#[derive(Debug, Clone, Copy)]
enum IcsCandidateSource {
    PlainShared,
    PlainCalendar,
    PlainPersonal,
    PlainAttendee,
    DecryptedShared,
    DecryptedCalendar,
    DecryptedPersonal,
    DecryptedAttendee,
}

impl IcsCandidateSource {
    fn is_decrypted(self) -> bool {
        matches!(
            self,
            Self::DecryptedShared
                | Self::DecryptedCalendar
                | Self::DecryptedPersonal
                | Self::DecryptedAttendee
        )
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::PlainShared => "plain-shared",
            Self::PlainCalendar => "plain-calendar",
            Self::PlainPersonal => "plain-personal",
            Self::PlainAttendee => "plain-attendee",
            Self::DecryptedShared => "decrypted-shared",
            Self::DecryptedCalendar => "decrypted-calendar",
            Self::DecryptedPersonal => "decrypted-personal",
            Self::DecryptedAttendee => "decrypted-attendee",
        }
    }
}

impl CalendarDecryptContext {
    pub fn render_event_ics(&self, event: &CalendarEvent) -> Option<String> {
        best_event_ics(event, Some(self))
    }
}

pub async fn build_calendar_decrypt_context(
    runtime_accounts: &Arc<RuntimeAccountRegistry>,
    account_id: &str,
    calendar_id: &str,
) -> Option<CalendarDecryptContext> {
    if looks_like_local_uuid(calendar_id) {
        return None;
    }
    let account_id = AccountId(account_id.to_string());
    let session = runtime_accounts.get_session(&account_id).await?;
    let auth_material = runtime_accounts.get_auth_material(&account_id).await?;
    let passphrase_b64 = session.key_passphrase.as_deref()?;
    let passphrase = BASE64.decode(passphrase_b64).ok()?;

    let user_keyring = keys::unlock_user_keys(&auth_material.user_keys, &passphrase).ok()?;
    let address_keyrings =
        build_address_keyrings(&auth_material.addresses, &passphrase, &user_keyring);
    if address_keyrings.is_empty() {
        return None;
    }

    let client = ProtonClient::authenticated_with_mode(
        session.api_mode.base_url(),
        session.api_mode,
        &session.uid,
        &session.access_token,
    )
    .ok()?;
    let bootstrap = calendar::get_calendar_bootstrap(&client, calendar_id)
        .await
        .ok()?;
    let calendar_passphrase = decrypt_calendar_passphrase(&bootstrap, &address_keyrings)?;
    let keyring = keys::unlock_private_keys(
        bootstrap.keys.iter().map(|key| key.private_key.as_str()),
        &calendar_passphrase,
    )
    .ok()?;
    Some(CalendarDecryptContext { keyring })
}

fn looks_like_local_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    let bytes = value.as_bytes();
    for (idx, byte) in bytes.iter().enumerate() {
        let is_hyphen = matches!(idx, 8 | 13 | 18 | 23);
        if is_hyphen {
            if *byte != b'-' {
                return false;
            }
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

pub fn best_event_ics(
    event: &CalendarEvent,
    decrypt_context: Option<&CalendarDecryptContext>,
) -> Option<String> {
    let mut best: Option<String> = None;
    let mut best_score = i32::MIN;
    let mut best_source: Option<IcsCandidateSource> = None;

    for (source, candidate) in plaintext_candidates(event) {
        let score = ics_score(&candidate, source);
        if score > best_score {
            best_score = score;
            best_source = Some(source);
            best = Some(candidate);
        }
    }

    if let Some(ctx) = decrypt_context {
        for (source, candidate) in decrypted_candidates(event, ctx) {
            let score = ics_score(&candidate, source);
            if score > best_score {
                best_score = score;
                best_source = Some(source);
                best = Some(candidate);
            }
        }
    }

    if let (Some(source), Some(ics)) = (best_source, best.as_ref()) {
        let upper = ics.to_ascii_uppercase();
        let summary = first_property_value(ics, "SUMMARY");
        let location = first_property_value(ics, "LOCATION");
        let description = first_property_value(ics, "DESCRIPTION");
        tracing::debug!(
            event_id = %event.id,
            calendar_id = %event.calendar_id,
            source = source.as_str(),
            score = best_score,
            decrypted = source.is_decrypted(),
            has_summary = upper.contains("SUMMARY:"),
            has_location = upper.contains("LOCATION:"),
            has_description = upper.contains("DESCRIPTION:"),
            summary_len = summary.as_ref().map(|value| value.len()).unwrap_or(0),
            location_len = location.as_ref().map(|value| value.len()).unwrap_or(0),
            description_len = description.as_ref().map(|value| value.len()).unwrap_or(0),
            summary = summary.as_deref().unwrap_or(""),
            location = location.as_deref().unwrap_or(""),
            payload_len = ics.len(),
            "dav calendar ics candidate selected"
        );
    }

    best
}

fn build_address_keyrings(
    addresses: &[Address],
    passphrase: &[u8],
    user_keyring: &Keyring,
) -> HashMap<String, Keyring> {
    let mut out = HashMap::new();
    for address in addresses {
        if address.status != 1 || address.keys.is_empty() {
            continue;
        }
        match keys::unlock_address_keys(&address.keys, passphrase, user_keyring) {
            Ok(keyring) => {
                out.insert(address.email.trim().to_ascii_lowercase(), keyring);
            }
            Err(err) => {
                tracing::debug!(
                    address = %address.email,
                    error = %err,
                    "failed to unlock address keys for calendar decryption"
                );
            }
        }
    }
    out
}

fn decrypt_calendar_passphrase(
    bootstrap: &CalendarBootstrap,
    address_keyrings: &HashMap<String, Keyring>,
) -> Option<Vec<u8>> {
    for member_passphrase in &bootstrap.passphrase.member_passphrases {
        let member_email = bootstrap
            .members
            .iter()
            .find(|member| member.id == member_passphrase.member_id)
            .map(|member| member.email.trim().to_ascii_lowercase());

        if let Some(email) = member_email.as_deref() {
            if let Some(keyring) = address_keyrings.get(email) {
                if let Ok(passphrase) =
                    decrypt::decrypt_message_body(keyring, &member_passphrase.passphrase)
                {
                    if !passphrase.is_empty() {
                        return Some(passphrase);
                    }
                }
            }
        }

        for keyring in address_keyrings.values() {
            if let Ok(passphrase) =
                decrypt::decrypt_message_body(keyring, &member_passphrase.passphrase)
            {
                if !passphrase.is_empty() {
                    return Some(passphrase);
                }
            }
        }
    }
    None
}

fn plaintext_candidates(event: &CalendarEvent) -> Vec<(IcsCandidateSource, String)> {
    let mut out = Vec::new();
    collect_plaintext_candidates(
        &mut out,
        &event.shared_events,
        IcsCandidateSource::PlainShared,
    );
    collect_plaintext_candidates(
        &mut out,
        &event.calendar_events,
        IcsCandidateSource::PlainCalendar,
    );
    collect_plaintext_candidates(
        &mut out,
        &event.personal_events,
        IcsCandidateSource::PlainPersonal,
    );
    collect_plaintext_candidates(
        &mut out,
        &event.attendees_events,
        IcsCandidateSource::PlainAttendee,
    );
    out
}

fn collect_plaintext_candidates(
    out: &mut Vec<(IcsCandidateSource, String)>,
    parts: &[CalendarEventPart],
    source: IcsCandidateSource,
) {
    out.extend(
        parts
            .iter()
            .filter_map(|part| extract_inline_ics_payload(&part.data).map(|ics| (source, ics))),
    );
}

fn decrypted_candidates(
    event: &CalendarEvent,
    ctx: &CalendarDecryptContext,
) -> Vec<(IcsCandidateSource, String)> {
    let mut out = Vec::new();
    for part in &event.shared_events {
        if let Some(ics) = decrypt_part(part, &event.shared_key_packet, &ctx.keyring) {
            out.push((IcsCandidateSource::DecryptedShared, ics));
        }
    }
    for part in &event.calendar_events {
        let key_packet = if event.calendar_key_packet.trim().is_empty() {
            &event.shared_key_packet
        } else {
            &event.calendar_key_packet
        };
        if let Some(ics) = decrypt_part(part, key_packet, &ctx.keyring) {
            out.push((IcsCandidateSource::DecryptedCalendar, ics));
        }
    }
    for part in &event.personal_events {
        if let Some(ics) = decrypt_part(part, &event.shared_key_packet, &ctx.keyring) {
            out.push((IcsCandidateSource::DecryptedPersonal, ics));
        }
    }
    for part in &event.attendees_events {
        if let Some(ics) = decrypt_part(part, &event.shared_key_packet, &ctx.keyring) {
            out.push((IcsCandidateSource::DecryptedAttendee, ics));
        }
    }
    out
}

fn decrypt_part(part: &CalendarEventPart, key_packet: &str, keyring: &Keyring) -> Option<String> {
    if part.kind != 1 || key_packet.trim().is_empty() {
        return None;
    }
    let data_packets = BASE64.decode(part.data.trim()).ok()?;
    let decrypted = decrypt::decrypt_attachment(keyring, key_packet, &data_packets).ok()?;
    let text = String::from_utf8(decrypted).ok()?;
    extract_inline_ics_payload(&text)
}

fn extract_inline_ics_payload(raw: &str) -> Option<String> {
    let payload = if raw
        .trim_start()
        .starts_with("-----BEGIN PGP SIGNED MESSAGE-----")
    {
        extract_clearsigned_body(raw)?
    } else {
        raw.to_string()
    };
    let start = payload.find("BEGIN:VCALENDAR")?;
    let end = payload.rfind("END:VCALENDAR")? + "END:VCALENDAR".len();
    (end > start).then(|| normalize_ics_payload(&payload[start..end]))
}

fn extract_clearsigned_body(raw: &str) -> Option<String> {
    let mut body = Vec::new();
    let mut in_body = false;

    for line in raw.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
            continue;
        }
        if trimmed.starts_with("Hash:") {
            continue;
        }
        if trimmed.starts_with("-----BEGIN PGP SIGNATURE-----") {
            break;
        }
        if !in_body {
            if trimmed.is_empty() {
                in_body = true;
            }
            continue;
        }
        body.push(trimmed.strip_prefix("- ").unwrap_or(trimmed).to_string());
    }

    (!body.is_empty()).then(|| body.join("\n"))
}

fn ics_score(ics: &str, source: IcsCandidateSource) -> i32 {
    let upper = ics.to_ascii_uppercase();
    let mut score = 0;
    if source.is_decrypted() {
        score += 50;
    }
    for needle in [
        "SUMMARY:",
        "LOCATION:",
        "DESCRIPTION:",
        "ORGANIZER",
        "ATTENDEE",
        "STATUS:",
        "RRULE:",
        "RECURRENCE-ID",
        "DTSTART",
        "DTEND",
    ] {
        if upper.contains(needle) {
            score += 20;
        }
    }
    score + (ics.len() as i32 / 32)
}

pub fn normalize_ics_payload(raw: &str) -> String {
    let unfolded = unfold_ics_lines(raw);
    let canonical = canonicalize_ics_lines(&unfolded);
    canonical.join("\r\n") + "\r\n"
}

pub fn unfold_ics_lines(raw: &str) -> Vec<String> {
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines: Vec<String> = Vec::new();
    for line in normalized.split('\n') {
        if let Some(rest) = line.strip_prefix([' ', '\t']) {
            if let Some(previous) = lines.last_mut() {
                previous.push_str(rest);
                continue;
            }
        }
        lines.push(line.to_string());
    }
    while matches!(lines.last(), Some(last) if last.is_empty()) {
        lines.pop();
    }
    lines
}

fn canonicalize_ics_lines(lines: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(lines.len() + 3);
    let mut inserted_calendar_defaults = false;

    for line in lines {
        let trimmed = line.trim_end();
        if trimmed.eq_ignore_ascii_case("BEGIN:VCALENDAR") {
            out.push("BEGIN:VCALENDAR".to_string());
            inserted_calendar_defaults = true;
            continue;
        }
        out.push(normalize_ics_property(trimmed));
    }

    if inserted_calendar_defaults {
        ensure_calendar_header(&mut out);
    }
    out
}

fn ensure_calendar_header(lines: &mut Vec<String>) {
    let begin_index = lines
        .iter()
        .position(|line| line.eq_ignore_ascii_case("BEGIN:VCALENDAR"));
    let Some(begin_index) = begin_index else {
        return;
    };

    let has_version = lines
        .iter()
        .any(|line| line.to_ascii_uppercase().starts_with("VERSION:"));
    let has_prodid = lines
        .iter()
        .any(|line| line.to_ascii_uppercase().starts_with("PRODID:"));
    let has_calscale = lines
        .iter()
        .any(|line| line.to_ascii_uppercase().starts_with("CALSCALE:"));

    let mut insert_at = begin_index + 1;
    if !has_prodid {
        lines.insert(insert_at, "PRODID:-//OpenProton Bridge//EN".to_string());
        insert_at += 1;
    }
    if !has_version {
        lines.insert(insert_at, "VERSION:2.0".to_string());
        insert_at += 1;
    }
    if !has_calscale {
        lines.insert(insert_at, "CALSCALE:GREGORIAN".to_string());
    }
}

fn normalize_ics_property(line: &str) -> String {
    let Some((left, value)) = line.split_once(':') else {
        return line.to_string();
    };
    let Some((name, params)) = split_property_name_and_params(left) else {
        return line.to_string();
    };
    let mut kept_params = Vec::new();
    let mut decode_qp = false;
    for param in params {
        let upper = param.to_ascii_uppercase();
        if upper == "ENCODING=QUOTED-PRINTABLE" {
            decode_qp = true;
            continue;
        }
        if upper.starts_with("CHARSET=") {
            continue;
        }
        kept_params.push(param);
    }

    let value = if decode_qp {
        decode_quoted_printable_text(value)
    } else {
        value.to_string()
    };

    if kept_params.is_empty() {
        format!("{name}:{value}")
    } else {
        format!("{name};{}:{value}", kept_params.join(";"))
    }
}

fn split_property_name_and_params(left: &str) -> Option<(&str, Vec<&str>)> {
    let mut parts = left.split(';');
    let name = parts.next()?;
    Some((name, parts.collect()))
}

fn decode_quoted_printable_text(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        match bytes[idx] {
            b'=' if idx + 2 < bytes.len() => {
                if let (Some(high), Some(low)) = (
                    decode_hex_nibble(bytes[idx + 1]),
                    decode_hex_nibble(bytes[idx + 2]),
                ) {
                    out.push((high << 4) | low);
                    idx += 3;
                    continue;
                }
                out.push(bytes[idx]);
                idx += 1;
            }
            b'=' => {
                idx += 1;
            }
            other => {
                out.push(other);
                idx += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn first_property_value(ics: &str, property: &str) -> Option<String> {
    let prefix = format!("{property}:");
    let folded_prefix = format!("{property};");
    for line in ics.lines() {
        if let Some(value) = line.strip_prefix(&prefix) {
            return Some(value.trim().to_string());
        }
        if line.starts_with(&folded_prefix) {
            if let Some((_, value)) = line.split_once(':') {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::api::calendar::{CalendarEvent, CalendarEventPart};

    use super::{
        best_event_ics, extract_clearsigned_body, extract_inline_ics_payload, first_property_value,
        normalize_ics_payload,
    };

    #[test]
    fn prefers_richer_plaintext_ics_payload() {
        let event = CalendarEvent {
            shared_events: vec![CalendarEventPart {
                member_id: String::new(),
                kind: 0,
                data: "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:a\nDTSTART:20260307T080000Z\nEND:VEVENT\nEND:VCALENDAR".to_string(),
                signature: None,
                author: None,
            }],
            calendar_events: vec![CalendarEventPart {
                member_id: String::new(),
                kind: 0,
                data: "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:a\nDTSTART:20260307T080000Z\nSUMMARY:Meeting\nLOCATION:Office\nDESCRIPTION:Notes\nEND:VEVENT\nEND:VCALENDAR".to_string(),
                signature: None,
                author: None,
            }],
            ..CalendarEvent::default()
        };

        let ics = best_event_ics(&event, None).unwrap();
        assert!(ics.contains("SUMMARY:Meeting"));
        assert!(ics.contains("LOCATION:Office"));
        assert!(ics.contains("DESCRIPTION:Notes"));
    }

    #[test]
    fn prefers_decrypted_candidate_on_equal_shape() {
        let event = CalendarEvent {
            shared_events: vec![CalendarEventPart {
                member_id: String::new(),
                kind: 0,
                data: "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:a\nDTSTART:20260307T080000Z\nSUMMARY:Sparse\nEND:VEVENT\nEND:VCALENDAR".to_string(),
                signature: None,
                author: None,
            }],
            ..CalendarEvent::default()
        };

        let ics = best_event_ics(&event, None).unwrap();
        assert!(ics.contains("SUMMARY:Sparse"));
    }

    #[test]
    fn extracts_ics_from_clearsigned_payload() {
        let payload = "-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA256\r\n\r\nBEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\nSUMMARY:Meeting\r\nLOCATION:Office\r\nDESCRIPTION:Notes\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n-----BEGIN PGP SIGNATURE-----\r\nsig\r\n-----END PGP SIGNATURE-----\r\n";
        let ics = extract_inline_ics_payload(payload).unwrap();
        assert!(ics.starts_with("BEGIN:VCALENDAR\r\n"));
        assert!(ics.contains("SUMMARY:Meeting\r\n"));
        assert!(ics.contains("LOCATION:Office\r\n"));
        assert!(ics.contains("DESCRIPTION:Notes\r\n"));
        assert!(!ics.contains("BEGIN PGP SIGNED MESSAGE"));
        assert!(!ics.contains("BEGIN PGP SIGNATURE"));
    }

    #[test]
    fn extracts_clearsigned_body_without_signature_block() {
        let payload = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nBEGIN:VCALENDAR\nBEGIN:VEVENT\nSUMMARY:Meeting\nEND:VEVENT\nEND:VCALENDAR\n-----BEGIN PGP SIGNATURE-----\nsig\n-----END PGP SIGNATURE-----\n";
        let body = extract_clearsigned_body(payload).unwrap();
        assert!(body.starts_with("BEGIN:VCALENDAR\n"));
        assert!(body.contains("SUMMARY:Meeting\n"));
        assert!(!body.contains("BEGIN PGP SIGNATURE"));
    }

    #[test]
    fn extracts_property_values_with_params() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY;LANGUAGE=en:Hello\r\nLOCATION:Office\r\nDESCRIPTION:Notes\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert_eq!(
            first_property_value(ics, "SUMMARY").as_deref(),
            Some("Hello")
        );
        assert_eq!(
            first_property_value(ics, "LOCATION").as_deref(),
            Some("Office")
        );
        assert_eq!(
            first_property_value(ics, "DESCRIPTION").as_deref(),
            Some("Notes")
        );
    }

    #[test]
    fn unfolds_folded_lines_and_inserts_calendar_defaults() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Very long\r\n value\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let normalized = normalize_ics_payload(ics);
        assert!(normalized.contains("PRODID:-//OpenProton Bridge//EN\r\n"));
        assert!(normalized.contains("VERSION:2.0\r\n"));
        assert!(normalized.contains("CALSCALE:GREGORIAN\r\n"));
        assert!(normalized.contains("SUMMARY:Very longvalue\r\n"));
    }

    #[test]
    fn decodes_quoted_printable_text_properties() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY;ENCODING=QUOTED-PRINTABLE;CHARSET=UTF-8:Hello=20World\r\nDESCRIPTION;ENCODING=QUOTED-PRINTABLE:Line=201\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let normalized = normalize_ics_payload(ics);
        assert!(normalized.contains("SUMMARY:Hello World\r\n"));
        assert!(normalized.contains("DESCRIPTION:Line 1\r\n"));
        assert!(!normalized.contains("QUOTED-PRINTABLE"));
        assert!(!normalized.contains("CHARSET="));
    }
}
