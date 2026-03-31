use std::collections::HashMap;

use crate::error::{DavError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavDepth {
    Zero,
    One,
    Infinity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub account_id: String,
    pub primary_email: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountResource {
    Principal,
    ScheduleInbox,
    ScheduleOutbox,
    AddressbooksHome,
    AddressbookDefault,
    CalendarsHome,
    CalendarCollection(String),
}

pub fn parse_depth(headers: &HashMap<String, String>) -> Result<DavDepth> {
    let Some(depth) = headers.get("depth").map(|value| value.trim()) else {
        return Ok(DavDepth::Infinity);
    };
    match depth {
        "0" => Ok(DavDepth::Zero),
        "1" => Ok(DavDepth::One),
        "infinity" => Ok(DavDepth::Infinity),
        _ => Err(DavError::InvalidRequest("invalid Depth header")),
    }
}

pub fn parse_account_resource_path(path: &str) -> Option<(String, AccountResource)> {
    let mut segments = path
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty());
    if segments.next()? != "dav" {
        return None;
    }
    let account_id = segments.next()?.to_string();
    let target = match (segments.next()?, segments.next(), segments.next()) {
        ("principal", None, None) => AccountResource::Principal,
        ("principal", Some("inbox"), None) => AccountResource::ScheduleInbox,
        ("principal", Some("outbox"), None) => AccountResource::ScheduleOutbox,
        ("addressbooks", None, None) => AccountResource::AddressbooksHome,
        ("addressbooks", Some("default"), None) => AccountResource::AddressbookDefault,
        ("calendars", None, None) => AccountResource::CalendarsHome,
        ("calendars", Some(calendar_id), None) => {
            if calendar_id.is_empty() {
                return None;
            }
            AccountResource::CalendarCollection(calendar_id.to_string())
        }
        _ => return None,
    };
    Some((account_id, target))
}

pub fn normalize_path(path: &str) -> String {
    let mut normalized = path
        .split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(path)
        .trim()
        .to_string();
    if normalized.is_empty() {
        normalized = "/".to_string();
    }
    if !normalized.starts_with('/') {
        normalized.insert(0, '/');
    }
    if normalized.ends_with('/') {
        normalized
    } else {
        format!("{normalized}/")
    }
}

pub fn is_safe_path(path: &str) -> bool {
    if path.is_empty() || !path.starts_with('/') || path.contains('\0') || path.contains('\\') {
        return false;
    }
    let Some(decoded) = decode_percent_path(path) else {
        return false;
    };
    if decoded.contains('\0') || decoded.contains('\\') || decoded.contains("//") {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return false;
    }
    !decoded
        .split('/')
        .any(|segment| segment == ".." || segment == ".")
}

fn decode_percent_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;

    while idx < bytes.len() {
        if bytes[idx] == b'%' {
            let high = hex_value(*bytes.get(idx + 1)?)?;
            let low = hex_value(*bytes.get(idx + 2)?)?;
            out.push((high << 4) | low);
            idx += 3;
            continue;
        }
        out.push(bytes[idx]);
        idx += 1;
    }

    String::from_utf8(out).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub fn account_id_hint(path: &str) -> Option<&str> {
    let mut segments = path
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty());
    if segments.next()? != "dav" {
        return None;
    }
    let account_id = segments.next()?;
    if account_id.eq_ignore_ascii_case("principals") {
        return None;
    }
    Some(account_id)
}

pub fn path_without_query(path: &str) -> &str {
    path.split_once('?').map(|(head, _)| head).unwrap_or(path)
}

pub fn parse_status_code(status: &str) -> Option<u16> {
    status.split_whitespace().next()?.parse::<u16>().ok()
}

pub fn looks_like_local_uuid(value: &str) -> bool {
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
