use std::collections::HashMap;

use crate::bridge::auth_router::AuthRoute;

use super::discovery;
use super::error::{DavError, Result};
use super::http::DavResponse;
use super::xml::{multistatus_xml, DavPropResource, DavResourceKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavDepth {
    Zero,
    One,
    Infinity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccountResource {
    Principal,
    AddressbooksHome,
    AddressbookDefault,
    CalendarsHome,
    CalendarDefault,
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

pub fn handle_propfind(
    raw_path: &str,
    headers: &HashMap<String, String>,
    auth: &AuthRoute,
) -> Result<DavResponse> {
    let depth = parse_depth(headers)?;
    let path = normalize_path(raw_path);

    if path == discovery::PRINCIPAL_ME_PATH {
        let resources = principal_resources(auth, depth);
        return Ok(multistatus_response(resources));
    }

    let Some((account_id, target)) = parse_account_resource_path(&path) else {
        return Ok(not_found_response());
    };
    if account_id != auth.account_id.0 {
        return Ok(forbidden_response());
    }

    let resources = match target {
        AccountResource::Principal => principal_resources(auth, depth),
        AccountResource::AddressbooksHome => addressbook_home_resources(auth, depth),
        AccountResource::AddressbookDefault => vec![default_addressbook_resource(auth)],
        AccountResource::CalendarsHome => calendar_home_resources(auth, depth),
        AccountResource::CalendarDefault => vec![default_calendar_resource(auth)],
    };
    Ok(multistatus_response(resources))
}

fn principal_resources(auth: &AuthRoute, depth: DavDepth) -> Vec<DavPropResource> {
    let mut resources = vec![principal_resource(auth)];
    if depth != DavDepth::Zero {
        resources.push(addressbook_home_resource(auth));
        resources.push(calendar_home_resource(auth));
    }
    resources
}

fn addressbook_home_resources(auth: &AuthRoute, depth: DavDepth) -> Vec<DavPropResource> {
    let mut resources = vec![addressbook_home_resource(auth)];
    if depth != DavDepth::Zero {
        resources.push(default_addressbook_resource(auth));
    }
    resources
}

fn calendar_home_resources(auth: &AuthRoute, depth: DavDepth) -> Vec<DavPropResource> {
    let mut resources = vec![calendar_home_resource(auth)];
    if depth != DavDepth::Zero {
        resources.push(default_calendar_resource(auth));
    }
    resources
}

fn principal_resource(auth: &AuthRoute) -> DavPropResource {
    let principal = discovery::principal_path(&auth.account_id.0);
    DavPropResource {
        href: principal.clone(),
        display_name: auth.primary_email.clone(),
        kind: DavResourceKind::Principal,
        current_user_principal: Some(principal),
        addressbook_home_set: Some(discovery::addressbook_home_path(&auth.account_id.0)),
        calendar_home_set: Some(discovery::calendar_home_path(&auth.account_id.0)),
    }
}

fn addressbook_home_resource(auth: &AuthRoute) -> DavPropResource {
    DavPropResource {
        href: discovery::addressbook_home_path(&auth.account_id.0),
        display_name: "Address Books".to_string(),
        kind: DavResourceKind::AddressbookHome,
        current_user_principal: None,
        addressbook_home_set: None,
        calendar_home_set: None,
    }
}

fn default_addressbook_resource(auth: &AuthRoute) -> DavPropResource {
    DavPropResource {
        href: discovery::default_addressbook_path(&auth.account_id.0),
        display_name: "Default Address Book".to_string(),
        kind: DavResourceKind::Addressbook,
        current_user_principal: None,
        addressbook_home_set: None,
        calendar_home_set: None,
    }
}

fn calendar_home_resource(auth: &AuthRoute) -> DavPropResource {
    DavPropResource {
        href: discovery::calendar_home_path(&auth.account_id.0),
        display_name: "Calendars".to_string(),
        kind: DavResourceKind::CalendarHome,
        current_user_principal: None,
        addressbook_home_set: None,
        calendar_home_set: None,
    }
}

fn default_calendar_resource(auth: &AuthRoute) -> DavPropResource {
    DavPropResource {
        href: discovery::default_calendar_path(&auth.account_id.0),
        display_name: "Default Calendar".to_string(),
        kind: DavResourceKind::Calendar,
        current_user_principal: None,
        addressbook_home_set: None,
        calendar_home_set: None,
    }
}

fn parse_account_resource_path(path: &str) -> Option<(String, AccountResource)> {
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
        ("addressbooks", None, None) => AccountResource::AddressbooksHome,
        ("addressbooks", Some("default"), None) => AccountResource::AddressbookDefault,
        ("calendars", None, None) => AccountResource::CalendarsHome,
        ("calendars", Some("default"), None) => AccountResource::CalendarDefault,
        _ => return None,
    };
    Some((account_id, target))
}

fn multistatus_response(resources: Vec<DavPropResource>) -> DavResponse {
    DavResponse {
        status: "207 Multi-Status",
        headers: vec![("Content-Type", "application/xml; charset=utf-8".to_string())],
        body: multistatus_xml(&resources),
    }
}

fn forbidden_response() -> DavResponse {
    DavResponse {
        status: "403 Forbidden",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"forbidden\n".to_vec(),
    }
}

fn not_found_response() -> DavResponse {
    DavResponse {
        status: "404 Not Found",
        headers: vec![("Content-Type", "text/plain; charset=utf-8".to_string())],
        body: b"not found\n".to_vec(),
    }
}

fn normalize_path(path: &str) -> String {
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::bridge::auth_router::AuthRoute;
    use crate::bridge::types::AccountId;

    use super::{handle_propfind, parse_depth, DavDepth};

    fn auth() -> AuthRoute {
        AuthRoute {
            account_id: AccountId("uid-1".to_string()),
            primary_email: "alice@proton.me".to_string(),
        }
    }

    #[test]
    fn parses_depth_values() {
        let mut headers = HashMap::new();
        headers.insert("depth".to_string(), "1".to_string());
        assert_eq!(parse_depth(&headers).unwrap(), DavDepth::One);
    }

    #[test]
    fn propfind_principal_me_returns_multistatus() {
        let response =
            handle_propfind("/dav/principals/me/", &HashMap::new(), &auth()).expect("response");
        let body = String::from_utf8(response.body).expect("utf8");
        assert_eq!(response.status, "207 Multi-Status");
        assert!(body.contains("<d:multistatus"));
        assert!(body.contains("/dav/uid-1/principal/"));
    }

    #[test]
    fn propfind_rejects_cross_account_paths() {
        let response =
            handle_propfind("/dav/uid-2/principal/", &HashMap::new(), &auth()).expect("response");
        assert_eq!(response.status, "403 Forbidden");
    }
}
