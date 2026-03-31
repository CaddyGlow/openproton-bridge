use std::collections::HashSet;

use regex::Regex;

use crate::discovery;
use crate::error::{DavError, Result};
use crate::http::DavResponse;
use crate::types::AuthContext;
use crate::xml::{multistatus_xml_for_propfind, DavPropResource, DavPropfindMode, DavResourceKind};

pub fn parse_propfind_mode(body: &[u8]) -> Result<DavPropfindMode> {
    if body.is_empty() {
        return Ok(DavPropfindMode::AllProp);
    }
    let body = std::str::from_utf8(body)
        .map_err(|_| DavError::InvalidRequest("PROPFIND body is not utf-8"))?;
    if body.contains("propname") {
        return Ok(DavPropfindMode::PropName);
    }
    if !body.contains("prop") {
        return Ok(DavPropfindMode::AllProp);
    }
    let prop_re = Regex::new(
        r"(?is)<(?:[A-Za-z0-9_-]+:)?prop\b[^>]*>(?P<body>.*?)</(?:[A-Za-z0-9_-]+:)?prop>",
    )
    .expect("prop regex should compile");
    let tag_re = Regex::new(r"(?is)<(?:[A-Za-z0-9_-]+:)?(?P<name>[A-Za-z0-9_-]+)\b")
        .expect("tag regex should compile");
    let Some(prop_body) = prop_re
        .captures(body)
        .and_then(|caps| caps.name("body"))
        .map(|m| m.as_str())
    else {
        return Ok(DavPropfindMode::AllProp);
    };
    let requested = tag_re
        .captures_iter(prop_body)
        .filter_map(|caps| caps.name("name"))
        .map(|name| name.as_str().to_string())
        .filter(|name| name != "prop")
        .collect::<HashSet<_>>();
    if requested.is_empty() {
        Ok(DavPropfindMode::AllProp)
    } else {
        Ok(DavPropfindMode::Prop(requested))
    }
}

pub fn multistatus_response(
    resources: Vec<DavPropResource>,
    mode: &DavPropfindMode,
) -> DavResponse {
    DavResponse {
        status: "207 Multi-Status",
        headers: vec![("Content-Type", "application/xml; charset=utf-8".to_string())],
        body: multistatus_xml_for_propfind(&resources, mode),
    }
}

pub fn principal_resource(auth: &AuthContext) -> DavPropResource {
    let principal = discovery::principal_path(&auth.account_id);
    DavPropResource {
        href: principal.clone(),
        display_name: auth.primary_email.clone(),
        kind: DavResourceKind::Principal,
        current_user_principal: Some(principal),
        principal_url: Some(discovery::principal_path(&auth.account_id)),
        principal_collection_set: Some(discovery::principal_collection_set_path()),
        addressbook_home_set: Some(discovery::addressbook_home_path(&auth.account_id)),
        calendar_home_set: Some(discovery::calendar_home_path(&auth.account_id)),
        calendar_user_addresses: vec![format!("mailto:{}", auth.primary_email)],
        schedule_inbox_url: None,
        schedule_outbox_url: None,
        owner: Some(discovery::principal_path(&auth.account_id)),
        current_user_privileges: vec!["read", "write", "write-properties", "bind", "unbind"],
        quota_available_bytes: None,
        quota_used_bytes: None,
        resource_id: Some(auth.account_id.clone()),
        calendar_free_busy_set: Vec::new(),
        schedule_calendar_transp: None,
        schedule_default_calendar_url: None,
        calendar_color: None,
        calendar_description: None,
        calendar_ctag: None,
        sync_token: None,
        supported_calendar_components: Vec::new(),
        supported_reports: vec![
            "expand-property",
            "principal-property-search",
            "principal-search-property-set",
        ],
        push_config: None,
    }
}

pub fn schedule_inbox_resource(auth: &AuthContext) -> DavPropResource {
    DavPropResource {
        href: discovery::schedule_inbox_path(&auth.account_id),
        display_name: "Inbox".to_string(),
        kind: DavResourceKind::ScheduleInbox,
        current_user_principal: None,
        principal_url: None,
        principal_collection_set: None,
        addressbook_home_set: None,
        calendar_home_set: None,
        calendar_user_addresses: Vec::new(),
        schedule_inbox_url: None,
        schedule_outbox_url: None,
        owner: Some(discovery::principal_path(&auth.account_id)),
        current_user_privileges: vec!["read", "write"],
        quota_available_bytes: None,
        quota_used_bytes: None,
        resource_id: None,
        calendar_free_busy_set: Vec::new(),
        schedule_calendar_transp: None,
        schedule_default_calendar_url: None,
        calendar_color: None,
        calendar_description: None,
        calendar_ctag: None,
        sync_token: None,
        supported_calendar_components: Vec::new(),
        supported_reports: Vec::new(),
        push_config: None,
    }
}

pub fn schedule_outbox_resource(auth: &AuthContext) -> DavPropResource {
    DavPropResource {
        href: discovery::schedule_outbox_path(&auth.account_id),
        display_name: "Outbox".to_string(),
        kind: DavResourceKind::ScheduleOutbox,
        current_user_principal: None,
        principal_url: None,
        principal_collection_set: None,
        addressbook_home_set: None,
        calendar_home_set: None,
        calendar_user_addresses: Vec::new(),
        schedule_inbox_url: None,
        schedule_outbox_url: None,
        owner: Some(discovery::principal_path(&auth.account_id)),
        current_user_privileges: vec!["read", "write"],
        quota_available_bytes: None,
        quota_used_bytes: None,
        resource_id: None,
        calendar_free_busy_set: Vec::new(),
        schedule_calendar_transp: None,
        schedule_default_calendar_url: None,
        calendar_color: None,
        calendar_description: None,
        calendar_ctag: None,
        sync_token: None,
        supported_calendar_components: Vec::new(),
        supported_reports: Vec::new(),
        push_config: None,
    }
}

pub fn non_empty_display_name(name: String) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
