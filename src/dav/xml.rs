use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavResourceKind {
    Principal,
    ScheduleInbox,
    ScheduleOutbox,
    AddressbookHome,
    Addressbook,
    CalendarHome,
    Calendar,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DavPropResource {
    pub href: String,
    pub display_name: String,
    pub kind: DavResourceKind,
    pub current_user_principal: Option<String>,
    pub principal_url: Option<String>,
    pub principal_collection_set: Option<String>,
    pub addressbook_home_set: Option<String>,
    pub calendar_home_set: Option<String>,
    pub calendar_user_addresses: Vec<String>,
    pub schedule_inbox_url: Option<String>,
    pub schedule_outbox_url: Option<String>,
    pub owner: Option<String>,
    pub current_user_privileges: Vec<&'static str>,
    pub quota_available_bytes: Option<u64>,
    pub quota_used_bytes: Option<u64>,
    pub resource_id: Option<String>,
    pub calendar_free_busy_set: Vec<String>,
    pub schedule_calendar_transp: Option<&'static str>,
    pub schedule_default_calendar_url: Option<String>,
    pub calendar_color: Option<String>,
    pub calendar_description: Option<String>,
    pub calendar_ctag: Option<String>,
    pub sync_token: Option<String>,
    pub supported_calendar_components: Vec<&'static str>,
    pub supported_reports: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DavPropfindMode {
    AllProp,
    PropName,
    Prop(HashSet<String>),
}

pub fn multistatus_xml(resources: &[DavPropResource]) -> Vec<u8> {
    multistatus_xml_for_propfind(resources, &DavPropfindMode::AllProp)
}

pub fn multistatus_xml_for_propfind(
    resources: &[DavPropResource],
    mode: &DavPropfindMode,
) -> Vec<u8> {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:ical="http://apple.com/ns/ical/">"#,
    );
    for resource in resources {
        xml.push_str("<d:response>");
        xml.push_str("<d:href>");
        xml.push_str(&escape_xml(&resource.href));
        xml.push_str("</d:href>");
        xml.push_str("<d:propstat><d:prop>");
        write_named_or_valued_property(
            &mut xml,
            mode,
            "displayname",
            "<d:displayname>",
            "</d:displayname>",
            Some(&escape_xml(&resource.display_name)),
        );
        write_named_or_valued_property(
            &mut xml,
            mode,
            "resourcetype",
            "<d:resourcetype>",
            "</d:resourcetype>",
            Some(resource_type_xml(resource.kind)),
        );

        if let Some(current) = &resource.current_user_principal {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "current-user-principal",
                "<d:current-user-principal>",
                "</d:current-user-principal>",
                Some(&format!("<d:href>{}</d:href>", escape_xml(current))),
            );
        }
        if let Some(principal_url) = &resource.principal_url {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "principal-URL",
                "<d:principal-URL>",
                "</d:principal-URL>",
                Some(&format!("<d:href>{}</d:href>", escape_xml(principal_url))),
            );
        }
        if let Some(collection_set) = &resource.principal_collection_set {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "principal-collection-set",
                "<d:principal-collection-set>",
                "</d:principal-collection-set>",
                Some(&format!("<d:href>{}</d:href>", escape_xml(collection_set))),
            );
        }
        if let Some(home) = &resource.addressbook_home_set {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "addressbook-home-set",
                "<card:addressbook-home-set>",
                "</card:addressbook-home-set>",
                Some(&format!("<d:href>{}</d:href>", escape_xml(home))),
            );
        }
        if let Some(home) = &resource.calendar_home_set {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "calendar-home-set",
                "<cal:calendar-home-set>",
                "</cal:calendar-home-set>",
                Some(&format!("<d:href>{}</d:href>", escape_xml(home))),
            );
        }
        if !resource.calendar_user_addresses.is_empty() {
            let mut value = String::new();
            for address in &resource.calendar_user_addresses {
                value.push_str("<d:href>");
                value.push_str(&escape_xml(address));
                value.push_str("</d:href>");
            }
            write_named_or_valued_property(
                &mut xml,
                mode,
                "calendar-user-address-set",
                "<cal:calendar-user-address-set>",
                "</cal:calendar-user-address-set>",
                Some(&value),
            );
        }
        if let Some(inbox) = &resource.schedule_inbox_url {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "schedule-inbox-URL",
                "<cal:schedule-inbox-URL>",
                "</cal:schedule-inbox-URL>",
                Some(&format!("<d:href>{}</d:href>", escape_xml(inbox))),
            );
        }
        if let Some(outbox) = &resource.schedule_outbox_url {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "schedule-outbox-URL",
                "<cal:schedule-outbox-URL>",
                "</cal:schedule-outbox-URL>",
                Some(&format!("<d:href>{}</d:href>", escape_xml(outbox))),
            );
        }
        if let Some(owner) = &resource.owner {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "owner",
                "<d:owner>",
                "</d:owner>",
                Some(&format!("<d:href>{}</d:href>", escape_xml(owner))),
            );
        }
        if !resource.current_user_privileges.is_empty() {
            let mut value = String::from("<d:current-user-privilege-set>");
            for privilege in &resource.current_user_privileges {
                value.push_str("<d:privilege>");
                match *privilege {
                    "read" => value.push_str("<d:read/>"),
                    "write" => value.push_str("<d:write/>"),
                    "write-properties" => value.push_str("<d:write-properties/>"),
                    "bind" => value.push_str("<d:bind/>"),
                    "unbind" => value.push_str("<d:unbind/>"),
                    _ => {}
                }
                value.push_str("</d:privilege>");
            }
            value.push_str("</d:current-user-privilege-set>");
            write_named_or_valued_property(
                &mut xml,
                mode,
                "current-user-privilege-set",
                "",
                "",
                Some(&value),
            );
        }
        if let Some(quota_available_bytes) = resource.quota_available_bytes {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "quota-available-bytes",
                "<d:quota-available-bytes>",
                "</d:quota-available-bytes>",
                Some(&quota_available_bytes.to_string()),
            );
        }
        if let Some(quota_used_bytes) = resource.quota_used_bytes {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "quota-used-bytes",
                "<d:quota-used-bytes>",
                "</d:quota-used-bytes>",
                Some(&quota_used_bytes.to_string()),
            );
        }
        if let Some(resource_id) = &resource.resource_id {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "resource-id",
                "<d:resource-id>",
                "</d:resource-id>",
                Some(&format!("<d:href>urn:uuid:{}</d:href>", escape_xml(resource_id))),
            );
        }
        if !resource.calendar_free_busy_set.is_empty() {
            let mut value = String::new();
            for href in &resource.calendar_free_busy_set {
                value.push_str("<d:href>");
                value.push_str(&escape_xml(href));
                value.push_str("</d:href>");
            }
            write_named_or_valued_property(
                &mut xml,
                mode,
                "calendar-free-busy-set",
                "<cal:calendar-free-busy-set>",
                "</cal:calendar-free-busy-set>",
                Some(&value),
            );
        }
        if let Some(transp) = &resource.schedule_calendar_transp {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "schedule-calendar-transp",
                "<cal:schedule-calendar-transp>",
                "</cal:schedule-calendar-transp>",
                Some(&format!("<cal:{transp}/>")),
            );
        }
        if let Some(url) = &resource.schedule_default_calendar_url {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "schedule-default-calendar-URL",
                "<cal:schedule-default-calendar-URL>",
                "</cal:schedule-default-calendar-URL>",
                Some(&format!("<d:href>{}</d:href>", escape_xml(url))),
            );
        }
        if let Some(color) = &resource.calendar_color {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "calendar-color",
                "<ical:calendar-color>",
                "</ical:calendar-color>",
                Some(&escape_xml(color)),
            );
        }
        if let Some(description) = &resource.calendar_description {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "calendar-description",
                "<cal:calendar-description>",
                "</cal:calendar-description>",
                Some(&escape_xml(description)),
            );
        }
        if let Some(ctag) = &resource.calendar_ctag {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "getctag",
                "<cs:getctag>",
                "</cs:getctag>",
                Some(&escape_xml(ctag)),
            );
        }
        if let Some(sync_token) = &resource.sync_token {
            write_named_or_valued_property(
                &mut xml,
                mode,
                "sync-token",
                "<d:sync-token>",
                "</d:sync-token>",
                Some(&escape_xml(sync_token)),
            );
        }
        if !resource.supported_calendar_components.is_empty() {
            let mut value = String::new();
            for component in &resource.supported_calendar_components {
                value.push_str(r#"<cal:comp name=""#);
                value.push_str(component);
                value.push_str(r#""/>"#);
            }
            write_named_or_valued_property(
                &mut xml,
                mode,
                "supported-calendar-component-set",
                "<cal:supported-calendar-component-set>",
                "</cal:supported-calendar-component-set>",
                Some(&value),
            );
        }
        if !resource.supported_reports.is_empty() {
            let mut value = String::new();
            for report in &resource.supported_reports {
                value.push_str("<d:supported-report><d:report>");
                match *report {
                    "calendar-query" => value.push_str("<cal:calendar-query/>"),
                    "calendar-multiget" => value.push_str("<cal:calendar-multiget/>"),
                    "sync-collection" => value.push_str("<d:sync-collection/>"),
                    "expand-property" => value.push_str("<d:expand-property/>"),
                    "principal-property-search" => value.push_str("<d:principal-property-search/>"),
                    "principal-search-property-set" => {
                        value.push_str("<d:principal-search-property-set/>")
                    }
                    _ => {}
                }
                value.push_str("</d:report></d:supported-report>");
            }
            write_named_or_valued_property(
                &mut xml,
                mode,
                "supported-report-set",
                "<d:supported-report-set>",
                "</d:supported-report-set>",
                Some(&value),
            );
        }

        xml.push_str("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>");
        xml.push_str("</d:response>");
    }
    xml.push_str("</d:multistatus>");
    xml.into_bytes()
}

fn write_named_or_valued_property(
    xml: &mut String,
    mode: &DavPropfindMode,
    local_name: &str,
    open_tag: &str,
    close_tag: &str,
    value: Option<&str>,
) {
    if !should_emit_property(mode, local_name) {
        return;
    }
    match mode {
        DavPropfindMode::PropName => {
            if let Some(self_closing) = self_closing_tag(open_tag, close_tag) {
                xml.push_str(&self_closing);
            }
        }
        DavPropfindMode::AllProp | DavPropfindMode::Prop(_) => {
            if let Some(value) = value {
                if open_tag.is_empty() && close_tag.is_empty() {
                    xml.push_str(value);
                    return;
                }
                xml.push_str(open_tag);
                xml.push_str(value);
                xml.push_str(close_tag);
            }
        }
    }
}

fn should_emit_property(mode: &DavPropfindMode, local_name: &str) -> bool {
    match mode {
        DavPropfindMode::AllProp | DavPropfindMode::PropName => true,
        DavPropfindMode::Prop(names) => names.contains(local_name),
    }
}

fn self_closing_tag(open_tag: &str, close_tag: &str) -> Option<String> {
    let open_tag = open_tag.trim();
    let close_tag = close_tag.trim();
    if open_tag.is_empty() || close_tag.is_empty() {
        return None;
    }
    let tag_name = open_tag
        .strip_prefix('<')?
        .strip_suffix('>')?
        .split_whitespace()
        .next()?;
    Some(format!("<{tag_name}/>"))
}

fn resource_type_xml(kind: DavResourceKind) -> &'static str {
    match kind {
        DavResourceKind::Principal => "<d:principal/>",
        DavResourceKind::ScheduleInbox => "<d:collection/><cal:schedule-inbox/>",
        DavResourceKind::ScheduleOutbox => "<d:collection/><cal:schedule-outbox/>",
        DavResourceKind::AddressbookHome => "<d:collection/><card:addressbook/>",
        DavResourceKind::Addressbook => "<d:collection/><card:addressbook/>",
        DavResourceKind::CalendarHome => "<d:collection/>",
        DavResourceKind::Calendar => "<d:collection/><cal:calendar/>",
    }
}

fn escape_xml(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{multistatus_xml, multistatus_xml_for_propfind, DavPropResource, DavPropfindMode, DavResourceKind};

    #[test]
    fn multistatus_contains_expected_namespaces_and_fields() {
        let payload = multistatus_xml(&[DavPropResource {
            href: "/dav/uid-1/principal/".to_string(),
            display_name: "alice@proton.me".to_string(),
            kind: DavResourceKind::Principal,
            current_user_principal: Some("/dav/uid-1/principal/".to_string()),
            principal_url: Some("/dav/uid-1/principal/".to_string()),
            principal_collection_set: Some("/dav/".to_string()),
            addressbook_home_set: Some("/dav/uid-1/addressbooks/".to_string()),
            calendar_home_set: Some("/dav/uid-1/calendars/".to_string()),
            calendar_user_addresses: vec!["mailto:alice@proton.me".to_string()],
            schedule_inbox_url: None,
            schedule_outbox_url: None,
            owner: Some("/dav/uid-1/principal/".to_string()),
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
            supported_reports: vec![
                "expand-property",
                "principal-property-search",
                "principal-search-property-set",
            ],
        }]);
        let xml = String::from_utf8(payload).expect("xml is utf8");
        assert!(xml.contains(r#"xmlns:d="DAV:""#));
        assert!(xml.contains("<d:multistatus"));
        assert!(xml.contains("<d:principal/>"));
        assert!(xml.contains("<d:principal-URL>"));
        assert!(xml.contains("<d:principal-collection-set>"));
        assert!(xml.contains("<cal:calendar-user-address-set>"));
        assert!(!xml.contains("<cal:schedule-inbox-URL>"));
        assert!(!xml.contains("<cal:schedule-outbox-URL>"));
        assert!(xml.contains("<card:addressbook-home-set>"));
        assert!(xml.contains("<cal:calendar-home-set>"));
    }

    #[test]
    fn calendar_resource_includes_collection_metadata() {
        let payload = multistatus_xml(&[DavPropResource {
            href: "/dav/uid-1/calendars/work/".to_string(),
            display_name: "Work".to_string(),
            kind: DavResourceKind::Calendar,
            current_user_principal: None,
            principal_url: None,
            principal_collection_set: None,
            addressbook_home_set: None,
            calendar_home_set: None,
            calendar_user_addresses: Vec::new(),
            schedule_inbox_url: None,
            schedule_outbox_url: None,
            owner: None,
            current_user_privileges: Vec::new(),
            quota_available_bytes: Some(1_000_000_000),
            quota_used_bytes: Some(0),
            resource_id: Some("work".to_string()),
            calendar_free_busy_set: vec!["/dav/uid-1/calendars/work/".to_string()],
            schedule_calendar_transp: None,
            schedule_default_calendar_url: None,
            calendar_color: Some("#00AAFF".to_string()),
            calendar_description: Some("Team calendar".to_string()),
            calendar_ctag: Some("work-10".to_string()),
            sync_token: Some("https://openproton.local/sync/work-10".to_string()),
            supported_calendar_components: vec!["VEVENT"],
            supported_reports: vec!["calendar-query", "calendar-multiget", "sync-collection"],
        }]);
        let xml = String::from_utf8(payload).expect("xml is utf8");
        assert!(xml.contains("<cs:getctag>work-10</cs:getctag>"));
        assert!(xml.contains("<d:sync-token>https://openproton.local/sync/work-10</d:sync-token>"));
        assert!(xml.contains(r#"<cal:comp name="VEVENT"/>"#));
        assert!(xml.contains("<ical:calendar-color>#00AAFF</ical:calendar-color>"));
        assert!(xml.contains("<d:supported-report-set>"));
        assert!(xml.contains("<cal:calendar-query/>"));
        assert!(xml.contains("<cal:calendar-multiget/>"));
        assert!(xml.contains("<d:sync-collection/>"));
        assert!(xml.contains("<d:quota-available-bytes>1000000000</d:quota-available-bytes>"));
        assert!(xml.contains("<d:resource-id><d:href>urn:uuid:work</d:href></d:resource-id>"));
        assert!(xml.contains("<cal:calendar-free-busy-set>"));
        assert!(!xml.contains("<cal:schedule-calendar-transp>"));
        assert!(!xml.contains("<cal:schedule-default-calendar-URL>"));
    }

    #[test]
    fn propfind_prop_mode_filters_unrequested_properties() {
        let mut requested = HashSet::new();
        requested.insert("displayname".to_string());
        requested.insert("getctag".to_string());
        let payload = multistatus_xml_for_propfind(
            &[DavPropResource {
                href: "/dav/uid-1/calendars/work/".to_string(),
                display_name: "Work".to_string(),
                kind: DavResourceKind::Calendar,
                current_user_principal: None,
                principal_url: None,
                principal_collection_set: None,
                addressbook_home_set: None,
                calendar_home_set: None,
                calendar_user_addresses: Vec::new(),
                schedule_inbox_url: None,
                schedule_outbox_url: None,
                owner: None,
                current_user_privileges: Vec::new(),
                quota_available_bytes: Some(1_000_000_000),
                quota_used_bytes: Some(0),
                resource_id: Some("work".to_string()),
                calendar_free_busy_set: vec!["/dav/uid-1/calendars/work/".to_string()],
                schedule_calendar_transp: None,
                schedule_default_calendar_url: None,
                calendar_color: Some("#00AAFF".to_string()),
                calendar_description: Some("Team calendar".to_string()),
                calendar_ctag: Some("work-10".to_string()),
                sync_token: Some("https://openproton.local/sync/work-10".to_string()),
                supported_calendar_components: vec!["VEVENT"],
                supported_reports: vec!["calendar-query", "calendar-multiget", "sync-collection"],
            }],
            &DavPropfindMode::Prop(requested),
        );
        let xml = String::from_utf8(payload).expect("xml is utf8");
        assert!(xml.contains("<d:displayname>Work</d:displayname>"));
        assert!(xml.contains("<cs:getctag>work-10</cs:getctag>"));
        assert!(!xml.contains("<d:sync-token>"));
        assert!(!xml.contains("<d:supported-report-set>"));
    }
}
