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
    pub push_config: Option<WebDavPushConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebDavPushConfig {
    pub vapid_public_key: String,
    pub topic: String,
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
        r#"<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/" xmlns:ical="http://apple.com/ns/ical/" xmlns:push="https://bitfire.at/webdav-push">"#,
    );
    for resource in resources {
        let mut ok_props = String::new();
        let mut missing_props = String::new();
        xml.push_str("<d:response>");
        xml.push_str("<d:href>");
        xml.push_str(&escape_xml(&resource.href));
        xml.push_str("</d:href>");
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "displayname",
            "<d:displayname>",
            "</d:displayname>",
            "<d:displayname/>",
            Some(&escape_xml(&resource.display_name)),
        );
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "resourcetype",
            "<d:resourcetype>",
            "</d:resourcetype>",
            "<d:resourcetype/>",
            Some(resource_type_xml(resource.kind)),
        );

        let current_user_principal = resource
            .current_user_principal
            .as_ref()
            .map(|current| format!("<d:href>{}</d:href>", escape_xml(current)));
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "current-user-principal",
            "<d:current-user-principal>",
            "</d:current-user-principal>",
            "<d:current-user-principal/>",
            current_user_principal.as_deref(),
        );
        let principal_url = resource
            .principal_url
            .as_ref()
            .map(|principal_url| format!("<d:href>{}</d:href>", escape_xml(principal_url)));
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "principal-URL",
            "<d:principal-URL>",
            "</d:principal-URL>",
            "<d:principal-URL/>",
            principal_url.as_deref(),
        );
        let principal_collection_set = resource
            .principal_collection_set
            .as_ref()
            .map(|collection_set| format!("<d:href>{}</d:href>", escape_xml(collection_set)));
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "principal-collection-set",
            "<d:principal-collection-set>",
            "</d:principal-collection-set>",
            "<d:principal-collection-set/>",
            principal_collection_set.as_deref(),
        );
        let addressbook_home_set = resource
            .addressbook_home_set
            .as_ref()
            .map(|home| format!("<d:href>{}</d:href>", escape_xml(home)));
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "addressbook-home-set",
            "<card:addressbook-home-set>",
            "</card:addressbook-home-set>",
            "<card:addressbook-home-set/>",
            addressbook_home_set.as_deref(),
        );
        let calendar_home_set = resource
            .calendar_home_set
            .as_ref()
            .map(|home| format!("<d:href>{}</d:href>", escape_xml(home)));
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "calendar-home-set",
            "<cal:calendar-home-set>",
            "</cal:calendar-home-set>",
            "<cal:calendar-home-set/>",
            calendar_home_set.as_deref(),
        );
        let calendar_user_addresses = if resource.calendar_user_addresses.is_empty() {
            None
        } else {
            let mut value = String::new();
            for address in &resource.calendar_user_addresses {
                value.push_str("<d:href>");
                value.push_str(&escape_xml(address));
                value.push_str("</d:href>");
            }
            Some(value)
        };
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "calendar-user-address-set",
            "<cal:calendar-user-address-set>",
            "</cal:calendar-user-address-set>",
            "<cal:calendar-user-address-set/>",
            calendar_user_addresses.as_deref(),
        );
        let schedule_inbox_url = resource
            .schedule_inbox_url
            .as_ref()
            .map(|inbox| format!("<d:href>{}</d:href>", escape_xml(inbox)));
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "schedule-inbox-URL",
            "<cal:schedule-inbox-URL>",
            "</cal:schedule-inbox-URL>",
            "<cal:schedule-inbox-URL/>",
            schedule_inbox_url.as_deref(),
        );
        let schedule_outbox_url = resource
            .schedule_outbox_url
            .as_ref()
            .map(|outbox| format!("<d:href>{}</d:href>", escape_xml(outbox)));
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "schedule-outbox-URL",
            "<cal:schedule-outbox-URL>",
            "</cal:schedule-outbox-URL>",
            "<cal:schedule-outbox-URL/>",
            schedule_outbox_url.as_deref(),
        );
        let owner = resource
            .owner
            .as_ref()
            .map(|owner| format!("<d:href>{}</d:href>", escape_xml(owner)));
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "owner",
            "<d:owner>",
            "</d:owner>",
            "<d:owner/>",
            owner.as_deref(),
        );
        let current_user_privileges = if resource.current_user_privileges.is_empty() {
            None
        } else {
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
            Some(value)
        };
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "current-user-privilege-set",
            "",
            "",
            "<d:current-user-privilege-set/>",
            current_user_privileges.as_deref(),
        );
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "getcontentlength",
            "<d:getcontentlength>",
            "</d:getcontentlength>",
            "<d:getcontentlength/>",
            collection_content_length(resource.kind),
        );
        let quota_available_bytes = resource
            .quota_available_bytes
            .map(|value| value.to_string());
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "quota-available-bytes",
            "<d:quota-available-bytes>",
            "</d:quota-available-bytes>",
            "<d:quota-available-bytes/>",
            quota_available_bytes.as_deref(),
        );
        let quota_used_bytes = resource.quota_used_bytes.map(|value| value.to_string());
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "quota-used-bytes",
            "<d:quota-used-bytes>",
            "</d:quota-used-bytes>",
            "<d:quota-used-bytes/>",
            quota_used_bytes.as_deref(),
        );
        let resource_id = resource
            .resource_id
            .as_ref()
            .map(|resource_id| format!("<d:href>urn:uuid:{}</d:href>", escape_xml(resource_id)));
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "resource-id",
            "<d:resource-id>",
            "</d:resource-id>",
            "<d:resource-id/>",
            resource_id.as_deref(),
        );
        let calendar_free_busy_set = if resource.calendar_free_busy_set.is_empty() {
            None
        } else {
            let mut value = String::new();
            for href in &resource.calendar_free_busy_set {
                value.push_str("<d:href>");
                value.push_str(&escape_xml(href));
                value.push_str("</d:href>");
            }
            Some(value)
        };
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "calendar-free-busy-set",
            "<cal:calendar-free-busy-set>",
            "</cal:calendar-free-busy-set>",
            "<cal:calendar-free-busy-set/>",
            calendar_free_busy_set.as_deref(),
        );
        let schedule_calendar_transp = resource
            .schedule_calendar_transp
            .as_ref()
            .map(|transp| format!("<cal:{transp}/>"));
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "schedule-calendar-transp",
            "<cal:schedule-calendar-transp>",
            "</cal:schedule-calendar-transp>",
            "<cal:schedule-calendar-transp/>",
            schedule_calendar_transp.as_deref(),
        );
        let schedule_default_calendar_url = resource
            .schedule_default_calendar_url
            .as_ref()
            .map(|url| format!("<d:href>{}</d:href>", escape_xml(url)));
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "schedule-default-calendar-URL",
            "<cal:schedule-default-calendar-URL>",
            "</cal:schedule-default-calendar-URL>",
            "<cal:schedule-default-calendar-URL/>",
            schedule_default_calendar_url.as_deref(),
        );
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "calendar-color",
            "<ical:calendar-color>",
            "</ical:calendar-color>",
            "<ical:calendar-color/>",
            resource.calendar_color.as_deref(),
        );
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "calendar-description",
            "<cal:calendar-description>",
            "</cal:calendar-description>",
            "<cal:calendar-description/>",
            resource.calendar_description.as_deref(),
        );
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "getctag",
            "<cs:getctag>",
            "</cs:getctag>",
            "<cs:getctag/>",
            resource.calendar_ctag.as_deref(),
        );
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "sync-token",
            "<d:sync-token>",
            "</d:sync-token>",
            "<d:sync-token/>",
            resource.sync_token.as_deref(),
        );
        let supported_calendar_components = if resource.supported_calendar_components.is_empty() {
            None
        } else {
            let mut value = String::new();
            for component in &resource.supported_calendar_components {
                value.push_str(r#"<cal:comp name=""#);
                value.push_str(component);
                value.push_str(r#""/>"#);
            }
            Some(value)
        };
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "supported-calendar-component-set",
            "<cal:supported-calendar-component-set>",
            "</cal:supported-calendar-component-set>",
            "<cal:supported-calendar-component-set/>",
            supported_calendar_components.as_deref(),
        );
        let supported_reports = if resource.supported_reports.is_empty() {
            None
        } else {
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
            Some(value)
        };
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "supported-report-set",
            "<d:supported-report-set>",
            "</d:supported-report-set>",
            "<d:supported-report-set/>",
            supported_reports.as_deref(),
        );

        let push_transports_xml = resource.push_config.as_ref().map(|pc| {
            format!(
                "<push:web-push>\
                 <push:vapid-public-key type=\"p256ecdsa\">{}</push:vapid-public-key>\
                 </push:web-push>",
                escape_xml(&pc.vapid_public_key),
            )
        });
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "transports",
            "<push:transports>",
            "</push:transports>",
            "<push:transports/>",
            push_transports_xml.as_deref(),
        );
        let push_topic = resource
            .push_config
            .as_ref()
            .map(|pc| escape_xml(&pc.topic));
        write_named_or_valued_property(
            &mut ok_props,
            &mut missing_props,
            mode,
            "topic",
            "<push:topic>",
            "</push:topic>",
            "<push:topic/>",
            push_topic.as_deref(),
        );

        if !ok_props.is_empty() {
            xml.push_str("<d:propstat><d:prop>");
            xml.push_str(&ok_props);
            xml.push_str("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>");
        }
        if !missing_props.is_empty() {
            xml.push_str("<d:propstat><d:prop>");
            xml.push_str(&missing_props);
            xml.push_str("</d:prop><d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>");
        }
        xml.push_str("</d:response>");
    }
    xml.push_str("</d:multistatus>");
    xml.into_bytes()
}

#[allow(clippy::too_many_arguments)]
fn write_named_or_valued_property(
    ok_props: &mut String,
    missing_props: &mut String,
    mode: &DavPropfindMode,
    local_name: &str,
    open_tag: &str,
    close_tag: &str,
    empty_tag: &str,
    value: Option<&str>,
) {
    if !should_emit_property(mode, local_name) {
        return;
    }
    match mode {
        DavPropfindMode::PropName => {
            if let Some(self_closing) = self_closing_tag(open_tag, close_tag) {
                ok_props.push_str(&self_closing);
            }
        }
        DavPropfindMode::AllProp | DavPropfindMode::Prop(_) => {
            if let Some(value) = value {
                if open_tag.is_empty() && close_tag.is_empty() {
                    ok_props.push_str(value);
                    return;
                }
                ok_props.push_str(open_tag);
                ok_props.push_str(value);
                ok_props.push_str(close_tag);
            } else if matches!(mode, DavPropfindMode::Prop(_)) && !empty_tag.is_empty() {
                missing_props.push_str(empty_tag);
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

fn collection_content_length(kind: DavResourceKind) -> Option<&'static str> {
    match kind {
        DavResourceKind::Principal => None,
        DavResourceKind::ScheduleInbox
        | DavResourceKind::ScheduleOutbox
        | DavResourceKind::AddressbookHome
        | DavResourceKind::Addressbook
        | DavResourceKind::CalendarHome
        | DavResourceKind::Calendar => Some("0"),
    }
}

pub fn escape_xml(input: &str) -> String {
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

    use super::{
        multistatus_xml, multistatus_xml_for_propfind, DavPropResource, DavPropfindMode,
        DavResourceKind,
    };

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
            push_config: None,
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
                push_config: None,
            }],
            &DavPropfindMode::Prop(requested),
        );
        let xml = String::from_utf8(payload).expect("xml is utf8");
        assert!(xml.contains("<d:displayname>Work</d:displayname>"));
        assert!(xml.contains("<cs:getctag>work-10</cs:getctag>"));
        assert!(!xml.contains("<d:sync-token>"));
        assert!(!xml.contains("<d:supported-report-set>"));
    }

    #[test]
    fn calendar_resource_reports_zero_content_length() {
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
            }],
            &DavPropfindMode::AllProp,
        );
        let xml = String::from_utf8(payload).expect("xml is utf8");
        assert!(xml.contains("<d:getcontentlength>0</d:getcontentlength>"));
    }
}
