#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DavResourceKind {
    Principal,
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
    pub addressbook_home_set: Option<String>,
    pub calendar_home_set: Option<String>,
}

pub fn multistatus_xml(resources: &[DavPropResource]) -> Vec<u8> {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:cal="urn:ietf:params:xml:ns:caldav">"#,
    );
    for resource in resources {
        xml.push_str("<d:response>");
        xml.push_str("<d:href>");
        xml.push_str(&escape_xml(&resource.href));
        xml.push_str("</d:href>");
        xml.push_str("<d:propstat><d:prop>");
        xml.push_str("<d:displayname>");
        xml.push_str(&escape_xml(&resource.display_name));
        xml.push_str("</d:displayname>");
        xml.push_str("<d:resourcetype>");
        xml.push_str(resource_type_xml(resource.kind));
        xml.push_str("</d:resourcetype>");

        if let Some(current) = &resource.current_user_principal {
            xml.push_str("<d:current-user-principal><d:href>");
            xml.push_str(&escape_xml(current));
            xml.push_str("</d:href></d:current-user-principal>");
        }
        if let Some(home) = &resource.addressbook_home_set {
            xml.push_str("<card:addressbook-home-set><d:href>");
            xml.push_str(&escape_xml(home));
            xml.push_str("</d:href></card:addressbook-home-set>");
        }
        if let Some(home) = &resource.calendar_home_set {
            xml.push_str("<cal:calendar-home-set><d:href>");
            xml.push_str(&escape_xml(home));
            xml.push_str("</d:href></cal:calendar-home-set>");
        }

        xml.push_str("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>");
        xml.push_str("</d:response>");
    }
    xml.push_str("</d:multistatus>");
    xml.into_bytes()
}

fn resource_type_xml(kind: DavResourceKind) -> &'static str {
    match kind {
        DavResourceKind::Principal => "<d:principal/>",
        DavResourceKind::AddressbookHome => "<d:collection/><card:addressbook/>",
        DavResourceKind::Addressbook => "<d:collection/><card:addressbook/>",
        DavResourceKind::CalendarHome => "<d:collection/><cal:calendar/>",
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
    use super::{multistatus_xml, DavPropResource, DavResourceKind};

    #[test]
    fn multistatus_contains_expected_namespaces_and_fields() {
        let payload = multistatus_xml(&[DavPropResource {
            href: "/dav/uid-1/principal/".to_string(),
            display_name: "alice@proton.me".to_string(),
            kind: DavResourceKind::Principal,
            current_user_principal: Some("/dav/uid-1/principal/".to_string()),
            addressbook_home_set: Some("/dav/uid-1/addressbooks/".to_string()),
            calendar_home_set: Some("/dav/uid-1/calendars/".to_string()),
        }]);
        let xml = String::from_utf8(payload).expect("xml is utf8");
        assert!(xml.contains(r#"xmlns:d="DAV:""#));
        assert!(xml.contains("<d:multistatus"));
        assert!(xml.contains("<d:principal/>"));
        assert!(xml.contains("<card:addressbook-home-set>"));
        assert!(xml.contains("<cal:calendar-home-set>"));
    }
}
