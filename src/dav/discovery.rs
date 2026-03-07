use super::http::DavResponse;

pub const DAV_ROOT_PATH: &str = "/";
pub const WELL_KNOWN_CARDDAV: &str = "/.well-known/carddav";
pub const WELL_KNOWN_CALDAV: &str = "/.well-known/caldav";
pub const PRINCIPAL_ME_PATH: &str = "/dav/principals/me/";

pub fn discovery_redirect(path: &str) -> Option<DavResponse> {
    if !matches!(path, DAV_ROOT_PATH | WELL_KNOWN_CARDDAV | WELL_KNOWN_CALDAV) {
        return None;
    }

    Some(DavResponse {
        status: "301 Moved Permanently",
        headers: vec![
            ("Location", PRINCIPAL_ME_PATH.to_string()),
            ("Content-Type", "text/plain; charset=utf-8".to_string()),
        ],
        body: format!("Moved to {PRINCIPAL_ME_PATH}\n").into_bytes(),
    })
}

pub fn principal_path(account_id: &str) -> String {
    format!("/dav/{account_id}/principal/")
}

pub fn principal_collection_set_path() -> String {
    "/dav/".to_string()
}

pub fn schedule_inbox_path(account_id: &str) -> String {
    format!("/dav/{account_id}/principal/inbox/")
}

pub fn schedule_outbox_path(account_id: &str) -> String {
    format!("/dav/{account_id}/principal/outbox/")
}

pub fn addressbook_home_path(account_id: &str) -> String {
    format!("/dav/{account_id}/addressbooks/")
}

pub fn calendar_home_path(account_id: &str) -> String {
    format!("/dav/{account_id}/calendars/")
}

pub fn default_addressbook_path(account_id: &str) -> String {
    format!("/dav/{account_id}/addressbooks/default/")
}

pub fn default_calendar_path(account_id: &str) -> String {
    format!("/dav/{account_id}/calendars/default/")
}

#[cfg(test)]
mod tests {
    use super::{
        discovery_redirect, DAV_ROOT_PATH, PRINCIPAL_ME_PATH, WELL_KNOWN_CALDAV, WELL_KNOWN_CARDDAV,
    };

    #[test]
    fn well_known_paths_redirect_to_principal() {
        let carddav = discovery_redirect(WELL_KNOWN_CARDDAV).expect("carddav should redirect");
        assert_eq!(carddav.status, "301 Moved Permanently");
        assert!(carddav
            .headers
            .iter()
            .any(|(k, v)| *k == "Location" && v == PRINCIPAL_ME_PATH));

        let caldav = discovery_redirect(WELL_KNOWN_CALDAV).expect("caldav should redirect");
        assert_eq!(caldav.status, "301 Moved Permanently");
    }

    #[test]
    fn root_path_redirects_to_principal() {
        let root = discovery_redirect(DAV_ROOT_PATH).expect("root should redirect");
        assert_eq!(root.status, "301 Moved Permanently");
        assert!(root
            .headers
            .iter()
            .any(|(k, v)| *k == "Location" && v == PRINCIPAL_ME_PATH));
    }
}
