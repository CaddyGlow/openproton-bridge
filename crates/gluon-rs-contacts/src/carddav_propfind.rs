use gluon_rs_dav::discovery;
use gluon_rs_dav::types::AuthContext;
use gluon_rs_dav::xml::{DavPropResource, DavResourceKind};

pub fn addressbook_home_resource(auth: &AuthContext) -> DavPropResource {
    DavPropResource {
        href: discovery::addressbook_home_path(&auth.account_id),
        display_name: "Address Books".to_string(),
        kind: DavResourceKind::AddressbookHome,
        current_user_principal: None,
        principal_url: None,
        principal_collection_set: None,
        addressbook_home_set: None,
        calendar_home_set: None,
        calendar_user_addresses: Vec::new(),
        schedule_inbox_url: None,
        schedule_outbox_url: None,
        owner: Some(discovery::principal_path(&auth.account_id)),
        current_user_privileges: vec!["read"],
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

pub fn default_addressbook_resource(auth: &AuthContext) -> DavPropResource {
    DavPropResource {
        href: discovery::default_addressbook_path(&auth.account_id),
        display_name: "Default Address Book".to_string(),
        kind: DavResourceKind::Addressbook,
        current_user_principal: None,
        principal_url: None,
        principal_collection_set: None,
        addressbook_home_set: None,
        calendar_home_set: None,
        calendar_user_addresses: Vec::new(),
        schedule_inbox_url: None,
        schedule_outbox_url: None,
        owner: Some(discovery::principal_path(&auth.account_id)),
        current_user_privileges: vec!["read"],
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
