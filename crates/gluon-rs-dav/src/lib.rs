pub mod auth;
pub mod discovery;
pub mod error;
pub mod etag;
pub mod http;
pub mod propfind;
pub mod report;
pub mod server;
pub mod types;
pub mod xml;

pub use auth::{DavAuthError, DavAuthenticator};
pub use error::{DavError, Result};
pub use http::{DavRequest, DavResponse};
pub use propfind::{
    multistatus_response, non_empty_display_name, parse_propfind_mode, principal_resource,
    schedule_inbox_resource, schedule_outbox_resource,
};
pub use report::{
    extract_sync_token, extract_xml_attribute, extract_xml_element, extract_xml_start_tags,
    has_named_xml_tag, invalid_report_payload_response, is_xml_like,
    make_calendar_event_report_item, make_contact_report_item, multistatus_report_response,
    not_implemented_report, parse_calendar_collection_path, parse_ics_date, parse_ics_timestamp,
    sync_collection_response, ReportItem,
};
pub use server::{
    clear_runtime_tls_config, handle_connection, install_runtime_tls_config_from_dir,
    run_server_with_listener_and_config, run_server_with_listener_and_config_and_tls_config,
    DavRequestRouter, DavServer, DavServerConfig, DavServerHandle,
};
pub use types::{
    account_id_hint, is_safe_path, looks_like_local_uuid, normalize_path,
    parse_account_resource_path, parse_depth, path_without_query, AccountResource, AuthContext,
    DavDepth,
};
pub use xml::{
    escape_xml, multistatus_xml, multistatus_xml_for_propfind, DavPropResource, DavPropfindMode,
    DavResourceKind, WebDavPushConfig,
};
