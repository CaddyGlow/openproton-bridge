use std::time::{SystemTime, UNIX_EPOCH};

use gluon_rs_dav::http::DavResponse;
use gluon_rs_dav::report;
use gluon_rs_dav::{DavError, Result};

use crate::store::ContactsStore;
use crate::types::QueryPage;

pub fn addressbook_query(store: &ContactsStore, account_id: &str) -> Result<DavResponse> {
    let contacts = store
        .list_contacts(
            false,
            QueryPage {
                limit: 500,
                offset: 0,
            },
        )
        .map_err(|err| DavError::Backend(err.to_string()))?;
    let items = contacts
        .iter()
        .map(|contact| {
            report::make_contact_report_item(account_id, &contact.id, contact.updated_at_ms, None)
        })
        .collect::<Vec<_>>();
    tracing::debug!(
        report = "addressbook-query",
        account_id,
        item_count = items.len(),
        "dav report assembled"
    );
    Ok(report::multistatus_report_response(&items))
}

pub fn carddav_sync_collection(
    store: &ContactsStore,
    account_id: &str,
    body: &str,
) -> Result<DavResponse> {
    let contacts = store
        .list_contacts(
            true,
            QueryPage {
                limit: 500,
                offset: 0,
            },
        )
        .map_err(|err| DavError::Backend(err.to_string()))?;
    let since = extract_sync_token_version(body);
    let current_token = contacts
        .iter()
        .map(|item| item.updated_at_ms)
        .max()
        .unwrap_or_else(epoch_millis);
    store
        .set_sync_state_int(&sync_scope("carddav", account_id), current_token)
        .map_err(|err| DavError::Backend(err.to_string()))?;
    let items = contacts
        .iter()
        .filter(|contact| since.is_none_or(|token| contact.updated_at_ms > token))
        .map(|contact| {
            report::make_contact_report_item(account_id, &contact.id, contact.updated_at_ms, None)
        })
        .collect::<Vec<_>>();
    tracing::debug!(
        report = "sync-collection",
        protocol = "carddav",
        account_id,
        item_count = items.len(),
        sync_token = current_token,
        "dav report assembled"
    );
    Ok(report::sync_collection_response(
        &items,
        &current_token.to_string(),
    ))
}

pub fn parse_addressbook_query_request(body: &str) -> Result<()> {
    let query = gluon_rs_dav::extract_xml_element(body, "addressbook-query").ok_or(
        DavError::InvalidRequest("addressbook-query request is malformed"),
    )?;
    if gluon_rs_dav::extract_xml_start_tags(query, "prop-filter")
        .into_iter()
        .any(|tag| gluon_rs_dav::extract_xml_attribute(&tag, "name").is_none())
    {
        return Err(DavError::InvalidRequest(
            "addressbook-query property filters must include name attribute",
        ));
    }
    Ok(())
}

fn sync_scope(protocol: &str, account_id: &str) -> String {
    format!("dav.{protocol}.{account_id}.sync_token")
}

fn extract_sync_token_version(body: &str) -> Option<i64> {
    gluon_rs_dav::extract_sync_token(body).and_then(|token| token.trim().parse::<i64>().ok())
}

fn epoch_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
