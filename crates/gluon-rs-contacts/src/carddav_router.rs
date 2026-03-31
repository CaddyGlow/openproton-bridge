use std::collections::HashMap;
use std::sync::Arc;

use gluon_rs_dav::discovery;
use gluon_rs_dav::http::DavResponse;
use gluon_rs_dav::propfind::{self, multistatus_response};
use gluon_rs_dav::report;
use gluon_rs_dav::server::DavRequestRouter;
use gluon_rs_dav::types::{
    parse_account_resource_path, parse_depth, AccountResource, AuthContext, DavDepth,
};
use gluon_rs_dav::{DavError, Result};

use crate::carddav;
use crate::carddav_propfind;
use crate::carddav_report;
use crate::store::ContactsStore;

pub struct CardDavRouter {
    stores: HashMap<String, Arc<ContactsStore>>,
}

impl CardDavRouter {
    pub fn new(stores: HashMap<String, Arc<ContactsStore>>) -> Self {
        Self { stores }
    }
}

#[async_trait::async_trait]
impl DavRequestRouter for CardDavRouter {
    async fn route_request(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
        account_id: &str,
        primary_email: &str,
    ) -> Result<Option<DavResponse>> {
        let auth = AuthContext {
            account_id: account_id.to_string(),
            primary_email: primary_email.to_string(),
        };

        if method == "PROPFIND" {
            return self.handle_propfind(path, body, headers, &auth);
        }

        let Some(store) = self.stores.get(account_id) else {
            return Ok(None);
        };

        if method == "REPORT" {
            return self.handle_report(path, body, &auth, store);
        }

        carddav::handle_request(method, path, headers, body, &auth, store)
    }
}

impl CardDavRouter {
    fn handle_propfind(
        &self,
        raw_path: &str,
        body: &[u8],
        headers: &HashMap<String, String>,
        auth: &AuthContext,
    ) -> Result<Option<DavResponse>> {
        let depth = parse_depth(headers)?;
        let path = gluon_rs_dav::normalize_path(raw_path);
        let mode = propfind::parse_propfind_mode(body)?;

        if path == discovery::PRINCIPAL_ME_PATH {
            let mut resources = vec![propfind::principal_resource(auth)];
            if depth != DavDepth::Zero {
                resources.push(carddav_propfind::addressbook_home_resource(auth));
            }
            return Ok(Some(multistatus_response(resources, &mode)));
        }

        let Some((account_id, target)) = parse_account_resource_path(&path) else {
            return Ok(None);
        };
        if account_id != auth.account_id {
            return Ok(None);
        }

        match target {
            AccountResource::AddressbooksHome => {
                let mut resources = vec![carddav_propfind::addressbook_home_resource(auth)];
                if depth != DavDepth::Zero {
                    resources.push(carddav_propfind::default_addressbook_resource(auth));
                }
                Ok(Some(multistatus_response(resources, &mode)))
            }
            AccountResource::AddressbookDefault => Ok(Some(multistatus_response(
                vec![carddav_propfind::default_addressbook_resource(auth)],
                &mode,
            ))),
            _ => Ok(None),
        }
    }

    fn handle_report(
        &self,
        raw_path: &str,
        body: &[u8],
        auth: &AuthContext,
        store: &ContactsStore,
    ) -> Result<Option<DavResponse>> {
        let path = gluon_rs_dav::normalize_path(raw_path);
        let body_text = std::str::from_utf8(body)
            .map_err(|_| DavError::InvalidRequest("REPORT body is not utf-8"))?;
        if body_text.trim().is_empty() {
            return Ok(Some(report::invalid_report_payload_response(
                "REPORT body is missing or empty",
                &path,
                body_text,
            )));
        }

        let card_collection = discovery::default_addressbook_path(&auth.account_id);
        if path != card_collection {
            return Ok(None);
        }

        if body_text.contains("addressbook-query") {
            if let Err(err) = carddav_report::parse_addressbook_query_request(body_text) {
                return Ok(Some(report::invalid_report_payload_response(
                    &err.to_string(),
                    &path,
                    body_text,
                )));
            }
            return Ok(Some(carddav_report::addressbook_query(
                store,
                &auth.account_id,
            )?));
        }
        if body_text.contains("sync-collection") {
            return Ok(Some(carddav_report::carddav_sync_collection(
                store,
                &auth.account_id,
                body_text,
            )?));
        }
        if report::is_xml_like(body_text) {
            return Ok(Some(report::invalid_report_payload_response(
                "unsupported CardDAV REPORT payload",
                &path,
                body_text,
            )));
        }
        Ok(Some(report::not_implemented_report()))
    }
}
