use std::collections::HashMap;
use std::sync::Arc;

use gluon_rs_dav::discovery;
use gluon_rs_dav::http::DavResponse;
use gluon_rs_dav::propfind::{self, multistatus_response};
use gluon_rs_dav::server::DavRequestRouter;
use gluon_rs_dav::types::{
    parse_account_resource_path, parse_depth, AccountResource, AuthContext, DavDepth,
};
use gluon_rs_dav::Result;

use crate::caldav_propfind;
use crate::store::CalendarStore;
use crate::types::QueryPage;

/// CalDAV request handler implementing the `DavRequestRouter` trait.
///
/// The `caldav_handler` is an opaque async function provided by the main crate
/// that handles the CalDAV-specific request logic (GET/PUT/DELETE events,
/// MKCALENDAR, PROPPATCH, REPORT). This allows the handler to integrate
/// with Proton API, crypto, etc. without the library crate needing those deps.
pub struct CalDavRouter {
    stores: HashMap<String, Arc<CalendarStore>>,
    caldav_handler: Arc<dyn CalDavHandler>,
}

/// Trait for the CalDAV request handler that the main crate implements.
///
/// This wraps the complex CalDAV logic (crypto, API sync) that depends on
/// main crate types. The library crate handles PROPFIND routing; everything
/// else is delegated to this handler.
#[async_trait::async_trait]
pub trait CalDavHandler: Send + Sync {
    async fn handle_request(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
        account_id: &str,
        primary_email: &str,
    ) -> Result<Option<DavResponse>>;
}

impl CalDavRouter {
    pub fn new(
        stores: HashMap<String, Arc<CalendarStore>>,
        caldav_handler: Arc<dyn CalDavHandler>,
    ) -> Self {
        Self {
            stores,
            caldav_handler,
        }
    }
}

#[async_trait::async_trait]
impl DavRequestRouter for CalDavRouter {
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

        // Delegate CalDAV operations (REPORT, GET, PUT, DELETE, MKCALENDAR,
        // PROPPATCH, POST) to the handler provided by the main crate.
        self.caldav_handler
            .handle_request(method, path, headers, body, account_id, primary_email)
            .await
    }
}

impl CalDavRouter {
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
                resources.push(caldav_propfind::calendar_home_resource(auth));
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
            AccountResource::ScheduleInbox => Ok(Some(multistatus_response(
                vec![propfind::schedule_inbox_resource(auth)],
                &mode,
            ))),
            AccountResource::ScheduleOutbox => Ok(Some(multistatus_response(
                vec![propfind::schedule_outbox_resource(auth)],
                &mode,
            ))),
            AccountResource::CalendarsHome => {
                let store = self.stores.get(&auth.account_id);
                Ok(Some(multistatus_response(
                    self.calendar_home_resources(auth, depth, store.map(Arc::as_ref)),
                    &mode,
                )))
            }
            AccountResource::CalendarCollection(calendar_id) => {
                let store = self.stores.get(&auth.account_id);
                let calendar =
                    store.and_then(|store| store.get_calendar(&calendar_id, false).ok().flatten());
                Ok(Some(multistatus_response(
                    vec![caldav_propfind::calendar_collection_resource(
                        auth,
                        &calendar_id,
                        calendar.as_ref(),
                        store.map(Arc::as_ref),
                        None,
                    )],
                    &mode,
                )))
            }
            _ => Ok(None),
        }
    }

    fn calendar_home_resources(
        &self,
        auth: &AuthContext,
        depth: DavDepth,
        store: Option<&CalendarStore>,
    ) -> Vec<gluon_rs_dav::DavPropResource> {
        let mut resources = vec![caldav_propfind::calendar_home_resource(auth)];
        if depth != DavDepth::Zero {
            let mut has_calendars = false;
            if let Some(store) = store {
                if let Ok(calendars) = store.list_calendars(
                    false,
                    QueryPage {
                        limit: 500,
                        offset: 0,
                    },
                ) {
                    for calendar in calendars {
                        if !caldav_propfind::should_advertise_calendar(&calendar) {
                            continue;
                        }
                        has_calendars = true;
                        resources.push(caldav_propfind::calendar_collection_resource(
                            auth,
                            &calendar.id,
                            Some(&calendar),
                            Some(store),
                            None,
                        ));
                    }
                }
            }
            if !has_calendars {
                resources.push(caldav_propfind::default_calendar_resource(auth));
            }
        }
        resources
    }
}
