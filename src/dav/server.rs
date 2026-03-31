use std::collections::HashMap;
use std::sync::Arc;

use gluon_rs_calendar::CalDavRouter;
use gluon_rs_contacts::CardDavRouter;
use gluon_rs_dav::server::{DavRequestRouter, DavServerConfig};

use crate::bridge::accounts::RuntimeAccountRegistry;
use crate::bridge::auth_router::AuthRouter;
use crate::pim::store::PimStore;

use super::bridge_auth::BridgeDavAuth;
use super::bridge_caldav::BridgeCalDavHandler;
use super::push;

pub use gluon_rs_dav::server::{
    clear_runtime_tls_config, handle_connection, install_runtime_tls_config_from_dir,
    run_server_with_listener_and_config, run_server_with_listener_and_config_and_tls_config,
    DavServer, DavServerHandle,
};

pub struct DavSetup {
    pub auth_router: AuthRouter,
    pub pim_stores: HashMap<String, Arc<PimStore>>,
    pub runtime_accounts: Option<Arc<RuntimeAccountRegistry>>,
    pub push_subscriptions: Option<push::PushSubscriptionStore>,
    pub vapid_keys: Option<Arc<push::VapidKeyPair>>,
}

impl DavSetup {
    pub fn into_server_config(self) -> DavServerConfig {
        let authenticator = Arc::new(BridgeDavAuth::new(self.auth_router));

        // Build separate store handles for the DAV routers (WAL mode allows concurrent readers)
        let contacts_stores: HashMap<String, Arc<gluon_rs_contacts::ContactsStore>> = self
            .pim_stores
            .iter()
            .filter_map(|(account_id, pim_store)| {
                pim_store
                    .contacts_store_for_dav()
                    .map(|cs| (account_id.clone(), cs))
            })
            .collect();

        let calendar_stores: HashMap<String, Arc<gluon_rs_calendar::CalendarStore>> = self
            .pim_stores
            .iter()
            .filter_map(|(account_id, pim_store)| {
                pim_store
                    .calendar_store_for_dav()
                    .map(|cs| (account_id.clone(), cs))
            })
            .collect();

        let carddav_router: Arc<dyn DavRequestRouter> =
            Arc::new(CardDavRouter::new(contacts_stores));

        let caldav_handler = Arc::new(BridgeCalDavHandler {
            pim_stores: self.pim_stores,
            runtime_accounts: self.runtime_accounts,
            push_subscriptions: self.push_subscriptions,
        });
        let caldav_router: Arc<dyn DavRequestRouter> =
            Arc::new(CalDavRouter::new(calendar_stores, caldav_handler));

        DavServerConfig {
            authenticator,
            routers: vec![carddav_router, caldav_router],
        }
    }
}
