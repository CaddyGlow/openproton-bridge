use gluon_rs_dav::auth::DavAuthenticator;
use gluon_rs_dav::types::AuthContext;

use crate::bridge::auth_router::AuthRouter;

/// Adapts the bridge `AuthRouter` to the `DavAuthenticator` trait from gluon-rs-dav.
pub struct BridgeDavAuth {
    router: AuthRouter,
}

impl BridgeDavAuth {
    pub fn new(router: AuthRouter) -> Self {
        Self { router }
    }
}

impl DavAuthenticator for BridgeDavAuth {
    fn resolve_login(&self, username: &str, password: &str) -> Option<AuthContext> {
        let route = self.router.resolve_login(username, password)?;
        Some(AuthContext {
            account_id: route.account_id.0,
            primary_email: route.primary_email,
        })
    }
}
