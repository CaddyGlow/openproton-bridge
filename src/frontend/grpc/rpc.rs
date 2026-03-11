struct DecodedLoginPassword {
    value: String,
    used_base64_compat: bool,
}

#[derive(Debug)]
enum LoginPasswordDecodeError {
    InvalidUtf8,
    Missing,
}

impl LoginPasswordDecodeError {
    fn into_status(self) -> Status {
        match self {
            Self::InvalidUtf8 => Status::invalid_argument("password must be valid utf-8"),
            Self::Missing => Status::invalid_argument("password is required"),
        }
    }
}

fn looks_like_padded_base64(input: &str) -> bool {
    if input.len() < 8 || !input.len().is_multiple_of(4) {
        return false;
    }
    if !input.ends_with('=') {
        return false;
    }

    input
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

fn decode_login_password_bytes(
    raw: Vec<u8>,
) -> Result<DecodedLoginPassword, LoginPasswordDecodeError> {
    let utf8 = String::from_utf8(raw).map_err(|_| LoginPasswordDecodeError::InvalidUtf8)?;
    if utf8.is_empty() {
        return Err(LoginPasswordDecodeError::Missing);
    }

    if looks_like_padded_base64(&utf8) {
        if let Ok(decoded) = BASE64.decode(utf8.as_bytes()) {
            if !decoded.is_empty() {
                if let Ok(decoded_utf8) = String::from_utf8(decoded) {
                    return Ok(DecodedLoginPassword {
                        value: decoded_utf8,
                        used_base64_compat: true,
                    });
                }
            }
        }
    }

    Ok(DecodedLoginPassword {
        value: utf8,
        used_base64_compat: false,
    })
}

fn handle_stream_recv_error(
    service: &BridgeService,
    err: tokio::sync::broadcast::error::RecvError,
) {
    match err {
        tokio::sync::broadcast::error::RecvError::Lagged(skipped) => {
            warn!(
                skipped,
                "grpc event stream lagged; emitting generic error marker"
            );
            service.emit_generic_error(pb::ErrorCode::UnknownError);
        }
        tokio::sync::broadcast::error::RecvError::Closed => {}
    }
}

fn to_pim_page(page: Option<pb::PimPage>) -> crate::pim::query::QueryPage {
    let defaults = crate::pim::query::QueryPage::default();
    match page {
        Some(page) => {
            let limit = if page.limit == 0 {
                defaults.limit
            } else {
                page.limit as usize
            };
            crate::pim::query::QueryPage {
                limit,
                offset: page.offset as usize,
            }
        }
        None => defaults,
    }
}

fn to_pb_pim_contact(contact: crate::pim::types::StoredContact) -> pb::PimContact {
    pb::PimContact {
        id: contact.id,
        uid: contact.uid,
        name: contact.name,
        size: contact.size,
        create_time: contact.create_time,
        modify_time: contact.modify_time,
        deleted: contact.deleted,
        updated_at_ms: contact.updated_at_ms,
    }
}

fn to_pb_pim_calendar(calendar: crate::pim::types::StoredCalendar) -> pb::PimCalendar {
    pb::PimCalendar {
        id: calendar.id,
        name: calendar.name,
        description: calendar.description,
        color: calendar.color,
        display: calendar.display,
        calendar_type: calendar.calendar_type,
        flags: calendar.flags,
        deleted: calendar.deleted,
        updated_at_ms: calendar.updated_at_ms,
    }
}

fn to_pb_pim_calendar_event(event: crate::pim::types::StoredCalendarEvent) -> pb::PimCalendarEvent {
    pb::PimCalendarEvent {
        id: event.id,
        calendar_id: event.calendar_id,
        uid: event.uid,
        shared_event_id: event.shared_event_id,
        start_time: event.start_time,
        end_time: event.end_time,
        deleted: event.deleted,
        updated_at_ms: event.updated_at_ms,
    }
}

fn unix_now_millis_i64() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn to_api_contact(
    contact: pb::PimContact,
    emails: Vec<pb::PimContactEmail>,
    cards: Vec<pb::PimContactCard>,
) -> crate::api::contacts::Contact {
    let contact_id = contact.id.clone();
    let mapped_emails = emails
        .into_iter()
        .enumerate()
        .map(|(index, email)| crate::api::contacts::ContactEmail {
            id: if email.id.trim().is_empty() {
                format!("{contact_id}:email:{index}")
            } else {
                email.id
            },
            email: email.email,
            name: email.name,
            kind: email.kind,
            defaults: email.defaults,
            order: email.order,
            contact_id: contact_id.clone(),
            label_ids: email.label_i_ds,
            last_used_time: email.last_used_time,
        })
        .collect::<Vec<_>>();
    let mapped_cards = cards
        .into_iter()
        .map(|card| crate::api::contacts::ContactCard {
            card_type: card.card_type,
            data: card.data,
            signature: card.signature,
        })
        .collect::<Vec<_>>();
    crate::api::contacts::Contact {
        metadata: crate::api::contacts::ContactMetadata {
            id: contact.id.clone(),
            name: contact.name,
            uid: if contact.uid.trim().is_empty() {
                contact.id
            } else {
                contact.uid
            },
            size: contact.size,
            create_time: if contact.create_time > 0 {
                contact.create_time
            } else {
                unix_now_millis_i64()
            },
            modify_time: if contact.modify_time > 0 {
                contact.modify_time
            } else {
                unix_now_millis_i64()
            },
            contact_emails: mapped_emails,
            label_ids: Vec::new(),
        },
        cards: mapped_cards,
    }
}

fn to_api_calendar(calendar: pb::PimCalendar) -> crate::api::calendar::Calendar {
    crate::api::calendar::Calendar {
        id: calendar.id,
        name: calendar.name,
        description: calendar.description,
        color: calendar.color,
        display: calendar.display,
        calendar_type: calendar.calendar_type,
        flags: calendar.flags,
    }
}

fn to_api_calendar_event(event: pb::PimCalendarEvent) -> crate::api::calendar::CalendarEvent {
    let create_time = if event.start_time > 0 {
        event.start_time
    } else {
        unix_now_millis_i64()
    };
    crate::api::calendar::CalendarEvent {
        id: event.id.clone(),
        uid: if event.uid.trim().is_empty() {
            event.id
        } else {
            event.uid
        },
        calendar_id: event.calendar_id,
        shared_event_id: event.shared_event_id,
        create_time,
        last_edit_time: create_time,
        start_time: event.start_time,
        end_time: event.end_time,
        ..crate::api::calendar::CalendarEvent::default()
    }
}

impl BridgeService {
    #[allow(clippy::result_large_err)]
    async fn managed_sessions(&self) -> Result<Vec<Session>, Status> {
        self.state
            .runtime_supervisor
            .session_manager()
            .load_sessions_from_vault()
            .await
            .map_err(|err| Status::internal(format!("failed to load managed sessions: {err}")))
    }

    #[allow(clippy::result_large_err)]
    async fn managed_session_by_lookup(&self, lookup: &str) -> Result<Session, Status> {
        let lookup = lookup.trim();
        if lookup.is_empty() {
            return Err(Status::invalid_argument("user id is required"));
        }

        self.managed_sessions()
            .await?
            .into_iter()
            .find(|session| session.uid == lookup || session.email.eq_ignore_ascii_case(lookup))
            .ok_or_else(|| Status::not_found("user not found"))
    }

    #[allow(clippy::result_large_err)]
    async fn resolve_pim_store_for_account_selector(
        &self,
        account_selector: &str,
    ) -> Result<crate::pim::store::PimStore, Status> {
        let selector = account_selector.trim();
        if selector.is_empty() {
            return Err(Status::invalid_argument("accountID is required"));
        }

        let sessions = self.managed_sessions().await?;
        let Some(session) = sessions.into_iter().find(|session| {
            session.uid == selector || session.email.eq_ignore_ascii_case(selector)
        }) else {
            return Err(Status::not_found(format!(
                "unknown account selector: {selector}"
            )));
        };

        let bootstrap = vault::load_gluon_store_bootstrap(self.settings_dir(), &[session.uid])
            .map_err(|err| match err {
                vault::VaultError::AccountNotFound(_) => Status::not_found(format!(
                    "no gluon bootstrap account for selector: {selector}"
                )),
                other => status_from_vault_error(other),
            })?;
        let Some(account) = bootstrap.accounts.first() else {
            return Err(Status::not_found(format!(
                "no gluon account for selector: {selector}"
            )));
        };

        let gluon_paths = self
            .state
            .runtime_paths
            .gluon_paths(Some(bootstrap.gluon_dir.as_str()));
        let db_path = gluon_paths.account_db_path(&account.storage_user_id);
        crate::pim::store::PimStore::new(db_path)
            .map_err(|err| Status::internal(format!("failed to open pim store: {err}")))
    }

    #[allow(clippy::result_large_err)]
    fn ensure_expected_contact_updated_at(
        &self,
        store: &crate::pim::store::PimStore,
        contact_id: &str,
        expected_updated_at_ms: Option<i64>,
    ) -> Result<(), Status> {
        let Some(expected) = expected_updated_at_ms else {
            return Ok(());
        };
        let current = store.get_contact(contact_id, true).map_err(|err| {
            Status::internal(format!("failed to read current contact state: {err}"))
        })?;
        let Some(current) = current else {
            return Err(Status::aborted(format!(
                "stale write rejected for contact {}; current row missing",
                contact_id
            )));
        };
        if current.updated_at_ms != expected {
            return Err(Status::aborted(format!(
                "stale write rejected for contact {}; expected updatedAtMs {}, current {}",
                contact_id, expected, current.updated_at_ms
            )));
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn ensure_expected_calendar_updated_at(
        &self,
        store: &crate::pim::store::PimStore,
        calendar_id: &str,
        expected_updated_at_ms: Option<i64>,
    ) -> Result<(), Status> {
        let Some(expected) = expected_updated_at_ms else {
            return Ok(());
        };
        let current = store.get_calendar(calendar_id, true).map_err(|err| {
            Status::internal(format!("failed to read current calendar state: {err}"))
        })?;
        let Some(current) = current else {
            return Err(Status::aborted(format!(
                "stale write rejected for calendar {}; current row missing",
                calendar_id
            )));
        };
        if current.updated_at_ms != expected {
            return Err(Status::aborted(format!(
                "stale write rejected for calendar {}; expected updatedAtMs {}, current {}",
                calendar_id, expected, current.updated_at_ms
            )));
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn ensure_expected_calendar_event_updated_at(
        &self,
        store: &crate::pim::store::PimStore,
        event_id: &str,
        expected_updated_at_ms: Option<i64>,
    ) -> Result<(), Status> {
        let Some(expected) = expected_updated_at_ms else {
            return Ok(());
        };
        let current = store.get_calendar_event(event_id, true).map_err(|err| {
            Status::internal(format!(
                "failed to read current calendar event state: {err}"
            ))
        })?;
        let Some(current) = current else {
            return Err(Status::aborted(format!(
                "stale write rejected for calendar event {}; current row missing",
                event_id
            )));
        };
        if current.updated_at_ms != expected {
            return Err(Status::aborted(format!(
                "stale write rejected for calendar event {}; expected updatedAtMs {}, current {}",
                event_id, expected, current.updated_at_ms
            )));
        }
        Ok(())
    }

    async fn stage_two_password_login(&self, pending: PendingLogin) {
        let username = pending.username.clone();
        info!(
            pkg = "bridge/login",
            user_id = %pending.uid,
            username = %username,
            "Requesting mailbox password"
        );
        *self.state.pending_login.lock().await = Some(pending);
        self.emit_login_two_password_requested(&username);
    }
}

#[allow(clippy::result_large_err)]
fn resolve_optimize_cache_accounts(
    sessions: &[Session],
    selector: &str,
) -> Result<Vec<Session>, Status> {
    if sessions.is_empty() {
        return Err(Status::failed_precondition("no accounts are configured"));
    }

    let selector = selector.trim();
    if selector.is_empty() {
        return Ok(sessions.to_vec());
    }

    if let Ok(index) = selector.parse::<usize>() {
        let Some(session) = sessions.get(index) else {
            return Err(Status::invalid_argument(format!(
                "account index {index} is out of range (max {})",
                sessions.len().saturating_sub(1)
            )));
        };
        return Ok(vec![session.clone()]);
    }

    let session = sessions.iter().find(|session| {
        session.uid == selector
            || session.email.eq_ignore_ascii_case(selector)
            || session.display_name.eq_ignore_ascii_case(selector)
    });

    match session {
        Some(session) => Ok(vec![session.clone()]),
        None => Err(Status::not_found(format!(
            "unknown account selector: {selector}"
        ))),
    }
}

#[allow(clippy::result_large_err)]
fn resolve_optimize_cache_mailboxes(mailboxes: &[String]) -> Result<Vec<String>, Status> {
    if mailboxes.is_empty() {
        return Ok(crate::imap::mailbox::system_mailboxes()
            .iter()
            .filter(|mailbox| mailbox.selectable)
            .map(|mailbox| mailbox.name.to_string())
            .collect());
    }

    let mut out = Vec::with_capacity(mailboxes.len());
    let mut seen = HashSet::new();
    for raw_mailbox in mailboxes {
        let name = raw_mailbox.trim();
        if name.is_empty() {
            return Err(Status::invalid_argument("mailbox name is empty"));
        }

        let Some(mailbox) = crate::imap::mailbox::find_mailbox(name) else {
            return Err(Status::invalid_argument(format!("unknown mailbox: {name}")));
        };
        if !mailbox.selectable {
            return Err(Status::invalid_argument(format!(
                "mailbox is not selectable: {name}"
            )));
        }

        let name = mailbox.name.to_string();
        if seen.insert(name.clone()) {
            out.push(name);
        }
    }

    if out.is_empty() {
        return Err(Status::invalid_argument("no valid mailbox names provided"));
    }
    Ok(out)
}

fn resolve_optimize_cache_concurrency(raw_concurrency: u32) -> usize {
    if raw_concurrency == 0 {
        return OPTIMIZE_CACHE_CONCURRENCY;
    }

    let requested = raw_concurrency as usize;
    requested.clamp(1, OPTIMIZE_CACHE_CONCURRENCY_MAX)
}

fn scoped_cache_mailbox(account_id: &str, mailbox: &str) -> String {
    format!("{account_id}::{mailbox}")
}

#[allow(clippy::result_large_err)]
async fn load_cache_auth_material(
    runtime_accounts: &Arc<bridge::accounts::RuntimeAccountRegistry>,
    account_id: &bridge::types::AccountId,
    account_session: &mut Session,
    client: &mut ProtonClient,
) -> Option<Arc<bridge::accounts::RuntimeAuthMaterial>> {
    if let Some(material) = runtime_accounts.get_auth_material(account_id).await {
        return Some(material);
    }

    let mut cached_session = account_session.clone();
    let load_user = async {
        loop {
            match api::users::get_user(client).await {
                Ok(response) => break Ok(response),
                Err(err) if api::error::is_auth_error(&err) => {
                    let refreshed = runtime_accounts
                        .refresh_session_if_stale(&account_id, Some(&cached_session.access_token))
                        .await
                        .map_err(|refresh_err| {
                            format!("failed to refresh session: {refresh_err}")
                        })?;
                    *account_session = refreshed.clone();
                    cached_session = refreshed;
                    *client = ProtonClient::authenticated_with_mode(
                        cached_session.api_mode.base_url(),
                        cached_session.api_mode,
                        &cached_session.uid,
                        &cached_session.access_token,
                    )
                    .map_err(|err| format!("failed to create authenticated client: {err}"))?;
                    continue;
                }
                Err(err) => {
                    return Err(format!("failed to fetch user metadata: {err}"));
                }
            }
        }
    };
    let user_response = match load_user.await {
        Ok(response) => response,
        Err(err) => {
            warn!(account_id = %account_id.0, error = %err, "failed to load auth material");
            return None;
        }
    };

    let mut refreshed_session = account_session.clone();
    let load_addresses = async {
        loop {
            match api::users::get_addresses(client).await {
                Ok(response) => break Ok(response),
                Err(err) if api::error::is_auth_error(&err) => {
                    let refreshed = runtime_accounts
                        .refresh_session_if_stale(
                            &account_id,
                            Some(&refreshed_session.access_token),
                        )
                        .await
                        .map_err(|refresh_err| {
                            format!(
                                "failed to refresh session before addresses fetch: {refresh_err}"
                            )
                        })?;
                    *account_session = refreshed.clone();
                    refreshed_session = refreshed;
                    *client = ProtonClient::authenticated_with_mode(
                        refreshed_session.api_mode.base_url(),
                        refreshed_session.api_mode,
                        &refreshed_session.uid,
                        &refreshed_session.access_token,
                    )
                    .map_err(|err| format!("failed to create authenticated client: {err}"))?;
                    continue;
                }
                Err(err) => {
                    return Err(format!("failed to fetch addresses: {err}"));
                }
            }
        }
    };
    let addresses_response = match load_addresses.await {
        Ok(response) => response,
        Err(err) => {
            warn!(account_id = %account_id.0, error = %err, "failed to load account addresses");
            return None;
        }
    };

    let material = Arc::new(bridge::accounts::RuntimeAuthMaterial {
        user_keys: user_response.user.keys,
        addresses: addresses_response.addresses,
    });
    if let Err(err) = runtime_accounts
        .set_auth_material(account_id, material.clone())
        .await
    {
        warn!(
            account_id = %account_id.0,
            error = %err,
            "failed to cache account auth material"
        );
    }
    Some(material)
}

#[allow(clippy::result_large_err)]
async fn optimize_cache_message(
    mailbox: String,
    uid: u32,
    proton_id: String,
    mut client: ProtonClient,
    access_token: String,
    runtime_accounts: Arc<bridge::accounts::RuntimeAccountRegistry>,
    account_id: crate::bridge::types::AccountId,
    addr_keyrings: Arc<HashMap<String, Arc<crate::crypto::keys::Keyring>>>,
    store: Arc<dyn crate::imap::store::MessageStore>,
) -> bool {
    let msg_resp = match crate::api::messages::get_message(&client, &proton_id).await {
        Ok(msg) => msg,
        Err(err) if api::error::is_auth_error(&err) => {
            let refreshed_session = match runtime_accounts
                .refresh_session_if_stale(&account_id, Some(&access_token))
                .await
            {
                Ok(session) => session,
                Err(refresh_err) => {
                    warn!(
                        account_id = %account_id.0,
                        proton_id = %proton_id,
                        error = %refresh_err,
                        "failed to refresh token while optimizing cache"
                    );
                    return false;
                }
            };
            client = match ProtonClient::authenticated_with_mode(
                refreshed_session.api_mode.base_url(),
                refreshed_session.api_mode,
                &refreshed_session.uid,
                &refreshed_session.access_token,
            ) {
                Ok(authenticated) => authenticated,
                Err(err) => {
                    warn!(
                        account_id = %account_id.0,
                        proton_id = %proton_id,
                        error = %err,
                        "failed to recreate authenticated client while optimizing cache"
                    );
                    return false;
                }
            };
            match crate::api::messages::get_message(&client, &proton_id).await {
                Ok(msg) => msg,
                Err(err) => {
                    warn!(
                        account_id = %account_id.0,
                        proton_id = %proton_id,
                        error = %err,
                        "failed to fetch message while optimizing cache"
                    );
                    return false;
                }
            }
        }
        Err(err) => {
            warn!(
                account_id = %account_id.0,
                proton_id = %proton_id,
                error = %err,
                "failed to fetch message while optimizing cache"
            );
            return false;
        }
    };

    let msg = &msg_resp.message;
    let Some(keyring) = addr_keyrings.get(&msg.metadata.address_id) else {
        warn!(
            account_id = %account_id.0,
            proton_id = %proton_id,
            address_id = %msg.metadata.address_id,
            "no address keyring for message; skipping cache optimization"
        );
        return false;
    };

    let data = match crate::imap::rfc822::build_rfc822(&client, keyring, msg).await {
        Ok(data) => data,
        Err(err) => {
            warn!(
                account_id = %account_id.0,
                proton_id = %proton_id,
                error = %err,
                "failed to build RFC822 while optimizing cache"
            );
            return false;
        }
    };

    if let Err(err) = store.store_rfc822(&mailbox, uid, data).await {
        warn!(
            account_id = %account_id.0,
            mailbox = %mailbox,
            uid,
            error = %err,
            "failed to store optimized RFC822 cache entry"
        );
        return false;
    }

    true
}

#[allow(clippy::result_large_err)]
async fn run_cache_optimization_for_account(
    runtime_accounts: Arc<bridge::accounts::RuntimeAccountRegistry>,
    store: Arc<dyn crate::imap::store::MessageStore>,
    account: Session,
    mailboxes: Vec<String>,
    semaphore: Arc<Semaphore>,
) {
    let account_id = crate::bridge::types::AccountId(account.uid.clone());
    let mut account_session = match runtime_accounts.with_valid_access_token(&account_id).await {
        Ok(session) => session,
        Err(err) => {
            warn!(
                account_id = %account.uid,
                error = %err,
                "optimizing cache failed while loading account session"
            );
            return;
        }
    };

    let mut client = match ProtonClient::authenticated_with_mode(
        account_session.api_mode.base_url(),
        account_session.api_mode,
        &account_session.uid,
        &account_session.access_token,
    ) {
        Ok(client) => client,
        Err(err) => {
            warn!(
                account_id = %account.uid,
                error = %err,
                "failed to create authenticated client for cache optimization"
            );
            return;
        }
    };

    let mut passphrase = match account_session.key_passphrase.as_deref() {
        Some(raw) => match BASE64.decode(raw) {
            Ok(passphrase) => passphrase,
            Err(err) => {
                warn!(
                    account_id = %account.uid,
                    error = %err,
                    "invalid key passphrase encoding for cache optimization"
                );
                return;
            }
        },
        None => {
            warn!(
                account_id = %account.uid,
                "no key passphrase in session; skipping cache optimization"
            );
            return;
        }
    };

    let auth_material = match load_cache_auth_material(
        &runtime_accounts,
        &account_id,
        &mut account_session,
        &mut client,
    )
    .await
    {
        Some(material) => material,
        None => {
            warn!(
                account_id = %account.uid,
                "failed to load auth material for cache optimization"
            );
            passphrase.zeroize();
            return;
        }
    };

    let user_keyring =
        match crate::crypto::keys::unlock_user_keys(&auth_material.user_keys, &passphrase) {
            Ok(kr) => kr,
            Err(err) => {
                passphrase.zeroize();
                warn!(
                    account_id = %account.uid,
                    error = %err,
                    "failed to unlock user keys for cache optimization"
                );
                return;
            }
        };

    let mut addr_keyrings = HashMap::new();
    for addr in &auth_material.addresses {
        if addr.status != 1 || addr.keys.is_empty() {
            continue;
        }

        match crate::crypto::keys::unlock_address_keys(&addr.keys, &passphrase, &user_keyring) {
            Ok(address_keyring) => {
                addr_keyrings.insert(addr.id.clone(), Arc::new(address_keyring));
            }
            Err(err) => {
                warn!(
                    account_id = %account.uid,
                    address_id = %addr.id,
                    error = %err,
                    "failed to unlock address keyring for cache optimization"
                );
            }
        }
    }

    passphrase.zeroize();

    let addr_keyrings = Arc::new(addr_keyrings);
    if addr_keyrings.is_empty() {
        warn!(
            account_id = %account.uid,
            "cache optimization skipped: no unlocked address keyrings"
        );
        return;
    }

    let access_token = account_session.access_token;
    let mut handles = Vec::new();
    let mut pending_jobs = 0usize;

    for mailbox in mailboxes.iter() {
        let scoped = scoped_cache_mailbox(&account.uid, mailbox);
        let uids = match store.list_uids(&scoped).await {
            Ok(uids) => uids,
            Err(err) => {
                warn!(
                    account_id = %account.uid,
                    mailbox = %mailbox,
                    error = %err,
                    "failed to list mailbox uids while optimizing cache"
                );
                continue;
            }
        };

        for uid in uids {
            match store.get_rfc822(&scoped, uid).await {
                Ok(Some(_)) => continue,
                Ok(None) => {}
                Err(err) => {
                    warn!(
                        account_id = %account.uid,
                        mailbox = %scoped,
                        uid,
                        error = %err,
                        "failed to check RFC822 cache while optimizing"
                    );
                    continue;
                }
            }

            let proton_id = match store.get_proton_id(&scoped, uid).await {
                Ok(Some(proton_id)) => proton_id,
                Ok(None) => continue,
                Err(err) => {
                    warn!(
                        account_id = %account.uid,
                        mailbox = %scoped,
                        uid,
                        error = %err,
                        "missing proton id while optimizing cache"
                    );
                    continue;
                }
            };

            let handle = {
                let runtime_accounts = runtime_accounts.clone();
                let store = store.clone();
                let client = client.clone();
                let account_id = account_id.clone();
                let mailbox = scoped.clone();
                let proton_id = proton_id.clone();
                let addr_keyrings = addr_keyrings.clone();
                let access_token = access_token.clone();
                let semaphore = semaphore.clone();

                tokio::spawn(async move {
                    let permit = match semaphore.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(err) => {
                            warn!(
                                error = %err,
                                account_id = %account_id.0,
                                "cache optimization semaphore closed"
                            );
                            return false;
                        }
                    };
                    let _permit = permit;
                    optimize_cache_message(
                        mailbox,
                        uid,
                        proton_id,
                        client,
                        access_token,
                        runtime_accounts,
                        account_id,
                        addr_keyrings,
                        store,
                    )
                    .await
                })
            };
            handles.push(handle);
            pending_jobs += 1;
        }
    }

    let mut optimized = 0usize;
    for handle in handles {
        match handle.await {
            Ok(true) => optimized += 1,
            Ok(false) => {}
            Err(err) => {
                warn!(
                    account_id = %account.uid,
                    error = %err,
                    "cache optimization task join failed"
                );
            }
        }
    }

    if pending_jobs > 0 {
        info!(
            account_id = %account.uid,
            pending_jobs,
            optimized,
            "cache optimization finished for account"
        );
    }
}

#[allow(clippy::result_large_err)]
async fn run_cache_optimization(
    runtime_accounts: Arc<bridge::accounts::RuntimeAccountRegistry>,
    store: Arc<dyn crate::imap::store::MessageStore>,
    accounts: Vec<Session>,
    mailboxes: Vec<String>,
    concurrency: usize,
) {
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();
    for account in accounts {
        let runtime_accounts = runtime_accounts.clone();
        let store = store.clone();
        let mailboxes = mailboxes.clone();
        let semaphore = semaphore.clone();
        handles.push(tokio::spawn(async move {
            run_cache_optimization_for_account(
                runtime_accounts,
                store,
                account,
                mailboxes,
                semaphore,
            )
            .await;
        }));
    }

    for handle in handles {
        if let Err(err) = handle.await {
            warn!(error = %err, "cache optimization account worker failed");
        }
    }
}

#[tonic::async_trait]
impl pb::bridge_server::Bridge for BridgeService {
    async fn check_tokens(&self, request: Request<String>) -> Result<Response<String>, Status> {
        debug!(pkg = "grpc", "CheckTokens");
        let path = request.into_inner();
        if path.trim().is_empty() {
            return Err(Status::invalid_argument("client config path is empty"));
        }

        let payload = tokio::fs::read(&path)
            .await
            .map_err(|e| Status::not_found(format!("failed to read client config: {e}")))?;
        let cfg: GrpcClientConfig = serde_json::from_slice(&payload)
            .map_err(|e| Status::invalid_argument(format!("invalid client config json: {e}")))?;
        Ok(Response::new(cfg.token))
    }

    async fn add_log_entry(
        &self,
        request: Request<pb::AddLogEntryRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let level = pb::LogLevel::try_from(req.level).unwrap_or(pb::LogLevel::LogInfo);
        match level {
            pb::LogLevel::LogPanic | pb::LogLevel::LogFatal | pb::LogLevel::LogError => {
                tracing::error!(target = req.r#package.as_str(), "{}", req.message);
            }
            pb::LogLevel::LogWarn => {
                tracing::warn!(target = req.r#package.as_str(), "{}", req.message);
            }
            pb::LogLevel::LogInfo => {
                tracing::info!(target = req.r#package.as_str(), "{}", req.message);
            }
            pb::LogLevel::LogDebug => {
                tracing::debug!(target = req.r#package.as_str(), "{}", req.message);
            }
            pb::LogLevel::LogTrace => {
                tracing::trace!(target = req.r#package.as_str(), "{}", req.message);
            }
        }
        Ok(Response::new(()))
    }

    async fn gui_ready(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::GuiReadyResponse>, Status> {
        debug!(pkg = "grpc", "GuiReady");
        let settings = self.state.app_settings.lock().await;
        self.emit_all_users_loaded();
        self.emit_show_main_window();
        Ok(Response::new(pb::GuiReadyResponse {
            show_splash_screen: settings.show_on_startup,
        }))
    }

    async fn restart(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        self.stop_mail_runtime_for_transition("restart").await;
        self.emit_show_main_window();
        let _ = self.state.shutdown_tx.send(true);
        Ok(Response::new(()))
    }

    async fn trigger_repair(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        tracing::info!(
            pkg = "grpc/bridge",
            transition = "trigger_repair",
            "repair requested"
        );
        let service = self.clone();
        tokio::spawn(async move {
            let runtime_transition_guard = service.state.mail_runtime_transition_lock.lock().await;
            match vault::list_sessions(service.settings_dir()) {
                Ok(sessions) => {
                    for session in sessions {
                        let checkpoint = vault::StoredEventCheckpoint {
                            last_event_id: String::new(),
                            last_event_ts: None,
                            sync_state: None,
                        };
                        if let Err(err) = vault::save_event_checkpoint_by_account_id(
                            service.settings_dir(),
                            &session.uid,
                            &checkpoint,
                        ) {
                            tracing::warn!(
                                user_id = %session.uid,
                                error = %err,
                                "failed to reset event checkpoint during repair"
                            );
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, "failed to list sessions during repair");
                }
            }
            drop(runtime_transition_guard);

            service
                .refresh_sync_workers_for_transition("trigger_repair")
                .await;
            tracing::info!(
                pkg = "grpc/bridge",
                transition = "trigger_repair",
                "repair transition completed"
            );
            service.emit_repair_started();
            service.emit_show_main_window();
        });
        Ok(Response::new(()))
    }

    async fn optimize_cache(
        &self,
        request: Request<pb::OptimizeCacheRequest>,
    ) -> Result<Response<pb::OptimizeCacheResponse>, Status> {
        let req = request.into_inner();
        let selector = req.account_selector.trim();
        let concurrency = resolve_optimize_cache_concurrency(req.concurrency);
        debug!(
            pkg = "grpc",
            account_selector = %selector,
            mailboxes = req.mailboxes.len(),
            concurrency,
            "OptimizeCache"
        );

        let sessions = self.managed_sessions().await?;
        let accounts = resolve_optimize_cache_accounts(&sessions, selector)?;
        let mailboxes = resolve_optimize_cache_mailboxes(&req.mailboxes)?;

        let runtime_accounts = self.state.runtime_supervisor.session_manager().runtime_accounts();

        let account_ids = accounts
            .iter()
            .map(|session| session.uid.clone())
            .collect::<Vec<_>>();
        let bootstrap = vault::load_gluon_store_bootstrap(self.settings_dir(), &account_ids)
            .map_err(|err| match err {
                vault::VaultError::AccountNotFound(account_id) => {
                    Status::not_found(format!("no gluon bootstrap account for {account_id}"))
                }
                other => status_from_vault_error(other),
            })?;

        let account_storage_ids = bootstrap
            .accounts
            .into_iter()
            .map(|account| (account.account_id.clone(), account.storage_user_id.clone()))
            .collect::<HashMap<_, _>>();
        let gluon_paths = self
            .state
            .runtime_paths
            .gluon_paths(Some(bootstrap.gluon_dir.as_str()));
        let store = crate::imap::store::new_runtime_message_store(
            gluon_paths.root().to_path_buf(),
            account_storage_ids,
        )
        .map_err(|err| Status::internal(format!("failed to open runtime message store: {err}")))?;

        tokio::spawn(async move {
            run_cache_optimization(runtime_accounts, store, accounts, mailboxes, concurrency).await;
        });

        Ok(Response::new(pb::OptimizeCacheResponse { started: true }))
    }

    async fn trigger_reset(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        tracing::info!(
            pkg = "grpc/bridge",
            transition = "trigger_reset",
            "reset requested"
        );
        self.stop_mail_runtime_for_transition("trigger_reset").await;
        vault::remove_session(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        self.state
            .runtime_supervisor
            .session_manager()
            .remove_all_sessions()
            .await;
        let _ = tokio::fs::remove_file(self.grpc_mail_settings_path()).await;
        let _ = tokio::fs::remove_file(self.grpc_app_settings_path()).await;
        self.clear_session_access_tokens().await;
        *self.state.pending_login.lock().await = None;
        *self.state.pending_hv.lock().await = None;
        self.refresh_sync_workers_for_transition("trigger_reset")
            .await;
        tracing::info!(
            pkg = "grpc/bridge",
            transition = "trigger_reset",
            "reset transition completed"
        );
        self.emit_reset_finished();
        Ok(Response::new(()))
    }

    async fn show_on_startup(&self, _request: Request<()>) -> Result<Response<bool>, Status> {
        debug!(pkg = "grpc", "ShowOnStartup");
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.show_on_startup))
    }

    async fn set_is_autostart_on(&self, request: Request<bool>) -> Result<Response<()>, Status> {
        let mut settings = self.state.app_settings.lock().await;
        settings.is_autostart_on = request.into_inner();
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        self.emit_toggle_autostart_finished();
        Ok(Response::new(()))
    }

    async fn is_autostart_on(&self, _request: Request<()>) -> Result<Response<bool>, Status> {
        debug!(pkg = "grpc", "IsAutostartOn");
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.is_autostart_on))
    }

    async fn set_is_beta_enabled(&self, request: Request<bool>) -> Result<Response<()>, Status> {
        let mut settings = self.state.app_settings.lock().await;
        settings.is_beta_enabled = request.into_inner();
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn is_beta_enabled(&self, _request: Request<()>) -> Result<Response<bool>, Status> {
        debug!(pkg = "grpc", "IsBetaEnabled");
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.is_beta_enabled))
    }

    async fn set_is_all_mail_visible(
        &self,
        request: Request<bool>,
    ) -> Result<Response<()>, Status> {
        let mut settings = self.state.app_settings.lock().await;
        settings.is_all_mail_visible = request.into_inner();
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn is_all_mail_visible(&self, _request: Request<()>) -> Result<Response<bool>, Status> {
        debug!(pkg = "grpc", "IsAllMailVisible");
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.is_all_mail_visible))
    }

    async fn set_is_telemetry_disabled(
        &self,
        request: Request<bool>,
    ) -> Result<Response<()>, Status> {
        let mut settings = self.state.app_settings.lock().await;
        settings.is_telemetry_disabled = request.into_inner();
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn is_telemetry_disabled(&self, _request: Request<()>) -> Result<Response<bool>, Status> {
        debug!(pkg = "grpc", "IsTelemetryDisabled");
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.is_telemetry_disabled))
    }

    async fn disk_cache_path(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        debug!(pkg = "grpc", "DiskCachePath");
        let path = self.state.active_disk_cache_path.lock().await.clone();
        Ok(Response::new(path.display().to_string()))
    }

    async fn set_disk_cache_path(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let path = request.into_inner();
        if path.trim().is_empty() {
            return Err(Status::invalid_argument("disk cache path is empty"));
        }

        let target = PathBuf::from(path.trim());
        let session_manager = self.state.runtime_supervisor.session_manager();
        let current = match resolve_live_gluon_cache_root(&self.state.runtime_paths, &session_manager).await {
            Some(path) => path,
            None => self.state.active_disk_cache_path.lock().await.clone(),
        };
        if let Err(err) = move_disk_cache_payload(&current, &target).await {
            self.emit_disk_cache_error(pb::DiskCacheErrorType::CantMoveDiskCacheError);
            self.emit_disk_cache_path_change_finished();
            return Err(Status::internal(format!(
                "failed to move disk cache path: {err}"
            )));
        }

        *self.state.active_disk_cache_path.lock().await = target.clone();

        let mut settings = self.state.app_settings.lock().await;
        settings.disk_cache_path = target.display().to_string();
        if let Err(err) = save_app_settings(&self.grpc_app_settings_path(), &settings).await {
            self.emit_disk_cache_error(pb::DiskCacheErrorType::CantMoveDiskCacheError);
            self.emit_disk_cache_path_change_finished();
            return Err(Status::internal(format!(
                "failed to save app settings: {err}"
            )));
        }

        if let Err(err) = vault::save_gluon_dir(self.settings_dir(), &settings.disk_cache_path) {
            if !matches!(err, vault::VaultError::NotLoggedIn) {
                self.emit_disk_cache_error(pb::DiskCacheErrorType::CantMoveDiskCacheError);
                self.emit_disk_cache_path_change_finished();
                return Err(Status::internal(format!(
                    "failed to persist gluon cache root after disk cache move: {err}"
                )));
            }
        }

        self.emit_disk_cache_path_changed(&settings.disk_cache_path);
        self.emit_disk_cache_path_change_finished();
        self.refresh_sync_workers_for_transition("set_disk_cache_path")
            .await;
        Ok(Response::new(()))
    }

    async fn set_is_do_h_enabled(&self, request: Request<bool>) -> Result<Response<()>, Status> {
        let mut settings = self.state.app_settings.lock().await;
        settings.is_doh_enabled = request.into_inner();
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn is_do_h_enabled(&self, _request: Request<()>) -> Result<Response<bool>, Status> {
        debug!(pkg = "grpc", "IsDohEnabled");
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.is_doh_enabled))
    }

    async fn set_color_scheme_name(
        &self,
        request: Request<String>,
    ) -> Result<Response<()>, Status> {
        let name = request.into_inner();
        if name.trim().is_empty() {
            return Err(Status::invalid_argument("color scheme name is empty"));
        }
        let mut settings = self.state.app_settings.lock().await;
        settings.color_scheme_name = name;
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn color_scheme_name(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        debug!(pkg = "grpc", "ColorSchemeName");
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.color_scheme_name.clone()))
    }

    async fn current_email_client(
        &self,
        _request: Request<()>,
    ) -> Result<Response<String>, Status> {
        debug!(pkg = "grpc", "CurrentEmailClient");
        Ok(Response::new(format!(
            "{DEFAULT_EMAIL_CLIENT} ({})",
            std::env::consts::OS
        )))
    }

    async fn logs_path(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        debug!(pkg = "grpc", "LogsPath");
        let path = self.logs_dir();
        tokio::fs::create_dir_all(&path)
            .await
            .map_err(|e| Status::internal(format!("failed to create logs directory: {e}")))?;
        Ok(Response::new(path.display().to_string()))
    }

    async fn license_path(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        debug!(pkg = "grpc", "LicensePath");
        let path = resolve_license_path();
        info!(path = %path, "License file path");
        Ok(Response::new(path))
    }

    async fn release_notes_page_link(
        &self,
        _request: Request<()>,
    ) -> Result<Response<String>, Status> {
        Ok(Response::new(
            "https://github.com/ProtonMail/proton-bridge/releases".to_string(),
        ))
    }

    async fn dependency_licenses_link(
        &self,
        _request: Request<()>,
    ) -> Result<Response<String>, Status> {
        Ok(Response::new(
            "https://github.com/ProtonMail/proton-bridge/blob/master/COPYING_NOTES.md".to_string(),
        ))
    }

    async fn landing_page_link(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        Ok(Response::new("https://proton.me/mail/bridge".to_string()))
    }

    async fn report_bug(
        &self,
        request: Request<pb::ReportBugRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        tracing::warn!(
            title = %req.title,
            os_type = %req.os_type,
            os_version = %req.os_version,
            include_logs = req.include_logs,
            "bug report requested via grpc"
        );
        let service = self.clone();
        tokio::spawn(async move {
            if req.title.trim().is_empty() || req.description.trim().is_empty() {
                tracing::warn!("bug report rejected: missing title or description");
                service.emit_report_bug_error();
            } else {
                service.emit_report_bug_success();
            }
            service.emit_report_bug_finished();
        });
        Ok(Response::new(()))
    }

    async fn force_launcher(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let launcher = request.into_inner();
        let mut settings = self.state.app_settings.lock().await;
        settings.forced_launcher = launcher;
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn set_main_executable(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let executable = request.into_inner();
        debug!(pkg = "grpc", executable = %executable, "SetMainExecutable");
        let mut settings = self.state.app_settings.lock().await;
        settings.main_executable = executable;
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn request_knowledge_base_suggestions(
        &self,
        request: Request<String>,
    ) -> Result<Response<()>, Status> {
        let query = request.into_inner();
        tracing::info!(
            query = %query,
            "knowledge base suggestion request received"
        );
        let service = self.clone();
        tokio::spawn(async move {
            let trimmed = query.trim().to_string();
            if !trimmed.is_empty() {
                let encoded = trimmed.replace(' ', "+");
                service.emit_knowledge_base_suggestions(vec![pb::KnowledgeBaseSuggestion {
                    url: format!("https://proton.me/support/search?q={encoded}"),
                    title: format!("Search Proton support for \"{trimmed}\""),
                }]);
            } else {
                service.emit_knowledge_base_suggestions(Vec::new());
            }
        });
        Ok(Response::new(()))
    }

    async fn login(&self, request: Request<pb::LoginRequest>) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let username = req.username.trim().to_string();
        if username.is_empty() {
            return Err(Status::invalid_argument("username is required"));
        }

        let decoded_password = decode_login_password_bytes(req.password)
            .map_err(LoginPasswordDecodeError::into_status)?;
        let password = decoded_password.value;
        if decoded_password.used_base64_compat {
            info!(
                username = %username,
                "decoded login password through base64 compatibility path"
            );
        }
        let requested_api_mode = match req
            .api_mode
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(raw) => crate::api::types::ApiMode::from_str_name(raw).ok_or_else(|| {
                Status::invalid_argument("apiMode must be one of: bridge, webmail")
            })?,
            None => crate::api::types::ApiMode::Bridge,
        };
        let requested_scopes = if req.requested_scopes.is_empty() {
            None
        } else {
            Some(req.requested_scopes.clone())
        };
        let required_scopes = api::auth::normalize_scope_list(requested_scopes.as_deref());

        let request_use_hv_details = req.use_hv_details.unwrap_or(false);
        let request_hv_token_override = req
            .human_verification_token
            .as_deref()
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(str::to_string);
        let mut hv_details = None;
        {
            let hv_guard = self.state.pending_hv.lock().await;
            if let Some(pending_hv) = hv_guard.as_ref() {
                if !username.eq_ignore_ascii_case(&pending_hv.username) {
                    if request_use_hv_details {
                        return Err(Status::invalid_argument(
                            "username does not match pending human verification",
                        ));
                    }
                } else {
                    hv_details = Some(pending_hv.details.clone());
                    if !request_use_hv_details {
                        info!(
                            username = %username,
                            "auto-reusing pending human verification details for login retry"
                        );
                    }
                }
            } else if request_use_hv_details {
                return Err(Status::failed_precondition(
                    "no pending human verification challenge",
                ));
            }
        }

        if let Some(token_override) = request_hv_token_override {
            let Some(details) = hv_details.as_mut() else {
                return Err(Status::failed_precondition(
                    "no pending human verification challenge for provided human verification token",
                ));
            };
            details.human_verification_token = token_override;
            info!(
                username = %username,
                token_len = details.human_verification_token.len(),
                "using explicit human verification token override for login"
            );
        }

        info!(
            username = %username,
            request_use_hv_details,
            requested_scope_count = required_scopes.len(),
            using_hv_details = hv_details.is_some(),
            "starting grpc login attempt"
        );

        let mut effective_api_mode = requested_api_mode;
        let mut tried_mode_fallback = false;
        let mut client =
            ProtonClient::with_api_mode(effective_api_mode).map_err(status_from_api_error)?;
        let auth = loop {
            match api::auth::login(
                &mut client,
                &username,
                &password,
                hv_details.as_ref(),
                requested_scopes.as_deref(),
            )
            .await
            {
                Ok(auth) => break auth,
                Err(err) => {
                    if !tried_mode_fallback && matches!(&err, ApiError::Api { code: 10004, .. }) {
                        let fallback_mode = effective_api_mode.alternate();
                        warn!(
                            username = %username,
                            previous_mode = effective_api_mode.as_str(),
                            fallback_mode = fallback_mode.as_str(),
                            "grpc login mode gated by Proton, retrying with alternate mode"
                        );
                        effective_api_mode = fallback_mode;
                        tried_mode_fallback = true;
                        client = ProtonClient::with_api_mode(effective_api_mode)
                            .map_err(status_from_api_error)?;
                        continue;
                    }

                    if let Some(hv) = human_verification_details(&err) {
                        let hv_url = hv.challenge_url();
                        info!(
                            username = %username,
                            methods = ?hv.human_verification_methods,
                            "received human verification challenge from Proton"
                        );
                        let mut pending_hv = self.state.pending_hv.lock().await;
                        *pending_hv = Some(PendingHumanVerification {
                            username: username.clone(),
                            details: hv,
                        });
                        self.emit_login_error(format!(
                            "human verification required; open {hv_url}, complete CAPTCHA, then retry login"
                        ));
                    } else {
                        if matches!(&err, ApiError::Api { code: 12087, .. }) {
                            if let Some(hv) = any_human_verification_details(&err) {
                                let hv_url = hv.challenge_url();
                                let mut pending_hv = self.state.pending_hv.lock().await;
                                *pending_hv = Some(PendingHumanVerification {
                                    username: username.clone(),
                                    details: hv,
                                });
                                self.emit_login_error(format!(
                                    "captcha validation failed; open {hv_url}, complete CAPTCHA again, then retry login. \
                                     If your client can provide the `pm_captcha` token, send it as `humanVerificationToken`."
                                ));
                            } else {
                                *self.state.pending_hv.lock().await = None;
                                self.emit_login_error(
                                    "captcha validation failed; start login again to get a fresh challenge",
                                );
                            }
                        } else {
                            self.emit_login_error(err.to_string());
                        }
                        warn!(username = %username, error = %err, "grpc login failed");
                    }
                    return Err(status_from_api_error(err));
                }
            }
        };
        info!(username = %username, "grpc login auth phase completed");
        *self.state.pending_hv.lock().await = None;
        let auth_granted_scopes = api::auth::normalize_scope_string(auth.scope.as_deref());

        if auth.two_factor.requires_second_factor() {
            if auth.two_factor.totp_required() {
                info!(
                    pkg = "bridge/login",
                    user_id = %auth.uid,
                    username = %username,
                    "Requesting TOTP"
                );
            }
            let pending = PendingLogin {
                username: username.clone(),
                password,
                api_mode: effective_api_mode,
                required_scopes: required_scopes.clone(),
                auth_granted_scopes: auth_granted_scopes.clone(),
                uid: auth.uid,
                access_token: auth.access_token,
                refresh_token: auth.refresh_token,
                client,
                fido_authentication_options: auth.two_factor.fido_authentication_options(),
            };
            *self.state.pending_login.lock().await = Some(pending);
            if auth.two_factor.totp_required() {
                self.emit_login_tfa_requested(&username);
            } else if auth.two_factor.fido_supported() {
                self.emit_login_error("security key authentication required; call LoginFido");
            } else {
                self.emit_login_error("second-factor authentication required");
            }
            return Ok(Response::new(()));
        }

        if auth.requires_two_passwords()
            || self.requires_second_password(&client, &password).await?
        {
            let pending = PendingLogin {
                username: username.clone(),
                password,
                api_mode: effective_api_mode,
                required_scopes: required_scopes.clone(),
                auth_granted_scopes: auth_granted_scopes.clone(),
                uid: auth.uid,
                access_token: auth.access_token,
                refresh_token: auth.refresh_token,
                client,
                fido_authentication_options: None,
            };
            self.stage_two_password_login(pending).await;
            return Ok(Response::new(()));
        }

        let session = self
            .complete_login(
                client,
                CompleteLoginArgs {
                    api_mode: effective_api_mode,
                    uid: auth.uid,
                    access_token: auth.access_token,
                    refresh_token: auth.refresh_token,
                    username,
                    password,
                    required_scopes,
                    granted_scopes: auth_granted_scopes,
                },
            )
            .await?;
        debug!(email = %session.email, "login completed through grpc");
        Ok(Response::new(()))
    }

    async fn login2_fa(&self, request: Request<pb::LoginRequest>) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let username = req.username.trim().to_string();
        let code = String::from_utf8(req.password)
            .map_err(|_| Status::invalid_argument("2FA code must be valid utf-8"))?;

        info!(username = %username, "starting grpc 2FA submission");

        let mut pending_guard = self.state.pending_login.lock().await;
        let Some(mut pending) = pending_guard.take() else {
            return Err(Status::failed_precondition("no pending login for 2FA"));
        };

        if !username.is_empty() && !username.eq_ignore_ascii_case(&pending.username) {
            *pending_guard = Some(pending);
            return Err(Status::invalid_argument(
                "username does not match pending login",
            ));
        }

        let second_factor = match api::auth::submit_2fa(&mut pending.client, code.trim()).await {
            Ok(result) => result,
            Err(err) => {
                *pending_guard = Some(pending);
                self.emit_login_error(err.to_string());
                warn!(username = %username, error = %err, "grpc 2FA submission failed");
                return Err(status_from_api_error(err));
            }
        };
        if let Some(token) = &second_factor.access_token {
            pending.access_token = token.clone();
        }
        if let Some(token) = &second_factor.refresh_token {
            pending.refresh_token = token.clone();
        }
        if let Some(uid) = &second_factor.uid {
            pending.uid = uid.clone();
        }
        // Refresh token after 2FA to match Go bridge behavior (auto 401 retry).
        match api::auth::refresh_auth(
            &mut pending.client,
            &pending.uid,
            &pending.refresh_token,
            Some(&pending.access_token),
        )
        .await
        {
            Ok(refreshed) => {
                pending.access_token = refreshed.access_token;
                pending.refresh_token = refreshed.refresh_token;
                if !refreshed.uid.is_empty() {
                    pending.uid = refreshed.uid;
                }
            }
            Err(err) => {
                warn!(username = %username, error = %err, "post-2FA token refresh failed");
            }
        }
        info!(username = %username, "grpc 2FA submission accepted");

        drop(pending_guard);
        let granted_scopes = api::auth::normalize_scope_list(Some(&second_factor.scopes));
        let granted_scopes = if granted_scopes.is_empty() {
            pending.auth_granted_scopes.clone()
        } else {
            granted_scopes
        };

        self.complete_login(
            pending.client,
            CompleteLoginArgs {
                api_mode: pending.api_mode,
                uid: pending.uid,
                access_token: pending.access_token,
                refresh_token: pending.refresh_token,
                username: pending.username,
                password: pending.password,
                required_scopes: pending.required_scopes,
                granted_scopes,
            },
        )
        .await?;
        info!(username = %username, "grpc 2FA login flow completed");
        Ok(Response::new(()))
    }

    async fn login2_passwords(
        &self,
        request: Request<pb::LoginRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let username = req.username.trim().to_string();
        let decoded_password = decode_login_password_bytes(req.password)
            .map_err(LoginPasswordDecodeError::into_status)?;
        let password = decoded_password.value;
        if decoded_password.used_base64_compat {
            info!(
                username = %username,
                "decoded second-stage login password through base64 compatibility path"
            );
        }

        let mut pending_guard = self.state.pending_login.lock().await;
        let Some(pending) = pending_guard.take() else {
            return Err(Status::failed_precondition(
                "no pending login for second password",
            ));
        };

        if !username.is_empty() && !username.eq_ignore_ascii_case(&pending.username) {
            *pending_guard = Some(pending);
            return Err(Status::invalid_argument(
                "username does not match pending login",
            ));
        }
        drop(pending_guard);

        self.complete_login(
            pending.client,
            CompleteLoginArgs {
                api_mode: pending.api_mode,
                uid: pending.uid,
                access_token: pending.access_token,
                refresh_token: pending.refresh_token,
                username: pending.username,
                password,
                required_scopes: pending.required_scopes,
                granted_scopes: pending.auth_granted_scopes,
            },
        )
        .await?;

        Ok(Response::new(()))
    }

    async fn login_fido(&self, request: Request<pb::LoginRequest>) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let username = req.username.trim().to_string();
        if req.password.is_empty() {
            return Err(Status::invalid_argument(
                "FIDO assertion payload must not be empty",
            ));
        }

        let mut pending_guard = self.state.pending_login.lock().await;
        let Some(mut pending) = pending_guard.take() else {
            return Err(Status::failed_precondition("no pending login for FIDO"));
        };

        if !username.is_empty() && !username.eq_ignore_ascii_case(&pending.username) {
            *pending_guard = Some(pending);
            return Err(Status::invalid_argument(
                "username does not match pending login",
            ));
        }

        let Some(authentication_options) = pending.fido_authentication_options.clone() else {
            *pending_guard = Some(pending);
            return Err(Status::failed_precondition(
                "pending login has no FIDO challenge",
            ));
        };

        let second_factor = match api::auth::submit_fido_2fa(
            &mut pending.client,
            &authentication_options,
            &req.password,
        )
        .await
        {
            Ok(result) => result,
            Err(err) => {
                *pending_guard = Some(pending);
                self.emit_login_error(err.to_string());
                return Err(status_from_api_error(err));
            }
        };
        if let Some(token) = &second_factor.access_token {
            pending.access_token = token.clone();
        }
        if let Some(token) = &second_factor.refresh_token {
            pending.refresh_token = token.clone();
        }
        if let Some(uid) = &second_factor.uid {
            pending.uid = uid.clone();
        }
        // Refresh token after 2FA to match Go bridge behavior (auto 401 retry).
        match api::auth::refresh_auth(
            &mut pending.client,
            &pending.uid,
            &pending.refresh_token,
            Some(&pending.access_token),
        )
        .await
        {
            Ok(refreshed) => {
                pending.access_token = refreshed.access_token;
                pending.refresh_token = refreshed.refresh_token;
                if !refreshed.uid.is_empty() {
                    pending.uid = refreshed.uid;
                }
            }
            Err(err) => {
                warn!(username = %username, error = %err, "post-2FA FIDO token refresh failed");
            }
        }

        drop(pending_guard);
        let granted_scopes = api::auth::normalize_scope_list(Some(&second_factor.scopes));
        let granted_scopes = if granted_scopes.is_empty() {
            pending.auth_granted_scopes.clone()
        } else {
            granted_scopes
        };

        self.complete_login(
            pending.client,
            CompleteLoginArgs {
                api_mode: pending.api_mode,
                uid: pending.uid,
                access_token: pending.access_token,
                refresh_token: pending.refresh_token,
                username: pending.username,
                password: pending.password,
                required_scopes: pending.required_scopes,
                granted_scopes,
            },
        )
        .await?;

        Ok(Response::new(()))
    }

    async fn login_abort(
        &self,
        request: Request<pb::LoginAbortRequest>,
    ) -> Result<Response<()>, Status> {
        let username = request.into_inner().username;
        let mut pending = self.state.pending_login.lock().await;
        if pending
            .as_ref()
            .map(|item| username.is_empty() || item.username.eq_ignore_ascii_case(&username))
            .unwrap_or(false)
        {
            *pending = None;
            self.emit_login_error("login aborted");
        }
        drop(pending);
        if username.is_empty() {
            *self.state.pending_hv.lock().await = None;
        } else {
            let mut pending_hv = self.state.pending_hv.lock().await;
            if pending_hv
                .as_ref()
                .map(|item| item.username.eq_ignore_ascii_case(&username))
                .unwrap_or(false)
            {
                *pending_hv = None;
            }
        }
        Ok(Response::new(()))
    }

    async fn fido_assertion_abort(
        &self,
        request: Request<pb::LoginAbortRequest>,
    ) -> Result<Response<()>, Status> {
        let username = request.into_inner().username;
        let mut pending = self.state.pending_login.lock().await;
        let should_abort = pending
            .as_ref()
            .map(|item| {
                item.fido_authentication_options.is_some()
                    && (username.is_empty() || item.username.eq_ignore_ascii_case(&username))
            })
            .unwrap_or(false);
        if should_abort {
            *pending = None;
            self.emit_login_error("fido assertion aborted");
        }
        Ok(Response::new(()))
    }

    async fn get_user_list(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::UserListResponse>, Status> {
        debug!(pkg = "grpc", "GetUserList");
        let sessions = self.managed_sessions().await?;
        let mut users = Vec::with_capacity(sessions.len());
        for session in &sessions {
            let split_mode =
                vault::load_split_mode_by_account_id(self.settings_dir(), &session.uid)
                    .ok()
                    .flatten()
                    .unwrap_or(false);
            let api_data = self.fetch_user_api_data(session).await;
            users.push(session_to_user(session, split_mode, api_data.as_ref()));
        }
        Ok(Response::new(pb::UserListResponse { users }))
    }

    async fn get_user(&self, request: Request<String>) -> Result<Response<pb::User>, Status> {
        let lookup = request.into_inner();
        debug!(pkg = "grpc", userID = %lookup, "GetUser");
        let session = self.managed_session_by_lookup(&lookup).await?;
        let split_mode = vault::load_split_mode_by_account_id(self.settings_dir(), &session.uid)
            .ok()
            .flatten()
            .unwrap_or(false);
        let api_data = self.fetch_user_api_data(&session).await;
        Ok(Response::new(session_to_user(
            &session,
            split_mode,
            api_data.as_ref(),
        )))
    }

    async fn set_user_split_mode(
        &self,
        request: Request<pb::UserSplitModeRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let account_id = self.managed_session_by_lookup(&req.user_id).await?.uid;

        vault::save_split_mode_by_account_id(self.settings_dir(), &account_id, req.active)
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        self.emit_user_changed(&account_id);
        tracing::info!(
            user_id = %account_id,
            active = req.active,
            "set user split mode applied"
        );
        Ok(Response::new(()))
    }

    async fn send_bad_event_user_feedback(
        &self,
        request: Request<pb::UserBadEventFeedbackRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let session = self.managed_session_by_lookup(&req.user_id).await?;
        tracing::warn!(
            user_id = %session.uid,
            do_resync = req.do_resync,
            "user bad event feedback received"
        );

        if req.do_resync {
            self.refresh_sync_workers().await.map_err(|err| {
                Status::internal(format!("failed to refresh sync workers: {err}"))
            })?;
            return Ok(Response::new(()));
        }

        vault::remove_session_by_email(self.settings_dir(), &session.email)
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        let _ = self
            .state
            .runtime_supervisor
            .session_manager()
            .remove_session(&crate::bridge::types::AccountId(session.uid.clone()))
            .await;
        self.remove_session_access_token(&session.uid).await;
        self.emit_user_disconnected(&session.email);
        self.refresh_sync_workers_for_transition("send_bad_event_user_feedback_logout")
            .await;
        Ok(Response::new(()))
    }

    async fn logout_user(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let value = request.into_inner();
        let session = self.managed_session_by_lookup(&value).await?;

        vault::remove_session_by_email(self.settings_dir(), &session.email)
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        tracing::info!(
            pkg = "grpc/bridge",
            user_id = %session.uid,
            email = %session.email,
            "logout requested"
        );
        let _ = self
            .state
            .runtime_supervisor
            .session_manager()
            .remove_session(&crate::bridge::types::AccountId(session.uid.clone()))
            .await;
        self.remove_session_access_token(&session.uid).await;
        self.emit_user_disconnected(&session.email);
        self.refresh_sync_workers_for_transition("logout_user")
            .await;
        tracing::info!(
            pkg = "grpc/bridge",
            user_id = %session.uid,
            email = %session.email,
            "logout completed"
        );
        Ok(Response::new(()))
    }

    async fn remove_user(&self, request: Request<String>) -> Result<Response<()>, Status> {
        self.logout_user(request).await
    }

    async fn render_mutt_config(
        &self,
        request: Request<pb::RenderMuttConfigRequest>,
    ) -> Result<Response<pb::RenderMuttConfigResponse>, Status> {
        let req = request.into_inner();
        let session = if req.account_selector.trim().is_empty() {
            self.managed_sessions()
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    Status::failed_precondition(
                        "no active account found; pass account_selector or login first",
                    )
                })?
        } else {
            let selector = req.account_selector.trim();
            let sessions = self.managed_sessions().await?;
            if sessions.is_empty() {
                return Err(Status::failed_precondition("no accounts are configured"));
            }
            if let Ok(index) = selector.parse::<usize>() {
                sessions.get(index).cloned().ok_or_else(|| {
                    Status::invalid_argument(format!(
                        "account index {index} is out of range (max {})",
                        sessions.len().saturating_sub(1)
                    ))
                })?
            } else {
                sessions
                    .into_iter()
                    .find(|session| {
                        session.uid == selector
                            || session.email.eq_ignore_ascii_case(selector)
                            || session.display_name.eq_ignore_ascii_case(selector)
                    })
                    .ok_or_else(|| {
                        Status::not_found(format!("unknown account selector: {selector}"))
                    })?
            }
        };
        let settings = self.state.mail_settings.lock().await.clone();

        let account_address = if req.address_override.trim().is_empty() {
            session.email.clone()
        } else {
            req.address_override.trim().to_string()
        };

        let bridge_password = session
            .bridge_password
            .clone()
            .filter(|value| !value.trim().is_empty());
        if req.include_password && bridge_password.is_none() {
            return Err(Status::failed_precondition(format!(
                "bridge password is missing for {}; re-login to regenerate it or omit include_password",
                session.email
            )));
        }

        let imap_port = u16::try_from(settings.imap_port)
            .ok()
            .filter(|port| *port > 0)
            .ok_or_else(|| {
                Status::internal(format!(
                    "invalid IMAP port in mail settings: {}",
                    settings.imap_port
                ))
            })?;
        let smtp_port = u16::try_from(settings.smtp_port)
            .ok()
            .filter(|port| *port > 0)
            .ok_or_else(|| {
                Status::internal(format!(
                    "invalid SMTP port in mail settings: {}",
                    settings.smtp_port
                ))
            })?;

        let rendered_config = client_config::render_mutt_config(
            &client_config::MuttConfigTemplate {
                account_address,
                display_name: session.display_name,
                hostname: "127.0.0.1".to_string(),
                imap_port,
                smtp_port,
                use_ssl_for_imap: settings.use_ssl_for_imap,
                use_ssl_for_smtp: settings.use_ssl_for_smtp,
                bridge_password,
            },
            req.include_password,
        );
        Ok(Response::new(pb::RenderMuttConfigResponse {
            rendered_config,
        }))
    }

    async fn configure_user_apple_mail(
        &self,
        request: Request<pb::ConfigureAppleMailRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let session = self.managed_session_by_lookup(&req.user_id).await?;
        let requested_address = req.address.trim();
        if !requested_address.is_empty() && !session.email.eq_ignore_ascii_case(requested_address) {
            return Err(Status::invalid_argument(
                "address must match a known user address",
            ));
        }

        let mut changed_settings = None;
        {
            let mut settings = self.state.mail_settings.lock().await;
            if !settings.use_ssl_for_smtp {
                settings.use_ssl_for_smtp = true;
                save_mail_settings(&self.grpc_mail_settings_path(), &settings)
                    .await
                    .map_err(|e| Status::internal(format!("failed to save mail settings: {e}")))?;
                changed_settings = Some(settings.clone());
            }
        }
        if let Some(settings) = changed_settings.as_ref() {
            self.emit_mail_settings_changed(settings);
        }

        tracing::info!(
            user_id = %session.uid,
            address = %if requested_address.is_empty() {
                session.email.as_str()
            } else {
                requested_address
            },
            "configure user apple mail requested; automatic platform integration is unavailable"
        );
        Err(Status::unimplemented(
            "Apple Mail auto-configuration is not implemented",
        ))
    }

    async fn check_update(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        self.emit_update_is_latest_version();
        self.emit_update_check_finished();
        Ok(Response::new(()))
    }

    async fn install_update(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        tracing::info!("install update requested; triggering controlled shutdown");
        let _ = self.state.shutdown_tx.send(true);
        Ok(Response::new(()))
    }

    async fn set_is_automatic_update_on(
        &self,
        request: Request<bool>,
    ) -> Result<Response<()>, Status> {
        let mut settings = self.state.app_settings.lock().await;
        settings.is_automatic_update_on = request.into_inner();
        save_app_settings(&self.grpc_app_settings_path(), &settings)
            .await
            .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
        Ok(Response::new(()))
    }

    async fn is_automatic_update_on(
        &self,
        _request: Request<()>,
    ) -> Result<Response<bool>, Status> {
        debug!(pkg = "grpc", "IsAutomaticUpdateOn");
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.is_automatic_update_on))
    }

    async fn available_keychains(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::AvailableKeychainsResponse>, Status> {
        debug!(pkg = "grpc", "AvailableKeychains");
        let keychains = available_keychain_helpers();
        Ok(Response::new(pb::AvailableKeychainsResponse { keychains }))
    }

    async fn set_current_keychain(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let keychain = request.into_inner();
        let available = available_keychain_helpers();
        self.set_current_keychain_with_available(&keychain, &available)
            .await?;
        Ok(Response::new(()))
    }

    async fn current_keychain(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        debug!(pkg = "grpc", "CurrentKeychain");
        if let Some(helper) = vault::get_keychain_helper(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?
        {
            return Ok(Response::new(helper));
        }
        let settings = self.state.app_settings.lock().await;
        Ok(Response::new(settings.current_keychain.clone()))
    }

    async fn mail_server_settings(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::ImapSmtpSettings>, Status> {
        debug!(pkg = "grpc", "ConnectionMode");
        let settings = self.state.mail_settings.lock().await.clone();
        Ok(Response::new(pb::ImapSmtpSettings {
            imap_port: settings.imap_port,
            smtp_port: settings.smtp_port,
            use_ssl_for_imap: settings.use_ssl_for_imap,
            use_ssl_for_smtp: settings.use_ssl_for_smtp,
        }))
    }

    async fn set_mail_server_settings(
        &self,
        request: Request<pb::ImapSmtpSettings>,
    ) -> Result<Response<()>, Status> {
        let incoming = request.into_inner();
        if let Some(status) = validate_port(incoming.imap_port) {
            return Err(status);
        }
        if let Some(status) = validate_port(incoming.smtp_port) {
            return Err(status);
        }

        let mut settings = self.state.mail_settings.lock().await;
        let previous = settings.clone();
        let next = StoredMailSettings {
            imap_port: incoming.imap_port,
            smtp_port: incoming.smtp_port,
            use_ssl_for_imap: incoming.use_ssl_for_imap,
            use_ssl_for_smtp: incoming.use_ssl_for_smtp,
            imap_read_backend: previous.imap_read_backend,
            pim_reconcile_tick_secs: previous.pim_reconcile_tick_secs,
            pim_contacts_reconcile_secs: previous.pim_contacts_reconcile_secs,
            pim_calendar_reconcile_secs: previous.pim_calendar_reconcile_secs,
            pim_calendar_horizon_reconcile_secs: previous.pim_calendar_horizon_reconcile_secs,
        };
        *settings = next.clone();
        save_mail_settings(&self.grpc_mail_settings_path(), &next)
            .await
            .map_err(|e| Status::internal(format!("failed to save mail settings: {e}")))?;
        drop(settings);

        if let Err(err) = self
            .apply_mail_runtime_settings_change(previous.clone(), next.clone())
            .await
        {
            let mut rollback_settings = self.state.mail_settings.lock().await;
            *rollback_settings = previous.clone();
            save_mail_settings(&self.grpc_mail_settings_path(), &previous)
                .await
                .map_err(|e| Status::internal(format!("failed to rollback mail settings: {e}")))?;
            return Err(err);
        }

        self.emit_mail_settings_changed(&next);
        self.emit_mail_settings_finished();

        Ok(Response::new(()))
    }

    async fn hostname(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        debug!(pkg = "grpc", "Hostname");
        Ok(Response::new(self.state.bind_host.clone()))
    }

    async fn is_port_free(&self, request: Request<i32>) -> Result<Response<bool>, Status> {
        let port = request.into_inner();
        if !(1..=65535).contains(&port) {
            return Ok(Response::new(false));
        }
        Ok(Response::new(is_port_free(port as u16).await))
    }

    async fn pim_list_contacts(
        &self,
        request: Request<pb::PimListContactsRequest>,
    ) -> Result<Response<pb::PimContactListResponse>, Status> {
        let req = request.into_inner();
        let store = self.resolve_pim_store_for_account_selector(&req.account_id).await?;
        let contacts = store
            .list_contacts(req.include_deleted, to_pim_page(req.page))
            .map_err(|err| Status::internal(format!("failed to list contacts: {err}")))?;
        Ok(Response::new(pb::PimContactListResponse {
            contacts: contacts.into_iter().map(to_pb_pim_contact).collect(),
        }))
    }

    async fn pim_get_contact(
        &self,
        request: Request<pb::PimGetContactRequest>,
    ) -> Result<Response<pb::PimContact>, Status> {
        let req = request.into_inner();
        if req.contact_id.trim().is_empty() {
            return Err(Status::invalid_argument("contactID is required"));
        }

        let store = self.resolve_pim_store_for_account_selector(&req.account_id).await?;
        let contact = store
            .get_contact(req.contact_id.as_str(), req.include_deleted)
            .map_err(|err| Status::internal(format!("failed to get contact: {err}")))?;
        let Some(contact) = contact else {
            return Err(Status::not_found(format!(
                "contact not found: {}",
                req.contact_id
            )));
        };
        Ok(Response::new(to_pb_pim_contact(contact)))
    }

    async fn pim_search_contacts_by_email(
        &self,
        request: Request<pb::PimSearchContactsByEmailRequest>,
    ) -> Result<Response<pb::PimContactListResponse>, Status> {
        let req = request.into_inner();
        if req.email_like.trim().is_empty() {
            return Err(Status::invalid_argument("emailLike is required"));
        }

        let store = self.resolve_pim_store_for_account_selector(&req.account_id).await?;
        let contacts = store
            .search_contacts_by_email(req.email_like.as_str(), to_pim_page(req.page))
            .map_err(|err| Status::internal(format!("failed to search contacts: {err}")))?;
        Ok(Response::new(pb::PimContactListResponse {
            contacts: contacts.into_iter().map(to_pb_pim_contact).collect(),
        }))
    }

    async fn pim_list_calendars(
        &self,
        request: Request<pb::PimListCalendarsRequest>,
    ) -> Result<Response<pb::PimCalendarListResponse>, Status> {
        let req = request.into_inner();
        let store = self.resolve_pim_store_for_account_selector(&req.account_id).await?;
        let calendars = store
            .list_calendars(req.include_deleted, to_pim_page(req.page))
            .map_err(|err| Status::internal(format!("failed to list calendars: {err}")))?;
        Ok(Response::new(pb::PimCalendarListResponse {
            calendars: calendars.into_iter().map(to_pb_pim_calendar).collect(),
        }))
    }

    async fn pim_get_calendar(
        &self,
        request: Request<pb::PimGetCalendarRequest>,
    ) -> Result<Response<pb::PimCalendar>, Status> {
        let req = request.into_inner();
        if req.calendar_id.trim().is_empty() {
            return Err(Status::invalid_argument("calendarID is required"));
        }

        let store = self.resolve_pim_store_for_account_selector(&req.account_id).await?;
        let calendar = store
            .get_calendar(req.calendar_id.as_str(), req.include_deleted)
            .map_err(|err| Status::internal(format!("failed to get calendar: {err}")))?;
        let Some(calendar) = calendar else {
            return Err(Status::not_found(format!(
                "calendar not found: {}",
                req.calendar_id
            )));
        };
        Ok(Response::new(to_pb_pim_calendar(calendar)))
    }

    async fn pim_list_calendar_events(
        &self,
        request: Request<pb::PimListCalendarEventsRequest>,
    ) -> Result<Response<pb::PimCalendarEventListResponse>, Status> {
        let req = request.into_inner();
        if req.calendar_id.trim().is_empty() {
            return Err(Status::invalid_argument("calendarID is required"));
        }
        if let (Some(start), Some(end)) = (req.start_time_from, req.start_time_to) {
            if start > end {
                return Err(Status::invalid_argument(
                    "startTimeFrom must be <= startTimeTo",
                ));
            }
        }

        let store = self.resolve_pim_store_for_account_selector(&req.account_id).await?;
        let events = store
            .list_calendar_events(
                req.calendar_id.as_str(),
                req.include_deleted,
                crate::pim::query::CalendarEventRange {
                    start_time_from: req.start_time_from,
                    start_time_to: req.start_time_to,
                },
                to_pim_page(req.page),
            )
            .map_err(|err| Status::internal(format!("failed to list calendar events: {err}")))?;
        Ok(Response::new(pb::PimCalendarEventListResponse {
            events: events.into_iter().map(to_pb_pim_calendar_event).collect(),
        }))
    }

    async fn pim_upsert_contact(
        &self,
        request: Request<pb::PimUpsertContactRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let Some(contact) = req.contact else {
            return Err(Status::invalid_argument("contact is required"));
        };
        if contact.id.trim().is_empty() {
            return Err(Status::invalid_argument("contact.id is required"));
        }
        let api_contact = to_api_contact(contact, req.emails, req.cards);
        let store = self.resolve_pim_store_for_account_selector(&req.account_id).await?;
        self.ensure_expected_contact_updated_at(
            &store,
            api_contact.metadata.id.as_str(),
            req.expected_updated_at_ms,
        )?;
        store
            .upsert_contact(&api_contact)
            .map_err(|err| Status::internal(format!("failed to upsert contact: {err}")))?;
        Ok(Response::new(()))
    }

    async fn pim_delete_contact(
        &self,
        request: Request<pb::PimDeleteContactRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        if req.contact_id.trim().is_empty() {
            return Err(Status::invalid_argument("contactID is required"));
        }
        let store = self.resolve_pim_store_for_account_selector(&req.account_id).await?;
        self.ensure_expected_contact_updated_at(
            &store,
            req.contact_id.as_str(),
            req.expected_updated_at_ms,
        )?;
        let result = if req.hard_delete {
            store.hard_delete_contact(req.contact_id.as_str())
        } else {
            store.soft_delete_contact(req.contact_id.as_str())
        };
        result.map_err(|err| Status::internal(format!("failed to delete contact: {err}")))?;
        Ok(Response::new(()))
    }

    async fn pim_upsert_calendar(
        &self,
        request: Request<pb::PimUpsertCalendarRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let Some(calendar) = req.calendar else {
            return Err(Status::invalid_argument("calendar is required"));
        };
        if calendar.id.trim().is_empty() {
            return Err(Status::invalid_argument("calendar.id is required"));
        }
        let api_calendar = to_api_calendar(calendar);
        let store = self.resolve_pim_store_for_account_selector(&req.account_id).await?;
        self.ensure_expected_calendar_updated_at(
            &store,
            api_calendar.id.as_str(),
            req.expected_updated_at_ms,
        )?;
        store
            .upsert_calendar(&api_calendar)
            .map_err(|err| Status::internal(format!("failed to upsert calendar: {err}")))?;
        Ok(Response::new(()))
    }

    async fn pim_delete_calendar(
        &self,
        request: Request<pb::PimDeleteCalendarRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        if req.calendar_id.trim().is_empty() {
            return Err(Status::invalid_argument("calendarID is required"));
        }
        let store = self.resolve_pim_store_for_account_selector(&req.account_id).await?;
        self.ensure_expected_calendar_updated_at(
            &store,
            req.calendar_id.as_str(),
            req.expected_updated_at_ms,
        )?;
        let result = if req.hard_delete {
            store.hard_delete_calendar(req.calendar_id.as_str())
        } else {
            store.soft_delete_calendar(req.calendar_id.as_str())
        };
        result.map_err(|err| Status::internal(format!("failed to delete calendar: {err}")))?;
        Ok(Response::new(()))
    }

    async fn pim_upsert_calendar_event(
        &self,
        request: Request<pb::PimUpsertCalendarEventRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let Some(event) = req.event else {
            return Err(Status::invalid_argument("event is required"));
        };
        if event.id.trim().is_empty() {
            return Err(Status::invalid_argument("event.id is required"));
        }
        if event.calendar_id.trim().is_empty() {
            return Err(Status::invalid_argument("event.calendarID is required"));
        }
        let api_event = to_api_calendar_event(event);
        let store = self.resolve_pim_store_for_account_selector(&req.account_id).await?;
        self.ensure_expected_calendar_event_updated_at(
            &store,
            api_event.id.as_str(),
            req.expected_updated_at_ms,
        )?;
        store
            .upsert_calendar_event(&api_event)
            .map_err(|err| Status::internal(format!("failed to upsert calendar event: {err}")))?;
        Ok(Response::new(()))
    }

    async fn pim_delete_calendar_event(
        &self,
        request: Request<pb::PimDeleteCalendarEventRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        if req.event_id.trim().is_empty() {
            return Err(Status::invalid_argument("eventID is required"));
        }
        let store = self.resolve_pim_store_for_account_selector(&req.account_id).await?;
        self.ensure_expected_calendar_event_updated_at(
            &store,
            req.event_id.as_str(),
            req.expected_updated_at_ms,
        )?;
        let result = if req.hard_delete {
            store.hard_delete_calendar_event(req.event_id.as_str())
        } else {
            store.soft_delete_calendar_event(req.event_id.as_str())
        };
        result
            .map_err(|err| Status::internal(format!("failed to delete calendar event: {err}")))?;
        Ok(Response::new(()))
    }

    async fn pim_reconcile_metrics(
        &self,
        _request: Request<()>,
    ) -> Result<Response<pb::PimReconcileMetricsResponse>, Status> {
        let runtime_running = self.state.runtime_supervisor.is_running().await;
        let snapshot = self
            .state
            .runtime_supervisor
            .pim_reconcile_metrics()
            .await
            .unwrap_or_default();
        Ok(Response::new(pb::PimReconcileMetricsResponse {
            runtime_running,
            sweeps_total: snapshot.sweeps_total,
            last_sweep_elapsed_ms: snapshot.last_sweep_elapsed_ms,
            last_sweep_completed_at_ms: snapshot.last_sweep_completed_at_ms,
            accounts_seen_total: snapshot.accounts_seen_total,
            accounts_with_store_total: snapshot.accounts_with_store_total,
            accounts_skipped_no_session_total: snapshot.accounts_skipped_no_session_total,
            client_init_failures_total: snapshot.client_init_failures_total,
            contacts_runs_due_total: snapshot.contacts_runs_due_total,
            contacts_success_total: snapshot.contacts_success_total,
            contacts_failures_total: snapshot.contacts_failures_total,
            calendar_full_runs_due_total: snapshot.calendar_full_runs_due_total,
            calendar_full_success_total: snapshot.calendar_full_success_total,
            calendar_full_failures_total: snapshot.calendar_full_failures_total,
            calendar_horizon_runs_due_total: snapshot.calendar_horizon_runs_due_total,
            calendar_horizon_success_total: snapshot.calendar_horizon_success_total,
            calendar_horizon_failures_total: snapshot.calendar_horizon_failures_total,
            contacts_rows_upserted_total: snapshot.contacts_rows_upserted_total,
            contacts_rows_soft_deleted_total: snapshot.contacts_rows_soft_deleted_total,
            calendar_rows_upserted_total: snapshot.calendar_rows_upserted_total,
            calendar_rows_soft_deleted_total: snapshot.calendar_rows_soft_deleted_total,
        }))
    }

    async fn is_tls_certificate_installed(
        &self,
        _request: Request<()>,
    ) -> Result<Response<bool>, Status> {
        let installed = is_mail_tls_certificate_installed(self.settings_dir())
            .await
            .map_err(|e| {
                Status::internal(format!("failed to check TLS certificate status: {e}"))
            })?;
        Ok(Response::new(installed))
    }

    async fn install_tls_certificate(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        install_mail_tls_certificate(self.settings_dir())
            .await
            .map_err(|e| Status::internal(format!("failed to install TLS certificate: {e}")))?;
        Ok(Response::new(()))
    }

    async fn export_tls_certificates(
        &self,
        request: Request<String>,
    ) -> Result<Response<()>, Status> {
        let output_dir = request.into_inner();
        if output_dir.trim().is_empty() {
            return Err(Status::invalid_argument("output folder is required"));
        }

        ensure_mail_tls_certificate(self.settings_dir())
            .await
            .map_err(|e| Status::internal(format!("failed to ensure TLS certificate: {e}")))?;

        let (cert_path, key_path) = mail_cert_paths(self.settings_dir());
        let cert_bytes = tokio::fs::read(cert_path)
            .await
            .map_err(|e| Status::internal(format!("failed to read cert: {e}")))?;
        let key_bytes = tokio::fs::read(key_path)
            .await
            .map_err(|e| Status::internal(format!("failed to read key: {e}")))?;

        let target = PathBuf::from(output_dir);
        tokio::fs::create_dir_all(&target)
            .await
            .map_err(|e| Status::internal(format!("failed to create output folder: {e}")))?;
        tokio::fs::write(target.join("cert.pem"), cert_bytes)
            .await
            .map_err(|e| Status::internal(format!("failed to write cert: {e}")))?;
        tokio::fs::write(target.join("key.pem"), key_bytes)
            .await
            .map_err(|e| Status::internal(format!("failed to write key: {e}")))?;

        Ok(Response::new(()))
    }

    type RunEventStreamStream =
        Pin<Box<dyn Stream<Item = Result<pb::StreamEvent, Status>> + Send + 'static>>;

    async fn run_event_stream(
        &self,
        _request: Request<pb::EventStreamRequest>,
    ) -> Result<Response<Self::RunEventStreamStream>, Status> {
        debug!(pkg = "grpc", "Starting Event stream");
        let mut active = self.state.active_stream_stop.lock().await;
        if active.is_some() {
            return Err(Status::already_exists("the service is already streaming"));
        }

        let (stop_tx, mut stop_rx) = watch::channel(false);
        *active = Some(stop_tx);
        drop(active);

        let (mut rx, buffered_events) = {
            let backlog = self
                .state
                .event_backlog
                .lock()
                .map_err(|_| Status::internal("event backlog lock poisoned"))?;
            let buffered = backlog.iter().cloned().collect::<Vec<_>>();
            let rx = self.state.event_tx.subscribe();
            (rx, buffered)
        };
        let (out_tx, out_rx) = mpsc::channel::<Result<pb::StreamEvent, Status>>(32);
        let state = self.state.clone();
        let service = self.clone();

        tokio::spawn(async move {
            for buffered in buffered_events {
                if out_tx.send(Ok(buffered)).await.is_err() {
                    let mut active = state.active_stream_stop.lock().await;
                    *active = None;
                    return;
                }
            }
            loop {
                tokio::select! {
                    _ = out_tx.closed() => {
                        break;
                    }
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                    recv = rx.recv() => {
                        match recv {
                            Ok(event) => {
                                if out_tx.send(Ok(event)).await.is_err() {
                                    break;
                                }
                            }
                            Err(err @ tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                handle_stream_recv_error(&service, err);
                            }
                            Err(err @ tokio::sync::broadcast::error::RecvError::Closed) => {
                                handle_stream_recv_error(&service, err);
                                break;
                            }
                        }
                    }
                }
            }
            let mut active = state.active_stream_stop.lock().await;
            *active = None;
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(out_rx))))
    }

    async fn stop_event_stream(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        let active = self.state.active_stream_stop.lock().await;
        let Some(stop_tx) = active.as_ref() else {
            return Err(Status::not_found("the service is not streaming"));
        };
        let _ = stop_tx.send(true);
        Ok(Response::new(()))
    }

    async fn version(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        debug!(pkg = "grpc", "Version");
        Ok(Response::new(env!("CARGO_PKG_VERSION").to_string()))
    }

    async fn go_os(&self, _request: Request<()>) -> Result<Response<String>, Status> {
        debug!(pkg = "grpc", "GoOs");
        Ok(Response::new(std::env::consts::OS.to_string()))
    }

    async fn quit(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        self.stop_mail_runtime_for_transition("quit").await;
        let _ = self.state.shutdown_tx.send(true);
        Ok(Response::new(()))
    }
}

#[cfg(test)]
mod grpc_wire_tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn build_test_service(vault_dir: PathBuf) -> BridgeService {
        let runtime_paths = RuntimePaths::resolve(Some(&vault_dir)).expect("runtime paths");
        let app_settings = StoredAppSettings::with_defaults_for(&runtime_paths.disk_cache_dir());
        let active_disk_cache_path = effective_disk_cache_path(&app_settings, &runtime_paths);
        let (event_tx, _) = broadcast::channel(16);
        let (shutdown_tx, _) = watch::channel(false);
        let state = Arc::new(GrpcState {
            runtime_supervisor: Arc::new(bridge::runtime_supervisor::RuntimeSupervisor::new(
                runtime_paths.clone(),
            )),
            runtime_paths,
            bind_host: "127.0.0.1".to_string(),
            active_disk_cache_path: Mutex::new(active_disk_cache_path),
            event_tx,
            event_backlog: std::sync::Mutex::new(VecDeque::new()),
            active_stream_stop: Mutex::new(None),
            pending_login: Mutex::new(None),
            pending_hv: Mutex::new(None),
            session_access_tokens: Mutex::new(HashMap::new()),
            shutdown_tx,
            mail_settings: Mutex::new(StoredMailSettings::default()),
            mail_runtime_transition_lock: Mutex::new(()),
            app_settings: Mutex::new(app_settings),
            sync_workers_enabled: false,
            sync_event_workers: Mutex::new(None),
        });
        BridgeService::new(state)
    }

    #[test]
    fn grpc_wire_password_decode_accepts_utf8_and_base64_payload() {
        let plain = decode_login_password_bytes(b"plain-password".to_vec()).expect("plain decode");
        assert_eq!(plain.value, "plain-password");
        assert!(!plain.used_base64_compat);

        let compat =
            decode_login_password_bytes(b"c2Vjb25kLXBhc3M=".to_vec()).expect("base64 decode");
        assert_eq!(compat.value, "second-pass");
        assert!(compat.used_base64_compat);
    }

    #[tokio::test]
    async fn grpc_wire_login2_passwords_requires_pending_login() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = build_test_service(dir.path().to_path_buf());

        let utf8_status = <BridgeService as pb::bridge_server::Bridge>::login2_passwords(
            &service,
            Request::new(pb::LoginRequest {
                username: "alice@example.com".to_string(),
                password: b"mailbox-secret".to_vec(),
                use_hv_details: None,
                human_verification_token: None,
                api_mode: None,
                requested_scopes: Vec::new(),
            }),
        )
        .await
        .expect_err("missing pending login should fail");
        assert_eq!(utf8_status.code(), tonic::Code::FailedPrecondition);
        assert!(utf8_status.message().contains("no pending login"));

        let b64_status = <BridgeService as pb::bridge_server::Bridge>::login2_passwords(
            &service,
            Request::new(pb::LoginRequest {
                username: "alice@example.com".to_string(),
                password: b"bWFpbGJveC1zZWNyZXQ=".to_vec(),
                use_hv_details: None,
                human_verification_token: None,
                api_mode: None,
                requested_scopes: Vec::new(),
            }),
        )
        .await
        .expect_err("missing pending login should fail");
        assert_eq!(b64_status.code(), tonic::Code::FailedPrecondition);
        assert!(b64_status.message().contains("no pending login"));
    }

    #[tokio::test]
    async fn grpc_wire_two_password_stage_emits_event_and_completes_login() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/core/v4/users"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000,
                "User": {
                    "ID": "user-1",
                    "Name": "alice",
                    "DisplayName": "Alice",
                    "Email": "alice@example.com",
                    "Keys": [{
                        "ID": "key-1",
                        "PrivateKey": "unused",
                        "Active": 1
                    }]
                }
            })))
            .mount(&server)
            .await;

        let key_salt = BASE64.encode([7u8; 16]);
        Mock::given(method("GET"))
            .and(path("/core/v4/keys/salts"))
            .and(header("x-pm-uid", "uid-1"))
            .and(header("Authorization", "Bearer access-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "Code": 1000,
                "KeySalts": [{
                    "ID": "key-1",
                    "KeySalt": key_salt,
                }]
            })))
            .mount(&server)
            .await;

        let pending_client = ProtonClient::authenticated_with_mode(
            &server.uri(),
            crate::api::types::ApiMode::Bridge,
            "uid-1",
            "access-1",
        )
        .expect("pending client");

        service
            .stage_two_password_login(PendingLogin {
                username: "alice@example.com".to_string(),
                password: "account-secret".to_string(),
                api_mode: crate::api::types::ApiMode::Bridge,
                required_scopes: Vec::new(),
                auth_granted_scopes: vec!["mail".to_string()],
                uid: "uid-1".to_string(),
                access_token: "access-1".to_string(),
                refresh_token: "refresh-1".to_string(),
                client: pending_client,
                fido_authentication_options: None,
            })
            .await;

        <BridgeService as pb::bridge_server::Bridge>::login2_passwords(
            &service,
            Request::new(pb::LoginRequest {
                username: "alice@example.com".to_string(),
                password: b"bWFpbGJveC1zZWNyZXQ=".to_vec(),
                use_hv_details: None,
                human_verification_token: None,
                api_mode: None,
                requested_scopes: Vec::new(),
            }),
        )
        .await
        .expect("second-stage login should succeed");

        let first = events.recv().await.expect("first event");
        match first.event {
            Some(pb::stream_event::Event::Login(pb::LoginEvent {
                event: Some(pb::login_event::Event::TwoPasswordRequested(event)),
            })) => assert_eq!(event.username, "alice@example.com"),
            other => panic!("unexpected first event: {other:?}"),
        }

        let second = events.recv().await.expect("second event");
        match second.event {
            Some(pb::stream_event::Event::Login(pb::LoginEvent {
                event: Some(pb::login_event::Event::Finished(event)),
            })) => assert_eq!(event.user_id, "uid-1"),
            other => panic!("unexpected second event: {other:?}"),
        }

        let third = events.recv().await.expect("third event");
        match third.event {
            Some(pb::stream_event::Event::User(pb::UserEvent {
                event: Some(pb::user_event::Event::UserChanged(event)),
            })) => assert_eq!(event.user_id, "uid-1"),
            other => panic!("unexpected third event: {other:?}"),
        }

        let session = vault::load_session_by_account_id(service.settings_dir(), "uid-1")
            .expect("saved session");
        let expected_passphrase = api::srp::salt_for_key(
            b"mailbox-secret",
            "key-1",
            &[crate::api::types::KeySalt {
                id: "key-1".to_string(),
                key_salt: Some(BASE64.encode([7u8; 16])),
            }],
        )
        .expect("derive expected passphrase");
        assert_eq!(
            session.key_passphrase,
            Some(BASE64.encode(expected_passphrase))
        );
    }

    #[tokio::test]
    async fn grpc_wire_lagged_stream_emits_generic_error_event() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = build_test_service(dir.path().to_path_buf());
        let mut events = service.state.event_tx.subscribe();

        handle_stream_recv_error(
            &service,
            tokio::sync::broadcast::error::RecvError::Lagged(4),
        );

        let emitted = events.recv().await.expect("lagged event emission");
        match emitted.event {
            Some(pb::stream_event::Event::GenericError(event)) => {
                assert_eq!(event.code, pb::ErrorCode::UnknownError as i32);
            }
            other => panic!("unexpected lagged event payload: {other:?}"),
        }
    }
}
