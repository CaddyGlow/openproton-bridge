struct CompleteLoginArgs {
    api_mode: crate::api::types::ApiMode,
    uid: String,
    access_token: String,
    refresh_token: String,
    username: String,
    password: String,
    required_scopes: Vec<String>,
    granted_scopes: Vec<String>,
}

impl BridgeService {
    fn new(state: Arc<GrpcState>) -> Self {
        Self { state }
    }

    fn settings_dir(&self) -> &Path {
        self.state.runtime_paths.settings_dir()
    }

    fn logs_dir(&self) -> PathBuf {
        self.state.runtime_paths.logs_dir()
    }

    fn grpc_mail_settings_path(&self) -> PathBuf {
        self.state.runtime_paths.grpc_mail_settings_path()
    }

    fn grpc_app_settings_path(&self) -> PathBuf {
        self.state.runtime_paths.grpc_app_settings_path()
    }

    fn mail_runtime_config_from_settings(
        &self,
        settings: &StoredMailSettings,
    ) -> anyhow::Result<bridge::mail_runtime::MailRuntimeConfig> {
        let imap_port = u16::try_from(settings.imap_port).with_context(|| {
            format!("invalid IMAP port in grpc settings: {}", settings.imap_port)
        })?;
        let smtp_port = u16::try_from(settings.smtp_port).with_context(|| {
            format!("invalid SMTP port in grpc settings: {}", settings.smtp_port)
        })?;
        Ok(bridge::mail_runtime::MailRuntimeConfig {
            bind_host: self.state.bind_host.clone(),
            imap_port,
            smtp_port,
            dav_enable: false,
            dav_port: 8080,
            dav_tls_mode: bridge::mail_runtime::DavTlsMode::None,
            disable_tls: false,
            use_ssl_for_imap: settings.use_ssl_for_imap,
            use_ssl_for_smtp: settings.use_ssl_for_smtp,
            event_poll_interval: std::time::Duration::from_secs(30),
            pim_reconcile_tick_interval: std::time::Duration::from_secs(
                settings.pim_reconcile_tick_secs as u64,
            ),
            pim_contacts_reconcile_interval: std::time::Duration::from_secs(
                settings.pim_contacts_reconcile_secs as u64,
            ),
            pim_calendar_reconcile_interval: std::time::Duration::from_secs(
                settings.pim_calendar_reconcile_secs as u64,
            ),
            pim_calendar_horizon_reconcile_interval: std::time::Duration::from_secs(
                settings.pim_calendar_horizon_reconcile_secs as u64,
            ),
        })
    }

    async fn start_mail_runtime_with_settings(
        &self,
        settings: &StoredMailSettings,
        transition: bridge::mail_runtime::MailRuntimeTransition,
    ) -> Result<(), bridge::mail_runtime::MailRuntimeStartError> {
        let config = self
            .mail_runtime_config_from_settings(settings)
            .map_err(bridge::mail_runtime::MailRuntimeStartError::Prepare)?;
        self.state
            .runtime_supervisor
            .start(config, transition, None)
            .await
    }

    fn log_startup_mail_runtime_error(
        &self,
        settings: &StoredMailSettings,
        err: &bridge::mail_runtime::MailRuntimeStartError,
    ) {
        match err.protocol() {
            Some(bridge::mail_runtime::MailProtocol::Imap) => {
                warn!(
                    pkg = "grpc/bridge",
                    transition = "startup",
                    port = settings.imap_port,
                    ssl = settings.use_ssl_for_imap,
                    error = %err,
                    "Failed to start IMAP server on bridge start"
                );
                self.emit_mail_settings_error(
                    pb::MailServerSettingsErrorType::ImapPortStartupError,
                );
            }
            Some(bridge::mail_runtime::MailProtocol::Smtp) => {
                warn!(
                    pkg = "grpc/bridge",
                    transition = "startup",
                    port = settings.smtp_port,
                    ssl = settings.use_ssl_for_smtp,
                    error = %err,
                    "Failed to start SMTP server on bridge start"
                );
                self.emit_mail_settings_error(
                    pb::MailServerSettingsErrorType::SmtpPortStartupError,
                );
            }
            Some(bridge::mail_runtime::MailProtocol::Dav) => {
                warn!(
                    pkg = "grpc/bridge",
                    transition = "startup",
                    error = %err,
                    "Failed to start DAV server on bridge start"
                );
            }
            None => {
                warn!(
                    pkg = "grpc/bridge",
                    transition = "startup",
                    error = %err,
                    "failed to start grpc mail runtime"
                );
            }
        }
    }

    fn emit_mail_runtime_change_error(
        &self,
        settings: &StoredMailSettings,
        err: &bridge::mail_runtime::MailRuntimeStartError,
    ) {
        match err.protocol() {
            Some(bridge::mail_runtime::MailProtocol::Imap) => {
                warn!(
                    pkg = "grpc/bridge",
                    transition = "settings_change",
                    port = settings.imap_port,
                    ssl = settings.use_ssl_for_imap,
                    error = %err,
                    "failed to restart IMAP server after settings change"
                );
                self.emit_mail_settings_error(pb::MailServerSettingsErrorType::ImapPortChangeError);
            }
            Some(bridge::mail_runtime::MailProtocol::Smtp) => {
                warn!(
                    pkg = "grpc/bridge",
                    transition = "settings_change",
                    port = settings.smtp_port,
                    ssl = settings.use_ssl_for_smtp,
                    error = %err,
                    "failed to restart SMTP server after settings change"
                );
                self.emit_mail_settings_error(pb::MailServerSettingsErrorType::SmtpPortChangeError);
            }
            Some(bridge::mail_runtime::MailProtocol::Dav) => {
                warn!(
                    pkg = "grpc/bridge",
                    transition = "settings_change",
                    error = %err,
                    "failed to restart DAV server after settings change"
                );
            }
            None => {
                warn!(
                    pkg = "grpc/bridge",
                    transition = "settings_change",
                    error = %err,
                    "failed to restart grpc mail runtime after settings change"
                );
            }
        }
    }

    async fn stop_mail_runtime_locked(&self, transition: &'static str) {
        if self.state.runtime_supervisor.is_running().await {
            info!(
                pkg = "grpc/bridge",
                transition, "stopping grpc mail runtime"
            );
            if let Err(err) = self.state.runtime_supervisor.stop(transition).await {
                warn!(
                    pkg = "grpc/bridge",
                    transition,
                    error = %err,
                    "failed to stop grpc mail runtime cleanly"
                );
            }
        }
    }

    async fn stop_mail_runtime_for_transition(&self, transition: &'static str) {
        let _guard = self.state.mail_runtime_transition_lock.lock().await;
        self.stop_mail_runtime_locked(transition).await;
    }

    async fn start_mail_runtime_on_startup(&self) {
        let _guard = self.state.mail_runtime_transition_lock.lock().await;
        let settings = self.state.mail_settings.lock().await.clone();

        let imap_port = u16::try_from(settings.imap_port).ok();
        let smtp_port = u16::try_from(settings.smtp_port).ok();
        let mut startup_conflict = false;

        if let Some(imap_port) = imap_port {
            if !is_bind_port_free(&self.state.bind_host, imap_port).await {
                startup_conflict = true;
                self.log_startup_mail_runtime_error(
                    &settings,
                    &bridge::mail_runtime::MailRuntimeStartError::ImapBind {
                        addr: format!("{}:{imap_port}", self.state.bind_host),
                        source: std::io::Error::new(
                            std::io::ErrorKind::AddrInUse,
                            "IMAP port already in use",
                        ),
                    },
                );
            }
        }
        if let Some(smtp_port) = smtp_port {
            if !is_bind_port_free(&self.state.bind_host, smtp_port).await {
                startup_conflict = true;
                self.log_startup_mail_runtime_error(
                    &settings,
                    &bridge::mail_runtime::MailRuntimeStartError::SmtpBind {
                        addr: format!("{}:{smtp_port}", self.state.bind_host),
                        source: std::io::Error::new(
                            std::io::ErrorKind::AddrInUse,
                            "SMTP port already in use",
                        ),
                    },
                );
            }
        }
        if settings.use_ssl_for_imap
            && !is_bind_port_free(
                &self.state.bind_host,
                bridge::mail_runtime::DEFAULT_IMAP_IMPLICIT_TLS_PORT,
            )
            .await
        {
            startup_conflict = true;
            self.log_startup_mail_runtime_error(
                &settings,
                &bridge::mail_runtime::MailRuntimeStartError::ImapImplicitTlsBind {
                    addr: format!(
                        "{}:{}",
                        self.state.bind_host,
                        bridge::mail_runtime::DEFAULT_IMAP_IMPLICIT_TLS_PORT
                    ),
                    source: std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        "IMAP implicit TLS port already in use",
                    ),
                },
            );
        }
        if settings.use_ssl_for_smtp
            && !is_bind_port_free(
                &self.state.bind_host,
                bridge::mail_runtime::DEFAULT_SMTP_IMPLICIT_TLS_PORT,
            )
            .await
        {
            startup_conflict = true;
            self.log_startup_mail_runtime_error(
                &settings,
                &bridge::mail_runtime::MailRuntimeStartError::SmtpImplicitTlsBind {
                    addr: format!(
                        "{}:{}",
                        self.state.bind_host,
                        bridge::mail_runtime::DEFAULT_SMTP_IMPLICIT_TLS_PORT
                    ),
                    source: std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        "SMTP implicit TLS port already in use",
                    ),
                },
            );
        }
        if startup_conflict {
            return;
        }

        let has_sessions = match self.state.runtime_supervisor.session_manager().has_sessions().await
        {
            Ok(has_sessions) => has_sessions,
            Err(err) => {
                warn!(
                    pkg = "grpc/bridge",
                    transition = "startup",
                    error = %err,
                    "failed to load managed sessions while deciding grpc mail runtime startup"
                );
                false
            }
        };
        if !has_sessions {
            info!(
                pkg = "grpc/bridge",
                transition = "startup",
                "skipping grpc mail runtime startup; no logged-in sessions"
            );
            return;
        }

        match self
            .start_mail_runtime_with_settings(
                &settings,
                bridge::mail_runtime::MailRuntimeTransition::Startup,
            )
            .await
        {
            Ok(()) => {}
            Err(err) => self.log_startup_mail_runtime_error(&settings, &err),
        }
    }

    async fn apply_mail_runtime_settings_change(
        &self,
        previous: StoredMailSettings,
        next: StoredMailSettings,
    ) -> Result<(), Status> {
        let _guard = self.state.mail_runtime_transition_lock.lock().await;

        let next_imap_port = u16::try_from(next.imap_port)
            .map_err(|_| Status::invalid_argument("IMAP port must be between 1 and 65535"))?;
        let next_smtp_port = u16::try_from(next.smtp_port)
            .map_err(|_| Status::invalid_argument("SMTP port must be between 1 and 65535"))?;
        if next.imap_port != previous.imap_port
            && !is_bind_port_free(&self.state.bind_host, next_imap_port).await
        {
            self.emit_mail_settings_error(pb::MailServerSettingsErrorType::ImapPortChangeError);
            return Err(Status::failed_precondition("IMAP port is not available"));
        }
        if next.smtp_port != previous.smtp_port
            && !is_bind_port_free(&self.state.bind_host, next_smtp_port).await
        {
            self.emit_mail_settings_error(pb::MailServerSettingsErrorType::SmtpPortChangeError);
            return Err(Status::failed_precondition("SMTP port is not available"));
        }
        if !previous.use_ssl_for_imap
            && next.use_ssl_for_imap
            && !is_bind_port_free(
                &self.state.bind_host,
                bridge::mail_runtime::DEFAULT_IMAP_IMPLICIT_TLS_PORT,
            )
            .await
        {
            self.emit_mail_settings_error(pb::MailServerSettingsErrorType::ImapPortChangeError);
            return Err(Status::failed_precondition(
                "IMAP implicit TLS port is not available",
            ));
        }
        if !previous.use_ssl_for_smtp
            && next.use_ssl_for_smtp
            && !is_bind_port_free(
                &self.state.bind_host,
                bridge::mail_runtime::DEFAULT_SMTP_IMPLICIT_TLS_PORT,
            )
            .await
        {
            self.emit_mail_settings_error(pb::MailServerSettingsErrorType::SmtpPortChangeError);
            return Err(Status::failed_precondition(
                "SMTP implicit TLS port is not available",
            ));
        }

        if previous == next {
            return Ok(());
        }

        let has_sessions = self
            .state
            .runtime_supervisor
            .session_manager()
            .has_sessions()
            .await
            .unwrap_or(false);
        if !has_sessions {
            info!(
                pkg = "grpc/bridge",
                transition = "settings_change",
                "skipping grpc mail runtime restart because no sessions are available"
            );
            return Ok(());
        }

        if let Err(err) = self.state.runtime_supervisor.stop("settings_change").await {
            warn!(
                pkg = "grpc/bridge",
                transition = "settings_change",
                error = %err,
                "failed to stop previous grpc mail runtime before restart"
            );
        }

        match self
            .start_mail_runtime_with_settings(
                &next,
                bridge::mail_runtime::MailRuntimeTransition::SettingsChange,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(err) => {
                self.emit_mail_runtime_change_error(&next, &err);

                match self
                    .start_mail_runtime_with_settings(
                        &previous,
                        bridge::mail_runtime::MailRuntimeTransition::Startup,
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(restore_err) => {
                        warn!(
                            pkg = "grpc/bridge",
                            transition = "settings_change_rollback",
                            error = %restore_err,
                            "failed to restore previous grpc mail runtime after settings change failure"
                        );
                    }
                }

                match err.protocol() {
                    Some(bridge::mail_runtime::MailProtocol::Imap) => {
                        Err(Status::failed_precondition("IMAP port is not available"))
                    }
                    Some(bridge::mail_runtime::MailProtocol::Smtp) => {
                        Err(Status::failed_precondition("SMTP port is not available"))
                    }
                    Some(bridge::mail_runtime::MailProtocol::Dav) => {
                        Err(Status::failed_precondition("DAV port is not available"))
                    }
                    None => Err(Status::internal(format!(
                        "failed to apply mail runtime settings: {err}"
                    ))),
                }
            }
        }
    }

    fn sync_state_key(&self) -> usize {
        Arc::as_ptr(&self.state) as usize
    }

    fn current_sync_worker_generation(&self) -> u64 {
        let registry = sync_lifecycle_registry()
            .lock()
            .expect("sync lifecycle registry poisoned");
        registry
            .get(&self.sync_state_key())
            .map(|state| state.generation)
            .unwrap_or(0)
    }

    fn next_sync_worker_generation(&self) -> u64 {
        let mut registry = sync_lifecycle_registry()
            .lock()
            .expect("sync lifecycle registry poisoned");
        let state = registry.entry(self.sync_state_key()).or_default();
        state.generation = state.generation.saturating_add(1);
        state.generation
    }

    fn clear_active_syncing_users(&self) {
        let mut users_to_finish = {
            let mut registry = sync_lifecycle_registry()
                .lock()
                .expect("sync lifecycle registry poisoned");
            let state = registry.entry(self.sync_state_key()).or_default();
            let users: Vec<String> = state.active_users.keys().cloned().collect();
            state.active_users.clear();
            users
        };
        users_to_finish.sort();
        users_to_finish.dedup();
        for user_id in users_to_finish {
            self.emit_sync_finished(&user_id);
        }
    }

    async fn refresh_sync_workers(&self) -> anyhow::Result<()> {
        if !self.state.sync_workers_enabled {
            debug!(
                pkg = "grpc/sync",
                "sync owner refresh disabled; skipping mail runtime restart"
            );
            return Ok(());
        }

        let _worker_generation = self.next_sync_worker_generation();
        self.clear_active_syncing_users();
        let legacy_group = {
            let mut guard = self.state.sync_event_workers.lock().await;
            guard.take()
        };
        if let Some(group) = legacy_group {
            info!(
                pkg = "grpc/sync",
                owner = "mail_runtime",
                "shutting down legacy grpc-owned sync worker group"
            );
            group.shutdown().await;
        }

        let _guard = self.state.mail_runtime_transition_lock.lock().await;
        let settings = self.state.mail_settings.lock().await.clone();
        let has_sessions = match self.state.runtime_supervisor.session_manager().has_sessions().await
        {
            Ok(has_sessions) => has_sessions,
            Err(err) => {
                warn!(
                    pkg = "grpc/sync",
                    error = %err,
                    "failed to load managed sessions while refreshing grpc sync owner"
                );
                false
            }
        };

        let had_runtime = self.state.runtime_supervisor.is_running().await;
        if had_runtime {
            info!(
                pkg = "grpc/sync",
                owner = "mail_runtime",
                "stopping grpc mail runtime before sync-owner refresh"
            );
            if let Err(err) = self.state.runtime_supervisor.stop("sync_refresh").await {
                warn!(
                    pkg = "grpc/sync",
                    owner = "mail_runtime",
                    error = %err,
                    "failed to stop grpc mail runtime during sync-owner refresh"
                );
            }
        }

        if !has_sessions {
            info!(
                pkg = "grpc/sync",
                owner = "mail_runtime",
                "no sessions available after transition; sync owner remains stopped"
            );
            return Ok(());
        }

        let runtime_transition = if had_runtime {
            bridge::mail_runtime::MailRuntimeTransition::SettingsChange
        } else {
            bridge::mail_runtime::MailRuntimeTransition::Startup
        };
        match self
            .start_mail_runtime_with_settings(&settings, runtime_transition)
            .await
        {
            Ok(()) => {
                info!(
                    pkg = "grpc/sync",
                    owner = "mail_runtime",
                    "refreshed grpc sync owner via mail runtime restart"
                );
            }
            Err(err) => {
                self.emit_mail_runtime_change_error(&settings, &err);
                anyhow::bail!("failed to restart grpc mail runtime sync owner: {err}");
            }
        }

        Ok(())
    }

    async fn shutdown_sync_workers(&self) {
        let _ = self.next_sync_worker_generation();
        self.clear_active_syncing_users();

        let previous_group = {
            let mut guard = self.state.sync_event_workers.lock().await;
            guard.take()
        };
        if let Some(group) = previous_group {
            group.shutdown().await;
        }
    }

    async fn refresh_sync_workers_for_transition(&self, transition: &'static str) {
        info!(
            pkg = "grpc/sync",
            transition,
            owner = "mail_runtime",
            "refreshing grpc sync owner for transition"
        );
        if let Err(err) = self.refresh_sync_workers().await {
            warn!(
                pkg = "grpc/sync",
                transition,
                error = %err,
                owner = "mail_runtime",
                "failed to refresh grpc sync owner during transition"
            );
            return;
        }
        info!(
            pkg = "grpc/sync",
            transition,
            owner = "mail_runtime",
            "grpc sync owner refreshed for transition"
        );
    }

    fn status_from_vault_error_with_events(&self, err: vault::VaultError) -> Status {
        if matches!(
            err,
            vault::VaultError::MissingVaultKey | vault::VaultError::KeychainAccess(_)
        ) {
            self.emit_keychain_rebuild();
        }
        status_from_vault_error(err)
    }

    async fn set_current_keychain_with_available(
        &self,
        keychain_raw: &str,
        available: &[String],
    ) -> Result<(), Status> {
        let result = async {
            let helper = keychain_raw.trim();
            if helper.is_empty() {
                return Err(Status::invalid_argument("keychain name is empty"));
            }
            let Some(backend) = keychain_helper_to_backend(helper) else {
                return Err(Status::invalid_argument(format!(
                    "unknown keychain helper: {helper}"
                )));
            };
            if !available.iter().any(|candidate| candidate == helper) {
                self.emit_keychain_has_no_keychain();
                return Err(Status::failed_precondition(format!(
                    "keychain helper unavailable on this host: {helper}"
                )));
            }
            vault::sync_vault_key_to_backend(self.settings_dir(), backend)
                .map_err(|err| self.status_from_vault_error_with_events(err))?;
            vault::set_keychain_helper(self.settings_dir(), helper)
                .map_err(|err| self.status_from_vault_error_with_events(err))?;
            let mut settings = self.state.app_settings.lock().await;
            settings.current_keychain = helper.to_string();
            save_app_settings(&self.grpc_app_settings_path(), &settings)
                .await
                .map_err(|e| Status::internal(format!("failed to save app settings: {e}")))?;
            Ok(())
        }
        .await;
        self.emit_keychain_change_finished();
        self.emit_show_main_window();
        let _ = self.state.shutdown_tx.send(true);
        result
    }

    fn emit_event(&self, event: pb::stream_event::Event) {
        let stream_event = pb::StreamEvent { event: Some(event) };
        if let Some(event) = stream_event.event.as_ref() {
            debug!(pkg = "grpc", event = ?event, "Sending event");
        }
        if let Ok(mut backlog) = self.state.event_backlog.lock() {
            backlog.push_back(stream_event.clone());
            while backlog.len() > MAX_BUFFERED_STREAM_EVENTS {
                let _ = backlog.pop_front();
            }
        }
        let _ = self.state.event_tx.send(stream_event);
    }

    fn emit_login_error(&self, message: impl Into<String>) {
        self.emit_event(pb::stream_event::Event::Login(pb::LoginEvent {
            event: Some(pb::login_event::Event::Error(pb::LoginErrorEvent {
                r#type: pb::LoginErrorType::ConnectionError as i32,
                message: message.into(),
            })),
        }));
    }

    fn emit_show_main_window(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::ShowMainWindow(
                pb::ShowMainWindowEvent {},
            )),
        }));
    }

    fn emit_all_users_loaded(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::AllUsersLoaded(
                pb::AllUsersLoadedEvent {},
            )),
        }));
    }

    fn emit_login_tfa_requested(&self, username: &str) {
        self.emit_event(pb::stream_event::Event::Login(pb::LoginEvent {
            event: Some(pb::login_event::Event::TfaRequested(
                pb::LoginTfaRequestedEvent {
                    username: username.to_string(),
                },
            )),
        }));
    }

    fn emit_login_two_password_requested(&self, username: &str) {
        self.emit_event(pb::stream_event::Event::Login(pb::LoginEvent {
            event: Some(pb::login_event::Event::TwoPasswordRequested(
                pb::LoginTwoPasswordsRequestedEvent {
                    username: username.to_string(),
                },
            )),
        }));
    }

    fn emit_login_finished(&self, user_id: &str) {
        self.emit_event(pb::stream_event::Event::Login(pb::LoginEvent {
            event: Some(pb::login_event::Event::Finished(pb::LoginFinishedEvent {
                user_id: user_id.to_string(),
                was_signed_out: false,
            })),
        }));
    }

    fn emit_user_changed(&self, user_id: &str) {
        self.emit_event(pb::stream_event::Event::User(pb::UserEvent {
            event: Some(pb::user_event::Event::UserChanged(pb::UserChangedEvent {
                user_id: user_id.to_string(),
            })),
        }));
    }

    fn emit_sync_started(&self, user_id: &str) {
        self.emit_event(pb::stream_event::Event::User(pb::UserEvent {
            event: Some(pb::user_event::Event::SyncStartedEvent(
                pb::SyncStartedEvent {
                    user_id: user_id.to_string(),
                },
            )),
        }));
    }

    fn emit_sync_started_for_generation(&self, user_id: &str, worker_generation: u64) {
        if self.current_sync_worker_generation() != worker_generation {
            return;
        }

        let should_emit = {
            let mut registry = sync_lifecycle_registry()
                .lock()
                .expect("sync lifecycle registry poisoned");
            let state = registry.entry(self.sync_state_key()).or_default();
            if state.generation != worker_generation {
                return;
            }
            match state.active_users.get(user_id).copied() {
                Some(existing_generation) if existing_generation == worker_generation => false,
                _ => {
                    state
                        .active_users
                        .insert(user_id.to_string(), worker_generation);
                    true
                }
            }
        };

        if should_emit {
            self.emit_sync_started(user_id);
        }
    }

    fn emit_sync_progress(&self, user_id: &str, progress: f64, elapsed_ms: i64, remaining_ms: i64) {
        self.emit_event(pb::stream_event::Event::User(pb::UserEvent {
            event: Some(pb::user_event::Event::SyncProgressEvent(
                pb::SyncProgressEvent {
                    user_id: user_id.to_string(),
                    progress,
                    elapsed_ms,
                    remaining_ms,
                },
            )),
        }));
    }

    fn emit_sync_progress_for_generation(
        &self,
        user_id: &str,
        progress: f64,
        elapsed_ms: i64,
        remaining_ms: i64,
        worker_generation: u64,
    ) {
        if self.current_sync_worker_generation() != worker_generation {
            return;
        }

        let should_emit = {
            let registry = sync_lifecycle_registry()
                .lock()
                .expect("sync lifecycle registry poisoned");
            let Some(state) = registry.get(&self.sync_state_key()) else {
                return;
            };
            state.active_users.get(user_id).copied() == Some(worker_generation)
        };

        if should_emit {
            self.emit_sync_progress(user_id, progress, elapsed_ms, remaining_ms);
        }
    }

    fn emit_sync_finished(&self, user_id: &str) {
        self.emit_event(pb::stream_event::Event::User(pb::UserEvent {
            event: Some(pb::user_event::Event::SyncFinishedEvent(
                pb::SyncFinishedEvent {
                    user_id: user_id.to_string(),
                },
            )),
        }));
    }

    fn emit_sync_finished_for_generation(&self, user_id: &str, worker_generation: u64) {
        let should_emit = {
            let mut registry = sync_lifecycle_registry()
                .lock()
                .expect("sync lifecycle registry poisoned");
            let Some(state) = registry.get_mut(&self.sync_state_key()) else {
                return;
            };
            if state.generation != worker_generation {
                return;
            }
            state.active_users.remove(user_id).is_some()
        };

        if should_emit {
            self.emit_sync_finished(user_id);
        }
    }

    fn emit_user_disconnected(&self, username: &str) {
        self.emit_event(pb::stream_event::Event::User(pb::UserEvent {
            event: Some(pb::user_event::Event::UserDisconnected(
                pb::UserDisconnectedEvent {
                    username: username.to_string(),
                },
            )),
        }));
    }

    fn emit_mail_settings_changed(&self, settings: &StoredMailSettings) {
        self.emit_event(pb::stream_event::Event::MailServerSettings(
            pb::MailServerSettingsEvent {
                event: Some(
                    pb::mail_server_settings_event::Event::MailServerSettingsChanged(
                        pb::MailServerSettingsChangedEvent {
                            settings: Some(pb::ImapSmtpSettings {
                                imap_port: settings.imap_port,
                                smtp_port: settings.smtp_port,
                                use_ssl_for_imap: settings.use_ssl_for_imap,
                                use_ssl_for_smtp: settings.use_ssl_for_smtp,
                            }),
                        },
                    ),
                ),
            },
        ));
    }

    fn emit_mail_settings_finished(&self) {
        self.emit_event(pb::stream_event::Event::MailServerSettings(
            pb::MailServerSettingsEvent {
                event: Some(
                    pb::mail_server_settings_event::Event::ChangeMailServerSettingsFinished(
                        pb::ChangeMailServerSettingsFinishedEvent {},
                    ),
                ),
            },
        ));
    }

    fn emit_mail_settings_error(&self, error_type: pb::MailServerSettingsErrorType) {
        self.emit_event(pb::stream_event::Event::MailServerSettings(
            pb::MailServerSettingsEvent {
                event: Some(pb::mail_server_settings_event::Event::Error(
                    pb::MailServerSettingsErrorEvent {
                        r#type: error_type as i32,
                    },
                )),
            },
        ));
    }

    fn emit_update_is_latest_version(&self) {
        self.emit_event(pb::stream_event::Event::Update(pb::UpdateEvent {
            event: Some(pb::update_event::Event::IsLatestVersion(
                pb::UpdateIsLatestVersion {},
            )),
        }));
    }

    fn emit_update_check_finished(&self) {
        self.emit_event(pb::stream_event::Event::Update(pb::UpdateEvent {
            event: Some(pb::update_event::Event::CheckFinished(
                pb::UpdateCheckFinished {},
            )),
        }));
    }

    fn emit_generic_error(&self, code: pb::ErrorCode) {
        self.emit_event(pb::stream_event::Event::GenericError(
            pb::GenericErrorEvent { code: code as i32 },
        ));
    }

    fn emit_keychain_change_finished(&self) {
        self.emit_event(pb::stream_event::Event::Keychain(pb::KeychainEvent {
            event: Some(pb::keychain_event::Event::ChangeKeychainFinished(
                pb::ChangeKeychainFinishedEvent {},
            )),
        }));
    }

    fn emit_keychain_has_no_keychain(&self) {
        self.emit_event(pb::stream_event::Event::Keychain(pb::KeychainEvent {
            event: Some(pb::keychain_event::Event::HasNoKeychain(
                pb::HasNoKeychainEvent {},
            )),
        }));
    }

    fn emit_keychain_rebuild(&self) {
        self.emit_event(pb::stream_event::Event::Keychain(pb::KeychainEvent {
            event: Some(pb::keychain_event::Event::RebuildKeychain(
                pb::RebuildKeychainEvent {},
            )),
        }));
    }

    fn emit_toggle_autostart_finished(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::ToggleAutostartFinished(
                pb::ToggleAutostartFinishedEvent {},
            )),
        }));
    }

    fn emit_report_bug_success(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::ReportBugSuccess(
                pb::ReportBugSuccessEvent {},
            )),
        }));
    }

    fn emit_report_bug_error(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::ReportBugError(
                pb::ReportBugErrorEvent {},
            )),
        }));
    }

    fn emit_report_bug_finished(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::ReportBugFinished(
                pb::ReportBugFinishedEvent {},
            )),
        }));
    }

    fn emit_reset_finished(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::ResetFinished(
                pb::ResetFinishedEvent {},
            )),
        }));
    }

    fn emit_repair_started(&self) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::RepairStarted(
                pb::RepairStartedEvent {},
            )),
        }));
    }

    fn emit_knowledge_base_suggestions(&self, suggestions: Vec<pb::KnowledgeBaseSuggestion>) {
        self.emit_event(pb::stream_event::Event::App(pb::AppEvent {
            event: Some(pb::app_event::Event::KnowledgeBaseSuggestions(
                pb::KnowledgeBaseSuggestionsEvent { suggestions },
            )),
        }));
    }

    fn emit_disk_cache_path_changed(&self, path: &str) {
        self.emit_event(pb::stream_event::Event::Cache(pb::DiskCacheEvent {
            event: Some(pb::disk_cache_event::Event::PathChanged(
                pb::DiskCachePathChangedEvent {
                    path: path.to_string(),
                },
            )),
        }));
    }

    fn emit_disk_cache_path_change_finished(&self) {
        self.emit_event(pb::stream_event::Event::Cache(pb::DiskCacheEvent {
            event: Some(pb::disk_cache_event::Event::PathChangeFinished(
                pb::DiskCachePathChangeFinishedEvent {},
            )),
        }));
    }

    fn emit_disk_cache_error(&self, error_type: pb::DiskCacheErrorType) {
        self.emit_event(pb::stream_event::Event::Cache(pb::DiskCacheEvent {
            event: Some(pb::disk_cache_event::Event::Error(
                pb::DiskCacheErrorEvent {
                    r#type: error_type as i32,
                },
            )),
        }));
    }

    async fn cache_session_access_token(&self, session: &Session) {
        if session.uid.trim().is_empty() || session.access_token.trim().is_empty() {
            return;
        }
        self.state
            .session_access_tokens
            .lock()
            .await
            .insert(session.uid.clone(), session.access_token.clone());
    }

    async fn remove_session_access_token(&self, user_id: &str) {
        self.state
            .session_access_tokens
            .lock()
            .await
            .remove(user_id);
    }

    async fn clear_session_access_tokens(&self) {
        self.state.session_access_tokens.lock().await.clear();
    }

    async fn resolve_session_access_token(&self, session: &Session) -> Option<String> {
        if !session.access_token.trim().is_empty() {
            return Some(session.access_token.clone());
        }
        let account_id = bridge::types::AccountId(session.uid.clone());
        if let Some(managed) = self
            .state
            .runtime_supervisor
            .session_manager()
            .runtime_accounts()
            .get_session(&account_id)
            .await
        {
            if !managed.access_token.trim().is_empty() {
                self.cache_session_access_token(&managed).await;
                return Some(managed.access_token);
            }
        }
        self.state
            .session_access_tokens
            .lock()
            .await
            .get(&session.uid)
            .cloned()
    }

    async fn refresh_session_access_token(&self, session: &Session) -> Option<String> {
        if cfg!(test) || session.uid.trim().is_empty() {
            return None;
        }

        let account_id = bridge::types::AccountId(session.uid.clone());
        let session_manager = self.state.runtime_supervisor.session_manager();
        if let Err(err) = session_manager.upsert_session(session.clone()).await {
            warn!(
                user_id = %session.uid,
                error = %err,
                "failed to seed grpc session manager before metadata refresh"
            );
            return None;
        }
        let refreshed = if session.access_token.trim().is_empty() {
            session_manager.with_valid_access_token(&account_id).await
        } else {
            session_manager
                .refresh_session_if_stale(&account_id, Some(session.access_token.as_str()))
                .await
        };

        match refreshed {
            Ok(updated) if !updated.access_token.trim().is_empty() => {
                self.cache_session_access_token(&updated).await;
                Some(updated.access_token)
            }
            Ok(_) => None,
            Err(err) => {
                warn!(
                    user_id = %session.uid,
                    error = %err,
                    "failed to refresh access token for grpc user metadata"
                );
                None
            }
        }
    }

    async fn fetch_user_api_data(&self, session: &Session) -> Option<UserApiData> {
        if cfg!(test) {
            return None;
        }

        let mut access_token = self.resolve_session_access_token(session).await;
        if access_token.is_none() {
            access_token = self.refresh_session_access_token(session).await;
        }
        let mut access_token = access_token?;

        let first_attempt = {
            let mut client = match ProtonClient::with_api_mode(session.api_mode) {
                Ok(client) => client,
                Err(err) => {
                    warn!(
                        user_id = %session.uid,
                        error = %err,
                        "failed to initialize grpc metadata client"
                    );
                    return None;
                }
            };
            client.set_auth(&session.uid, &access_token);
            api::users::get_user(&client)
                .await
                .map(|resp| resp.user.into())
        };

        match first_attempt {
            Ok(api_data) => return Some(api_data),
            Err(err) if api::error::is_auth_error(&err) => {
                self.remove_session_access_token(&session.uid).await;
                if let Some(refreshed_token) = self.refresh_session_access_token(session).await {
                    access_token = refreshed_token;
                } else {
                    warn!(
                        user_id = %session.uid,
                        error = %err,
                        "failed to fetch grpc user metadata with cached token"
                    );
                    return None;
                }
            }
            Err(err) => {
                warn!(
                    user_id = %session.uid,
                    error = %err,
                    "failed to fetch grpc user metadata"
                );
                return None;
            }
        }

        let mut client = match ProtonClient::with_api_mode(session.api_mode) {
            Ok(client) => client,
            Err(err) => {
                warn!(
                    user_id = %session.uid,
                    error = %err,
                    "failed to initialize grpc metadata client after refresh"
                );
                return None;
            }
        };
        client.set_auth(&session.uid, &access_token);

        match api::users::get_user(&client)
            .await
            .map(|resp| resp.user.into())
        {
            Ok(api_data) => Some(api_data),
            Err(err) => {
                warn!(
                    user_id = %session.uid,
                    error = %err,
                    "failed to fetch grpc user metadata after token refresh"
                );
                None
            }
        }
    }

    async fn complete_login(
        &self,
        mut client: ProtonClient,
        args: CompleteLoginArgs,
    ) -> Result<Session, Status> {
        fn missing_required_login_scopes(
            required_scopes: &[String],
            granted_scopes: &[String],
        ) -> Vec<String> {
            if required_scopes.is_empty() {
                return Vec::new();
            }

            required_scopes
                .iter()
                .filter(|scope| !api::auth::has_scope(granted_scopes, scope))
                .cloned()
                .collect()
        }

        let CompleteLoginArgs {
            api_mode,
            uid,
            access_token,
            refresh_token,
            username,
            password,
            required_scopes,
            granted_scopes,
        } = args;

        let missing_scopes = missing_required_login_scopes(&required_scopes, &granted_scopes);
        if !missing_scopes.is_empty() {
            let granted =
                api::auth::scope_list_to_string(&granted_scopes).unwrap_or_else(|| "none".to_string());
            warn!(
                missing_scopes = %missing_scopes.join(" "),
                granted_scopes = %granted,
                "grpc login requested scopes not granted; continuing with granted scopes"
            );
        }

        let user_resp = api::users::get_user(&client)
            .await
            .map_err(status_from_api_error)?;
        let user = &user_resp.user;

        let salts_resp = api::users::get_salts(&client)
            .await
            .map_err(status_from_api_error)?;

        let key_passphrase = {
            let mut derived = None;
            for key in user.keys.iter().filter(|k| k.active == 1) {
                match api::srp::salt_for_key(password.as_bytes(), &key.id, &salts_resp.key_salts) {
                    Ok(passphrase) => {
                        derived = Some(BASE64.encode(&passphrase));
                        break;
                    }
                    Err(err) => {
                        debug!(key_id = %key.id, error = %err, "key passphrase derivation attempt failed");
                    }
                }
            }

            if derived.is_none() {
                warn!("could not derive key passphrase from any active user key");
            }
            derived
        };

        let bridge_password = vault::load_session_by_account_id(self.settings_dir(), &uid)
            .ok()
            .and_then(|stored| stored.bridge_password)
            .or_else(|| {
                vault::load_session_by_email(self.settings_dir(), &user.email)
                    .ok()
                    .and_then(|stored| stored.bridge_password)
            })
            .unwrap_or_else(generate_bridge_password);
        let session = Session {
            uid: uid.clone(),
            access_token,
            refresh_token,
            email: user.email.clone(),
            display_name: if user.display_name.is_empty() {
                username
            } else {
                user.display_name.clone()
            },
            api_mode,
            key_passphrase,
            bridge_password: Some(bridge_password),
        };

        vault::save_session_with_user_id(&session, Some(user.id.as_str()), self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        vault::set_default_email(self.settings_dir(), &session.email)
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        if let Err(err) = self
            .state
            .runtime_supervisor
            .session_manager()
            .upsert_session(session.clone())
            .await
        {
            warn!(
                user_id = %session.uid,
                error = %err,
                "failed to update session manager after grpc login"
            );
        }

        client.set_auth(&session.uid, &session.access_token);
        self.cache_session_access_token(&session).await;

        self.emit_login_finished(&session.uid);
        self.emit_user_changed(&session.uid);
        self.refresh_sync_workers_for_transition("login").await;

        Ok(session)
    }

    async fn requires_second_password(
        &self,
        client: &ProtonClient,
        password: &str,
    ) -> Result<bool, Status> {
        let user_resp = api::users::get_user(client)
            .await
            .map_err(status_from_api_error)?;
        let salts_resp = api::users::get_salts(client)
            .await
            .map_err(status_from_api_error)?;

        let mut has_active_keys = false;
        for key in user_resp.user.keys.iter().filter(|key| key.active == 1) {
            has_active_keys = true;
            if api::srp::salt_for_key(password.as_bytes(), &key.id, &salts_resp.key_salts).is_ok() {
                return Ok(false);
            }
        }

        Ok(has_active_keys)
    }
}
