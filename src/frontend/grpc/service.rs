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

    async fn refresh_sync_workers(&self) -> anyhow::Result<()> {
        if !self.state.sync_workers_enabled {
            return Ok(());
        }

        let active_disk_cache_path = self.state.active_disk_cache_path.lock().await.clone();
        let next_group =
            maybe_start_grpc_sync_workers(&self.state.runtime_paths, self, &active_disk_cache_path)
                .await?;

        let previous_group = {
            let mut guard = self.state.sync_event_workers.lock().await;
            std::mem::replace(&mut *guard, next_group)
        };

        if let Some(group) = previous_group {
            group.shutdown().await;
        }

        Ok(())
    }

    async fn shutdown_sync_workers(&self) {
        let previous_group = {
            let mut guard = self.state.sync_event_workers.lock().await;
            guard.take()
        };
        if let Some(group) = previous_group {
            group.shutdown().await;
        }
    }

    async fn refresh_sync_workers_for_transition(&self, transition: &'static str) {
        if let Err(err) = self.refresh_sync_workers().await {
            warn!(
                transition,
                error = %err,
                "failed to refresh grpc sync workers during transition"
            );
        }
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

    fn emit_login_tfa_requested(&self, username: &str) {
        self.emit_event(pb::stream_event::Event::Login(pb::LoginEvent {
            event: Some(pb::login_event::Event::TfaRequested(
                pb::LoginTfaRequestedEvent {
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

    fn emit_sync_finished(&self, user_id: &str) {
        self.emit_event(pb::stream_event::Event::User(pb::UserEvent {
            event: Some(pb::user_event::Event::SyncFinishedEvent(
                pb::SyncFinishedEvent {
                    user_id: user_id.to_string(),
                },
            )),
        }));
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
        self.state.session_access_tokens.lock().await.remove(user_id);
    }

    async fn clear_session_access_tokens(&self) {
        self.state.session_access_tokens.lock().await.clear();
    }

    async fn resolve_session_access_token(&self, session: &Session) -> Option<String> {
        if !session.access_token.trim().is_empty() {
            return Some(session.access_token.clone());
        }
        self.state
            .session_access_tokens
            .lock()
            .await
            .get(&session.uid)
            .cloned()
    }

    async fn refresh_session_access_token(&self, session: &Session) -> Option<String> {
        if cfg!(test) || session.uid.trim().is_empty() || session.refresh_token.trim().is_empty() {
            return None;
        }

        let mut client = ProtonClient::with_api_mode(session.api_mode).ok()?;
        let refreshed = match api::auth::refresh_auth(
            &mut client,
            &session.uid,
            &session.refresh_token,
            None,
        )
        .await
        {
            Ok(refreshed) => refreshed,
            Err(err) => {
                warn!(
                    user_id = %session.uid,
                    error = %err,
                    "failed to refresh access token for grpc user metadata"
                );
                return None;
            }
        };

        if refreshed.access_token.trim().is_empty() {
            return None;
        }

        let mut updated = session.clone();
        updated.access_token = refreshed.access_token.clone();
        updated.refresh_token = refreshed.refresh_token;
        if let Err(err) = vault::save_session(&updated, self.settings_dir()) {
            warn!(
                user_id = %session.uid,
                error = %err,
                "failed to persist refreshed session context"
            );
        }

        self.cache_session_access_token(&updated).await;
        Some(updated.access_token)
    }

    async fn fetch_user_api_data(&self, session: &Session) -> Option<UserApiData> {
        if cfg!(test) {
            return None;
        }

        let mut access_token = self.resolve_session_access_token(session).await;
        if access_token.is_none() {
            access_token = self.refresh_session_access_token(session).await;
        }
        let Some(mut access_token) = access_token else {
            return None;
        };

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
            api::users::get_user(&client).await.map(|resp| resp.user.into())
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

        match api::users::get_user(&client).await.map(|resp| resp.user.into()) {
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
        api_mode: crate::api::types::ApiMode,
        uid: String,
        access_token: String,
        refresh_token: String,
        username: String,
        password: String,
    ) -> Result<Session, Status> {
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

        let bridge_password = generate_bridge_password();
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

        vault::save_session(&session, self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        vault::set_default_email(self.settings_dir(), &session.email)
            .map_err(|err| self.status_from_vault_error_with_events(err))?;

        client.set_auth(&session.uid, &session.access_token);
        self.cache_session_access_token(&session).await;

        self.emit_login_finished(&session.uid);
        self.emit_user_changed(&session.uid);
        self.refresh_sync_workers_for_transition("login").await;

        Ok(session)
    }
}
