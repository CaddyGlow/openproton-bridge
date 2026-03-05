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

fn decode_login_password_bytes(raw: Vec<u8>) -> Result<DecodedLoginPassword, LoginPasswordDecodeError> {
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

#[allow(clippy::result_large_err)]
fn resolve_mutt_config_session(settings_dir: &Path, selector: &str) -> Result<Session, Status> {
    let selector = selector.trim();
    if selector.is_empty() {
        return vault::load_session(settings_dir).map_err(|err| match err {
            vault::VaultError::NotLoggedIn => Status::failed_precondition(
                "no active account found; pass account_selector or login first",
            ),
            other => status_from_vault_error(other),
        });
    }

    let sessions = vault::list_sessions(settings_dir).map_err(status_from_vault_error)?;
    if sessions.is_empty() {
        return Err(Status::failed_precondition("no accounts are configured"));
    }

    if let Ok(index) = selector.parse::<usize>() {
        if let Some(session) = sessions.get(index) {
            return Ok(session.clone());
        }
        return Err(Status::invalid_argument(format!(
            "account index {index} is out of range (max {})",
            sessions.len().saturating_sub(1)
        )));
    }

    sessions
        .into_iter()
        .find(|session| {
            session.uid == selector
                || session.email.eq_ignore_ascii_case(selector)
                || session.display_name.eq_ignore_ascii_case(selector)
        })
        .ok_or_else(|| Status::not_found(format!("unknown account selector: {selector}")))
}

impl BridgeService {
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

    async fn trigger_reset(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        tracing::info!(
            pkg = "grpc/bridge",
            transition = "trigger_reset",
            "reset requested"
        );
        self.stop_mail_runtime_for_transition("trigger_reset").await;
        vault::remove_session(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
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
        let current = match resolve_live_gluon_cache_root(&self.state.runtime_paths) {
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
            using_hv_details = hv_details.is_some(),
            "starting grpc login attempt"
        );

        let mut effective_api_mode = requested_api_mode;
        let mut tried_mode_fallback = false;
        let mut client =
            ProtonClient::with_api_mode(effective_api_mode).map_err(status_from_api_error)?;
        let auth = loop {
            match api::auth::login(&mut client, &username, &password, hv_details.as_ref()).await {
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
        let Some(pending) = pending_guard.take() else {
            return Err(Status::failed_precondition("no pending login for 2FA"));
        };

        if !username.is_empty() && !username.eq_ignore_ascii_case(&pending.username) {
            *pending_guard = Some(pending);
            return Err(Status::invalid_argument(
                "username does not match pending login",
            ));
        }

        if let Err(err) = api::auth::submit_2fa(&pending.client, code.trim()).await {
            *pending_guard = Some(pending);
            self.emit_login_error(err.to_string());
            warn!(username = %username, error = %err, "grpc 2FA submission failed");
            return Err(status_from_api_error(err));
        }
        info!(username = %username, "grpc 2FA submission accepted");

        drop(pending_guard);

        self.complete_login(
            pending.client,
            CompleteLoginArgs {
                api_mode: pending.api_mode,
                uid: pending.uid,
                access_token: pending.access_token,
                refresh_token: pending.refresh_token,
                username: pending.username,
                password: pending.password,
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
        let Some(pending) = pending_guard.take() else {
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

        if let Err(err) =
            api::auth::submit_fido_2fa(&pending.client, &authentication_options, &req.password)
                .await
        {
            *pending_guard = Some(pending);
            self.emit_login_error(err.to_string());
            return Err(status_from_api_error(err));
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
                password: pending.password,
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
        let sessions = vault::list_sessions(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
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
        let sessions = vault::list_sessions(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        let session = sessions
            .iter()
            .find(|s| s.uid == lookup || s.email.eq_ignore_ascii_case(&lookup))
            .ok_or_else(|| Status::not_found("user not found"))?;
        let split_mode = vault::load_split_mode_by_account_id(self.settings_dir(), &session.uid)
            .ok()
            .flatten()
            .unwrap_or(false);
        let api_data = self.fetch_user_api_data(session).await;
        Ok(Response::new(session_to_user(
            session,
            split_mode,
            api_data.as_ref(),
        )))
    }

    async fn set_user_split_mode(
        &self,
        request: Request<pb::UserSplitModeRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let sessions = vault::list_sessions(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        let account_id = sessions
            .iter()
            .find(|s| s.uid == req.user_id || s.email.eq_ignore_ascii_case(&req.user_id))
            .map(|s| s.uid.clone())
            .ok_or_else(|| Status::not_found("user not found"))?;

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
        let lookup = req.user_id.trim();
        if lookup.is_empty() {
            return Err(Status::invalid_argument("user id is required"));
        }
        let sessions = vault::list_sessions(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        let session = sessions
            .into_iter()
            .find(|s| s.uid == lookup || s.email.eq_ignore_ascii_case(lookup))
            .ok_or_else(|| Status::not_found("user not found"))?;
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
        self.remove_session_access_token(&session.uid).await;
        self.emit_user_disconnected(&session.email);
        self.refresh_sync_workers_for_transition("send_bad_event_user_feedback_logout")
            .await;
        Ok(Response::new(()))
    }

    async fn logout_user(&self, request: Request<String>) -> Result<Response<()>, Status> {
        let value = request.into_inner();
        let sessions = vault::list_sessions(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        let session = sessions
            .into_iter()
            .find(|s| s.uid == value || s.email.eq_ignore_ascii_case(&value))
            .ok_or_else(|| Status::not_found("user not found"))?;

        vault::remove_session_by_email(self.settings_dir(), &session.email)
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        tracing::info!(
            pkg = "grpc/bridge",
            user_id = %session.uid,
            email = %session.email,
            "logout requested"
        );
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
        let session = resolve_mutt_config_session(self.settings_dir(), &req.account_selector)?;
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
        Ok(Response::new(pb::RenderMuttConfigResponse { rendered_config }))
    }

    async fn configure_user_apple_mail(
        &self,
        request: Request<pb::ConfigureAppleMailRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        let lookup = req.user_id.trim();
        if lookup.is_empty() {
            return Err(Status::invalid_argument("user id is required"));
        }
        let sessions = vault::list_sessions(self.settings_dir())
            .map_err(|err| self.status_from_vault_error_with_events(err))?;
        let session = sessions
            .into_iter()
            .find(|s| s.uid == lookup || s.email.eq_ignore_ascii_case(lookup))
            .ok_or_else(|| Status::not_found("user not found"))?;
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

    async fn is_tls_certificate_installed(
        &self,
        _request: Request<()>,
    ) -> Result<Response<bool>, Status> {
        let (cert_path, key_path) = mail_cert_paths(self.settings_dir());
        Ok(Response::new(cert_path.exists() && key_path.exists()))
    }

    async fn install_tls_certificate(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        ensure_mail_tls_certificate(self.settings_dir())
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
