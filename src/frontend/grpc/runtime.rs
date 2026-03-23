#[derive(Clone)]
pub struct GrpcServerOptions {
    pub runtime_supervisor: Option<Arc<bridge::runtime_supervisor::RuntimeSupervisor>>,
    pub start_mail_runtime_on_startup: bool,
    pub stop_mail_runtime_on_shutdown: bool,
}

impl Default for GrpcServerOptions {
    fn default() -> Self {
        Self {
            runtime_supervisor: None,
            start_mail_runtime_on_startup: true,
            stop_mail_runtime_on_shutdown: true,
        }
    }
}

pub async fn run_server(runtime_paths: RuntimePaths, bind_host: String) -> anyhow::Result<()> {
    run_server_with_options(runtime_paths, bind_host, GrpcServerOptions::default()).await
}

pub async fn run_server_with_options(
    runtime_paths: RuntimePaths,
    bind_host: String,
    options: GrpcServerOptions,
) -> anyhow::Result<()> {
    let GrpcServerOptions {
        runtime_supervisor,
        start_mail_runtime_on_startup,
        stop_mail_runtime_on_shutdown,
    } = options;
    tokio::fs::create_dir_all(runtime_paths.settings_dir())
        .await
        .with_context(|| {
            format!(
                "failed to create settings dir {}",
                runtime_paths.settings_dir().display()
            )
        })?;

    let listener = TcpListener::bind(format!("{bind_host}:0"))
        .await
        .with_context(|| format!("failed to bind gRPC listener on {bind_host}"))?;
    let port = listener
        .local_addr()
        .context("failed to read listener local address")?
        .port();
    #[cfg(unix)]
    let (unix_listener, unix_socket_path, _unix_socket_cleanup) = {
        let path = compute_grpc_unix_socket_path()?;
        let listener = UnixListener::bind(&path).with_context(|| {
            format!(
                "failed to bind gRPC unix socket listener at {}",
                path.display()
            )
        })?;
        (listener, path.clone(), UnixSocketCleanup { path })
    };
    #[cfg(not(unix))]
    let unix_socket_path: Option<PathBuf> = None;

    let grpc_server_config_path = runtime_paths.grpc_server_config_path();
    let grpc_mail_settings_path = runtime_paths.grpc_mail_settings_path();
    let grpc_app_settings_path = runtime_paths.grpc_app_settings_path();
    let disk_cache_dir = runtime_paths.disk_cache_dir();

    let token = generate_server_token();
    let (cert_pem, key_pem) = generate_ephemeral_tls_cert()?;
    write_server_config(
        &grpc_server_config_path,
        &GrpcServerConfig {
            port,
            cert: cert_pem.clone(),
            token: token.clone(),
            file_socket_path: {
                #[cfg(unix)]
                {
                    unix_socket_path.display().to_string()
                }
                #[cfg(not(unix))]
                {
                    unix_socket_path
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_default()
                }
            },
        },
    )
    .await?;

    let settings = load_mail_settings(&grpc_mail_settings_path).await?;
    let app_settings = load_app_settings(&grpc_app_settings_path, &disk_cache_dir).await?;
    let active_disk_cache_path = effective_disk_cache_path(&app_settings, &runtime_paths);
    tokio::fs::create_dir_all(&active_disk_cache_path)
        .await
        .with_context(|| {
            format!(
                "failed to create active disk cache path {}",
                active_disk_cache_path.display()
            )
        })?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_tx, _) = broadcast::channel(128);
    let runtime_supervisor = runtime_supervisor.unwrap_or_else(|| {
        Arc::new(bridge::runtime_supervisor::RuntimeSupervisor::new(
            runtime_paths.clone(),
        ))
    });
    let state = Arc::new(GrpcState {
        runtime_paths: runtime_paths.clone(),
        runtime_supervisor,
        bind_host,
        active_disk_cache_path: Mutex::new(active_disk_cache_path),
        event_tx,
        event_backlog: std::sync::Mutex::new(VecDeque::new()),
        active_stream_stop: Mutex::new(None),
        pending_login: Mutex::new(None),
        pending_hv: Mutex::new(None),
        session_access_tokens: Mutex::new(HashMap::new()),
        shutdown_tx: shutdown_tx.clone(),
        mail_settings: Mutex::new(settings),
        mail_runtime_transition_lock: Mutex::new(()),
        app_settings: Mutex::new(app_settings),
        sync_workers_enabled: true,
        sync_event_workers: Mutex::new(None),
        user_api_data_cache: Mutex::new(HashMap::new()),
    });

    let service = BridgeService::new(state);
    info!(
        pkg = "grpc/sync",
        owner = "mail_runtime",
        "using mail runtime as the single grpc sync worker owner"
    );
    service
        .state
        .runtime_supervisor
        .set_sync_callback(service.build_sync_progress_callback());
    if start_mail_runtime_on_startup {
        service.start_mail_runtime_on_startup().await;
    } else {
        info!(
            pkg = "grpc/sync",
            owner = "mail_runtime",
            "skipping grpc mail runtime startup; runtime is externally managed"
        );
    }
    #[cfg(unix)]
    info!(pkg = "grpc", useFileSocket = true, "Starting gRPC server");
    #[cfg(not(unix))]
    info!(pkg = "grpc", useFileSocket = false, "Starting gRPC server");
    let service_for_shutdown = service.clone();
    let expected_token = token;
    let expected_token_tcp = expected_token.clone();
    let bridge_svc_tcp =
        pb::bridge_server::BridgeServer::with_interceptor(service, move |req: Request<()>| {
            if let Some(status) = validate_server_token(req.metadata(), &expected_token_tcp) {
                return Err(status);
            }
            Ok(req)
        });
    #[cfg(unix)]
    let bridge_svc_unix = pb::bridge_server::BridgeServer::with_interceptor(
        service_for_shutdown.clone(),
        move |req: Request<()>| {
            if let Some(status) = validate_server_token(req.metadata(), &expected_token) {
                return Err(status);
            }
            Ok(req)
        },
    );

    let cert_pem_tcp = cert_pem.clone();
    let key_pem_tcp = key_pem.clone();
    #[cfg(unix)]
    let cert_pem_unix = cert_pem.clone();
    #[cfg(unix)]
    let key_pem_unix = key_pem.clone();
    let shutdown_tx_ctrlc = shutdown_tx.clone();
    tokio::spawn(async move {
        let mut shutdown_requested = false;
        loop {
            if let Err(err) = tokio::signal::ctrl_c().await {
                warn!(error = %err, "failed to listen for Ctrl-C");
                break;
            }

            if !shutdown_requested {
                shutdown_requested = true;
                info!("Ctrl-C received, initiating graceful shutdown");
                let _ = shutdown_tx_ctrlc.send(true);
            } else {
                warn!("second Ctrl-C received, forcing process exit");
                std::process::exit(130);
            }
        }
    });

    #[cfg(unix)]
    info!(
        port,
        file_socket_path = %unix_socket_path.display(),
        "grpc frontend service listening"
    );
    #[cfg(unix)]
    info!(
        pkg = "grpc",
        "gRPC server listening on {}",
        unix_socket_path.display()
    );
    #[cfg(not(unix))]
    info!(port, "grpc frontend service listening");

    #[cfg(not(unix))]
    let server_result = async {
        Server::builder()
            .tls_config(
                ServerTlsConfig::new().identity(Identity::from_pem(cert_pem_tcp, key_pem_tcp)),
            )
            .context("failed to configure gRPC TLS")?
            .add_service(bridge_svc_tcp)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                wait_for_shutdown(shutdown_rx).await;
            })
            .await
            .context("gRPC server exited with error")
    }
    .await;
    #[cfg(unix)]
    let server_result = {
        let shutdown_rx_tcp = shutdown_rx.clone();
        let shutdown_rx_unix = shutdown_rx.clone();
        let shutdown_tx_on_exit = shutdown_tx.clone();

        let tcp_server = async move {
            Server::builder()
                .tls_config(
                    ServerTlsConfig::new().identity(Identity::from_pem(cert_pem_tcp, key_pem_tcp)),
                )
                .context("failed to configure gRPC TLS for tcp listener")?
                .add_service(bridge_svc_tcp)
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                    wait_for_shutdown(shutdown_rx_tcp).await;
                })
                .await
                .context("gRPC tcp server exited with error")
        };

        let unix_server = async move {
            Server::builder()
                .tls_config(
                    ServerTlsConfig::new()
                        .identity(Identity::from_pem(cert_pem_unix, key_pem_unix)),
                )
                .context("failed to configure gRPC TLS for unix listener")?
                .add_service(bridge_svc_unix)
                .serve_with_incoming_shutdown(UnixListenerStream::new(unix_listener), async move {
                    wait_for_shutdown(shutdown_rx_unix).await;
                })
                .await
                .context("gRPC unix socket server exited with error")
        };

        tokio::select! {
            result = tcp_server => {
                let _ = shutdown_tx_on_exit.send(true);
                result
            }
            result = unix_server => {
                let _ = shutdown_tx_on_exit.send(true);
                result
            }
        }
    };

    if stop_mail_runtime_on_shutdown {
        service_for_shutdown
            .stop_mail_runtime_for_transition("shutdown")
            .await;
    }
    service_for_shutdown.shutdown_sync_workers().await;

    server_result
}

async fn wait_for_shutdown(mut shutdown_rx: watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    loop {
        if shutdown_rx.changed().await.is_err() {
            return;
        }
        if *shutdown_rx.borrow() {
            return;
        }
    }
}
