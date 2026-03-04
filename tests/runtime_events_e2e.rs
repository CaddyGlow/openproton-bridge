use std::time::Duration;

use openproton_bridge::api::types::{ApiMode, Session};
use openproton_bridge::frontend::grpc::{self, pb};
use openproton_bridge::paths::RuntimePaths;
use openproton_bridge::vault;
use tokio::task::JoinHandle;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::Request;

struct RunningGrpc {
    _tempdir: tempfile::TempDir,
    token: String,
    cert_pem: String,
    port: u16,
    handle: Option<JoinHandle<anyhow::Result<()>>>,
}

impl RunningGrpc {
    async fn connect(&self) -> pb::bridge_client::BridgeClient<Channel> {
        let endpoint = Endpoint::from_shared(format!("https://localhost:{}", self.port))
            .expect("grpc endpoint")
            .tls_config(
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(self.cert_pem.clone()))
                    .domain_name("localhost"),
            )
            .expect("grpc tls config");

        pb::bridge_client::BridgeClient::new(endpoint.connect().await.expect("grpc connect"))
    }

    async fn shutdown(mut self) {
        if let Ok(mut client) = tokio::time::timeout(Duration::from_secs(5), self.connect()).await {
            let _ = client
                .quit(req_with_token((), &self.token))
                .await
                .map_err(|status| {
                    if status.code() != tonic::Code::Unavailable {
                        eprintln!(
                            "unexpected quit error while shutting down test grpc server: {status}"
                        );
                    }
                });
        }

        if let Some(handle) = self.handle.take() {
            let _ = tokio::time::timeout(Duration::from_secs(10), handle).await;
        }
    }
}

fn req_with_token<T>(payload: T, token: &str) -> Request<T> {
    let mut request = Request::new(payload);
    let value = MetadataValue::try_from(token).expect("valid token metadata");
    request.metadata_mut().insert("server-token", value);
    request
}

async fn start_runtime() -> RunningGrpc {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let runtime_paths = RuntimePaths::resolve(Some(tempdir.path())).expect("runtime paths");
    start_runtime_with_paths(tempdir, runtime_paths).await
}

async fn start_runtime_with_mail_settings(settings: pb::ImapSmtpSettings) -> RunningGrpc {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let runtime_paths = RuntimePaths::resolve(Some(tempdir.path())).expect("runtime paths");
    let payload = serde_json::json!({
        "imap_port": settings.imap_port,
        "smtp_port": settings.smtp_port,
        "use_ssl_for_imap": settings.use_ssl_for_imap,
        "use_ssl_for_smtp": settings.use_ssl_for_smtp,
    });
    tokio::fs::write(
        runtime_paths.grpc_mail_settings_path(),
        serde_json::to_vec_pretty(&payload).expect("mail settings json"),
    )
    .await
    .expect("write grpc mail settings");
    seed_fake_account(&runtime_paths);
    start_runtime_with_paths(tempdir, runtime_paths).await
}

async fn start_runtime_with_paths(
    tempdir: tempfile::TempDir,
    runtime_paths: RuntimePaths,
) -> RunningGrpc {
    let runtime_paths_for_task = runtime_paths.clone();

    let handle = tokio::spawn(async move {
        grpc::run_server(runtime_paths_for_task, "127.0.0.1".to_string()).await
    });

    let config_path = runtime_paths.grpc_server_config_path();
    let payload = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(data) = tokio::fs::read_to_string(&config_path).await {
                break data;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("grpc server config wait timeout");

    let parsed: serde_json::Value =
        serde_json::from_str(&payload).expect("grpc server config json");
    let port = parsed
        .get("port")
        .and_then(serde_json::Value::as_u64)
        .expect("grpc config port") as u16;
    let token = parsed
        .get("token")
        .and_then(serde_json::Value::as_str)
        .expect("grpc config token")
        .to_string();
    let cert_pem = parsed
        .get("cert")
        .and_then(serde_json::Value::as_str)
        .expect("grpc config cert")
        .to_string();

    RunningGrpc {
        _tempdir: tempdir,
        token,
        cert_pem,
        port,
        handle: Some(handle),
    }
}

async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind temp port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

async fn free_port_excluding(excluded: &[u16]) -> u16 {
    loop {
        let candidate = free_port().await;
        if !excluded.contains(&candidate) {
            return candidate;
        }
    }
}

fn seed_fake_account(runtime_paths: &RuntimePaths) {
    let session = Session {
        uid: "uid-runtime-events-e2e".to_string(),
        access_token: "access-token".to_string(),
        refresh_token: "refresh-token".to_string(),
        email: "runtime-events-e2e@example.com".to_string(),
        display_name: "Runtime Events E2E".to_string(),
        api_mode: ApiMode::Bridge,
        key_passphrase: None,
        bridge_password: Some("bridge-password".to_string()),
    };
    vault::save_session(&session, runtime_paths.settings_dir()).expect("seed fake session");
    vault::set_gluon_key_by_account_id(runtime_paths.settings_dir(), &session.uid, vec![3u8; 32])
        .expect("seed fake gluon key");
}

async fn next_update_event(
    stream: &mut tonic::Streaming<pb::StreamEvent>,
) -> pb::update_event::Event {
    loop {
        let next = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("event stream timeout")
            .expect("event stream status")
            .expect("event stream ended unexpectedly");

        if let Some(pb::stream_event::Event::Update(update)) = next.event {
            if let Some(event) = update.event {
                return event;
            }
        }
    }
}

async fn next_mail_settings_event(
    stream: &mut tonic::Streaming<pb::StreamEvent>,
) -> pb::mail_server_settings_event::Event {
    loop {
        let next = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("event stream timeout")
            .expect("event stream status")
            .expect("event stream ended unexpectedly");

        if let Some(pb::stream_event::Event::MailServerSettings(mail)) = next.event {
            if let Some(event) = mail.event {
                return event;
            }
        }
    }
}

async fn next_mail_settings_error_type(
    stream: &mut tonic::Streaming<pb::StreamEvent>,
) -> pb::MailServerSettingsErrorType {
    loop {
        let next = next_mail_settings_event(stream).await;
        if let pb::mail_server_settings_event::Event::Error(err) = next {
            return pb::MailServerSettingsErrorType::try_from(err.r#type)
                .expect("known mail settings error type");
        }
    }
}

async fn next_app_event(stream: &mut tonic::Streaming<pb::StreamEvent>) -> pb::app_event::Event {
    loop {
        let next = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("event stream timeout")
            .expect("event stream status")
            .expect("event stream ended unexpectedly");

        if let Some(pb::stream_event::Event::App(app)) = next.event {
            if let Some(event) = app.event {
                return event;
            }
        }
    }
}

#[tokio::test]
async fn runtime_events_check_update_emits_is_latest_then_finished() {
    let runtime = start_runtime().await;

    let mut event_client = runtime.connect().await;
    let mut control_client = runtime.connect().await;

    let mut stream = event_client
        .run_event_stream(req_with_token(
            pb::EventStreamRequest {
                client_platform: String::new(),
            },
            &runtime.token,
        ))
        .await
        .expect("run event stream")
        .into_inner();

    control_client
        .check_update(req_with_token((), &runtime.token))
        .await
        .expect("check update call");

    let first = next_update_event(&mut stream).await;
    assert!(matches!(first, pb::update_event::Event::IsLatestVersion(_)));

    let second = next_update_event(&mut stream).await;
    assert!(matches!(second, pb::update_event::Event::CheckFinished(_)));

    runtime.shutdown().await;
}

#[tokio::test]
async fn runtime_events_mail_settings_changed_then_finished_in_order() {
    let runtime = start_runtime().await;

    let mut event_client = runtime.connect().await;
    let mut control_client = runtime.connect().await;

    let mut stream = event_client
        .run_event_stream(req_with_token(
            pb::EventStreamRequest {
                client_platform: String::new(),
            },
            &runtime.token,
        ))
        .await
        .expect("run event stream")
        .into_inner();

    let requested = pb::ImapSmtpSettings {
        imap_port: i32::from(free_port().await),
        smtp_port: i32::from(free_port().await),
        use_ssl_for_imap: true,
        use_ssl_for_smtp: true,
    };

    control_client
        .set_mail_server_settings(req_with_token(requested, &runtime.token))
        .await
        .expect("set mail server settings");

    let first = next_mail_settings_event(&mut stream).await;
    match first {
        pb::mail_server_settings_event::Event::MailServerSettingsChanged(changed) => {
            let settings = changed.settings.expect("changed settings payload");
            assert_eq!(settings.imap_port, requested.imap_port);
            assert_eq!(settings.smtp_port, requested.smtp_port);
            assert_eq!(settings.use_ssl_for_imap, requested.use_ssl_for_imap);
            assert_eq!(settings.use_ssl_for_smtp, requested.use_ssl_for_smtp);
        }
        other => panic!("expected MailServerSettingsChanged, got {other:?}"),
    }

    let second = next_mail_settings_event(&mut stream).await;
    assert!(matches!(
        second,
        pb::mail_server_settings_event::Event::ChangeMailServerSettingsFinished(_)
    ));

    runtime.shutdown().await;
}

#[tokio::test]
async fn runtime_events_gui_ready_emits_all_users_loaded_then_main_window() {
    let runtime = start_runtime().await;

    let mut event_client = runtime.connect().await;
    let mut control_client = runtime.connect().await;

    let mut stream = event_client
        .run_event_stream(req_with_token(
            pb::EventStreamRequest {
                client_platform: String::new(),
            },
            &runtime.token,
        ))
        .await
        .expect("run event stream")
        .into_inner();

    let response = control_client
        .gui_ready(req_with_token((), &runtime.token))
        .await
        .expect("gui ready call")
        .into_inner();
    assert!(response.show_splash_screen);

    let first = next_app_event(&mut stream).await;
    assert!(matches!(first, pb::app_event::Event::AllUsersLoaded(_)));

    let second = next_app_event(&mut stream).await;
    assert!(matches!(second, pb::app_event::Event::ShowMainWindow(_)));

    runtime.shutdown().await;
}

#[tokio::test]
async fn runtime_events_startup_port_conflict_emits_startup_error_and_grpc_is_reachable() {
    let occupied_imap_port = free_port().await;
    let _occupied_imap_listener = tokio::net::TcpListener::bind(("127.0.0.1", occupied_imap_port))
        .await
        .expect("occupy startup imap port");
    let smtp_port = free_port().await;
    let runtime = start_runtime_with_mail_settings(pb::ImapSmtpSettings {
        imap_port: i32::from(occupied_imap_port),
        smtp_port: i32::from(smtp_port),
        use_ssl_for_imap: true,
        use_ssl_for_smtp: true,
    })
    .await;

    let mut event_client = runtime.connect().await;
    let mut control_client = runtime.connect().await;

    let mut stream = event_client
        .run_event_stream(req_with_token(
            pb::EventStreamRequest {
                client_platform: String::new(),
            },
            &runtime.token,
        ))
        .await
        .expect("run event stream")
        .into_inner();

    let startup_error = next_mail_settings_error_type(&mut stream).await;
    assert_eq!(
        startup_error,
        pb::MailServerSettingsErrorType::ImapPortStartupError
    );

    control_client
        .version(req_with_token((), &runtime.token))
        .await
        .expect("grpc should stay reachable after startup mail-runtime failure");

    runtime.shutdown().await;
}

#[tokio::test]
async fn runtime_events_mail_settings_conflict_emits_change_error_and_keeps_previous_runtime() {
    let initial_imap_port = free_port().await;
    let initial_smtp_port = free_port().await;
    let runtime = start_runtime_with_mail_settings(pb::ImapSmtpSettings {
        imap_port: i32::from(initial_imap_port),
        smtp_port: i32::from(initial_smtp_port),
        use_ssl_for_imap: true,
        use_ssl_for_smtp: true,
    })
    .await;

    let mut event_client = runtime.connect().await;
    let mut control_client = runtime.connect().await;

    let mut stream = event_client
        .run_event_stream(req_with_token(
            pb::EventStreamRequest {
                client_platform: String::new(),
            },
            &runtime.token,
        ))
        .await
        .expect("run event stream")
        .into_inner();

    let occupied_imap_port = free_port_excluding(&[initial_imap_port]).await;
    let _occupied_imap_listener = tokio::net::TcpListener::bind(("127.0.0.1", occupied_imap_port))
        .await
        .expect("occupy imap change port");

    let requested = pb::ImapSmtpSettings {
        imap_port: i32::from(occupied_imap_port),
        smtp_port: i32::from(free_port_excluding(&[initial_smtp_port]).await),
        use_ssl_for_imap: true,
        use_ssl_for_smtp: true,
    };
    let status = control_client
        .set_mail_server_settings(req_with_token(requested, &runtime.token))
        .await
        .expect_err("port conflict should reject settings update");
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);

    let change_error = next_mail_settings_error_type(&mut stream).await;
    assert_eq!(
        change_error,
        pb::MailServerSettingsErrorType::ImapPortChangeError
    );

    let persisted = control_client
        .mail_server_settings(req_with_token((), &runtime.token))
        .await
        .expect("mail settings call")
        .into_inner();
    assert_eq!(persisted.imap_port, i32::from(initial_imap_port));
    assert_eq!(persisted.smtp_port, i32::from(initial_smtp_port));

    runtime.shutdown().await;
}
