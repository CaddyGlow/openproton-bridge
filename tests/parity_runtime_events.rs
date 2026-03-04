use std::time::Duration;

use openproton_bridge::frontend::grpc::{self, pb};
use openproton_bridge::paths::RuntimePaths;
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
async fn parity_runtime_events_check_update_emits_is_latest_then_finished() {
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
async fn parity_runtime_events_mail_settings_changed_then_finished_in_order() {
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
async fn parity_runtime_events_gui_ready_emits_all_users_loaded_then_main_window() {
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
