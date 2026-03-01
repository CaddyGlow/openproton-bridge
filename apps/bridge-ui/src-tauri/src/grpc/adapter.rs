use super::config::{resolve_server_config_path, write_temp_client_token_file, GrpcServerConfig};
use super::pb;
use crate::state::AppState;
use serde::Serialize;
use std::path::Path;
use tauri::{AppHandle, Emitter};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::service::interceptor::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Status};
use uuid::Uuid;

type BridgeClient = pb::bridge_client::BridgeClient<InterceptedService<Channel, TokenInterceptor>>;

#[derive(Debug, Clone)]
struct TokenInterceptor {
    token: MetadataValue<Ascii>,
}

impl TokenInterceptor {
    fn new(token: &str) -> Result<Self, String> {
        let token_value = token
            .parse::<MetadataValue<Ascii>>()
            .map_err(|err| format!("invalid grpc server token: {err}"))?;

        Ok(Self { token: token_value })
    }
}

impl Interceptor for TokenInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        request
            .metadata_mut()
            .insert("server-token", self.token.clone());
        Ok(request)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamTickEvent {
    pub timestamp: String,
    pub message: String,
}

#[derive(Default)]
pub struct GrpcAdapter {
    stream_task: Option<JoinHandle<()>>,
    stop_tx: Option<oneshot::Sender<()>>,
    server_config: Option<GrpcServerConfig>,
}

impl GrpcAdapter {
    pub async fn connect(&mut self, app: AppHandle, state: AppState) -> Result<(), String> {
        if self.stream_task.is_some() {
            return Ok(());
        }

        let explicit_path = state.snapshot().await.config_path;
        let config_path = resolve_server_config_path(explicit_path.as_deref().map(Path::new))?;
        let server_config = GrpcServerConfig::from_json_file(&config_path)?;

        let mut client = connect_client(&server_config).await?;
        check_tokens(&mut client).await?;

        let request = pb::EventStreamRequest {
            client_platform: client_platform_name(),
        };
        let mut stream = client
            .run_event_stream(Request::new(request))
            .await
            .map_err(|err| format!("RunEventStream failed: {err}"))?
            .into_inner();

        state
            .update(|snapshot| {
                snapshot.connected = true;
                snapshot.stream_running = true;
                snapshot.last_error = None;
                snapshot.config_path = Some(config_path.display().to_string());
            })
            .await;

        let (stop_tx, mut stop_rx) = oneshot::channel();
        self.stop_tx = Some(stop_tx);
        self.server_config = Some(server_config);

        self.stream_task = Some(tokio::spawn(async move {
            let mut stream_error: Option<String> = None;

            loop {
                tokio::select! {
                    _ = &mut stop_rx => {
                        break;
                    }
                    next_item = stream.message() => {
                        match next_item {
                            Ok(Some(event)) => {
                                let payload = StreamTickEvent {
                                    timestamp: unix_timestamp_string(),
                                    message: summarize_stream_event(&event),
                                };
                                let _ = app.emit("bridge://stream-tick", payload);
                            }
                            Ok(None) => {
                                break;
                            }
                            Err(err) => {
                                stream_error = Some(format!("event stream error: {err}"));
                                break;
                            }
                        }
                    }
                }
            }

            let snapshot = state
                .update(|snapshot| {
                    snapshot.connected = false;
                    snapshot.stream_running = false;
                    if let Some(err) = stream_error.clone() {
                        snapshot.last_error = Some(err);
                    }
                })
                .await;

            let _ = app.emit("bridge://state-changed", snapshot);
        }));

        Ok(())
    }

    pub async fn disconnect(&mut self) {
        if let Some(config) = self.server_config.clone() {
            if let Ok(mut client) = connect_client(&config).await {
                let _ = client.stop_event_stream(()).await;
            }
        }

        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }

        if let Some(handle) = self.stream_task.take() {
            let _ = handle.await;
        }

        self.server_config = None;
    }
}

async fn connect_client(config: &GrpcServerConfig) -> Result<BridgeClient, String> {
    let port = match config.port {
        Some(port) => port,
        None => {
            if let Some(socket_path) = &config.file_socket_path {
                return Err(format!(
                    "grpc unix socket is not implemented yet in this UI adapter ({socket_path})"
                ));
            }

            return Err("grpc config is missing both port and fileSocketPath".to_string());
        }
    };

    let endpoint_url = format!("https://127.0.0.1:{port}");

    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(config.cert.clone()))
        .domain_name("127.0.0.1");

    let endpoint = Endpoint::from_shared(endpoint_url)
        .map_err(|err| format!("invalid grpc endpoint: {err}"))?
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .tls_config(tls)
        .map_err(|err| format!("failed to configure grpc tls: {err}"))?;

    let channel = endpoint
        .connect()
        .await
        .map_err(|err| format!("failed to connect grpc channel: {err}"))?;

    let interceptor = TokenInterceptor::new(&config.token)?;

    Ok(pb::bridge_client::BridgeClient::with_interceptor(
        channel,
        interceptor,
    ))
}

async fn check_tokens(client: &mut BridgeClient) -> Result<(), String> {
    let client_token = Uuid::new_v4().to_string();
    let token_file = write_temp_client_token_file(&client_token)?;

    let response: tonic::Response<String> = client
        .check_tokens(token_file.display().to_string())
        .await
        .map_err(|err| format!("CheckTokens failed: {err}"))?;

    let returned_token = response.into_inner();
    let result = if returned_token == client_token {
        Ok(())
    } else {
        Err("CheckTokens returned unexpected client token".to_string())
    };

    let _ = std::fs::remove_file(&token_file);

    result
}

fn summarize_stream_event(event: &pb::StreamEvent) -> String {
    let name = match event.event.as_ref() {
        Some(pb::stream_event::Event::App(_)) => "app",
        Some(pb::stream_event::Event::Login(_)) => "login",
        Some(pb::stream_event::Event::Update(_)) => "update",
        Some(pb::stream_event::Event::Cache(_)) => "cache",
        Some(pb::stream_event::Event::MailServerSettings(_)) => "mail_server_settings",
        Some(pb::stream_event::Event::Keychain(_)) => "keychain",
        Some(pb::stream_event::Event::Mail(_)) => "mail",
        Some(pb::stream_event::Event::User(_)) => "user",
        Some(pb::stream_event::Event::GenericError(_)) => "generic_error",
        None => "none",
    };

    format!("stream event: {name}")
}

fn client_platform_name() -> String {
    format!("{}-tauri", std::env::consts::OS)
}

fn unix_timestamp_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    format!("[{now}]")
}
