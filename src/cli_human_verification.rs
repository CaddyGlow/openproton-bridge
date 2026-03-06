use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context};
use reqwest::Url;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::api::types::HumanVerificationDetails;

const CAPTCHA_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_BYTES: usize = 16 * 1024;

pub async fn prompt_for_token(
    details: &HumanVerificationDetails,
) -> anyhow::Result<Option<String>> {
    let challenge_url = details.challenge_url();
    let server = CaptchaCaptureServer::start(challenge_url.clone()).await;

    match server {
        Ok(mut server) => {
            let local_url = server.local_url();
            let opened = open_in_browser(&local_url);

            eprintln!("Human verification required by Proton.");
            eprintln!("Local verification page URL:");
            eprintln!("{local_url}");
            eprintln!("OPENPROTON_HV_LOCAL_URL={local_url}");
            if opened {
                eprintln!(
                    "A local verification page was opened in your browser. Complete the challenge and the CLI will continue automatically."
                );
            } else {
                eprintln!(
                    "Open the local verification page in your browser to continue automatically:"
                );
            }
            eprintln!("Original Proton verification URL:");
            eprintln!("{challenge_url}");
            eprintln!("OPENPROTON_HV_VERIFY_URL={challenge_url}");
            eprintln!("Waiting for verification token...");
            let _ = std::io::stderr().flush();

            match server.wait_for_token().await {
                Ok(token) => {
                    eprintln!("Verification token received. Retrying authentication...");
                    server.close().await;
                    Ok(Some(token))
                }
                Err(err) => {
                    warn!(error = %err, "automatic CAPTCHA token capture failed");
                    eprintln!(
                        "Automatic token capture did not complete. Falling back to manual token entry."
                    );
                    server.close().await;
                    prompt_for_manual_token(&challenge_url)
                }
            }
        }
        Err(err) => {
            warn!(error = %err, "failed to start local human verification helper");
            eprintln!(
                "Could not start the local browser helper. Falling back to manual token entry."
            );
            prompt_for_manual_token(&challenge_url)
        }
    }
}

fn prompt_for_manual_token(challenge_url: &str) -> anyhow::Result<Option<String>> {
    eprintln!("Open this URL in your browser and complete the challenge:");
    eprintln!("{challenge_url}");
    eprint!("Paste CAPTCHA token from browser (optional, press ENTER to reuse URL token): ");
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("failed to read optional human verification token")?;
    let token = line.trim().to_string();
    if token.is_empty() {
        Ok(None)
    } else {
        Ok(Some(token))
    }
}

struct CaptchaCaptureServer {
    local_url: String,
    token_rx: Option<oneshot::Receiver<String>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl CaptchaCaptureServer {
    async fn start(challenge_url: String) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .context("failed to bind local verification helper")?;
        let local_addr = listener.local_addr()?;
        let local_url = format!("http://127.0.0.1:{}/captcha", local_addr.port());

        let (token_tx, token_rx) = oneshot::channel();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let token_tx = Arc::new(Mutex::new(Some(token_tx)));

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let Ok((stream, _)) = accept else {
                            break;
                        };
                        let token_tx = Arc::clone(&token_tx);
                        let challenge_url = challenge_url.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(stream, &challenge_url, token_tx).await {
                                debug!(error = %err, "human verification helper connection failed");
                            }
                        });
                    }
                }
            }
        });

        Ok(Self {
            local_url,
            token_rx: Some(token_rx),
            shutdown_tx: Some(shutdown_tx),
            task: Some(task),
        })
    }

    fn local_url(&self) -> String {
        self.local_url.clone()
    }

    async fn wait_for_token(&mut self) -> anyhow::Result<String> {
        let receiver = self
            .token_rx
            .as_mut()
            .context("verification helper receiver missing")?;
        match timeout(CAPTCHA_TIMEOUT, receiver).await {
            Ok(Ok(token)) => Ok(token),
            Ok(Err(_)) => Err(anyhow!(
                "verification helper closed before delivering a token"
            )),
            Err(_) => Err(anyhow!("verification helper timed out after 5 minutes")),
        }
    }

    async fn close(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    challenge_url: &str,
    token_tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
) -> anyhow::Result<()> {
    let request = read_request(&mut stream).await?;
    let target = parse_request_target(&request).context("missing request target")?;
    let path = parse_request_path(target).context("invalid request target")?;

    match path.path() {
        "/" | "/captcha" => {
            let page = build_local_capture_page(challenge_url)?;
            write_response(
                &mut stream,
                "200 OK",
                &[
                    ("Content-Type", "text/html; charset=utf-8"),
                    ("Cache-Control", "no-store"),
                ],
                page.as_bytes(),
            )
            .await?;
        }
        "/callback" => {
            if let Some(token) = path
                .query_pairs()
                .find_map(|(key, value)| (key == "token").then(|| value.into_owned()))
                .filter(|token| !token.trim().is_empty())
            {
                if let Some(sender) = token_tx.lock().ok().and_then(|mut guard| guard.take()) {
                    let _ = sender.send(token);
                }
            }
            write_response(
                &mut stream,
                "200 OK",
                &[("Content-Type", "text/plain; charset=utf-8")],
                b"OK",
            )
            .await?;
        }
        "/favicon.ico" => {
            write_response(&mut stream, "204 No Content", &[], b"").await?;
        }
        _ => {
            write_response(
                &mut stream,
                "404 Not Found",
                &[("Content-Type", "text/plain; charset=utf-8")],
                b"Not Found",
            )
            .await?;
        }
    }

    Ok(())
}

async fn read_request(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];

    loop {
        let read = timeout(REQUEST_TIMEOUT, stream.read(&mut chunk))
            .await
            .context("timed out reading verification helper request")??;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() >= MAX_REQUEST_BYTES {
            anyhow::bail!("verification helper request exceeded {MAX_REQUEST_BYTES} bytes");
        }
    }

    Ok(request)
}

fn parse_request_target(request: &[u8]) -> Option<&str> {
    let request = std::str::from_utf8(request).ok()?;
    let mut parts = request.lines().next()?.split_whitespace();
    let _method = parts.next()?;
    parts.next()
}

fn parse_request_path(target: &str) -> Option<Url> {
    Url::parse(&format!("http://127.0.0.1{target}")).ok()
}

fn with_force_web_messaging(challenge_url: &str) -> anyhow::Result<String> {
    let mut url = Url::parse(challenge_url).context("invalid Proton verification URL")?;
    let has_force_flag = url.query_pairs().any(|(key, _)| key == "ForceWebMessaging");
    if !has_force_flag {
        url.query_pairs_mut().append_pair("ForceWebMessaging", "1");
    }
    Ok(url.into())
}

fn build_local_capture_page(challenge_url: &str) -> anyhow::Result<String> {
    let verify_url = with_force_web_messaging(challenge_url)?;
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenProton Verification Helper</title>
  <style>
    body {{ margin: 0; font-family: system-ui, sans-serif; background: #f6f8fa; color: #1f2328; }}
    .banner {{ position: fixed; top: 0; left: 0; right: 0; z-index: 2; padding: 12px 16px; background: #0b1020; color: #fff; border-bottom: 2px solid #2f6feb; }}
    .tools {{ margin-top: 64px; padding: 10px 16px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }}
    .btn {{ border: 1px solid #d0d7de; border-radius: 6px; background: #fff; padding: 8px 12px; cursor: pointer; }}
    .frame {{ width: 100%; height: calc(100vh - 130px); border: 0; background: #fff; }}
    code {{ background: #eaedf0; padding: 2px 4px; border-radius: 4px; }}
  </style>
</head>
<body>
  <div id="opb-hv-banner" class="banner">
    Complete the Proton verification challenge below. Token capture is automatic.
  </div>
  <div class="tools">
    <button id="open-popup" class="btn" type="button">Open In New Tab</button>
    <span>If the embedded view is blocked, open <code id="verify-url"></code> in a new tab.</span>
  </div>
  <iframe id="verify-frame" class="frame" referrerpolicy="no-referrer"></iframe>
  <script>
  (function () {{
    const verifyUrl = {verify_url:?};
    const frame = document.getElementById('verify-frame');
    const banner = document.getElementById('opb-hv-banner');
    const code = document.getElementById('verify-url');
    const popupBtn = document.getElementById('open-popup');
    code.textContent = verifyUrl;
    frame.src = verifyUrl;
    let delivered = false;
    function mark(msg, ok) {{
      banner.textContent = msg;
      banner.style.borderColor = ok ? '#2da44e' : '#bf8700';
    }}
    function submitToken(token) {{
      if (delivered || !token) return;
      delivered = true;
      fetch('/callback?token=' + encodeURIComponent(token), {{ cache: 'no-store' }})
        .then(function () {{ mark('Verification complete. You can close this tab.', true); }})
        .catch(function () {{
          delivered = false;
          mark('Captured token but failed to deliver to CLI. Keep this page open and retry.', false);
        }});
    }}
    window.addEventListener('message', function (event) {{
      if (typeof event.data === 'string' && event.data.length > 10) {{
        submitToken(event.data);
        return;
      }}
      if (event.data && typeof event.data === 'object') {{
        if (typeof event.data.token === 'string') submitToken(event.data.token);
        if (event.data.payload && typeof event.data.payload.token === 'string') submitToken(event.data.payload.token);
      }}
    }});
    popupBtn.addEventListener('click', function () {{
      const popup = window.open(verifyUrl, '_blank');
      if (!popup) {{
        mark('Popup blocked. Open URL manually: ' + verifyUrl, false);
      }}
    }});
    mark('Waiting for verification token...', false);
  }})();
  </script>
</body>
</html>"#
    );
    Ok(html)
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> anyhow::Result<()> {
    let mut response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
    for (name, value) in headers {
        response.push_str(name);
        response.push_str(": ");
        response.push_str(value);
        response.push_str("\r\n");
    }
    response.push_str("Connection: close\r\n\r\n");

    timeout(REQUEST_TIMEOUT, stream.write_all(response.as_bytes()))
        .await
        .context("timed out writing verification helper response headers")??;
    if !body.is_empty() {
        timeout(REQUEST_TIMEOUT, stream.write_all(body))
            .await
            .context("timed out writing verification helper response body")??;
    }
    let _ = stream.shutdown().await;
    Ok(())
}

fn open_in_browser(url: &str) -> bool {
    #[cfg(target_os = "macos")]
    let command = ("open", vec![url]);
    #[cfg(target_os = "windows")]
    let command = ("cmd", vec!["/C", "start", "", url]);
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let command = ("xdg-open", vec![url]);

    std::process::Command::new(command.0)
        .args(command.1)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_force_web_messaging_preserves_existing_query() {
        let url =
            with_force_web_messaging("https://verify.proton.me/?methods=captcha&token=token-123")
                .expect("url");
        assert!(url.contains("methods=captcha"));
        assert!(url.contains("token=token-123"));
        assert!(url.contains("ForceWebMessaging=1"));
    }

    #[test]
    fn build_local_capture_page_contains_verify_url_and_callback_hook() {
        let page = build_local_capture_page(
            "https://verify.proton.me/?methods=captcha&token=token-123",
        )
        .expect("page");

        assert!(page.contains("iframe"));
        assert!(page.contains("ForceWebMessaging=1"));
        assert!(page.contains("window.addEventListener('message'"));
        assert!(page.contains("fetch('/callback?token=' + encodeURIComponent(token)"));
    }

    #[test]
    fn parse_request_path_decodes_callback_token() {
        let parsed = parse_request_path("/callback?token=pm%5Fcaptcha%20token").expect("parsed");
        let token = parsed
            .query_pairs()
            .find_map(|(key, value)| (key == "token").then(|| value.into_owned()))
            .expect("token");
        assert_eq!(token, "pm_captcha token");
    }
}
