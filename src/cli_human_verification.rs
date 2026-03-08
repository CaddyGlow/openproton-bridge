use std::io::Write;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context};
use regex::Regex;
use reqwest::redirect::Policy;
use reqwest::Url;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::api::types::HumanVerificationDetails;

const CAPTCHA_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;

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
        let challenge_with_force = with_force_web_messaging(&challenge_url)?;
        let parsed_challenge =
            Url::parse(&challenge_with_force).context("invalid Proton verification URL")?;
        let local_path = match parsed_challenge.query() {
            Some(query) if !query.trim().is_empty() => format!("/captcha?{query}"),
            _ => "/captcha".to_string(),
        };
        let local_url = format!("http://127.0.0.1:{}{local_path}", local_addr.port());

        let (token_tx, token_rx) = oneshot::channel();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let token_tx = Arc::new(Mutex::new(Some(token_tx)));
        let proxy_client = Arc::new(
            reqwest::Client::builder()
                .redirect(Policy::limited(10))
                .cookie_store(true)
                .build()
                .context("failed to build verification helper proxy HTTP client")?,
        );

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let Ok((stream, _)) = accept else {
                            break;
                        };
                        let token_tx = Arc::clone(&token_tx);
                        let proxy_client = Arc::clone(&proxy_client);
                        let challenge_with_force = challenge_with_force.clone();
                        let local_path = local_path.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(
                                stream,
                                &challenge_with_force,
                                &local_path,
                                &proxy_client,
                                token_tx,
                            )
                            .await
                            {
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
    initial_local_target: &str,
    proxy_client: &reqwest::Client,
    token_tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
) -> anyhow::Result<()> {
    let request = read_request(&mut stream).await?;
    let method = parse_request_method(&request).context("missing request method")?;
    let target = parse_request_target(&request).context("missing request target")?;
    let path = parse_request_path(target).context("invalid request target")?;

    match path.path() {
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
                &[(
                    "Content-Type".to_string(),
                    "text/plain; charset=utf-8".to_string(),
                )],
                b"OK",
            )
            .await?;
        }
        "/favicon.ico" => {
            write_response(&mut stream, "204 No Content", &Vec::new(), b"").await?;
        }
        _ => {
            let proxied = proxy_request(
                proxy_client,
                challenge_url,
                initial_local_target,
                method,
                target,
                &request,
            )
            .await?;
            write_response(
                &mut stream,
                &proxied.status_line,
                &proxied.headers,
                &proxied.body,
            )
            .await?;
        }
    }

    Ok(())
}

async fn read_request(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let mut expected_total_len: Option<usize> = None;

    loop {
        let read = timeout(REQUEST_TIMEOUT, stream.read(&mut chunk))
            .await
            .context("timed out reading verification helper request")??;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if expected_total_len.is_none() {
            if let Some(header_end) = find_header_end(&request) {
                let content_length = parse_content_length(&request).unwrap_or(0);
                expected_total_len = Some(header_end + 4 + content_length);
            }
        }
        if let Some(total_len) = expected_total_len {
            if request.len() >= total_len {
                break;
            }
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

fn parse_request_method(request: &[u8]) -> Option<&str> {
    let request = std::str::from_utf8(request).ok()?;
    request.lines().next()?.split_whitespace().next()
}

fn parse_request_path(target: &str) -> Option<Url> {
    Url::parse(&format!("http://127.0.0.1{target}")).ok()
}

fn parse_request_headers(request: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(request);
    let mut headers = Vec::new();
    for line in text.lines().skip(1) {
        if line.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    headers
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(request: &[u8]) -> Option<usize> {
    parse_request_headers(request)
        .into_iter()
        .find_map(|(name, value)| {
            if name.eq_ignore_ascii_case("content-length") {
                value.parse::<usize>().ok()
            } else {
                None
            }
        })
}

fn with_force_web_messaging(challenge_url: &str) -> anyhow::Result<String> {
    let mut url = Url::parse(challenge_url).context("invalid Proton verification URL")?;
    let has_force_flag = url.query_pairs().any(|(key, _)| key == "ForceWebMessaging");
    if !has_force_flag {
        url.query_pairs_mut().append_pair("ForceWebMessaging", "1");
    }
    Ok(url.into())
}

#[derive(Debug)]
struct ProxiedResponse {
    status_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn csp_meta_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?is)<meta\s+http-equiv=["']content-security-policy["'][^>]*>"#).unwrap()
    })
}

fn head_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<head\b[^>]*>").unwrap())
}

fn integrity_attr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)\s+integrity\s*=\s*["'][^"']*["']"#).unwrap())
}

fn crossorigin_attr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)\s+crossorigin\s*=\s*["'][^"']*["']"#).unwrap())
}

fn strip_csp_meta_tags(html: &str) -> String {
    csp_meta_re().replace_all(html, "").into_owned()
}

fn strip_integrity_attributes(html: &str) -> String {
    let without_integrity = integrity_attr_re().replace_all(html, "");
    crossorigin_attr_re()
        .replace_all(&without_integrity, "")
        .into_owned()
}

fn inject_token_capture_script(html: &str, challenge_origin: &str, challenge_url: &str) -> String {
    let challenge_origin = serde_json::to_string(challenge_origin)
        .unwrap_or_else(|_| "\"https://verify.proton.me\"".to_string());
    let challenge_url = serde_json::to_string(challenge_url)
        .unwrap_or_else(|_| "\"https://verify.proton.me/captcha\"".to_string());
    let injection = format!(
        r#"
<script>
(() => {{
  if (window.__openProtonCaptchaHookInstalled) {{
    return;
  }}
  window.__openProtonCaptchaHookInstalled = true;

  let delivered = false;
  let fallbackToken = null;
  let fallbackTimer = null;
  const initialChallengeUrl = {challenge_url};
  const localOrigin = window.location.origin;

  function parseToken(payload) {{
    let value = payload;
    if (typeof value === 'string') {{
      try {{
        value = JSON.parse(value);
      }} catch {{
        return null;
      }}
    }}

    if (!value || typeof value !== 'object') {{
      return null;
    }}

    const token =
      value.type === 'pm_captcha' && typeof value.token === 'string' && value.token.length > 0
        ? value.token
        : (
            value.type === 'HUMAN_VERIFICATION_SUCCESS' &&
            value.payload &&
            typeof value.payload === 'object' &&
            value.payload.type === 'captcha' &&
            typeof value.payload.token === 'string' &&
            value.payload.token.length > 0
          )
          ? value.payload.token
          : null;

    if (!token) {{
      return null;
    }}

    return {{ type: value.type, token }};
  }}

  function submitToken(token) {{
    if (delivered || !token) {{
      return;
    }}
    delivered = true;
    fetch('/callback?token=' + encodeURIComponent(token), {{ cache: 'no-store' }})
      .catch(() => {{
        delivered = false;
      }});
  }}

  window.addEventListener('message', (event) => {{
    if (
      event.origin !== localOrigin &&
      event.origin !== {challenge_origin} &&
      event.origin !== 'https://verify-api.proton.me'
    ) {{
      return;
    }}

    const parsed = parseToken(event.data);
    if (!parsed) {{
      return;
    }}

    if (parsed.type === 'pm_captcha') {{
      fallbackToken = parsed.token;
      if (!fallbackTimer) {{
        fallbackTimer = setTimeout(() => {{
          if (fallbackToken) {{
            submitToken(fallbackToken);
          }}
        }}, 2000);
      }}
      return;
    }}

    if (fallbackTimer) {{
      clearTimeout(fallbackTimer);
      fallbackTimer = null;
    }}
    submitToken(parsed.token);
  }});

  if (window.location.pathname === '/') {{
    window.history.replaceState(null, '', initialChallengeUrl);
  }}
}})();
</script>
"#
    );

    if html.contains("</body>") {
        html.replacen("</body>", &format!("{injection}</body>"), 1)
    } else if let Some(head_match) = head_re().find(html) {
        let mut rendered = String::with_capacity(html.len() + injection.len());
        rendered.push_str(&html[..head_match.end()]);
        rendered.push_str(&injection);
        rendered.push_str(&html[head_match.end()..]);
        rendered
    } else {
        format!("{html}{injection}")
    }
}

fn request_body<'a>(request: &'a [u8], header_end: usize) -> &'a [u8] {
    let start = header_end + 4;
    if request.len() <= start {
        &[]
    } else {
        &request[start..]
    }
}

fn upstream_url_for_target(
    challenge_url: &str,
    initial_local_target: &str,
    target: &str,
) -> anyhow::Result<String> {
    let target_path = parse_request_path(target).context("invalid request target path")?;
    let challenge = Url::parse(challenge_url).context("invalid Proton verification URL")?;
    let challenge_path = challenge.path().to_string();

    if target == initial_local_target {
        return Ok(challenge_url.to_string());
    }

    if target_path.path() == "/" {
        let mut upstream = challenge.clone();
        upstream.set_path(&challenge_path);
        upstream.set_query(target_path.query().or_else(|| challenge.query()));
        return Ok(upstream.to_string());
    }

    if target_path.path() == "/captcha" {
        let mut upstream = challenge.clone();
        upstream.set_path("/captcha");
        upstream.set_query(target_path.query().or_else(|| challenge.query()));
        return Ok(upstream.to_string());
    }

    if let Some(captcha_api_path) = target_path.path().strip_prefix("/api/core/v4/captcha") {
        let query_suffix = target_path
            .query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default();
        return Ok(format!(
            "https://verify-api.proton.me/core/v4/captcha{captcha_api_path}{query_suffix}"
        ));
    }

    if let Some(captcha_path) = target_path.path().strip_prefix("/captcha/") {
        let query_suffix = target_path
            .query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default();
        return Ok(format!(
            "https://verify-api.proton.me/captcha/{captcha_path}{query_suffix}"
        ));
    }

    if let Some(api_path) = target_path.path().strip_prefix("/api/") {
        let query_suffix = target_path
            .query()
            .map(|query| format!("?{query}"))
            .unwrap_or_default();
        return Ok(format!(
            "https://mail.proton.me/api/{api_path}{query_suffix}"
        ));
    }

    let origin = challenge.origin().ascii_serialization();
    let path_and_query = match target_path.query() {
        Some(query) => format!("{}?{query}", target_path.path()),
        None => target_path.path().to_string(),
    };
    Ok(format!("{origin}{path_and_query}"))
}

fn should_strip_response_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-security-policy")
        || name.eq_ignore_ascii_case("content-security-policy-report-only")
        || name.eq_ignore_ascii_case("x-frame-options")
        || name.eq_ignore_ascii_case("frame-options")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("transfer-encoding")
}

async fn proxy_request(
    proxy_client: &reqwest::Client,
    challenge_url: &str,
    initial_local_target: &str,
    method: &str,
    target: &str,
    raw_request: &[u8],
) -> anyhow::Result<ProxiedResponse> {
    let upstream_url = upstream_url_for_target(challenge_url, initial_local_target, target)?;
    let method =
        reqwest::Method::from_bytes(method.as_bytes()).context("invalid upstream HTTP method")?;
    let mut builder = proxy_client.request(method, &upstream_url);

    let challenge = Url::parse(challenge_url).context("invalid Proton verification URL")?;
    let challenge_origin = challenge.origin().ascii_serialization();
    let challenge_referer = challenge.as_str().to_string();
    for (name, value) in parse_request_headers(raw_request) {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("accept-encoding")
            || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        if name.eq_ignore_ascii_case("origin") {
            builder = builder.header("Origin", &challenge_origin);
            continue;
        }
        if name.eq_ignore_ascii_case("referer") {
            builder = builder.header("Referer", &challenge_referer);
            continue;
        }
        builder = builder.header(&name, &value);
    }

    let header_end = find_header_end(raw_request).context("incomplete request headers")?;
    let body = request_body(raw_request, header_end);
    if !body.is_empty() {
        builder = builder.body(body.to_vec());
    }

    let response = builder
        .send()
        .await
        .with_context(|| format!("verification helper proxy request failed: {upstream_url}"))?;
    let status = response.status();
    let status_line = format!(
        "{} {}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("Unknown")
    );
    let mut headers = Vec::new();
    for (name, value) in response.headers() {
        if should_strip_response_header(name.as_str()) {
            continue;
        }
        if let Ok(value) = value.to_str() {
            headers.push((name.as_str().to_string(), value.to_string()));
        }
    }
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("cache-control"))
    {
        headers.push(("Cache-Control".to_string(), "no-store".to_string()));
    }

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut body = response
        .bytes()
        .await
        .context("failed to read proxy response body")?
        .to_vec();
    if content_type.contains("text/html") {
        let html = String::from_utf8_lossy(&body);
        let html = strip_csp_meta_tags(&html);
        let html = strip_integrity_attributes(&html);
        body = inject_token_capture_script(&html, &challenge_origin, challenge_url).into_bytes();
    }

    Ok(ProxiedResponse {
        status_line,
        headers,
        body,
    })
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    headers: &[(String, String)],
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
    fn inject_token_capture_script_contains_callback_hook() {
        let page = inject_token_capture_script(
            "<html><body><main>captcha</main></body></html>",
            "https://verify.proton.me",
            "https://verify.proton.me/captcha?methods=captcha&token=token-123",
        );
        assert!(page.contains("window.addEventListener('message'"));
        assert!(page.contains("fetch('/callback?token=' + encodeURIComponent(token)"));
        assert!(page.contains("https://verify.proton.me"));
    }

    #[test]
    fn upstream_url_for_initial_target_uses_challenge_url() {
        let upstream = upstream_url_for_target(
            "https://verify.proton.me/?methods=captcha&token=token-123&ForceWebMessaging=1",
            "/captcha?methods=captcha&token=token-123&ForceWebMessaging=1",
            "/captcha?methods=captcha&token=token-123&ForceWebMessaging=1",
        )
        .expect("upstream");
        assert!(upstream.contains("verify.proton.me"));
        assert!(upstream.contains("ForceWebMessaging=1"));
    }

    #[test]
    fn upstream_url_for_nested_captcha_uses_origin_path() {
        let upstream = upstream_url_for_target(
            "https://verify.proton.me/?methods=captcha&token=token-123&ForceWebMessaging=1",
            "/captcha?methods=captcha&token=token-123&ForceWebMessaging=1",
            "/captcha?token=nested",
        )
        .expect("upstream");
        assert_eq!(upstream, "https://verify.proton.me/captcha?token=nested");
    }

    #[test]
    fn upstream_url_for_root_alias_stays_on_challenge_path() {
        let upstream = upstream_url_for_target(
            "https://verify.proton.me/captcha?methods=captcha&token=token-123&ForceWebMessaging=1",
            "/captcha?methods=captcha&token=token-123&ForceWebMessaging=1",
            "/",
        )
        .expect("upstream");
        assert_eq!(
            upstream,
            "https://verify.proton.me/captcha?methods=captcha&token=token-123&ForceWebMessaging=1"
        );
    }

    #[test]
    fn upstream_url_for_api_captcha_uses_verify_api_origin() {
        let upstream = upstream_url_for_target(
            "https://verify.proton.me/captcha?methods=captcha&token=token-123&ForceWebMessaging=1",
            "/captcha?methods=captcha&token=token-123&ForceWebMessaging=1",
            "/api/core/v4/captcha?Token=token-123&ForceWebMessaging=1",
        )
        .expect("upstream");
        assert_eq!(
            upstream,
            "https://verify-api.proton.me/core/v4/captcha?Token=token-123&ForceWebMessaging=1"
        );
    }

    #[test]
    fn upstream_url_for_captcha_assets_uses_verify_api_origin() {
        let upstream = upstream_url_for_target(
            "https://verify.proton.me/captcha?methods=captcha&token=token-123&ForceWebMessaging=1",
            "/captcha?methods=captcha&token=token-123&ForceWebMessaging=1",
            "/captcha/v1/assets/?purpose=login&token=token-123",
        )
        .expect("upstream");
        assert_eq!(
            upstream,
            "https://verify-api.proton.me/captcha/v1/assets/?purpose=login&token=token-123"
        );
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
