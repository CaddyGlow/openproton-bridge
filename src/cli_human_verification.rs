use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Context};
use regex::{Captures, Regex};
use reqwest::redirect::Policy;
use reqwest::Url;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex as AsyncMutex};
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
        let page_cache = Arc::new(AsyncMutex::new(None::<String>));

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let Ok((stream, _)) = accept else {
                            break;
                        };
                        let token_tx = Arc::clone(&token_tx);
                        let page_cache = Arc::clone(&page_cache);
                        let challenge_url = challenge_url.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_connection(stream, &challenge_url, page_cache, token_tx).await {
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
    page_cache: Arc<AsyncMutex<Option<String>>>,
    token_tx: Arc<Mutex<Option<oneshot::Sender<String>>>>,
) -> anyhow::Result<()> {
    let request = read_request(&mut stream).await?;
    let target = parse_request_target(&request).context("missing request target")?;
    let path = parse_request_path(target).context("invalid request target")?;

    match path.path() {
        "/" | "/captcha" => {
            let page = {
                let mut cached = page_cache.lock().await;
                if let Some(page) = cached.clone() {
                    page
                } else {
                    let page = fetch_and_build_page(challenge_url).await?;
                    *cached = Some(page.clone());
                    page
                }
            };
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

async fn fetch_and_build_page(challenge_url: &str) -> anyhow::Result<String> {
    let proxy_url = with_force_web_messaging(challenge_url)?;
    let client = reqwest::Client::builder()
        .redirect(Policy::limited(10))
        .build()
        .context("failed to build verification helper HTTP client")?;
    let html = client
        .get(proxy_url.clone())
        .header("Accept", "text/html,application/xhtml+xml")
        .header(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        )
        .send()
        .await
        .with_context(|| format!("failed to fetch Proton verification page from {proxy_url}"))?
        .error_for_status()
        .with_context(|| format!("Proton verification page request failed for {proxy_url}"))?
        .text()
        .await
        .context("failed to read Proton verification page body")?;

    build_proxied_captcha_page(challenge_url, &html)
}

fn with_force_web_messaging(challenge_url: &str) -> anyhow::Result<String> {
    let mut url = Url::parse(challenge_url).context("invalid Proton verification URL")?;
    let has_force_flag = url.query_pairs().any(|(key, _)| key == "ForceWebMessaging");
    if !has_force_flag {
        url.query_pairs_mut().append_pair("ForceWebMessaging", "1");
    }
    Ok(url.into())
}

fn build_proxied_captcha_page(challenge_url: &str, html: &str) -> anyhow::Result<String> {
    let url = Url::parse(challenge_url).context("invalid Proton verification URL")?;
    let origin = url.origin().ascii_serialization();

    let mut page = strip_csp_meta_tags(html);
    page = replace_or_insert_base_href(&page, &origin);
    page = integrity_attr_re().replace_all(&page, "").into_owned();
    page = crossorigin_attr_re().replace_all(&page, "").into_owned();
    page = relative_asset_re()
        .replace_all(&page, |captures: &Captures<'_>| {
            format!(r#"{}="{}{}""#, &captures[1], origin, &captures[2])
        })
        .into_owned();

    let injection = r#"
<div id="opb-hv-banner" style="position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#0b1020;color:#ffffff;padding:12px 16px;font-family:system-ui,sans-serif;font-size:14px;line-height:1.4;border-bottom:2px solid #2f6feb;">
    OpenProton Bridge local verification helper is capturing the Proton CAPTCHA token for this CLI session. Complete the challenge below and the terminal will continue automatically.
</div>
<div style="height:58px;"></div>
<script>
(function () {
    let delivered = false;
    function sendToken(token) {
        if (delivered || !token) return;
        delivered = true;
        fetch('/callback?token=' + encodeURIComponent(token), { cache: 'no-store' })
            .then(function () {
                const banner = document.getElementById('opb-hv-banner');
                if (banner) {
                    banner.textContent = 'Verification complete. You can close this tab.';
                    banner.style.borderColor = '#2da44e';
                }
            })
            .catch(function () {
                delivered = false;
            });
    }
    window.addEventListener('message', function (event) {
        if (typeof event.data === 'string' && event.data.length > 10) {
            sendToken(event.data);
            return;
        }
        if (event.data && typeof event.data === 'object' && typeof event.data.token === 'string') {
            sendToken(event.data.token);
        }
    });
})();
</script>
"#;

    if page.contains("</body>") {
        Ok(page.replacen("</body>", &format!("{injection}</body>"), 1))
    } else {
        Ok(format!("{page}{injection}"))
    }
}

fn strip_csp_meta_tags(html: &str) -> String {
    let mut output = String::with_capacity(html.len());
    let mut index = 0;
    let lower = html.to_ascii_lowercase();

    while let Some(relative_start) = lower[index..].find("<meta") {
        let start = index + relative_start;
        output.push_str(&html[index..start]);
        let Some(relative_end) = lower[start..].find('>') else {
            output.push_str(&html[start..]);
            return output;
        };
        let end = start + relative_end + 1;
        let tag = &lower[start..end];
        if !tag.contains("content-security-policy") {
            output.push_str(&html[start..end]);
        }
        index = end;
    }

    output.push_str(&html[index..]);
    output
}

fn replace_or_insert_base_href(html: &str, origin: &str) -> String {
    let base_tag = format!(r#"<base href="{origin}/">"#);
    if base_tag_re().is_match(html) {
        base_tag_re().replace(html, base_tag).into_owned()
    } else if head_re().is_match(html) {
        head_re()
            .replace(html, format!("<head>{base_tag}"))
            .into_owned()
    } else {
        format!("{base_tag}{html}")
    }
}

fn base_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)<base\s+href=["'][^"']*["'][^>]*>"#).unwrap())
}

fn head_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)<head>"#).unwrap())
}

fn integrity_attr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\s+integrity=["'][^"']*["']"#).unwrap())
}

fn crossorigin_attr_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\s+crossorigin(?:=["'][^"']*["'])?"#).unwrap())
}

fn relative_asset_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(src|href)=["'](/[^"']*)["']"#).unwrap())
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
    fn build_proxied_page_rewrites_html_for_local_proxy() {
        let html = r#"<!doctype html>
<html>
<head>
<meta http-equiv="content-security-policy" content="default-src 'self'">
<base href="/">
<link rel="modulepreload" href="/assets/app.js" integrity="sha256-abc" crossorigin="anonymous">
</head>
<body>
<script src="/assets/main.js" integrity="sha256-def" crossorigin></script>
</body>
</html>"#;

        let page = build_proxied_captcha_page(
            "https://verify.proton.me/?methods=captcha&token=token-123",
            html,
        )
        .expect("page");

        assert!(!page.contains("content-security-policy"));
        assert!(page.contains(r#"<base href="https://verify.proton.me/">"#));
        assert!(page.contains(r#"href="https://verify.proton.me/assets/app.js""#));
        assert!(page.contains(r#"src="https://verify.proton.me/assets/main.js""#));
        assert!(!page.contains("integrity="));
        assert!(!page.contains("crossorigin"));
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
