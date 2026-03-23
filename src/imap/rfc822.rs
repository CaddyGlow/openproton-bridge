use crate::api::client::ProtonClient;
use crate::api::messages;
use crate::api::types::Message;
use crate::crypto::decrypt;
use crate::crypto::keys::Keyring;

pub use gluon_rs_mail::rfc822::*;

use super::Result;

/// Build RFC 822 message bytes from a decrypted Proton message.
///
/// Uses the original headers from msg.header + decrypted body.
/// For messages with attachments, builds multipart/mixed.
pub async fn build_rfc822(
    client: &ProtonClient,
    keyring: &Keyring,
    msg: &Message,
) -> Result<Vec<u8>> {
    let decrypted_body = decrypt::decrypt_message_body(keyring, &msg.body)?;
    let body_text = String::from_utf8_lossy(&decrypted_body);

    // Parse and filter original headers - strip content-related headers we will set ourselves
    let filtered_headers = filter_headers(&msg.header);

    let mut output = Vec::new();

    if msg.attachments.is_empty() {
        // Simple message: headers + content-type + body
        output.extend_from_slice(filtered_headers.as_bytes());
        output.extend_from_slice(b"MIME-Version: 1.0\r\n");

        if msg.mime_type == "text/html" {
            output.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n");
        } else {
            output.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
        }
        output.extend_from_slice(b"Content-Transfer-Encoding: 8bit\r\n");
        output.extend_from_slice(b"\r\n");
        output.extend_from_slice(body_text.as_bytes());
    } else {
        // Multipart message with attachments
        let boundary = format!("----=_Part_{:016x}", rand::random::<u64>());

        output.extend_from_slice(filtered_headers.as_bytes());
        output.extend_from_slice(b"MIME-Version: 1.0\r\n");
        output.extend_from_slice(
            format!(
                "Content-Type: multipart/mixed; boundary=\"{}\"\r\n",
                boundary
            )
            .as_bytes(),
        );
        output.extend_from_slice(b"\r\n");

        // Body part
        output.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        if msg.mime_type == "text/html" {
            output.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n");
        } else {
            output.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
        }
        output.extend_from_slice(b"Content-Transfer-Encoding: 8bit\r\n");
        output.extend_from_slice(b"\r\n");
        output.extend_from_slice(body_text.as_bytes());
        output.extend_from_slice(b"\r\n");

        // Attachment parts
        for att in &msg.attachments {
            match fetch_and_decrypt_attachment(client, keyring, &att.key_packets, &att.id).await {
                Ok(att_data) => {
                    output.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
                    output.extend_from_slice(
                        format!("Content-Type: {}; name=\"{}\"\r\n", att.mime_type, att.name)
                            .as_bytes(),
                    );
                    output.extend_from_slice(b"Content-Transfer-Encoding: base64\r\n");
                    output.extend_from_slice(
                        format!(
                            "Content-Disposition: attachment; filename=\"{}\"\r\n",
                            att.name
                        )
                        .as_bytes(),
                    );
                    output.extend_from_slice(b"\r\n");

                    // Base64 encode the attachment data in 76-char lines
                    use base64::engine::general_purpose::STANDARD as BASE64;
                    use base64::Engine;
                    let encoded = BASE64.encode(&att_data);
                    for chunk in encoded.as_bytes().chunks(76) {
                        output.extend_from_slice(chunk);
                        output.extend_from_slice(b"\r\n");
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        attachment_id = %att.id,
                        error = %e,
                        "failed to decrypt attachment, skipping"
                    );
                }
            }
        }

        // Closing boundary
        output.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    }

    Ok(output)
}

async fn fetch_and_decrypt_attachment(
    client: &ProtonClient,
    keyring: &Keyring,
    key_packets_b64: &str,
    attachment_id: &str,
) -> Result<Vec<u8>> {
    let encrypted_data = messages::get_attachment(client, attachment_id).await?;
    let decrypted = decrypt::decrypt_attachment(keyring, key_packets_b64, &encrypted_data)?;
    Ok(decrypted)
}

/// Filter out Content-Type, Content-Transfer-Encoding, MIME-Version from original headers.
fn filter_headers(header: &str) -> String {
    let mut result = String::new();
    let mut skip = false;

    for line in header.split('\n') {
        let line = line.trim_end_matches('\r');

        // Continuation line (starts with whitespace)
        if line.starts_with(' ') || line.starts_with('\t') {
            if !skip {
                result.push_str(line);
                result.push_str("\r\n");
            }
            continue;
        }

        let lower = line.to_lowercase();
        skip = lower.starts_with("content-type:")
            || lower.starts_with("content-transfer-encoding:")
            || lower.starts_with("mime-version:");

        if !skip && !line.is_empty() {
            result.push_str(line);
            result.push_str("\r\n");
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_headers() {
        let header = "From: alice@proton.me\r\nContent-Type: text/html\r\nSubject: Hello\r\nMIME-Version: 1.0\r\nTo: bob@proton.me\r\n";
        let filtered = filter_headers(header);
        assert!(filtered.contains("From: alice@proton.me"));
        assert!(filtered.contains("Subject: Hello"));
        assert!(filtered.contains("To: bob@proton.me"));
        assert!(!filtered.contains("Content-Type"));
        assert!(!filtered.contains("MIME-Version"));
    }

    #[test]
    fn test_filter_headers_multiline() {
        let header = "From: alice@proton.me\r\nContent-Type: multipart/mixed;\r\n boundary=\"abc\"\r\nSubject: Hello\r\n";
        let filtered = filter_headers(header);
        assert!(filtered.contains("From: alice@proton.me"));
        assert!(filtered.contains("Subject: Hello"));
        assert!(!filtered.contains("Content-Type"));
        assert!(!filtered.contains("boundary"));
    }
}
