use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use tracing::info;

use crate::api::client::ProtonClient;
use crate::api::keys::get_public_keys;
use crate::api::messages::{create_draft, send_draft, UploadAttachmentReq};
use crate::api::types::{
    Address, CreateDraftReq, DraftTemplate, EmailAddress, MessagePackage, MessageRecipient,
    SendDraftReq, SessionKeyInfo, CLEAR_SCHEME, DETACHED_SIGNATURE, INTERNAL_SCHEME, NO_SIGNATURE,
    RECIPIENT_INTERNAL,
};
use crate::crypto::encrypt::{enc_split, encrypt_attachment, encrypt_session_key, sign_detached};
use crate::crypto::keys::Keyring;

use super::Result;
use super::SmtpError;

use openpgp::parse::Parse;

/// Parsed RFC 822 message ready for sending.
pub struct ParsedMessage {
    pub subject: String,
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub body: String,
    pub mime_type: String,
    pub attachments: Vec<ParsedAttachment>,
}

/// A parsed attachment from an RFC 822 message.
pub struct ParsedAttachment {
    pub filename: String,
    pub mime_type: String,
    pub disposition: String,
    pub content_id: String,
    pub data: Vec<u8>,
}

/// Parse an RFC 822 message from raw bytes.
pub fn parse_rfc822(raw: &[u8]) -> Result<ParsedMessage> {
    let parsed = mailparse::parse_mail(raw)
        .map_err(|e| SmtpError::MessageParse(format!("mailparse: {}", e)))?;

    let headers = &parsed.headers;

    let subject = headers
        .iter()
        .find(|h| h.get_key().eq_ignore_ascii_case("Subject"))
        .map(|h| h.get_value())
        .unwrap_or_default();

    let from = headers
        .iter()
        .find(|h| h.get_key().eq_ignore_ascii_case("From"))
        .map(|h| h.get_value())
        .unwrap_or_default();

    let to = parse_address_list(headers, "To");
    let cc = parse_address_list(headers, "Cc");
    let bcc = parse_address_list(headers, "Bcc");

    let (body, mime_type, attachments) = extract_body_and_attachments(&parsed)?;

    Ok(ParsedMessage {
        subject,
        from,
        to,
        cc,
        bcc,
        body,
        mime_type,
        attachments,
    })
}

fn parse_address_list(headers: &[mailparse::MailHeader], name: &str) -> Vec<String> {
    headers
        .iter()
        .find(|h| h.get_key().eq_ignore_ascii_case(name))
        .map(|h| {
            let value = h.get_value();
            mailparse::addrparse(&value)
                .map(|addrs| {
                    addrs
                        .iter()
                        .flat_map(|a| match a {
                            mailparse::MailAddr::Single(info) => vec![info.addr.clone()],
                            mailparse::MailAddr::Group(group) => {
                                group.addrs.iter().map(|a| a.addr.clone()).collect()
                            }
                        })
                        .collect()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default()
}

fn extract_body_and_attachments(
    parsed: &mailparse::ParsedMail,
) -> Result<(String, String, Vec<ParsedAttachment>)> {
    let mut body = String::new();
    let mut mime_type = "text/plain".to_string();
    let mut attachments = Vec::new();

    if parsed.subparts.is_empty() {
        // Simple message
        body = parsed
            .get_body()
            .map_err(|e| SmtpError::MessageParse(format!("body: {}", e)))?;
        mime_type = parsed.ctype.mimetype.clone();
    } else {
        // Multipart message
        for part in &parsed.subparts {
            let content_disposition = part
                .headers
                .iter()
                .find(|h| h.get_key().eq_ignore_ascii_case("Content-Disposition"))
                .map(|h| h.get_value())
                .unwrap_or_default();

            let is_attachment = content_disposition.starts_with("attachment")
                || content_disposition.starts_with("inline");

            if is_attachment && !part.ctype.mimetype.starts_with("text/") {
                let filename = part
                    .ctype
                    .params
                    .get("name")
                    .cloned()
                    .unwrap_or_else(|| "attachment".to_string());
                let data = part
                    .get_body_raw()
                    .map_err(|e| SmtpError::MessageParse(format!("attachment body: {}", e)))?;
                let content_id = part
                    .headers
                    .iter()
                    .find(|h| h.get_key().eq_ignore_ascii_case("Content-ID"))
                    .map(|h| {
                        let v = h.get_value();
                        v.trim_start_matches('<').trim_end_matches('>').to_string()
                    })
                    .unwrap_or_default();

                let disp = if content_disposition.starts_with("inline") {
                    "inline"
                } else {
                    "attachment"
                };

                attachments.push(ParsedAttachment {
                    filename,
                    mime_type: part.ctype.mimetype.clone(),
                    disposition: disp.to_string(),
                    content_id,
                    data,
                });
            } else if part.ctype.mimetype == "text/html" {
                body = part
                    .get_body()
                    .map_err(|e| SmtpError::MessageParse(format!("html body: {}", e)))?;
                mime_type = "text/html".to_string();
            } else if part.ctype.mimetype.starts_with("text/") && body.is_empty() {
                body = part
                    .get_body()
                    .map_err(|e| SmtpError::MessageParse(format!("text body: {}", e)))?;
                mime_type = part.ctype.mimetype.clone();
            } else if part.ctype.mimetype.starts_with("multipart/") {
                // Recurse into nested multipart
                let (sub_body, sub_mime, sub_atts) = extract_body_and_attachments(part)?;
                if body.is_empty() {
                    body = sub_body;
                    mime_type = sub_mime;
                }
                attachments.extend(sub_atts);
            }
        }
    }

    Ok((body, mime_type, attachments))
}

/// Extract the bare email address from an RFC 822 From header value.
#[cfg(test)]
fn extract_email(from: &str) -> String {
    if let Some(start) = from.rfind('<') {
        if let Some(end) = from.rfind('>') {
            return from[start + 1..end].trim().to_string();
        }
    }
    from.trim().to_string()
}

/// Find the sender address in the user's address list.
fn find_sender_address<'a>(addresses: &'a [Address], mail_from: &str) -> Option<&'a Address> {
    let from_lower = mail_from.to_lowercase();
    addresses
        .iter()
        .find(|a| a.status == 1 && a.send == 1 && a.email.to_lowercase() == from_lower)
}

/// Send a message through the Proton API.
///
/// Flow:
/// 1. Parse RFC 822 message
/// 2. Validate sender
/// 3. Create draft with encrypted body
/// 4. Upload attachments (if any)
/// 5. Lookup recipient keys
/// 6. Build send packages
/// 7. Send draft
pub async fn send_message(
    client: &ProtonClient,
    sender_keyring: &Keyring,
    addresses: &[Address],
    mail_from: &str,
    rcpt_to: &[String],
    raw_message: &[u8],
) -> Result<()> {
    // 1. Parse the raw message
    let parsed = parse_rfc822(raw_message)?;

    // 2. Validate sender
    let sender_addr = find_sender_address(addresses, mail_from)
        .ok_or_else(|| SmtpError::InvalidSender(mail_from.to_string()))?;

    if rcpt_to.is_empty() {
        return Err(SmtpError::NoRecipients);
    }

    struct PreparedAttachmentUpload {
        filename: String,
        mime_type: String,
        disposition: String,
        content_id: String,
        key_packets: Vec<u8>,
        data_packet: Vec<u8>,
        signature: Vec<u8>,
    }

    // 3. Create draft with encrypted body
    let encrypted_body = sender_keyring
        .encrypt_armored(parsed.body.as_bytes())
        .map_err(SmtpError::Crypto)?;

    // Build To/CC/BCC lists from rcpt_to + parsed headers
    let to_list: Vec<EmailAddress> = parsed
        .to
        .iter()
        .map(|a| EmailAddress {
            name: String::new(),
            address: a.clone(),
        })
        .collect();
    let cc_list: Vec<EmailAddress> = parsed
        .cc
        .iter()
        .map(|a| EmailAddress {
            name: String::new(),
            address: a.clone(),
        })
        .collect();
    let bcc_list: Vec<EmailAddress> = rcpt_to
        .iter()
        .filter(|r| {
            let rl = r.to_lowercase();
            !parsed.to.iter().any(|a| a.to_lowercase() == rl)
                && !parsed.cc.iter().any(|a| a.to_lowercase() == rl)
        })
        .map(|a| EmailAddress {
            name: String::new(),
            address: a.clone(),
        })
        .collect();

    let mut prepared_attachments = Vec::new();
    let mut draft_attachment_key_packets = Vec::new();
    for att in &parsed.attachments {
        let (key_pkts, data_pkts) =
            encrypt_attachment(sender_keyring, &att.data).map_err(SmtpError::Crypto)?;
        draft_attachment_key_packets.push(BASE64.encode(&key_pkts));
        let signature = sign_detached(sender_keyring, &att.data).map_err(SmtpError::Crypto)?;
        prepared_attachments.push(PreparedAttachmentUpload {
            filename: att.filename.clone(),
            mime_type: att.mime_type.clone(),
            disposition: att.disposition.clone(),
            content_id: att.content_id.clone(),
            key_packets: key_pkts,
            data_packet: data_pkts,
            signature,
        });
    }

    let draft_req = CreateDraftReq {
        message: DraftTemplate {
            subject: parsed.subject.clone(),
            sender: EmailAddress {
                name: sender_addr.display_name.clone(),
                address: sender_addr.email.clone(),
            },
            to_list,
            cc_list,
            bcc_list,
            body: encrypted_body,
            mime_type: parsed.mime_type.clone(),
            unread: 0,
            external_id: None,
        },
        attachment_key_packets: draft_attachment_key_packets,
        parent_id: None,
        action: 0,
    };

    let draft_resp = create_draft(client, &draft_req)
        .await
        .map_err(SmtpError::Api)?;
    let draft_id = &draft_resp.message.metadata.id;
    info!(draft_id = %draft_id, "draft created");

    // 4. Upload attachments (if any)
    let mut att_keys: HashMap<String, crate::crypto::encrypt::SessionKeyData> = HashMap::new();
    for att in prepared_attachments {
        let att_resp = crate::api::messages::upload_attachment(
            client,
            UploadAttachmentReq {
                message_id: draft_id.clone(),
                filename: att.filename,
                mime_type: att.mime_type,
                disposition: att.disposition,
                content_id: att.content_id,
                key_packets: att.key_packets.clone(),
                data_packet: att.data_packet,
                signature: att.signature,
            },
        )
        .await
        .map_err(SmtpError::Api)?;

        // Extract session key from attachment for the send package
        let session_key_data = crate::crypto::encrypt::extract_attachment_session_key(
            sender_keyring,
            &att.key_packets,
        )?;
        att_keys.insert(att_resp.attachment.id, session_key_data);
    }

    // 5. Lookup recipient keys
    let mut recipient_keys: HashMap<String, (i32, Option<openpgp::Cert>)> = HashMap::new();
    for addr in rcpt_to {
        match get_public_keys(client, addr).await {
            Ok(resp) => {
                let cert = if resp.recipient_type == RECIPIENT_INTERNAL && !resp.keys.is_empty() {
                    // Parse the first valid public key
                    resp.keys
                        .iter()
                        .find_map(|k| openpgp::Cert::from_bytes(k.public_key.as_bytes()).ok())
                } else {
                    None
                };
                recipient_keys.insert(addr.clone(), (resp.recipient_type, cert));
            }
            Err(e) => {
                tracing::warn!(address = %addr, error = %e, "could not fetch public keys, treating as external");
                recipient_keys.insert(addr.clone(), (crate::api::types::RECIPIENT_EXTERNAL, None));
            }
        }
    }

    // 6. Build send packages
    let (session_key, data_packets) =
        enc_split(sender_keyring, &parsed.body).map_err(SmtpError::Crypto)?;

    let body_b64 = BASE64.encode(&data_packets);

    // Separate internal and external recipients
    let mut internal_recipients: HashMap<String, MessageRecipient> = HashMap::new();
    let mut external_recipients: HashMap<String, MessageRecipient> = HashMap::new();
    let mut has_internal = false;
    let mut has_external = false;

    for (addr, (rtype, cert)) in &recipient_keys {
        if *rtype == RECIPIENT_INTERNAL {
            if let Some(cert) = cert {
                let body_key_packet =
                    encrypt_session_key(cert, &session_key).map_err(SmtpError::Crypto)?;

                let mut att_key_packets = HashMap::new();
                for (att_id, att_sk) in &att_keys {
                    let enc_att_key = encrypt_session_key(
                        cert,
                        &crate::crypto::encrypt::SessionKeyData {
                            key: att_sk.key.clone(),
                            algorithm: att_sk.algorithm.clone(),
                        },
                    )
                    .map_err(SmtpError::Crypto)?;
                    att_key_packets.insert(att_id.clone(), BASE64.encode(&enc_att_key));
                }

                internal_recipients.insert(
                    addr.clone(),
                    MessageRecipient {
                        recipient_type: INTERNAL_SCHEME,
                        signature: DETACHED_SIGNATURE,
                        body_key_packet: Some(BASE64.encode(&body_key_packet)),
                        attachment_key_packets: if att_key_packets.is_empty() {
                            None
                        } else {
                            Some(att_key_packets)
                        },
                    },
                );
                has_internal = true;
            }
        } else {
            external_recipients.insert(
                addr.clone(),
                MessageRecipient {
                    recipient_type: CLEAR_SCHEME,
                    signature: NO_SIGNATURE,
                    body_key_packet: None,
                    attachment_key_packets: None,
                },
            );
            has_external = true;
        }
    }

    let mut packages = Vec::new();

    if has_internal {
        packages.push(MessagePackage {
            addresses: internal_recipients,
            mime_type: parsed.mime_type.clone(),
            package_type: INTERNAL_SCHEME,
            body: body_b64.clone(),
            body_key: None,
            attachment_keys: None,
        });
    }

    if has_external {
        let mut att_session_keys = HashMap::new();
        for (att_id, att_sk) in &att_keys {
            att_session_keys.insert(
                att_id.clone(),
                SessionKeyInfo {
                    key: BASE64.encode(&att_sk.key),
                    algorithm: att_sk.algorithm.clone(),
                },
            );
        }

        packages.push(MessagePackage {
            addresses: external_recipients,
            mime_type: parsed.mime_type.clone(),
            package_type: CLEAR_SCHEME,
            body: body_b64,
            body_key: Some(SessionKeyInfo {
                key: BASE64.encode(&session_key.key),
                algorithm: session_key.algorithm.clone(),
            }),
            attachment_keys: if att_session_keys.is_empty() {
                None
            } else {
                Some(att_session_keys)
            },
        });
    }

    // 7. Send draft
    let send_req = SendDraftReq { packages };
    send_draft(client, draft_id, &send_req)
        .await
        .map_err(SmtpError::Api)?;

    info!(draft_id = %draft_id, "message sent");
    Ok(())
}

use sequoia_openpgp as openpgp;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_text_message() {
        let raw = b"From: alice@proton.me\r\nTo: bob@example.com\r\nSubject: Hello\r\n\r\nThis is the body.";
        let msg = parse_rfc822(raw).unwrap();
        assert_eq!(msg.subject, "Hello");
        assert_eq!(msg.to, vec!["bob@example.com"]);
        assert_eq!(msg.body, "This is the body.");
        assert_eq!(msg.mime_type, "text/plain");
        assert!(msg.attachments.is_empty());
    }

    #[test]
    fn test_parse_html_message() {
        let raw = b"From: alice@proton.me\r\nTo: bob@example.com\r\nSubject: HTML\r\nContent-Type: text/html\r\n\r\n<h1>Hello</h1>";
        let msg = parse_rfc822(raw).unwrap();
        assert_eq!(msg.subject, "HTML");
        assert_eq!(msg.mime_type, "text/html");
        assert!(msg.body.contains("<h1>Hello</h1>"));
    }

    #[test]
    fn test_parse_multipart_with_attachment() {
        let raw = b"From: alice@proton.me\r\n\
To: bob@example.com\r\n\
Subject: With Attachment\r\n\
Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\
\r\n\
--BOUNDARY\r\n\
Content-Type: text/plain\r\n\
\r\n\
Body text here.\r\n\
--BOUNDARY\r\n\
Content-Type: application/pdf; name=\"doc.pdf\"\r\n\
Content-Disposition: attachment; filename=\"doc.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
AAAA\r\n\
--BOUNDARY--\r\n";

        let msg = parse_rfc822(raw).unwrap();
        assert_eq!(msg.subject, "With Attachment");
        assert!(msg.body.contains("Body text here."));
        assert_eq!(msg.mime_type, "text/plain");
        assert_eq!(msg.attachments.len(), 1);
        assert_eq!(msg.attachments[0].filename, "doc.pdf");
        assert_eq!(msg.attachments[0].mime_type, "application/pdf");
        assert_eq!(msg.attachments[0].disposition, "attachment");
    }

    #[test]
    fn test_extract_email_with_angle_brackets() {
        assert_eq!(extract_email("Alice <alice@proton.me>"), "alice@proton.me");
        assert_eq!(extract_email("alice@proton.me"), "alice@proton.me");
        assert_eq!(
            extract_email("\"Alice Smith\" <alice@proton.me>"),
            "alice@proton.me"
        );
    }

    #[test]
    fn test_find_sender_address() {
        let addresses = vec![
            Address {
                id: "addr-1".to_string(),
                email: "alice@proton.me".to_string(),
                status: 1,
                receive: 1,
                send: 1,
                address_type: 1,
                order: 0,
                display_name: "Alice".to_string(),
                keys: vec![],
            },
            Address {
                id: "addr-2".to_string(),
                email: "disabled@proton.me".to_string(),
                status: 0,
                receive: 0,
                send: 0,
                address_type: 1,
                order: 0,
                display_name: "Disabled".to_string(),
                keys: vec![],
            },
        ];

        assert!(find_sender_address(&addresses, "alice@proton.me").is_some());
        assert!(find_sender_address(&addresses, "ALICE@PROTON.ME").is_some());
        assert!(find_sender_address(&addresses, "disabled@proton.me").is_none());
        assert!(find_sender_address(&addresses, "unknown@proton.me").is_none());
    }

    #[test]
    fn test_parse_address_list_multiple() {
        let raw =
            b"From: sender@test.com\r\nTo: a@test.com, b@test.com\r\nSubject: test\r\n\r\nbody";
        let msg = parse_rfc822(raw).unwrap();
        assert_eq!(msg.to, vec!["a@test.com", "b@test.com"]);
    }
}
