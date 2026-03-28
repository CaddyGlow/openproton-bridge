use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use super::*;

impl<R, W> ImapSession<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    pub async fn cmd_login(&mut self, tag: &str, username: &str, password: &str) -> Result<()> {
        if self.state != State::NotAuthenticated {
            return self.writer.tagged_bad(tag, "already authenticated").await;
        }
        self.do_login(tag, username, password).await
    }

    pub async fn do_login(&mut self, tag: &str, username: &str, password: &str) -> Result<()> {
        let auth_result = match self.config.connector.authorize(username, password).await {
            Ok(r) => r,
            Err(crate::imap_error::ImapError::AuthFailed) => {
                if self.config.login_jail_time > Duration::ZERO {
                    tokio::time::sleep(self.config.login_jail_time).await;
                }
                return self
                    .writer
                    .tagged_no(tag, "[AUTHENTICATIONFAILED] invalid credentials")
                    .await;
            }
            Err(e) => {
                warn!(error = %e, "connector authorize failed");
                if self.config.login_jail_time > Duration::ZERO {
                    tokio::time::sleep(self.config.login_jail_time).await;
                }
                return self
                    .writer
                    .tagged_no(tag, &format!("login failed: {e}"))
                    .await;
            }
        };

        // Convert MailboxInfo back to ResolvedMailbox for the session's user_labels
        self.user_labels = auth_result
            .mailboxes
            .into_iter()
            .map(|mb| mailbox::ResolvedMailbox {
                name: mb.name,
                label_id: mb.id,
                special_use: mb.special_use,
                selectable: mb.selectable,
            })
            .collect();

        self.authenticated_account_id = Some(auth_result.account_id.clone());
        self.storage_user_id = Some(
            self.config
                .gluon_connector
                .resolve_storage_user_id(Some(&auth_result.account_id))
                .to_string(),
        );
        self.state = State::Authenticated;

        match self
            .config
            .gluon_connector
            .acquire_store_session(Some(&auth_result.account_id))
            .await
        {
            Ok(session) => self.store_session = Some(session),
            Err(e) => {
                warn!(error = %e, "failed to acquire pinned store session, falling back to pool");
            }
        }

        if let Some(tx) = &self.config.event_tx {
            let _ = tx.send(crate::imap_types::SessionEvent::Login {
                session_id: self.connection_id,
                account_id: auth_result.account_id.clone(),
                email: auth_result.primary_email.clone(),
            });
        }

        info!(
            service = "imap",
            msg = "IMAP login successful",
            connection_id = self.connection_id,
            email = %auth_result.primary_email,
            "IMAP login successful"
        );
        self.writer.tagged_ok(tag, None, "LOGIN completed").await
    }

    pub async fn cmd_authenticate(
        &mut self,
        tag: &str,
        mechanism: &str,
        initial_response: Option<&str>,
    ) -> Result<()> {
        if self.state != State::NotAuthenticated {
            return self.writer.tagged_bad(tag, "already authenticated").await;
        }

        match mechanism.to_uppercase().as_str() {
            "PLAIN" => self.authenticate_plain(tag, initial_response).await,
            _ => {
                self.writer
                    .tagged_no(tag, "unsupported authentication mechanism")
                    .await
            }
        }
    }

    pub async fn authenticate_plain(
        &mut self,
        tag: &str,
        initial_response: Option<&str>,
    ) -> Result<()> {
        let encoded = if let Some(resp) = initial_response {
            resp.to_string()
        } else {
            self.writer.continuation("").await?;
            let mut line = String::new();
            self.reader.read_line(&mut line).await?;
            line.trim().to_string()
        };

        use base64::Engine;
        let decoded = match base64::engine::general_purpose::STANDARD.decode(&encoded) {
            Ok(d) => d,
            Err(_) => {
                return self
                    .writer
                    .tagged_no(tag, "[AUTHENTICATIONFAILED] invalid base64")
                    .await;
            }
        };

        // PLAIN format: authzid\0authcid\0password
        let parts: Vec<&[u8]> = decoded.splitn(3, |b| *b == 0).collect();
        if parts.len() != 3 {
            return self
                .writer
                .tagged_no(tag, "[AUTHENTICATIONFAILED] invalid PLAIN data")
                .await;
        }

        let username = String::from_utf8_lossy(parts[1]);
        let password = String::from_utf8_lossy(parts[2]);

        self.do_login(tag, &username, &password).await
    }

    /// Handle the LOGOUT command.
    pub async fn cmd_logout(&mut self, tag: &str) -> Result<()> {
        if let Some(tx) = &self.config.event_tx {
            let _ = tx.send(crate::imap_types::SessionEvent::Logout {
                session_id: self.connection_id,
            });
        }
        self.writer.untagged("BYE server logging out").await?;
        self.state = State::Logout;
        self.authenticated_account_id = None;
        self.storage_user_id = None;
        self.selected_mailbox = None;
        self.selected_mailbox_mod_seq = None;
        self.selected_mailbox_internal_id = None;
        self.selected_mailbox_uids.clear();
        self.selected_mailbox_flags.clear();
        self.store_session = None;
        self.writer.tagged_ok(tag, None, "LOGOUT completed").await
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_plain_auth_decode() {
        use base64::Engine;
        // PLAIN format: \0username\0password
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"\0alice\0secret");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        let parts: Vec<&[u8]> = decoded.splitn(3, |b| *b == 0).collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], b"alice");
        assert_eq!(parts[2], b"secret");
    }

    #[test]
    fn test_plain_auth_with_authzid() {
        use base64::Engine;
        // PLAIN with authzid: authzid\0authcid\0password
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"admin\0alice\0secret");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        let parts: Vec<&[u8]> = decoded.splitn(3, |b| *b == 0).collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], b"admin");
        assert_eq!(parts[1], b"alice");
        assert_eq!(parts[2], b"secret");
    }
}
