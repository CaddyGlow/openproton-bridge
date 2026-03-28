use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tracing::debug;

use super::*;

impl<R, W> ImapSession<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    pub async fn cmd_idle(&mut self, tag: &str) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        let scoped_mailbox = self
            .selected_mailbox
            .as_ref()
            .map(|mailbox| self.scoped_mailbox_name(mailbox))
            .ok_or_else(|| {
                crate::imap_error::ImapError::Protocol("no mailbox selected".to_string())
            })?;
        let mut update_rx = self.config.gluon_connector.subscribe_updates();
        self.writer.continuation("idling").await?;
        self.emit_selected_mailbox_exists_update().await?;

        let idle_deadline = tokio::time::Instant::now() + self.config.limits.idle_timeout;
        let idle_timeout = tokio::time::sleep_until(idle_deadline);
        tokio::pin!(idle_timeout);
        let bulk_time = self.config.idle_bulk_time;

        loop {
            let mut line = String::new();
            tokio::select! {
                _ = &mut idle_timeout => {
                    debug!("IDLE timeout");
                    break;
                }
                update = update_rx.recv() => {
                    match update {
                        Ok(update) if update.affects_scoped_mailbox(&scoped_mailbox) => {
                            if bulk_time > Duration::ZERO {
                                tokio::time::sleep(bulk_time).await;
                            }
                            self.emit_selected_mailbox_exists_update().await?;
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            self.emit_selected_mailbox_exists_update().await?;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
                read = self.reader.read_line(&mut line) => {
                    let n = read?;
                    if n == 0 {
                        return Ok(());
                    }

                    let trimmed = line.trim_end_matches(['\r', '\n']).trim();
                    if trimmed.eq_ignore_ascii_case("DONE") {
                        break;
                    }

                    if !trimmed.is_empty() {
                        self.writer.untagged("BAD expected DONE").await?;
                    }
                }
            }
        }

        self.writer.tagged_ok(tag, None, "IDLE terminated").await
    }
}
