use tokio::io::AsyncWriteExt;
use tracing::debug;

use super::*;

impl<R, W> ImapSession<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    pub async fn cmd_noop(&mut self, tag: &str) -> Result<()> {
        self.emit_selected_mailbox_exists_update().await?;
        self.writer.tagged_ok(tag, None, "NOOP completed").await
    }

    pub async fn cmd_check(&mut self, tag: &str) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }
        self.emit_selected_mailbox_exists_update().await?;
        self.writer.tagged_ok(tag, None, "CHECK completed").await
    }

    pub async fn cmd_close(&mut self, tag: &str) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }
        if !self.selected_read_only {
            // Silently expunge deleted messages for read-write selections.
            let _ = self.do_expunge(true, None).await?;
        }

        self.selected_mailbox = None;
        self.selected_mailbox_mod_seq = None;
        self.selected_mailbox_internal_id = None;
        self.selected_mailbox_uids.clear();
        self.selected_mailbox_flags.clear();
        self.selected_read_only = false;
        self.state = State::Authenticated;
        self.writer.tagged_ok(tag, None, "CLOSE completed").await
    }

    pub async fn cmd_unselect(&mut self, tag: &str) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }
        // Unlike CLOSE, do NOT expunge deleted messages
        self.selected_mailbox = None;
        self.selected_mailbox_mod_seq = None;
        self.selected_mailbox_internal_id = None;
        self.selected_mailbox_uids.clear();
        self.selected_mailbox_flags.clear();
        self.selected_read_only = false;
        self.state = State::Authenticated;
        self.writer.tagged_ok(tag, None, "UNSELECT completed").await
    }

    pub async fn cmd_capability(&mut self, tag: &str) -> Result<()> {
        let caps = if self.state == State::NotAuthenticated {
            if self.starttls_available {
                "CAPABILITY IMAP4rev1 STARTTLS IDLE UIDPLUS MOVE UNSELECT ID AUTH=PLAIN"
            } else {
                "CAPABILITY IMAP4rev1 IDLE UIDPLUS MOVE UNSELECT ID AUTH=PLAIN"
            }
        } else {
            "CAPABILITY IMAP4rev1 IDLE UIDPLUS MOVE UNSELECT ID"
        };
        self.writer.untagged(caps).await?;
        self.writer
            .tagged_ok(tag, None, "CAPABILITY completed")
            .await
    }

    pub async fn cmd_starttls(&mut self, tag: &str) -> Result<()> {
        if self.state != State::NotAuthenticated {
            return self
                .writer
                .tagged_bad(tag, "STARTTLS only in not-authenticated state")
                .await;
        }
        if !self.starttls_available {
            return self.writer.tagged_bad(tag, "STARTTLS unavailable").await;
        }
        self.writer
            .tagged_ok(tag, None, "begin TLS negotiation")
            .await
    }

    pub async fn cmd_id(
        &mut self,
        tag: &str,
        params: &Option<Vec<(String, String)>>,
    ) -> Result<()> {
        if let Some(params) = params {
            for (key, value) in params {
                debug!(key = %key, value = %value, "IMAP client ID");
            }
        }
        self.writer
            .untagged("ID (\"name\" \"gluon-rs-mail\" \"version\" \"0.1.0\")")
            .await?;
        self.writer.tagged_ok(tag, None, "ID completed").await
    }
}
