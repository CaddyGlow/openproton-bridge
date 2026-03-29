//! Action orchestration: coordinate remote connector calls + local store updates + state broadcasts.

use crate::imap_error::ImapResult;
use crate::imap_types::ScopedMailboxId;

use super::updates::StateUpdate;
use super::user::GluonUser;

/// Create a mailbox via connector and broadcast update.
pub async fn create_mailbox(user: &GluonUser, name: &str) -> ImapResult<()> {
    let scoped = ScopedMailboxId::from_parts(Some(&user.user_id), name);
    user.gluon_connector.create_mailbox(&scoped).await?;
    user.broadcast_update(StateUpdate::MailboxCreated {
        name: name.to_string(),
    });
    Ok(())
}

/// Delete a mailbox via connector and broadcast update.
pub async fn delete_mailbox(user: &GluonUser, name: &str) -> ImapResult<()> {
    let scoped = ScopedMailboxId::from_parts(Some(&user.user_id), name);
    user.gluon_connector.delete_mailbox(&scoped, false).await?;
    user.broadcast_update(StateUpdate::MailboxDeleted {
        name: name.to_string(),
    });
    Ok(())
}

/// Rename a mailbox via connector and broadcast update.
pub async fn rename_mailbox(user: &GluonUser, old_name: &str, new_name: &str) -> ImapResult<()> {
    let old_scoped = ScopedMailboxId::from_parts(Some(&user.user_id), old_name);
    let new_scoped = ScopedMailboxId::from_parts(Some(&user.user_id), new_name);
    user.gluon_connector
        .rename_mailbox(&old_scoped, &new_scoped)
        .await?;
    user.broadcast_update(StateUpdate::MailboxRenamed {
        old_name: old_name.to_string(),
        new_name: new_name.to_string(),
    });
    Ok(())
}
