use gluon_rs_mail::{CompatibleStore, ImapError, ImapResult, ScopedMailboxId};

pub(crate) fn storage_user_id_for_account<'a>(
    store: &'a CompatibleStore,
    account_id: &'a str,
) -> &'a str {
    store
        .bootstrap()
        .accounts
        .iter()
        .find(|account| account.account_id == account_id)
        .map(|account| account.storage_user_id.as_str())
        .unwrap_or(account_id)
}

pub(crate) fn resolve_parts(mailbox: &ScopedMailboxId) -> (&str, &str) {
    let account_id = mailbox.account_id().unwrap_or("__default__");
    let name = mailbox.mailbox_name();
    let name = if name.is_empty() { "INBOX" } else { name };
    (account_id, name)
}

pub(crate) fn resolve_mailbox_id(
    store: &CompatibleStore,
    mailbox: &ScopedMailboxId,
) -> ImapResult<Option<(String, u64)>> {
    let (account_id, name) = resolve_parts(mailbox);
    let storage_user_id = storage_user_id_for_account(store, account_id).to_string();
    let mb_id = store
        .resolve_mailbox_id(&storage_user_id, name)
        .map_err(map_err)?;
    Ok(mb_id.map(|id| (storage_user_id, id)))
}

pub(crate) fn map_err(e: gluon_rs_mail::GluonError) -> ImapError {
    ImapError::Protocol(format!("gluon-rs-mail store adapter failure: {e}"))
}
