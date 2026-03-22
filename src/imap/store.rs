pub struct MailboxStatus {
    pub uid_validity: u32,
    pub next_uid: u32,
    pub exists: u32,
    pub unseen: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxSnapshot {
    pub exists: u32,
    pub mod_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreEventKind {
    MailboxCreated,
    MessageAdded,
    MessageUpdated,
    MessageBodyUpdated,
    MessageFlagsUpdated,
    MessageRemoved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreEvent {
    pub mailbox: String,
    pub uid: Option<u32>,
    pub proton_id: Option<String>,
    pub kind: StoreEventKind,
    pub mod_seq: u64,
}
