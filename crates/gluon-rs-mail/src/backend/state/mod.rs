//! Per-session IMAP state management: state machine, mailbox snapshots,
//! cross-session updates, and action orchestration.

pub mod actions;
pub mod session;
pub mod snapshot;
pub mod updates;

pub use actions::FlagAction;
pub use session::{SessionPhase, SessionState};
pub use snapshot::SessionSnapshot;
pub use updates::StateUpdate;
