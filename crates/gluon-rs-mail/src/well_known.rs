// Proton label IDs. These are stable protocol constants.
pub const INBOX_LABEL: &str = "0";
pub const ALL_DRAFTS_LABEL: &str = "1";
pub const ALL_SENT_LABEL: &str = "2";
pub const TRASH_LABEL: &str = "3";
pub const SPAM_LABEL: &str = "4";
pub const ALL_MAIL_LABEL: &str = "5";
pub const ARCHIVE_LABEL: &str = "6";
pub const SENT_LABEL: &str = "7";
pub const DRAFTS_LABEL: &str = "8";
pub const STARRED_LABEL: &str = "10";

// Proton label types.
pub const LABEL_TYPE_LABEL: i32 = 1;
pub const LABEL_TYPE_CONTACT_GROUP: i32 = 2;
pub const LABEL_TYPE_FOLDER: i32 = 3;

// Proton message flag bitmasks.
pub const MESSAGE_FLAG_RECEIVED: i64 = 1 << 0;
pub const MESSAGE_FLAG_SENT: i64 = 1 << 1;
pub const MESSAGE_FLAG_REPLIED: i64 = 1 << 5;
pub const MESSAGE_FLAG_REPLIED_ALL: i64 = 1 << 6;
pub const MESSAGE_FLAG_FORWARDED: i64 = 1 << 7;
pub const MESSAGE_FLAG_IMPORTED: i64 = 1 << 9;
