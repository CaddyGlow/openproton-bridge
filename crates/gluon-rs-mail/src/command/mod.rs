pub mod fetch;
pub mod parse_helpers;
pub mod search;
pub mod sequence;
pub mod store;

// Re-export everything so `use gluon_rs_mail::command::*` still works.
pub use fetch::{parse_body_section, parse_fetch, parse_fetch_items, starts_fetch_item_keyword};
pub use parse_helpers::{
    parse_astring, parse_quoted_string, split_first_word, starts_search_keyword,
};
pub use search::{parse_imap_date, parse_search, parse_search_criteria, parse_search_criterion};
pub use sequence::{parse_sequence_set, SeqNum, SeqRange, SequenceSet};
pub use store::{parse_flag_list, parse_store};

use crate::imap_error::{ImapError, ImapResult as Result};

#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    Capability {
        tag: String,
    },
    Login {
        tag: String,
        username: String,
        password: String,
    },
    Logout {
        tag: String,
    },
    Noop {
        tag: String,
    },
    Idle {
        tag: String,
    },
    StartTls {
        tag: String,
    },
    List {
        tag: String,
        reference: String,
        pattern: String,
    },
    Lsub {
        tag: String,
        reference: String,
        pattern: String,
    },
    Select {
        tag: String,
        mailbox: String,
    },
    Create {
        tag: String,
        mailbox: String,
    },
    Subscribe {
        tag: String,
        mailbox: String,
    },
    Unsubscribe {
        tag: String,
        mailbox: String,
    },
    Status {
        tag: String,
        mailbox: String,
        items: Vec<StatusDataItem>,
    },
    Check {
        tag: String,
    },
    Close {
        tag: String,
    },
    Fetch {
        tag: String,
        sequence: SequenceSet,
        items: Vec<FetchItem>,
        uid: bool,
    },
    Store {
        tag: String,
        sequence: SequenceSet,
        action: StoreAction,
        flags: Vec<ImapFlag>,
        uid: bool,
    },
    Search {
        tag: String,
        criteria: Vec<SearchKey>,
        uid: bool,
    },
    Expunge {
        tag: String,
    },
    Copy {
        tag: String,
        sequence: SequenceSet,
        mailbox: String,
        uid: bool,
    },
    Move {
        tag: String,
        sequence: SequenceSet,
        mailbox: String,
        uid: bool,
    },
    Examine {
        tag: String,
        mailbox: String,
    },
    UidExpunge {
        tag: String,
        sequence: SequenceSet,
    },
    Append {
        tag: String,
        mailbox: String,
        flags: Vec<ImapFlag>,
        date: Option<String>,
        literal_size: u32,
    },
    Unselect {
        tag: String,
    },
    Delete {
        tag: String,
        mailbox: String,
    },
    Rename {
        tag: String,
        source: String,
        dest: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum FetchItem {
    Flags,
    Uid,
    Envelope,
    Rfc822,
    Rfc822Size,
    Rfc822Header,
    Rfc822Text,
    InternalDate,
    BodyStructure,
    Body,
    BodySection {
        section: Option<String>,
        peek: bool,
        partial: Option<(u32, u32)>,
    },
    All,
    Fast,
    Full,
}

#[derive(Debug, Clone, PartialEq)]
pub enum StoreAction {
    SetFlags,
    AddFlags,
    RemoveFlags,
    SetFlagsSilent,
    AddFlagsSilent,
    RemoveFlagsSilent,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ImapFlag {
    Seen,
    Flagged,
    Deleted,
    Draft,
    Answered,
    Recent,
    Other(String),
}

impl ImapFlag {
    pub fn as_str(&self) -> &str {
        match self {
            ImapFlag::Seen => "\\Seen",
            ImapFlag::Flagged => "\\Flagged",
            ImapFlag::Deleted => "\\Deleted",
            ImapFlag::Draft => "\\Draft",
            ImapFlag::Answered => "\\Answered",
            ImapFlag::Recent => "\\Recent",
            ImapFlag::Other(s) => s,
        }
    }

    pub fn parse(s: &str) -> ImapFlag {
        match s.to_lowercase().as_str() {
            "\\seen" => ImapFlag::Seen,
            "\\flagged" => ImapFlag::Flagged,
            "\\deleted" => ImapFlag::Deleted,
            "\\draft" => ImapFlag::Draft,
            "\\answered" => ImapFlag::Answered,
            "\\recent" => ImapFlag::Recent,
            _ => ImapFlag::Other(s.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SearchKey {
    All,
    Unseen,
    Seen,
    Flagged,
    Deleted,
    Answered,
    Draft,
    Subject(String),
    From(String),
    To(String),
    Uid(SequenceSet),
    Sequence(SequenceSet),
    Not(Box<SearchKey>),
    Or(Box<SearchKey>, Box<SearchKey>),
    // Date criteria (unix timestamps)
    Before(i64),
    Since(i64),
    On(i64),
    SentBefore(i64),
    SentSince(i64),
    SentOn(i64),
    // Size criteria
    Larger(i64),
    Smaller(i64),
    // Header criteria
    Cc(String),
    Bcc(String),
    Header(String, String),
    // Content criteria
    Body(String),
    Text(String),
    // Flag criteria
    Keyword(String),
    Unkeyword(String),
    New,
    Old,
    Recent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusDataItem {
    Messages,
    Recent,
    UidNext,
    UidValidity,
    Unseen,
}

// --- Main parse entry point ---

pub fn parse_command(line: &str) -> Result<Command> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() {
        return Err(ImapError::Protocol("empty command".to_string()));
    }

    let (tag, rest) = split_first_word(line)?;

    let (cmd_word, args) = match split_first_word(rest) {
        Ok((w, a)) => (w, a),
        Err(_) => (rest.to_string(), ""),
    };

    let cmd_upper = cmd_word.to_uppercase();

    if cmd_upper == "UID" {
        return parse_uid_command(&tag, args);
    }

    match cmd_upper.as_str() {
        "CAPABILITY" => Ok(Command::Capability { tag }),
        "LOGIN" => parse_login(&tag, args),
        "LOGOUT" => Ok(Command::Logout { tag }),
        "NOOP" => Ok(Command::Noop { tag }),
        "IDLE" => Ok(Command::Idle { tag }),
        "STARTTLS" => Ok(Command::StartTls { tag }),
        "LIST" => parse_list(&tag, args),
        "LSUB" => parse_lsub(&tag, args),
        "SELECT" => parse_select(&tag, args),
        "CREATE" => parse_create(&tag, args),
        "DELETE" => parse_delete(&tag, args),
        "SUBSCRIBE" => parse_subscribe(&tag, args),
        "UNSUBSCRIBE" => parse_unsubscribe(&tag, args),
        "STATUS" => parse_status(&tag, args),
        "CHECK" => Ok(Command::Check { tag }),
        "CLOSE" => Ok(Command::Close { tag }),
        "FETCH" => parse_fetch(&tag, args, false),
        "STORE" => parse_store(&tag, args, false),
        "SEARCH" => parse_search(&tag, args, false),
        "EXPUNGE" => Ok(Command::Expunge { tag }),
        "COPY" => parse_copy(&tag, args, false),
        "MOVE" => parse_move(&tag, args, false),
        "EXAMINE" => parse_examine(&tag, args),
        "APPEND" => parse_append(&tag, args),
        "UNSELECT" => Ok(Command::Unselect { tag }),
        "RENAME" => parse_rename(&tag, args),
        _ => Err(ImapError::Protocol(format!(
            "unknown command: {}",
            cmd_word
        ))),
    }
}

fn parse_uid_command(tag: &str, args: &str) -> Result<Command> {
    let (cmd_word, rest) = split_first_word(args)?;
    let cmd_upper = cmd_word.to_uppercase();

    match cmd_upper.as_str() {
        "FETCH" => parse_fetch(tag, rest, true),
        "STORE" => parse_store(tag, rest, true),
        "SEARCH" => parse_search(tag, rest, true),
        "COPY" => parse_copy(tag, rest, true),
        "MOVE" => parse_move(tag, rest, true),
        "EXPUNGE" => parse_uid_expunge(tag, rest),
        _ => Err(ImapError::Protocol(format!(
            "unknown UID subcommand: {}",
            cmd_word
        ))),
    }
}

fn parse_uid_expunge(tag: &str, args: &str) -> Result<Command> {
    let (seq_str, rest) = split_first_word(args)?;
    if !rest.trim().is_empty() {
        return Err(ImapError::Protocol(
            "UID EXPUNGE accepts exactly one sequence-set argument".to_string(),
        ));
    }
    let sequence = parse_sequence_set(&seq_str)?;
    Ok(Command::UidExpunge {
        tag: tag.to_string(),
        sequence,
    })
}

// --- Simple command parsers ---

fn parse_login(tag: &str, args: &str) -> Result<Command> {
    let (username, rest) = parse_astring(args.trim_start())?;
    let (password, _) = parse_astring(rest.trim_start())?;
    Ok(Command::Login {
        tag: tag.to_string(),
        username,
        password,
    })
}

fn parse_list(tag: &str, args: &str) -> Result<Command> {
    let (reference, rest) = parse_astring(args.trim_start())?;
    let (pattern, _) = parse_astring(rest.trim_start())?;
    Ok(Command::List {
        tag: tag.to_string(),
        reference,
        pattern,
    })
}

fn parse_lsub(tag: &str, args: &str) -> Result<Command> {
    let (reference, rest) = parse_astring(args.trim_start())?;
    let (pattern, _) = parse_astring(rest.trim_start())?;
    Ok(Command::Lsub {
        tag: tag.to_string(),
        reference,
        pattern,
    })
}

fn parse_create(tag: &str, args: &str) -> Result<Command> {
    let (mailbox, _) = parse_astring(args.trim_start())?;
    Ok(Command::Create {
        tag: tag.to_string(),
        mailbox,
    })
}

fn parse_delete(tag: &str, args: &str) -> Result<Command> {
    let (mailbox, _) = parse_astring(args.trim_start())?;
    Ok(Command::Delete {
        tag: tag.to_string(),
        mailbox,
    })
}

fn parse_rename(tag: &str, args: &str) -> Result<Command> {
    let (source, rest) = parse_astring(args.trim_start())?;
    let (dest, _) = parse_astring(rest.trim_start())?;
    Ok(Command::Rename {
        tag: tag.to_string(),
        source,
        dest,
    })
}

fn parse_subscribe(tag: &str, args: &str) -> Result<Command> {
    let (mailbox, _) = parse_astring(args.trim_start())?;
    Ok(Command::Subscribe {
        tag: tag.to_string(),
        mailbox,
    })
}

fn parse_unsubscribe(tag: &str, args: &str) -> Result<Command> {
    let (mailbox, _) = parse_astring(args.trim_start())?;
    Ok(Command::Unsubscribe {
        tag: tag.to_string(),
        mailbox,
    })
}

fn parse_select(tag: &str, args: &str) -> Result<Command> {
    let (mailbox, _) = parse_astring(args.trim_start())?;
    Ok(Command::Select {
        tag: tag.to_string(),
        mailbox,
    })
}

fn parse_examine(tag: &str, args: &str) -> Result<Command> {
    let (mailbox, _) = parse_astring(args.trim_start())?;
    Ok(Command::Examine {
        tag: tag.to_string(),
        mailbox,
    })
}

fn parse_append(tag: &str, args: &str) -> Result<Command> {
    let (mailbox, rest) = parse_astring(args.trim_start())?;
    let rest = rest.trim_start();

    let (flags, rest) = if rest.starts_with('(') {
        let close = rest
            .find(')')
            .ok_or_else(|| ImapError::Protocol("unclosed flag list".to_string()))?;
        let flag_str = &rest[..=close];
        (parse_flag_list(flag_str)?, rest[close + 1..].trim_start())
    } else {
        (Vec::new(), rest)
    };

    let (date, rest) = if rest.starts_with('"') {
        let (d, r) = parse_quoted_string(rest)?;
        (Some(d), r.trim_start())
    } else {
        (None, rest)
    };

    let literal_size = if rest.starts_with('{') {
        let end = rest
            .find('}')
            .ok_or_else(|| ImapError::Protocol("missing literal size".to_string()))?;
        let size_str = &rest[1..end];
        // Handle LITERAL+ non-synchronizing literal marker "+"
        let size_str = size_str.trim_end_matches('+');
        size_str
            .parse::<u32>()
            .map_err(|_| ImapError::Protocol("invalid literal size".to_string()))?
    } else {
        return Err(ImapError::Protocol(
            "APPEND requires literal data".to_string(),
        ));
    };

    Ok(Command::Append {
        tag: tag.to_string(),
        mailbox,
        flags,
        date,
        literal_size,
    })
}

fn parse_status(tag: &str, args: &str) -> Result<Command> {
    let (mailbox, rest) = parse_astring(args.trim_start())?;
    let items = parse_status_items(rest.trim_start())?;
    Ok(Command::Status {
        tag: tag.to_string(),
        mailbox,
        items,
    })
}

fn parse_status_items(s: &str) -> Result<Vec<StatusDataItem>> {
    let content = s.trim();
    if content.is_empty() {
        return Err(ImapError::Protocol("missing STATUS data items".to_string()));
    }

    let content = if content.starts_with('(') && content.ends_with(')') {
        &content[1..content.len() - 1]
    } else {
        content
    };

    let mut items = Vec::new();
    for token in content.split_whitespace() {
        let item = match token.to_ascii_uppercase().as_str() {
            "MESSAGES" => StatusDataItem::Messages,
            "RECENT" => StatusDataItem::Recent,
            "UIDNEXT" => StatusDataItem::UidNext,
            "UIDVALIDITY" => StatusDataItem::UidValidity,
            "UNSEEN" => StatusDataItem::Unseen,
            _ => {
                return Err(ImapError::Protocol(format!(
                    "unknown STATUS data item: {}",
                    token
                )))
            }
        };
        if !items.contains(&item) {
            items.push(item);
        }
    }

    if items.is_empty() {
        return Err(ImapError::Protocol("missing STATUS data items".to_string()));
    }
    Ok(items)
}

fn parse_copy(tag: &str, args: &str, uid: bool) -> Result<Command> {
    let (seq_str, rest) = split_first_word(args)?;
    let sequence = parse_sequence_set(&seq_str)?;
    let (mailbox, _) = parse_astring(rest.trim_start())?;
    Ok(Command::Copy {
        tag: tag.to_string(),
        sequence,
        mailbox,
        uid,
    })
}

fn parse_move(tag: &str, args: &str, uid: bool) -> Result<Command> {
    let (seq_str, rest) = split_first_word(args)?;
    let sequence = parse_sequence_set(&seq_str)?;
    let (mailbox, _) = parse_astring(rest.trim_start())?;
    Ok(Command::Move {
        tag: tag.to_string(),
        sequence,
        mailbox,
        uid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_capability() {
        let cmd = parse_command("a001 CAPABILITY").unwrap();
        assert_eq!(
            cmd,
            Command::Capability {
                tag: "a001".to_string()
            }
        );
    }

    #[test]
    fn test_parse_login() {
        let cmd = parse_command("a001 LOGIN user@proton.me \"my password\"").unwrap();
        assert_eq!(
            cmd,
            Command::Login {
                tag: "a001".to_string(),
                username: "user@proton.me".to_string(),
                password: "my password".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_login_both_quoted() {
        let cmd = parse_command("a001 LOGIN \"user@proton.me\" \"pass word\"").unwrap();
        assert_eq!(
            cmd,
            Command::Login {
                tag: "a001".to_string(),
                username: "user@proton.me".to_string(),
                password: "pass word".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_logout() {
        let cmd = parse_command("a002 LOGOUT").unwrap();
        assert_eq!(
            cmd,
            Command::Logout {
                tag: "a002".to_string()
            }
        );
    }

    #[test]
    fn test_parse_noop() {
        let cmd = parse_command("a003 NOOP").unwrap();
        assert_eq!(
            cmd,
            Command::Noop {
                tag: "a003".to_string()
            }
        );
    }

    #[test]
    fn test_parse_idle() {
        let cmd = parse_command("a003 IDLE").unwrap();
        assert_eq!(
            cmd,
            Command::Idle {
                tag: "a003".to_string()
            }
        );
    }

    #[test]
    fn test_parse_starttls() {
        let cmd = parse_command("a004 STARTTLS").unwrap();
        assert_eq!(
            cmd,
            Command::StartTls {
                tag: "a004".to_string()
            }
        );
    }

    #[test]
    fn test_parse_list() {
        let cmd = parse_command("a005 LIST \"\" \"*\"").unwrap();
        assert_eq!(
            cmd,
            Command::List {
                tag: "a005".to_string(),
                reference: "".to_string(),
                pattern: "*".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_select() {
        let cmd = parse_command("a006 SELECT INBOX").unwrap();
        assert_eq!(
            cmd,
            Command::Select {
                tag: "a006".to_string(),
                mailbox: "INBOX".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_select_quoted() {
        let cmd = parse_command("a006 SELECT \"All Mail\"").unwrap();
        assert_eq!(
            cmd,
            Command::Select {
                tag: "a006".to_string(),
                mailbox: "All Mail".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_status() {
        let cmd =
            parse_command("a006 STATUS \"Drafts\" (UIDNEXT UIDVALIDITY UNSEEN RECENT MESSAGES)")
                .unwrap();
        assert_eq!(
            cmd,
            Command::Status {
                tag: "a006".to_string(),
                mailbox: "Drafts".to_string(),
                items: vec![
                    StatusDataItem::UidNext,
                    StatusDataItem::UidValidity,
                    StatusDataItem::Unseen,
                    StatusDataItem::Recent,
                    StatusDataItem::Messages,
                ],
            }
        );
    }

    #[test]
    fn test_parse_check() {
        let cmd = parse_command("a006 CHECK").unwrap();
        assert_eq!(
            cmd,
            Command::Check {
                tag: "a006".to_string()
            }
        );
    }

    #[test]
    fn test_parse_fetch_flags() {
        let cmd = parse_command("a007 FETCH 1:* FLAGS").unwrap();
        match cmd {
            Command::Fetch {
                tag,
                sequence,
                items,
                uid,
            } => {
                assert_eq!(tag, "a007");
                assert!(!uid);
                assert_eq!(items, vec![FetchItem::Flags]);
                assert!(sequence.contains(1, 100));
                assert!(sequence.contains(100, 100));
            }
            _ => panic!("expected Fetch"),
        }
    }

    #[test]
    fn test_parse_uid_fetch() {
        let cmd = parse_command("a008 UID FETCH 1:100 (FLAGS UID)").unwrap();
        match cmd {
            Command::Fetch {
                tag, uid, items, ..
            } => {
                assert_eq!(tag, "a008");
                assert!(uid);
                assert!(items.contains(&FetchItem::Flags));
                assert!(items.contains(&FetchItem::Uid));
            }
            _ => panic!("expected Fetch"),
        }
    }

    #[test]
    fn test_parse_fetch_body_peek() {
        let cmd = parse_command("a009 FETCH 1 BODY.PEEK[]").unwrap();
        match cmd {
            Command::Fetch { items, .. } => {
                assert_eq!(
                    items,
                    vec![FetchItem::BodySection {
                        section: None,
                        peek: true,
                        partial: None,
                    }]
                );
            }
            _ => panic!("expected Fetch"),
        }
    }

    #[test]
    fn test_parse_fetch_body_partial() {
        let cmd = parse_command("a001 FETCH 1 BODY[]<0.1024>").unwrap();
        match cmd {
            Command::Fetch { items, .. } => {
                assert_eq!(
                    items,
                    vec![FetchItem::BodySection {
                        section: None,
                        peek: false,
                        partial: Some((0, 1024)),
                    }]
                );
            }
            _ => panic!("expected Fetch"),
        }

        let cmd = parse_command("a001 FETCH 1 BODY.PEEK[HEADER]<100.500>").unwrap();
        match cmd {
            Command::Fetch { items, .. } => {
                assert_eq!(
                    items,
                    vec![FetchItem::BodySection {
                        section: Some("HEADER".to_string()),
                        peek: true,
                        partial: Some((100, 500)),
                    }]
                );
            }
            _ => panic!("expected Fetch"),
        }
    }

    #[test]
    fn test_parse_append_basic() {
        let cmd = parse_command("a001 APPEND INBOX {310}").unwrap();
        match cmd {
            Command::Append {
                tag,
                mailbox,
                flags,
                date,
                literal_size,
            } => {
                assert_eq!(tag, "a001");
                assert_eq!(mailbox, "INBOX");
                assert!(flags.is_empty());
                assert!(date.is_none());
                assert_eq!(literal_size, 310);
            }
            _ => panic!("expected Append"),
        }
    }

    #[test]
    fn test_parse_append_with_flags_and_date() {
        let cmd = parse_command(
            "a001 APPEND \"Sent\" (\\Seen \\Flagged) \"14-Nov-2023 22:13:20 +0000\" {1024}",
        )
        .unwrap();
        match cmd {
            Command::Append {
                tag,
                mailbox,
                flags,
                date,
                literal_size,
            } => {
                assert_eq!(tag, "a001");
                assert_eq!(mailbox, "Sent");
                assert_eq!(flags, vec![ImapFlag::Seen, ImapFlag::Flagged]);
                assert_eq!(date.as_deref(), Some("14-Nov-2023 22:13:20 +0000"));
                assert_eq!(literal_size, 1024);
            }
            _ => panic!("expected Append"),
        }
    }

    #[test]
    fn test_parse_append_literal_plus() {
        let cmd = parse_command("a001 APPEND INBOX {310+}").unwrap();
        match cmd {
            Command::Append { literal_size, .. } => {
                assert_eq!(literal_size, 310);
            }
            _ => panic!("expected Append"),
        }
    }

    #[test]
    fn test_parse_store_add_flags() {
        let cmd = parse_command("a010 STORE 1 +FLAGS (\\Seen)").unwrap();
        match cmd {
            Command::Store {
                tag,
                action,
                flags,
                uid,
                ..
            } => {
                assert_eq!(tag, "a010");
                assert_eq!(action, StoreAction::AddFlags);
                assert_eq!(flags, vec![ImapFlag::Seen]);
                assert!(!uid);
            }
            _ => panic!("expected Store"),
        }
    }

    #[test]
    fn test_parse_uid_store() {
        let cmd = parse_command("a010 UID STORE 5 -FLAGS (\\Deleted \\Seen)").unwrap();
        match cmd {
            Command::Store {
                action, flags, uid, ..
            } => {
                assert_eq!(action, StoreAction::RemoveFlags);
                assert_eq!(flags, vec![ImapFlag::Deleted, ImapFlag::Seen]);
                assert!(uid);
            }
            _ => panic!("expected Store"),
        }
    }

    #[test]
    fn test_parse_search() {
        let cmd = parse_command("a011 SEARCH UNSEEN").unwrap();
        match cmd {
            Command::Search { criteria, uid, .. } => {
                assert!(!uid);
                assert_eq!(criteria, vec![SearchKey::Unseen]);
            }
            _ => panic!("expected Search"),
        }
    }

    #[test]
    fn test_parse_uid_search() {
        let cmd = parse_command("a011 UID SEARCH ALL").unwrap();
        match cmd {
            Command::Search { criteria, uid, .. } => {
                assert!(uid);
                assert_eq!(criteria, vec![SearchKey::All]);
            }
            _ => panic!("expected Search"),
        }
    }

    #[test]
    fn test_parse_expunge() {
        let cmd = parse_command("a012 EXPUNGE").unwrap();
        assert_eq!(
            cmd,
            Command::Expunge {
                tag: "a012".to_string()
            }
        );
    }

    #[test]
    fn test_parse_copy() {
        let cmd = parse_command("a013 COPY 1:5 Trash").unwrap();
        match cmd {
            Command::Copy {
                tag, mailbox, uid, ..
            } => {
                assert_eq!(tag, "a013");
                assert_eq!(mailbox, "Trash");
                assert!(!uid);
            }
            _ => panic!("expected Copy"),
        }
    }

    #[test]
    fn test_parse_move() {
        let cmd = parse_command("a013 MOVE 1:5 Archive").unwrap();
        match cmd {
            Command::Move {
                tag, mailbox, uid, ..
            } => {
                assert_eq!(tag, "a013");
                assert_eq!(mailbox, "Archive");
                assert!(!uid);
            }
            _ => panic!("expected Move"),
        }
    }

    #[test]
    fn test_parse_uid_move() {
        let cmd = parse_command("a013 UID MOVE 4,9 Trash").unwrap();
        match cmd {
            Command::Move {
                sequence,
                mailbox,
                uid,
                ..
            } => {
                assert!(uid);
                assert_eq!(mailbox, "Trash");
                assert!(sequence.contains(4, 9));
                assert!(sequence.contains(9, 9));
                assert!(!sequence.contains(7, 9));
            }
            _ => panic!("expected Move"),
        }
    }

    #[test]
    fn test_parse_close() {
        let cmd = parse_command("a014 CLOSE").unwrap();
        assert_eq!(
            cmd,
            Command::Close {
                tag: "a014".to_string()
            }
        );
    }

    #[test]
    fn test_parse_empty_command() {
        assert!(parse_command("").is_err());
    }

    #[test]
    fn test_parse_unknown_command() {
        assert!(parse_command("a099 BOGUS").is_err());
    }

    #[test]
    fn test_sequence_set_contains() {
        let set = parse_sequence_set("1:5,10,20:*").unwrap();
        assert!(set.contains(1, 100));
        assert!(set.contains(3, 100));
        assert!(set.contains(5, 100));
        assert!(!set.contains(6, 100));
        assert!(set.contains(10, 100));
        assert!(!set.contains(11, 100));
        assert!(set.contains(20, 100));
        assert!(set.contains(50, 100));
        assert!(set.contains(100, 100));
    }

    #[test]
    fn test_sequence_set_single() {
        let set = parse_sequence_set("42").unwrap();
        assert!(set.contains(42, 100));
        assert!(!set.contains(41, 100));
    }

    #[test]
    fn test_parse_fetch_all_macro() {
        let cmd = parse_command("a001 FETCH 1:* ALL").unwrap();
        match cmd {
            Command::Fetch { items, .. } => {
                assert_eq!(items, vec![FetchItem::All]);
            }
            _ => panic!("expected Fetch"),
        }
    }

    #[test]
    fn test_parse_fetch_multiple_items() {
        let cmd =
            parse_command("a001 FETCH 1 (FLAGS UID ENVELOPE RFC822.SIZE INTERNALDATE)").unwrap();
        match cmd {
            Command::Fetch { items, .. } => {
                assert_eq!(items.len(), 5);
                assert!(items.contains(&FetchItem::Flags));
                assert!(items.contains(&FetchItem::Uid));
                assert!(items.contains(&FetchItem::Envelope));
                assert!(items.contains(&FetchItem::Rfc822Size));
                assert!(items.contains(&FetchItem::InternalDate));
            }
            _ => panic!("expected Fetch"),
        }
    }

    #[test]
    fn test_parse_examine() {
        let cmd = parse_command("a006 EXAMINE INBOX").unwrap();
        assert_eq!(
            cmd,
            Command::Examine {
                tag: "a006".to_string(),
                mailbox: "INBOX".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_examine_quoted() {
        let cmd = parse_command("a007 EXAMINE \"Sent Items\"").unwrap();
        assert_eq!(
            cmd,
            Command::Examine {
                tag: "a007".to_string(),
                mailbox: "Sent Items".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_imap_date() {
        // 1-Jan-2000 = 946684800 unix timestamp
        let ts = parse_imap_date("1-Jan-2000").unwrap();
        assert_eq!(ts, 946684800);
    }

    #[test]
    fn test_parse_search_before() {
        let cmd = parse_command("a001 SEARCH BEFORE 1-Jan-2020").unwrap();
        match cmd {
            Command::Search { criteria, .. } => {
                assert_eq!(criteria.len(), 1);
                match &criteria[0] {
                    SearchKey::Before(ts) => {
                        // 1-Jan-2020 = 1577836800 unix timestamp
                        assert_eq!(*ts, 1577836800);
                    }
                    _ => panic!("expected Before"),
                }
            }
            _ => panic!("expected Search"),
        }
    }

    #[test]
    fn test_parse_search_before_rejects_day_zero() {
        assert!(parse_command("a001 SEARCH BEFORE 0-Jan-2020").is_err());
    }

    #[test]
    fn test_parse_search_larger() {
        let cmd = parse_command("a001 SEARCH LARGER 10000").unwrap();
        match cmd {
            Command::Search { criteria, .. } => {
                assert_eq!(criteria.len(), 1);
                match &criteria[0] {
                    SearchKey::Larger(size) => {
                        assert_eq!(*size, 10000_i64);
                    }
                    _ => panic!("expected Larger"),
                }
            }
            _ => panic!("expected Search"),
        }
    }

    #[test]
    fn test_parse_search_cc() {
        let cmd = parse_command("a001 SEARCH CC \"bob@example.com\"").unwrap();
        match cmd {
            Command::Search { criteria, .. } => {
                assert_eq!(criteria.len(), 1);
                match &criteria[0] {
                    SearchKey::Cc(s) => {
                        assert_eq!(s, "bob@example.com");
                    }
                    _ => panic!("expected Cc"),
                }
            }
            _ => panic!("expected Search"),
        }
    }

    #[test]
    fn test_parse_search_new() {
        let cmd = parse_command("a001 SEARCH NEW").unwrap();
        match cmd {
            Command::Search { criteria, .. } => {
                assert_eq!(criteria.len(), 1);
                assert_eq!(criteria[0], SearchKey::New);
            }
            _ => panic!("expected Search"),
        }
    }

    #[test]
    fn test_parse_uid_expunge() {
        let cmd = parse_command("a001 UID EXPUNGE 1:5,10").unwrap();
        match cmd {
            Command::UidExpunge { tag, sequence } => {
                assert_eq!(tag, "a001");
                assert!(sequence.contains(3, 10));
                assert!(sequence.contains(10, 10));
                assert!(!sequence.contains(7, 10));
            }
            _ => panic!("expected UidExpunge"),
        }
    }

    #[test]
    fn test_parse_fetch_rejects_zero_sequence_number() {
        assert!(parse_command("a001 FETCH 0 FLAGS").is_err());
    }

    #[test]
    fn test_parse_fetch_rejects_unknown_item() {
        assert!(parse_command("a001 FETCH 1 (FLAGS BOGUS)").is_err());
    }

    #[test]
    fn test_parse_search_rejects_unknown_criterion() {
        assert!(parse_command("a001 SEARCH BOGUS").is_err());
    }

    #[test]
    fn test_parse_uid_expunge_rejects_extra_args() {
        assert!(parse_command("a001 UID EXPUNGE 1:5 extra").is_err());
    }

    #[test]
    fn test_parse_unselect() {
        let cmd = parse_command("a001 UNSELECT").unwrap();
        match cmd {
            Command::Unselect { tag } => assert_eq!(tag, "a001"),
            _ => panic!("expected Unselect"),
        }
    }
}
