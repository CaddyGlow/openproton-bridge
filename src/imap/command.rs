use super::{ImapError, Result};

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
    Select {
        tag: String,
        mailbox: String,
    },
    Status {
        tag: String,
        mailbox: String,
        items: Vec<StatusDataItem>,
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
}

#[derive(Debug, Clone, PartialEq)]
pub struct SequenceSet {
    pub ranges: Vec<SeqRange>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SeqRange {
    pub start: SeqNum,
    pub end: Option<SeqNum>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SeqNum {
    Num(u32),
    Wild, // *
}

#[derive(Debug, Clone, PartialEq)]
pub enum FetchItem {
    Flags,
    Uid,
    Envelope,
    Rfc822Size,
    InternalDate,
    BodyStructure,
    Body,
    BodySection { section: Option<String>, peek: bool },
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
    Not(Box<SearchKey>),
    Or(Box<SearchKey>, Box<SearchKey>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusDataItem {
    Messages,
    Recent,
    UidNext,
    UidValidity,
    Unseen,
}

impl SequenceSet {
    pub fn contains(&self, num: u32, max: u32) -> bool {
        self.ranges.iter().any(|r| {
            let start = match r.start {
                SeqNum::Num(n) => n,
                SeqNum::Wild => max,
            };
            let end = match &r.end {
                Some(SeqNum::Num(n)) => *n,
                Some(SeqNum::Wild) => max,
                None => start,
            };
            let lo = start.min(end);
            let hi = start.max(end);
            num >= lo && num <= hi
        })
    }
}

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
        "SELECT" => parse_select(&tag, args),
        "STATUS" => parse_status(&tag, args),
        "CLOSE" => Ok(Command::Close { tag }),
        "FETCH" => parse_fetch(&tag, args, false),
        "STORE" => parse_store(&tag, args, false),
        "SEARCH" => parse_search(&tag, args, false),
        "EXPUNGE" => Ok(Command::Expunge { tag }),
        "COPY" => parse_copy(&tag, args, false),
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
        _ => Err(ImapError::Protocol(format!(
            "unknown UID subcommand: {}",
            cmd_word
        ))),
    }
}

fn split_first_word(s: &str) -> Result<(String, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return Err(ImapError::Protocol("unexpected end of input".to_string()));
    }
    match s.find(' ') {
        Some(pos) => Ok((s[..pos].to_string(), &s[pos + 1..])),
        None => Ok((s.to_string(), "")),
    }
}

fn parse_login(tag: &str, args: &str) -> Result<Command> {
    let (username, rest) = parse_astring(args.trim_start())?;
    let (password, _) = parse_astring(rest.trim_start())?;
    Ok(Command::Login {
        tag: tag.to_string(),
        username,
        password,
    })
}

fn parse_astring(s: &str) -> Result<(String, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return Err(ImapError::Protocol("expected string argument".to_string()));
    }

    if s.starts_with('"') {
        parse_quoted_string(s)
    } else {
        // atom
        let end = s.find([' ', ')', '(']).unwrap_or(s.len());
        if end == 0 {
            return Err(ImapError::Protocol("expected string argument".to_string()));
        }
        Ok((s[..end].to_string(), &s[end..]))
    }
}

fn parse_quoted_string(s: &str) -> Result<(String, &str)> {
    debug_assert!(s.starts_with('"'));
    let mut result = String::new();
    let mut chars = s[1..].char_indices();
    loop {
        match chars.next() {
            Some((_, '\\')) => {
                if let Some((_, c)) = chars.next() {
                    result.push(c);
                } else {
                    return Err(ImapError::Protocol(
                        "unterminated quoted string".to_string(),
                    ));
                }
            }
            Some((i, '"')) => {
                return Ok((result, &s[i + 2..]));
            }
            Some((_, c)) => result.push(c),
            None => {
                return Err(ImapError::Protocol(
                    "unterminated quoted string".to_string(),
                ))
            }
        }
    }
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

fn parse_select(tag: &str, args: &str) -> Result<Command> {
    let (mailbox, _) = parse_astring(args.trim_start())?;
    Ok(Command::Select {
        tag: tag.to_string(),
        mailbox,
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

fn parse_sequence_set(s: &str) -> Result<SequenceSet> {
    let mut ranges = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(colon) = part.find(':') {
            let start = parse_seq_num(&part[..colon])?;
            let end = parse_seq_num(&part[colon + 1..])?;
            ranges.push(SeqRange {
                start,
                end: Some(end),
            });
        } else {
            let num = parse_seq_num(part)?;
            ranges.push(SeqRange {
                start: num,
                end: None,
            });
        }
    }
    if ranges.is_empty() {
        return Err(ImapError::Protocol("empty sequence set".to_string()));
    }
    Ok(SequenceSet { ranges })
}

fn parse_seq_num(s: &str) -> Result<SeqNum> {
    if s == "*" {
        Ok(SeqNum::Wild)
    } else {
        s.parse::<u32>()
            .map(SeqNum::Num)
            .map_err(|_| ImapError::Protocol(format!("invalid sequence number: {}", s)))
    }
}

fn parse_fetch(tag: &str, args: &str, uid: bool) -> Result<Command> {
    let (seq_str, rest) = split_first_word(args)?;
    let sequence = parse_sequence_set(&seq_str)?;
    let items = parse_fetch_items(rest.trim())?;
    Ok(Command::Fetch {
        tag: tag.to_string(),
        sequence,
        items,
        uid,
    })
}

fn parse_fetch_items(s: &str) -> Result<Vec<FetchItem>> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ImapError::Protocol("no fetch items specified".to_string()));
    }

    // Check for macro names
    let upper = s.to_uppercase();
    match upper.as_str() {
        "ALL" => return Ok(vec![FetchItem::All]),
        "FAST" => return Ok(vec![FetchItem::Fast]),
        "FULL" => return Ok(vec![FetchItem::Full]),
        _ => {}
    }

    let content = if s.starts_with('(') && s.ends_with(')') {
        &s[1..s.len() - 1]
    } else {
        s
    };

    let mut items = Vec::new();
    let mut remaining = content.trim();

    while !remaining.is_empty() {
        let upper_rem = remaining.to_uppercase();
        if upper_rem.starts_with("FLAGS") {
            items.push(FetchItem::Flags);
            remaining = remaining[5..].trim_start();
        } else if upper_rem.starts_with("UID") {
            items.push(FetchItem::Uid);
            remaining = remaining[3..].trim_start();
        } else if upper_rem.starts_with("ENVELOPE") {
            items.push(FetchItem::Envelope);
            remaining = remaining[8..].trim_start();
        } else if upper_rem.starts_with("RFC822.SIZE") {
            items.push(FetchItem::Rfc822Size);
            remaining = remaining[11..].trim_start();
        } else if upper_rem.starts_with("INTERNALDATE") {
            items.push(FetchItem::InternalDate);
            remaining = remaining[12..].trim_start();
        } else if upper_rem.starts_with("BODYSTRUCTURE") {
            items.push(FetchItem::BodyStructure);
            remaining = remaining[13..].trim_start();
        } else if upper_rem.starts_with("BODY.PEEK[") {
            let (item, rest) = parse_body_section(remaining, true)?;
            items.push(item);
            remaining = rest.trim_start();
        } else if upper_rem.starts_with("BODY[") {
            let (item, rest) = parse_body_section(remaining, false)?;
            items.push(item);
            remaining = rest.trim_start();
        } else if upper_rem.starts_with("BODY")
            && !upper_rem.starts_with("BODY[")
            && !upper_rem.starts_with("BODY.")
        {
            items.push(FetchItem::Body);
            remaining = remaining[4..].trim_start();
        } else {
            // Skip unknown token
            let end = remaining.find(' ').unwrap_or(remaining.len());
            remaining = remaining[end..].trim_start();
        }
    }

    if items.is_empty() {
        return Err(ImapError::Protocol("no valid fetch items".to_string()));
    }

    Ok(items)
}

fn parse_body_section(s: &str, peek: bool) -> Result<(FetchItem, &str)> {
    let bracket_start = s
        .find('[')
        .ok_or_else(|| ImapError::Protocol("expected [".to_string()))?;
    let bracket_end = s
        .find(']')
        .ok_or_else(|| ImapError::Protocol("expected ]".to_string()))?;
    let section_str = &s[bracket_start + 1..bracket_end];
    let section = if section_str.is_empty() {
        None
    } else {
        Some(section_str.to_string())
    };

    Ok((
        FetchItem::BodySection { section, peek },
        &s[bracket_end + 1..],
    ))
}

fn parse_store(tag: &str, args: &str, uid: bool) -> Result<Command> {
    let (seq_str, rest) = split_first_word(args)?;
    let sequence = parse_sequence_set(&seq_str)?;
    let (action_str, rest) = split_first_word(rest)?;
    let action = match action_str.to_uppercase().as_str() {
        "FLAGS" => StoreAction::SetFlags,
        "+FLAGS" => StoreAction::AddFlags,
        "-FLAGS" => StoreAction::RemoveFlags,
        "FLAGS.SILENT" => StoreAction::SetFlagsSilent,
        "+FLAGS.SILENT" => StoreAction::AddFlagsSilent,
        "-FLAGS.SILENT" => StoreAction::RemoveFlagsSilent,
        _ => {
            return Err(ImapError::Protocol(format!(
                "unknown store action: {}",
                action_str
            )))
        }
    };
    let flags = parse_flag_list(rest.trim())?;
    Ok(Command::Store {
        tag: tag.to_string(),
        sequence,
        action,
        flags,
        uid,
    })
}

fn parse_flag_list(s: &str) -> Result<Vec<ImapFlag>> {
    let content = if s.starts_with('(') && s.ends_with(')') {
        &s[1..s.len() - 1]
    } else {
        s
    };

    let mut flags = Vec::new();
    for word in content.split_whitespace() {
        if !word.is_empty() {
            flags.push(ImapFlag::parse(word));
        }
    }
    Ok(flags)
}

fn parse_search(tag: &str, args: &str, uid: bool) -> Result<Command> {
    let criteria = parse_search_criteria(args.trim())?;
    Ok(Command::Search {
        tag: tag.to_string(),
        criteria,
        uid,
    })
}

fn parse_search_criteria(s: &str) -> Result<Vec<SearchKey>> {
    let mut criteria = Vec::new();
    let mut remaining = s;

    while !remaining.is_empty() {
        let upper = remaining.to_uppercase();
        if upper.starts_with("ALL") {
            criteria.push(SearchKey::All);
            remaining = remaining[3..].trim_start();
        } else if upper.starts_with("UNSEEN") {
            criteria.push(SearchKey::Unseen);
            remaining = remaining[6..].trim_start();
        } else if upper.starts_with("SEEN") {
            criteria.push(SearchKey::Seen);
            remaining = remaining[4..].trim_start();
        } else if upper.starts_with("FLAGGED") {
            criteria.push(SearchKey::Flagged);
            remaining = remaining[7..].trim_start();
        } else if upper.starts_with("DELETED") {
            criteria.push(SearchKey::Deleted);
            remaining = remaining[7..].trim_start();
        } else if upper.starts_with("ANSWERED") {
            criteria.push(SearchKey::Answered);
            remaining = remaining[8..].trim_start();
        } else if upper.starts_with("DRAFT") {
            criteria.push(SearchKey::Draft);
            remaining = remaining[5..].trim_start();
        } else if upper.starts_with("SUBJECT ") {
            remaining = &remaining[8..];
            let (val, rest) = parse_astring(remaining)?;
            criteria.push(SearchKey::Subject(val));
            remaining = rest.trim_start();
        } else if upper.starts_with("FROM ") {
            remaining = &remaining[5..];
            let (val, rest) = parse_astring(remaining)?;
            criteria.push(SearchKey::From(val));
            remaining = rest.trim_start();
        } else if upper.starts_with("TO ") {
            remaining = &remaining[3..];
            let (val, rest) = parse_astring(remaining)?;
            criteria.push(SearchKey::To(val));
            remaining = rest.trim_start();
        } else if upper.starts_with("UID ") {
            remaining = &remaining[4..];
            let (seq_str, rest) = split_first_word(remaining)?;
            let seq = parse_sequence_set(&seq_str)?;
            criteria.push(SearchKey::Uid(seq));
            remaining = rest.trim_start();
        } else if upper.starts_with("NOT ") {
            remaining = remaining[4..].trim_start();
            // Parse the next single criterion
            let sub_criteria = parse_search_criteria(remaining)?;
            if let Some(first) = sub_criteria.into_iter().next() {
                criteria.push(SearchKey::Not(Box::new(first)));
            }
            break;
        } else {
            // Skip unrecognized token
            let end = remaining.find(' ').unwrap_or(remaining.len());
            remaining = remaining[end..].trim_start();
        }
    }

    if criteria.is_empty() {
        criteria.push(SearchKey::All);
    }

    Ok(criteria)
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
                        peek: true
                    }]
                );
            }
            _ => panic!("expected Fetch"),
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
}
