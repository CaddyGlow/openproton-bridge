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
        "LSUB" => parse_lsub(&tag, args),
        "SELECT" => parse_select(&tag, args),
        "CREATE" => parse_create(&tag, args),
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
        let num = s
            .parse::<u32>()
            .map_err(|_| ImapError::Protocol(format!("invalid sequence number: {}", s)))?;
        if num == 0 {
            return Err(ImapError::Protocol(format!(
                "invalid sequence number (must be non-zero): {}",
                s
            )));
        }
        Ok(SeqNum::Num(num))
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

fn starts_fetch_item_keyword(upper: &str, keyword: &str) -> bool {
    if !upper.starts_with(keyword) {
        return false;
    }
    if upper.len() == keyword.len() {
        return true;
    }
    upper.as_bytes()[keyword.len()].is_ascii_whitespace()
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
        if starts_fetch_item_keyword(&upper_rem, "FLAGS") {
            items.push(FetchItem::Flags);
            remaining = remaining[5..].trim_start();
        } else if starts_fetch_item_keyword(&upper_rem, "UID") {
            items.push(FetchItem::Uid);
            remaining = remaining[3..].trim_start();
        } else if starts_fetch_item_keyword(&upper_rem, "ENVELOPE") {
            items.push(FetchItem::Envelope);
            remaining = remaining[8..].trim_start();
        } else if starts_fetch_item_keyword(&upper_rem, "RFC822.SIZE") {
            items.push(FetchItem::Rfc822Size);
            remaining = remaining[11..].trim_start();
        } else if starts_fetch_item_keyword(&upper_rem, "INTERNALDATE") {
            items.push(FetchItem::InternalDate);
            remaining = remaining[12..].trim_start();
        } else if starts_fetch_item_keyword(&upper_rem, "BODYSTRUCTURE") {
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
        } else if starts_fetch_item_keyword(&upper_rem, "BODY") {
            items.push(FetchItem::Body);
            remaining = remaining[4..].trim_start();
        } else {
            let token = remaining
                .split_whitespace()
                .next()
                .unwrap_or(remaining)
                .to_string();
            return Err(ImapError::Protocol(format!(
                "unknown fetch item: {}",
                token
            )));
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

    let rest = &s[bracket_end + 1..];

    // Parse optional partial: <origin.count>
    let (partial, rest) = if rest.starts_with('<') {
        if let Some(end) = rest.find('>') {
            let partial_str = &rest[1..end];
            if let Some((origin_str, count_str)) = partial_str.split_once('.') {
                let origin: u32 = origin_str
                    .parse()
                    .map_err(|_| ImapError::Protocol("invalid partial origin".to_string()))?;
                let count: u32 = count_str
                    .parse()
                    .map_err(|_| ImapError::Protocol("invalid partial count".to_string()))?;
                (Some((origin, count)), &rest[end + 1..])
            } else {
                (None, rest)
            }
        } else {
            (None, rest)
        }
    } else {
        (None, rest)
    };

    Ok((
        FetchItem::BodySection {
            section,
            peek,
            partial,
        },
        rest,
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

/// Parse IMAP date format "DD-Mon-YYYY" to unix timestamp (start of day UTC).
fn parse_imap_date(s: &str) -> Result<i64> {
    let months = [
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
    ];
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return Err(ImapError::Protocol(format!("invalid date: {}", s)));
    }
    let day: u32 = parts[0]
        .parse()
        .map_err(|_| ImapError::Protocol(format!("invalid day: {}", parts[0])))?;
    let month_str = parts[1].to_uppercase();
    let month = months
        .iter()
        .position(|&m| m == month_str)
        .ok_or_else(|| ImapError::Protocol(format!("invalid month: {}", parts[1])))?
        as u32
        + 1;
    let year: i32 = parts[2]
        .parse()
        .map_err(|_| ImapError::Protocol(format!("invalid year: {}", parts[2])))?;

    if day == 0 {
        return Err(ImapError::Protocol(format!("invalid day: {}", parts[0])));
    }

    // Simple calculation: days since epoch (1970-01-01)
    let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let is_leap = |y: i32| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mut max_day = days_in_month[(month - 1) as usize];
    if month == 2 && is_leap(year) {
        max_day += 1;
    }
    if day > max_day {
        return Err(ImapError::Protocol(format!("invalid day: {}", parts[0])));
    }

    let mut total_days: i64 = 0;
    for y in 1970..year {
        total_days += if is_leap(y) { 366 } else { 365 };
    }
    for m in 1..month {
        total_days += days_in_month[(m - 1) as usize] as i64;
        if m == 2 && is_leap(year) {
            total_days += 1;
        }
    }
    total_days += (day - 1) as i64;
    Ok(total_days * 86400)
}

fn parse_search_criteria(s: &str) -> Result<Vec<SearchKey>> {
    if s.trim().is_empty() {
        return Ok(vec![SearchKey::All]);
    }

    let mut criteria = Vec::new();
    let mut remaining = s.trim();

    while !remaining.is_empty() {
        let (criterion, rest) = parse_search_criterion(remaining)?;
        criteria.push(criterion);
        remaining = rest.trim_start();
    }

    Ok(criteria)
}

fn starts_search_keyword(upper: &str, keyword: &str) -> bool {
    if !upper.starts_with(keyword) {
        return false;
    }
    if upper.len() == keyword.len() {
        return true;
    }
    upper.as_bytes()[keyword.len()].is_ascii_whitespace()
}

fn parse_search_criterion(s: &str) -> Result<(SearchKey, &str)> {
    let remaining = s.trim_start();
    if remaining.is_empty() {
        return Err(ImapError::Protocol("missing SEARCH criterion".to_string()));
    }
    let upper = remaining.to_uppercase();

    if starts_search_keyword(&upper, "ALL") {
        Ok((SearchKey::All, remaining[3..].trim_start()))
    } else if starts_search_keyword(&upper, "UNSEEN") {
        Ok((SearchKey::Unseen, remaining[6..].trim_start()))
    } else if starts_search_keyword(&upper, "SEEN") {
        Ok((SearchKey::Seen, remaining[4..].trim_start()))
    } else if starts_search_keyword(&upper, "FLAGGED") {
        Ok((SearchKey::Flagged, remaining[7..].trim_start()))
    } else if starts_search_keyword(&upper, "DELETED") {
        Ok((SearchKey::Deleted, remaining[7..].trim_start()))
    } else if starts_search_keyword(&upper, "ANSWERED") {
        Ok((SearchKey::Answered, remaining[8..].trim_start()))
    } else if starts_search_keyword(&upper, "DRAFT") {
        Ok((SearchKey::Draft, remaining[5..].trim_start()))
    } else if starts_search_keyword(&upper, "NEW") {
        Ok((SearchKey::New, remaining[3..].trim_start()))
    } else if starts_search_keyword(&upper, "OLD") {
        Ok((SearchKey::Old, remaining[3..].trim_start()))
    } else if starts_search_keyword(&upper, "RECENT") {
        Ok((SearchKey::Recent, remaining[6..].trim_start()))
    } else if starts_search_keyword(&upper, "SUBJECT") {
        let remaining = &remaining[7..];
        let (val, rest) = parse_astring(remaining)?;
        Ok((SearchKey::Subject(val), rest.trim_start()))
    } else if starts_search_keyword(&upper, "FROM") {
        let remaining = &remaining[4..];
        let (val, rest) = parse_astring(remaining)?;
        Ok((SearchKey::From(val), rest.trim_start()))
    } else if starts_search_keyword(&upper, "TO") {
        let remaining = &remaining[2..];
        let (val, rest) = parse_astring(remaining)?;
        Ok((SearchKey::To(val), rest.trim_start()))
    } else if starts_search_keyword(&upper, "CC") {
        let remaining = &remaining[2..];
        let (val, rest) = parse_astring(remaining)?;
        Ok((SearchKey::Cc(val), rest.trim_start()))
    } else if starts_search_keyword(&upper, "BCC") {
        let remaining = &remaining[3..];
        let (val, rest) = parse_astring(remaining)?;
        Ok((SearchKey::Bcc(val), rest.trim_start()))
    } else if starts_search_keyword(&upper, "BODY") {
        let remaining = &remaining[4..];
        let (val, rest) = parse_astring(remaining)?;
        Ok((SearchKey::Body(val), rest.trim_start()))
    } else if starts_search_keyword(&upper, "TEXT") {
        let remaining = &remaining[4..];
        let (val, rest) = parse_astring(remaining)?;
        Ok((SearchKey::Text(val), rest.trim_start()))
    } else if starts_search_keyword(&upper, "KEYWORD") {
        let remaining = &remaining[7..];
        let (val, rest) = parse_astring(remaining)?;
        Ok((SearchKey::Keyword(val), rest.trim_start()))
    } else if starts_search_keyword(&upper, "UNKEYWORD") {
        let remaining = &remaining[9..];
        let (val, rest) = parse_astring(remaining)?;
        Ok((SearchKey::Unkeyword(val), rest.trim_start()))
    } else if starts_search_keyword(&upper, "HEADER") {
        let remaining = &remaining[6..];
        let (field, rest) = parse_astring(remaining)?;
        let (value, rest2) = parse_astring(rest.trim_start())?;
        Ok((SearchKey::Header(field, value), rest2.trim_start()))
    } else if starts_search_keyword(&upper, "BEFORE") {
        let remaining = &remaining[6..];
        let (date_str, rest) = parse_astring(remaining)?;
        let ts = parse_imap_date(&date_str)?;
        Ok((SearchKey::Before(ts), rest.trim_start()))
    } else if starts_search_keyword(&upper, "SINCE") {
        let remaining = &remaining[5..];
        let (date_str, rest) = parse_astring(remaining)?;
        let ts = parse_imap_date(&date_str)?;
        Ok((SearchKey::Since(ts), rest.trim_start()))
    } else if starts_search_keyword(&upper, "ON") {
        let remaining = &remaining[2..];
        let (date_str, rest) = parse_astring(remaining)?;
        let ts = parse_imap_date(&date_str)?;
        Ok((SearchKey::On(ts), rest.trim_start()))
    } else if starts_search_keyword(&upper, "SENTBEFORE") {
        let remaining = &remaining[10..];
        let (date_str, rest) = parse_astring(remaining)?;
        let ts = parse_imap_date(&date_str)?;
        Ok((SearchKey::SentBefore(ts), rest.trim_start()))
    } else if starts_search_keyword(&upper, "SENTSINCE") {
        let remaining = &remaining[9..];
        let (date_str, rest) = parse_astring(remaining)?;
        let ts = parse_imap_date(&date_str)?;
        Ok((SearchKey::SentSince(ts), rest.trim_start()))
    } else if starts_search_keyword(&upper, "SENTON") {
        let remaining = &remaining[6..];
        let (date_str, rest) = parse_astring(remaining)?;
        let ts = parse_imap_date(&date_str)?;
        Ok((SearchKey::SentOn(ts), rest.trim_start()))
    } else if starts_search_keyword(&upper, "LARGER") {
        let remaining = &remaining[6..];
        let (size_str, rest) = split_first_word(remaining)?;
        let size: i64 = size_str
            .parse()
            .map_err(|_| ImapError::Protocol(format!("invalid size: {}", size_str)))?;
        Ok((SearchKey::Larger(size), rest.trim_start()))
    } else if starts_search_keyword(&upper, "SMALLER") {
        let remaining = &remaining[7..];
        let (size_str, rest) = split_first_word(remaining)?;
        let size: i64 = size_str
            .parse()
            .map_err(|_| ImapError::Protocol(format!("invalid size: {}", size_str)))?;
        Ok((SearchKey::Smaller(size), rest.trim_start()))
    } else if starts_search_keyword(&upper, "UID") {
        let remaining = &remaining[3..];
        let (seq_str, rest) = split_first_word(remaining)?;
        let seq = parse_sequence_set(&seq_str)?;
        Ok((SearchKey::Uid(seq), rest.trim_start()))
    } else if starts_search_keyword(&upper, "OR") {
        let remaining = remaining[2..].trim_start();
        let (left, rest_left) = parse_search_criterion(remaining)?;
        let (right, rest_right) = parse_search_criterion(rest_left)?;
        Ok((SearchKey::Or(Box::new(left), Box::new(right)), rest_right))
    } else if starts_search_keyword(&upper, "NOT") {
        let remaining = remaining[3..].trim_start();
        let (inner, rest) = parse_search_criterion(remaining)?;
        Ok((SearchKey::Not(Box::new(inner)), rest))
    } else {
        let token = remaining
            .split_whitespace()
            .next()
            .unwrap_or(remaining)
            .to_string();
        Err(ImapError::Protocol(format!(
            "unknown SEARCH criterion: {}",
            token
        )))
    }
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
