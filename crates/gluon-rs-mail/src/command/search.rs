use crate::imap_error::{ImapError, ImapResult as Result};

use super::parse_helpers::{parse_astring, split_first_word, starts_search_keyword};
use super::sequence::parse_sequence_set;
use super::{Command, SearchKey};

pub fn parse_search(tag: &str, args: &str, uid: bool) -> Result<Command> {
    let criteria = parse_search_criteria(args.trim())?;
    Ok(Command::Search {
        tag: tag.to_string(),
        criteria,
        uid,
    })
}

/// Parse IMAP date format "DD-Mon-YYYY" to unix timestamp (start of day UTC).
pub fn parse_imap_date(s: &str) -> Result<i64> {
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

pub fn parse_search_criteria(s: &str) -> Result<Vec<SearchKey>> {
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

pub fn parse_search_criterion(s: &str) -> Result<(SearchKey, &str)> {
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
    } else if starts_search_keyword(&upper, "UNANSWERED") {
        Ok((
            SearchKey::Not(Box::new(SearchKey::Answered)),
            remaining[10..].trim_start(),
        ))
    } else if starts_search_keyword(&upper, "UNDELETED") {
        Ok((
            SearchKey::Not(Box::new(SearchKey::Deleted)),
            remaining[9..].trim_start(),
        ))
    } else if starts_search_keyword(&upper, "UNDRAFT") {
        Ok((
            SearchKey::Not(Box::new(SearchKey::Draft)),
            remaining[7..].trim_start(),
        ))
    } else if starts_search_keyword(&upper, "UNFLAGGED") {
        Ok((
            SearchKey::Not(Box::new(SearchKey::Flagged)),
            remaining[9..].trim_start(),
        ))
    } else if remaining.starts_with('(') {
        let close = remaining
            .find(')')
            .ok_or_else(|| ImapError::Protocol("unclosed paren in SEARCH".into()))?;
        let inner = remaining[1..close].trim();
        let (key, _) = parse_search_criterion(inner)?;
        Ok((key, remaining[close + 1..].trim_start()))
    } else if remaining
        .as_bytes()
        .first()
        .is_some_and(|b| b.is_ascii_digit() || *b == b'*')
    {
        // Message sequence set: e.g., "1:7" or "1,3,5" or "*"
        let (seq_str, rest) = split_first_word(remaining)?;
        let seq = parse_sequence_set(&seq_str)?;
        Ok((SearchKey::Sequence(seq), rest.trim_start()))
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
