use crate::imap_error::{ImapError, ImapResult as Result};

use super::parse_helpers::split_first_word;
use super::sequence::parse_sequence_set;
use super::{Command, FetchItem};

pub fn parse_fetch(tag: &str, args: &str, uid: bool) -> Result<Command> {
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

pub fn starts_fetch_item_keyword(upper: &str, keyword: &str) -> bool {
    if !upper.starts_with(keyword) {
        return false;
    }
    if upper.len() == keyword.len() {
        return true;
    }
    upper.as_bytes()[keyword.len()].is_ascii_whitespace()
}

pub fn parse_fetch_items(s: &str) -> Result<Vec<FetchItem>> {
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
        } else if starts_fetch_item_keyword(&upper_rem, "RFC822.HEADER") {
            items.push(FetchItem::Rfc822Header);
            remaining = remaining[13..].trim_start();
        } else if starts_fetch_item_keyword(&upper_rem, "RFC822.TEXT") {
            items.push(FetchItem::Rfc822Text);
            remaining = remaining[10..].trim_start();
        } else if starts_fetch_item_keyword(&upper_rem, "RFC822.SIZE") {
            items.push(FetchItem::Rfc822Size);
            remaining = remaining[11..].trim_start();
        } else if starts_fetch_item_keyword(&upper_rem, "RFC822") {
            items.push(FetchItem::Rfc822);
            remaining = remaining[6..].trim_start();
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

pub fn parse_body_section(s: &str, peek: bool) -> Result<(FetchItem, &str)> {
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
