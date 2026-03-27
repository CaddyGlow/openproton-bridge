use crate::imap_error::{ImapError, ImapResult as Result};

pub fn split_first_word(s: &str) -> Result<(String, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return Err(ImapError::Protocol("unexpected end of input".to_string()));
    }
    match s.find(' ') {
        Some(pos) => Ok((s[..pos].to_string(), &s[pos + 1..])),
        None => Ok((s.to_string(), "")),
    }
}

pub fn parse_astring(s: &str) -> Result<(String, &str)> {
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

pub fn parse_quoted_string(s: &str) -> Result<(String, &str)> {
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

pub fn starts_search_keyword(upper: &str, keyword: &str) -> bool {
    if !upper.starts_with(keyword) {
        return false;
    }
    if upper.len() == keyword.len() {
        return true;
    }
    upper.as_bytes()[keyword.len()].is_ascii_whitespace()
}
