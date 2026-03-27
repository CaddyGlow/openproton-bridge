use crate::imap_error::{ImapError, ImapResult as Result};

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

pub fn parse_sequence_set(s: &str) -> Result<SequenceSet> {
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
