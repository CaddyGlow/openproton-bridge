use crate::imap_error::{ImapError, ImapResult as Result};

use super::parse_helpers::split_first_word;
use super::sequence::parse_sequence_set;
use super::{Command, ImapFlag, StoreAction};

pub fn parse_store(tag: &str, args: &str, uid: bool) -> Result<Command> {
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

pub fn parse_flag_list(s: &str) -> Result<Vec<ImapFlag>> {
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
