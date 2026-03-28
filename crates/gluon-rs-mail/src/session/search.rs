use tokio::io::AsyncWriteExt;

use super::*;

impl<R, W> ImapSession<R, W>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: AsyncWriteExt + Unpin + Send,
{
    pub async fn cmd_search(
        &mut self,
        tag: &str,
        criteria: &[SearchKey],
        uid_mode: bool,
    ) -> Result<()> {
        if self.state != State::Selected {
            return self.writer.tagged_no(tag, "no mailbox selected").await;
        }

        self.refresh_selected_snapshot().await?;
        let mailbox = self.selected_mailbox.as_ref().unwrap().clone();
        let scoped_mailbox = self.scoped_mailbox_name(&mailbox);
        let _mailbox_view = self.config.mailbox_view.clone();
        let all_uids = self.selected_mailbox_uids.clone();
        let needs_rfc822 = criteria.iter().any(search_key_needs_rfc822);

        let mut results = Vec::new();
        let max_uid = all_uids.last().copied().unwrap_or(ImapUid::from(0u32));

        for (i, &uid) in all_uids.iter().enumerate() {
            let seq = i as u32 + 1;
            let meta = self
                .config
                .mailbox_view
                .get_metadata(&scoped_mailbox, uid)
                .await?;
            let flags = self
                .selected_mailbox_flags
                .get(&uid)
                .cloned()
                .unwrap_or_default();

            let mut rfc822_data = if needs_rfc822 {
                self.config
                    .mailbox_view
                    .get_rfc822(&scoped_mailbox, uid)
                    .await?
            } else {
                None
            };
            if needs_rfc822 && rfc822_data.is_none() {
                if let Some(meta) = meta.as_ref() {
                    rfc822_data = self
                        .fetch_and_cache_rfc822(&scoped_mailbox, uid, &meta.id)
                        .await?;
                }
            }

            let max_seq = all_uids.len() as u32;
            let matches = criteria.iter().all(|c| {
                evaluate_search_key(
                    c,
                    uid,
                    seq,
                    max_seq,
                    &meta,
                    &flags,
                    max_uid,
                    rfc822_data.as_deref(),
                )
            });

            if matches {
                if uid_mode {
                    results.push(uid.to_string());
                } else {
                    results.push(seq.to_string());
                }
            }
        }

        if results.is_empty() {
            self.writer.untagged("SEARCH").await?;
        } else {
            self.writer
                .untagged(&format!("SEARCH {}", results.join(" ")))
                .await?;
        }

        self.writer.tagged_ok(tag, None, "SEARCH completed").await
    }
}

pub fn evaluate_search_key(
    key: &SearchKey,
    uid: ImapUid,
    seq: u32,
    max_seq: u32,
    meta: &Option<crate::imap_types::MessageEnvelope>,
    flags: &[String],
    max_uid: ImapUid,
    rfc822_data: Option<&[u8]>,
) -> bool {
    match key {
        SearchKey::All => true,
        SearchKey::Seen => flags.iter().any(|f| f == "\\Seen"),
        SearchKey::Unseen => !flags.iter().any(|f| f == "\\Seen"),
        SearchKey::Flagged => flags.iter().any(|f| f == "\\Flagged"),
        SearchKey::Deleted => flags.iter().any(|f| f == "\\Deleted"),
        SearchKey::Answered => flags.iter().any(|f| f == "\\Answered"),
        SearchKey::Draft => flags.iter().any(|f| f == "\\Draft"),
        SearchKey::Recent => flags.iter().any(|f| f == "\\Recent"),
        SearchKey::New => {
            flags.iter().any(|f| f == "\\Recent") && !flags.iter().any(|f| f == "\\Seen")
        }
        SearchKey::Old => !flags.iter().any(|f| f == "\\Recent"),
        SearchKey::Keyword(kw) => flags.iter().any(|f| f.eq_ignore_ascii_case(kw)),
        SearchKey::Unkeyword(kw) => !flags.iter().any(|f| f.eq_ignore_ascii_case(kw)),
        SearchKey::Subject(s) => meta
            .as_ref()
            .map(|m| m.subject.to_lowercase().contains(&s.to_lowercase()))
            .unwrap_or(false),
        SearchKey::From(s) => {
            let s_lower = s.to_lowercase();
            let meta_match = meta
                .as_ref()
                .map(|m| {
                    m.sender.address.to_lowercase().contains(&s_lower)
                        || m.sender.name.to_lowercase().contains(&s_lower)
                })
                .unwrap_or(false);
            meta_match
                || rfc822_data
                    .map(|d| {
                        let hdr = extract_header_section(d);
                        search_raw_header(&hdr, "from", &s_lower)
                    })
                    .unwrap_or(false)
        }
        SearchKey::To(s) => {
            let s_lower = s.to_lowercase();
            let meta_match = meta
                .as_ref()
                .map(|m| {
                    m.to_list.iter().any(|a| {
                        a.address.to_lowercase().contains(&s_lower)
                            || a.name.to_lowercase().contains(&s_lower)
                    })
                })
                .unwrap_or(false);
            meta_match
                || rfc822_data
                    .map(|d| {
                        let hdr = extract_header_section(d);
                        search_raw_header(&hdr, "to", &s_lower)
                    })
                    .unwrap_or(false)
        }
        SearchKey::Cc(s) => {
            let s_lower = s.to_lowercase();
            let meta_match = meta
                .as_ref()
                .map(|m| {
                    m.cc_list.iter().any(|a| {
                        a.address.to_lowercase().contains(&s_lower)
                            || a.name.to_lowercase().contains(&s_lower)
                    })
                })
                .unwrap_or(false);
            meta_match
                || rfc822_data
                    .map(|d| {
                        let hdr = extract_header_section(d);
                        search_raw_header(&hdr, "cc", &s_lower)
                    })
                    .unwrap_or(false)
        }
        SearchKey::Bcc(s) => {
            let s_lower = s.to_lowercase();
            let meta_match = meta
                .as_ref()
                .map(|m| {
                    m.bcc_list.iter().any(|a| {
                        a.address.to_lowercase().contains(&s_lower)
                            || a.name.to_lowercase().contains(&s_lower)
                    })
                })
                .unwrap_or(false);
            meta_match
                || rfc822_data
                    .map(|d| {
                        let hdr = extract_header_section(d);
                        search_raw_header(&hdr, "bcc", &s_lower)
                    })
                    .unwrap_or(false)
        }
        SearchKey::Header(field, value) => {
            if let Some(data) = rfc822_data {
                let header_section = extract_header_section(data);
                let field_lower = field.to_lowercase();
                let value_lower = value.to_lowercase();
                header_section.lines().any(|line| {
                    if let Some(colon_pos) = line.find(':') {
                        let line_field = line[..colon_pos].trim().to_lowercase();
                        if line_field == field_lower {
                            let line_value = line[colon_pos + 1..].trim().to_lowercase();
                            return line_value.contains(&value_lower);
                        }
                    }
                    false
                })
            } else {
                false
            }
        }
        SearchKey::Body(s) => {
            if let Some(data) = rfc822_data {
                let body = extract_text_section(data);
                String::from_utf8_lossy(&body)
                    .to_lowercase()
                    .contains(&s.to_lowercase())
            } else {
                false
            }
        }
        SearchKey::Text(s) => {
            if let Some(data) = rfc822_data {
                String::from_utf8_lossy(data)
                    .to_lowercase()
                    .contains(&s.to_lowercase())
            } else {
                false
            }
        }
        SearchKey::Before(ts) => meta.as_ref().map(|m| m.time < *ts).unwrap_or(false),
        SearchKey::Since(ts) => meta.as_ref().map(|m| m.time >= *ts).unwrap_or(false),
        SearchKey::On(ts) => {
            // Match if message time is on the same day (within 24 hours starting at ts)
            meta.as_ref()
                .map(|m| m.time >= *ts && m.time < *ts + 86400)
                .unwrap_or(false)
        }
        SearchKey::SentBefore(ts) => {
            let sent_time = rfc822_data
                .and_then(extract_sent_date)
                .or_else(|| meta.as_ref().map(|m| m.time));
            sent_time.map(|t| t < *ts).unwrap_or(false)
        }
        SearchKey::SentSince(ts) => {
            let sent_time = rfc822_data
                .and_then(extract_sent_date)
                .or_else(|| meta.as_ref().map(|m| m.time));
            sent_time.map(|t| t >= *ts).unwrap_or(false)
        }
        SearchKey::SentOn(ts) => {
            let sent_time = rfc822_data
                .and_then(extract_sent_date)
                .or_else(|| meta.as_ref().map(|m| m.time));
            sent_time
                .map(|t| t >= *ts && t < *ts + 86400)
                .unwrap_or(false)
        }
        SearchKey::Larger(size) => meta.as_ref().map(|m| m.size > *size).unwrap_or(false),
        SearchKey::Smaller(size) => meta.as_ref().map(|m| m.size < *size).unwrap_or(false),
        SearchKey::Uid(s) => s.contains(uid.value(), max_uid.value()),
        SearchKey::Sequence(s) => s.contains(seq, max_seq),
        SearchKey::Not(inner) => {
            !evaluate_search_key(inner, uid, seq, max_seq, meta, flags, max_uid, rfc822_data)
        }
        SearchKey::Or(a, b) => {
            evaluate_search_key(a, uid, seq, max_seq, meta, flags, max_uid, rfc822_data)
                || evaluate_search_key(b, uid, seq, max_seq, meta, flags, max_uid, rfc822_data)
        }
    }
}

pub fn search_key_needs_rfc822(key: &SearchKey) -> bool {
    match key {
        SearchKey::Header(_, _)
        | SearchKey::Body(_)
        | SearchKey::Text(_)
        | SearchKey::From(_)
        | SearchKey::To(_)
        | SearchKey::Cc(_)
        | SearchKey::Bcc(_)
        | SearchKey::SentBefore(_)
        | SearchKey::SentSince(_)
        | SearchKey::SentOn(_) => true,
        SearchKey::Not(inner) => search_key_needs_rfc822(inner),
        SearchKey::Or(left, right) => {
            search_key_needs_rfc822(left) || search_key_needs_rfc822(right)
        }
        _ => false,
    }
}

/// Search raw header for a field containing a substring (case-insensitive).
/// Uses mailparse for proper folded-header handling.
pub fn search_raw_header(header: &str, field_name: &str, value_lower: &str) -> bool {
    if let Ok((headers, _)) = mailparse::parse_headers(header.as_bytes()) {
        use mailparse::MailHeaderMap;
        if let Some(val) = headers.get_first_value(field_name) {
            return val.to_lowercase().contains(value_lower);
        }
    }
    false
}

/// Extract the Date header from RFC822 data and parse it to a date-only
/// unix timestamp (start of day, ignoring time and timezone per RFC 3501 6.4.4).
///
/// For SENTBEFORE/SENTSINCE/SENTON, RFC 3501 says to disregard time and timezone
/// and compare only the date portion.
pub fn extract_sent_date(data: &[u8]) -> Option<i64> {
    let (headers, _) = mailparse::parse_headers(data).ok()?;
    use mailparse::MailHeaderMap;
    let date_str = headers.get_first_value("Date")?;
    parse_rfc2822_date_only(date_str.trim())
}

/// Parse an RFC2822 date string, returning the start-of-day timestamp (ignoring time and
/// timezone). This is what RFC 3501 SENTBEFORE/SENTSINCE/SENTON require.
pub fn parse_rfc2822_date_only(s: &str) -> Option<i64> {
    let months = [
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
    ];

    // Strip optional day-of-week prefix (e.g., "Mon, ")
    let s = if let Some(pos) = s.find(',') {
        s[pos + 1..].trim()
    } else {
        s.trim()
    };

    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let day: u32 = parts[0].parse().ok()?;
    let month = months
        .iter()
        .position(|&m| m.eq_ignore_ascii_case(parts[1]))? as u32
        + 1;
    let year: i32 = parts[2].parse().ok()?;

    // Return start of day (00:00:00 UTC) for the given date, ignoring time and timezone
    let days_in_month = [31u32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let is_leap = |y: i32| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);

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
    total_days += (day as i64) - 1;

    Some(total_days * 86400)
}

pub fn parse_rfc2822_date(s: &str) -> Option<i64> {
    let months = [
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
    ];

    // Strip optional day-of-week prefix (e.g., "Mon, ")
    let s = if let Some(pos) = s.find(',') {
        s[pos + 1..].trim()
    } else {
        s.trim()
    };

    // Expected formats:
    //   "14 Nov 2023 22:13:20 +0000"   (RFC 2822)
    //   "14-Nov-2023 22:13:20 +0000"   (IMAP internal date-time)
    let parts: Vec<&str> = s.split_whitespace().collect();

    // Try to parse IMAP date-time format (DD-Mon-YYYY HH:MM:SS +ZZZZ)
    let (day, month, year, time_idx) = if parts.len() >= 2 && parts[0].contains('-') {
        let date_parts: Vec<&str> = parts[0].split('-').collect();
        if date_parts.len() != 3 {
            return None;
        }
        let d: u32 = date_parts[0].parse().ok()?;
        let m = months
            .iter()
            .position(|&mo| mo.eq_ignore_ascii_case(date_parts[1]))? as u32
            + 1;
        let y: i32 = date_parts[2].parse().ok()?;
        (d, m, y, 1usize)
    } else if parts.len() >= 4 {
        let d: u32 = parts[0].parse().ok()?;
        let m = months
            .iter()
            .position(|&mo| mo.eq_ignore_ascii_case(parts[1]))? as u32
            + 1;
        let y: i32 = parts[2].parse().ok()?;
        (d, m, y, 3usize)
    } else {
        return None;
    };

    if time_idx >= parts.len() {
        return None;
    }
    let time_parts: Vec<&str> = parts[time_idx].split(':').collect();
    if time_parts.len() < 2 {
        return None;
    }
    let hours: i64 = time_parts[0].parse().ok()?;
    let minutes: i64 = time_parts[1].parse().ok()?;
    let seconds: i64 = if time_parts.len() > 2 {
        time_parts[2].parse().unwrap_or(0)
    } else {
        0
    };

    // Parse timezone offset
    let tz_idx = time_idx + 1;
    let tz_offset_secs: i64 = if parts.len() > tz_idx {
        let tz = parts[tz_idx];
        if tz.len() >= 4 {
            let sign = if tz.starts_with('-') { -1i64 } else { 1 };
            let tz_digits = tz.trim_start_matches(['+', '-']);
            if tz_digits.len() >= 4 {
                let tz_hours: i64 = tz_digits[..2].parse().unwrap_or(0);
                let tz_mins: i64 = tz_digits[2..4].parse().unwrap_or(0);
                sign * (tz_hours * 3600 + tz_mins * 60)
            } else {
                0
            }
        } else {
            0
        }
    } else {
        0
    };

    // Convert to unix timestamp
    let days_in_month = [31u32, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let is_leap = |y: i32| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);

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
    total_days += (day as i64) - 1;

    let timestamp = total_days * 86400 + hours * 3600 + minutes * 60 + seconds - tz_offset_secs;
    Some(timestamp)
}
