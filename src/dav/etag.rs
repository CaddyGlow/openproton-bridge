pub fn from_updated_ms(id: &str, updated_at_ms: i64) -> String {
    format!("\"{id}-{}\"", updated_at_ms.max(0))
}

pub fn if_match_satisfied(if_match: Option<&String>, current: Option<&str>) -> bool {
    let Some(condition) = if_match.map(|value| value.trim()) else {
        return true;
    };
    if condition == "*" {
        return current.is_some();
    }
    current.is_some_and(|etag| condition == etag)
}

pub fn if_none_match_satisfied(if_none_match: Option<&String>, current: Option<&str>) -> bool {
    let Some(condition) = if_none_match.map(|value| value.trim()) else {
        return true;
    };
    if condition == "*" {
        return current.is_none();
    }
    current != Some(condition)
}

#[cfg(test)]
mod tests {
    use super::{from_updated_ms, if_match_satisfied, if_none_match_satisfied};

    #[test]
    fn etag_is_deterministic() {
        assert_eq!(from_updated_ms("id", 123), "\"id-123\"");
    }

    #[test]
    fn preconditions_handle_wildcards() {
        assert!(if_match_satisfied(Some(&"*".to_string()), Some("\"a\"")));
        assert!(!if_match_satisfied(Some(&"*".to_string()), None));
        assert!(if_none_match_satisfied(Some(&"*".to_string()), None));
        assert!(!if_none_match_satisfied(
            Some(&"*".to_string()),
            Some("\"a\"")
        ));
    }
}
