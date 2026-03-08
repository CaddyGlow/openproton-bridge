use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuttConfigTemplate {
    pub account_address: String,
    pub display_name: String,
    pub hostname: String,
    pub imap_port: u16,
    pub smtp_port: u16,
    pub use_ssl_for_imap: bool,
    pub use_ssl_for_smtp: bool,
    pub bridge_password: Option<String>,
}

pub fn render_mutt_config(template: &MuttConfigTemplate, include_password: bool) -> String {
    let imap_scheme = if template.use_ssl_for_imap {
        "imaps"
    } else {
        "imap"
    };
    let smtp_scheme = if template.use_ssl_for_smtp {
        "smtps"
    } else {
        "smtp"
    };
    let smtp_user = percent_encode_userinfo(&template.account_address);
    let needs_starttls = !template.use_ssl_for_imap || !template.use_ssl_for_smtp;

    let mut out = String::new();
    out.push_str("# openproton-bridge generated mutt/neomutt config\n");
    out.push_str("# Paste into ~/.muttrc or source from a dedicated file.\n\n");
    let _ = writeln!(
        out,
        "set from = \"{}\"",
        escape_mutt_string(&template.account_address)
    );
    let _ = writeln!(
        out,
        "set realname = \"{}\"",
        escape_mutt_string(&template.display_name)
    );
    let _ = writeln!(
        out,
        "set imap_user = \"{}\"",
        escape_mutt_string(&template.account_address)
    );
    // Bridge IMAP currently authenticates via LOGIN command (not SASL AUTHENTICATE).
    out.push_str("set imap_authenticators = \"login\"\n");
    let _ = writeln!(
        out,
        "set folder = \"{imap_scheme}://{}:{}/\"",
        template.hostname, template.imap_port
    );
    out.push_str("set spoolfile = \"+INBOX\"\n");
    out.push_str("set postponed = \"+Drafts\"\n");
    out.push_str("set record = \"+Sent\"\n");
    out.push_str("\n# Threaded mailbox view with newest activity first.\n");
    out.push_str("set sort=threads\n");
    out.push_str("set sort_aux=last-date-received\n");
    out.push_str("set reverse_sort=yes\n");
    out.push_str("\n# Basic Vim-style navigation.\n");
    out.push_str("bind index j next-entry\n");
    out.push_str("bind index k previous-entry\n");
    out.push_str("bind pager j next-line\n");
    out.push_str("bind pager k previous-line\n");
    let _ = writeln!(
        out,
        "set smtp_url = \"{smtp_scheme}://{smtp_user}@{}:{}/\"",
        template.hostname, template.smtp_port
    );
    out.push_str("set ssl_force_tls = yes\n");
    if needs_starttls {
        out.push_str("set ssl_starttls = yes\n");
    } else {
        out.push_str("set ssl_starttls = no\n");
    }

    let password_value = template.bridge_password.as_deref().unwrap_or_default();
    if include_password {
        let _ = writeln!(
            out,
            "set imap_pass = \"{}\"",
            escape_mutt_string(password_value)
        );
        let _ = writeln!(
            out,
            "set smtp_pass = \"{}\"",
            escape_mutt_string(password_value)
        );
    } else {
        out.push_str("\n# Add your bridge password manually:\n");
        out.push_str("# set imap_pass = \"<bridge-password>\"\n");
        out.push_str("# set smtp_pass = \"<bridge-password>\"\n");
    }

    out.push_str(
        "\n# If certificate validation fails, install the Bridge certificate with\n# `openproton-bridge cert export <dir>` and trust it in your OS/mutt trust store.\n",
    );

    out
}

fn escape_mutt_string(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn percent_encode_userinfo(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_template() -> MuttConfigTemplate {
        MuttConfigTemplate {
            account_address: "alice+qa@proton.me".to_string(),
            display_name: "Alice Example".to_string(),
            hostname: "127.0.0.1".to_string(),
            imap_port: 1143,
            smtp_port: 1025,
            use_ssl_for_imap: false,
            use_ssl_for_smtp: false,
            bridge_password: Some("pw-123".to_string()),
        }
    }

    #[test]
    fn render_mutt_config_without_password_placeholders() {
        let rendered = render_mutt_config(&sample_template(), false);
        assert!(rendered.contains("set imap_authenticators = \"login\""));
        assert!(rendered.contains("set folder = \"imap://127.0.0.1:1143/\""));
        assert!(rendered.contains("set sort=threads"));
        assert!(rendered.contains("set sort_aux=last-date-received"));
        assert!(rendered.contains("set reverse_sort=yes"));
        assert!(rendered.contains("bind index j next-entry"));
        assert!(rendered.contains("bind pager k previous-line"));
        assert!(
            rendered.contains("set smtp_url = \"smtp://alice%2Bqa%40proton.me@127.0.0.1:1025/\"")
        );
        assert!(rendered.contains("set ssl_starttls = yes"));
        assert!(!rendered.contains("set imap_pass = \"pw-123\""));
        assert!(rendered.contains("# set imap_pass = \"<bridge-password>\""));
    }

    #[test]
    fn render_mutt_config_with_password_and_implicit_tls() {
        let mut template = sample_template();
        template.use_ssl_for_imap = true;
        template.use_ssl_for_smtp = true;
        template.bridge_password = Some("pw\"\\\\escaped".to_string());

        let rendered = render_mutt_config(&template, true);
        assert!(rendered.contains("set folder = \"imaps://127.0.0.1:1143/\""));
        assert!(
            rendered.contains("set smtp_url = \"smtps://alice%2Bqa%40proton.me@127.0.0.1:1025/\"")
        );
        assert!(rendered.contains("set ssl_starttls = no"));
        assert!(rendered.contains("set imap_pass = \"pw\\\"\\\\\\\\escaped\""));
        assert!(rendered.contains("set smtp_pass = \"pw\\\"\\\\\\\\escaped\""));
    }
}
