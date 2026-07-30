//! Shared `allowed_users` matching used by every chat channel.

/// Case-sensitivity selector for the allowlist comparison. The chat
/// platform defines which one applies; the helper does not infer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// Exact `==` match.
    Sensitive,
    /// `eq_ignore_ascii_case` — IRC nicks, Matrix MXIDs.
    CaseInsensitive,
}

/// Marks an entry as a deny rule rather than a grant.
///
/// `Config::channel_external_peers` emits `!<name>` when a matching peer group
/// grants `external_peers = ["*"]` while another sets `ignore`. A wildcard
/// leaves no explicit entry to subtract, so without a marker the documented
/// "union `external_peers`, then subtract `ignore`" contract would silently
/// lose the operator's deny. No chat platform admits a username beginning with
/// `!`, and an entry that did would now be denied rather than granted, so the
/// reservation fails closed.
pub const DENY_PREFIX: char = '!';

/// Whether a deny entry names `user`.
///
/// A deny rule is checked with the caller's own notion of identity *and* with a
/// normalized comparison (leading `@` stripped, ASCII case-insensitive), which
/// is how `ignore` is normalized when it is subtracted from explicit entries.
/// A blocklist errs toward denying, so matching a superset is the safe
/// direction: the alternative admits a sender the operator wrote down.
fn deny_names(entry: &str, user: &str, match_fn: &impl Fn(&str, &str) -> bool) -> bool {
    let normalize = |value: &str| value.trim().trim_start_matches('@').to_string();
    match_fn(entry, user) || normalize(entry).eq_ignore_ascii_case(&normalize(user))
}

/// Whether any deny entry in `allowed` names `user`.
///
/// Evaluated before the wildcard so an explicit deny always wins.
fn is_user_denied(allowed: &[String], user: &str, match_fn: &impl Fn(&str, &str) -> bool) -> bool {
    allowed
        .iter()
        .filter_map(|entry| entry.strip_prefix(DENY_PREFIX))
        .any(|entry| deny_names(entry, user, match_fn))
}

/// Whether `user` is explicitly denied, independent of any grant.
///
/// Needed by channels that accept more than one identifier for the same
/// account. Asking `is_user_allowed_by` per identifier is not sufficient
/// there: a deny on one alias is defeated by a wildcard grant reached through
/// another, so the sender has to be rejected when *any* of its identifiers is
/// denied.
#[must_use]
pub fn is_user_denied_by(
    allowed: &[String],
    user: &str,
    match_fn: impl Fn(&str, &str) -> bool,
) -> bool {
    is_user_denied(allowed, user, &match_fn)
}

#[must_use]
pub fn is_user_allowed(allowed: &[String], user: &str, mode: Match) -> bool {
    let matches = |entry: &str, user: &str| match mode {
        Match::Sensitive => entry == user,
        Match::CaseInsensitive => entry.eq_ignore_ascii_case(user),
    };
    if is_user_denied(allowed, user, &matches) {
        return false;
    }
    if allowed.iter().any(|u| u == "*") {
        return true;
    }
    allowed
        .iter()
        .filter(|entry| !entry.starts_with(DENY_PREFIX))
        .any(|entry| matches(entry, user))
}

#[must_use]
pub fn is_user_allowed_by(
    allowed: &[String],
    user: &str,
    match_fn: impl Fn(&str, &str) -> bool,
) -> bool {
    if is_user_denied(allowed, user, &match_fn) {
        return false;
    }
    if allowed.iter().any(|u| u == "*") {
        return true;
    }
    allowed
        .iter()
        .filter(|entry| !entry.starts_with(DENY_PREFIX))
        .any(|entry| match_fn(entry, user))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_allows_anyone() {
        let list = vec!["*".to_string()];
        assert!(is_user_allowed(&list, "alice", Match::Sensitive));
        assert!(is_user_allowed(&list, "ALICE", Match::Sensitive));
    }

    #[test]
    fn deny_marker_overrides_wildcard() {
        let list = vec!["*".to_string(), "!alice".to_string()];
        assert!(!is_user_allowed(&list, "alice", Match::Sensitive));
        // Everyone else still rides the wildcard.
        assert!(is_user_allowed(&list, "bob", Match::Sensitive));
    }

    #[test]
    fn deny_marker_overrides_an_explicit_grant() {
        // Subtraction in `channel_external_peers` normally removes the grant
        // before it reaches here, so this pins the precedence rather than the
        // config path: a deny wins wherever both appear.
        let list = vec!["alice".to_string(), "!alice".to_string()];
        assert!(!is_user_allowed(&list, "alice", Match::Sensitive));
    }

    #[test]
    fn deny_marker_is_not_itself_a_grant() {
        // Without the filter, `!alice` would authorize a sender literally
        // named `!alice`.
        let list = vec!["!alice".to_string()];
        assert!(!is_user_allowed(&list, "!alice", Match::Sensitive));
        assert!(!is_user_allowed(&list, "alice", Match::Sensitive));
    }

    #[test]
    fn deny_marker_ignores_case_and_a_leading_at() {
        // A blocklist errs toward denying: `ignore` is normalized when it is
        // subtracted, so the marker path must not admit a sender that the
        // subtraction path would have removed.
        let list = vec!["*".to_string(), "!@Alice".to_string()];
        assert!(!is_user_allowed(&list, "alice", Match::Sensitive));
        assert!(!is_user_allowed(&list, "@ALICE", Match::Sensitive));
    }

    #[test]
    fn by_deny_marker_overrides_wildcard_with_custom_matcher() {
        let eq = |e: &str, u: &str| e == u;
        let list = vec!["*".to_string(), "!alice".to_string()];
        assert!(!is_user_allowed_by(&list, "alice", eq));
        assert!(is_user_allowed_by(&list, "bob", eq));
    }

    #[test]
    fn by_deny_marker_uses_the_platform_matcher() {
        // The email-domain matcher treats a bare host as the whole domain, so
        // a deny written the same way must block the whole domain too.
        let matcher = |allowed: &str, email: &str| -> bool {
            let email_lower = email.to_lowercase();
            if allowed.starts_with('@') {
                email_lower.ends_with(&allowed.to_lowercase())
            } else if allowed.contains('@') {
                allowed.eq_ignore_ascii_case(email)
            } else {
                email_lower.ends_with(&format!("@{}", allowed.to_lowercase()))
            }
        };
        let list = vec!["*".to_string(), "!evil.com".to_string()];
        assert!(!is_user_allowed_by(&list, "spammer@evil.com", matcher));
        assert!(is_user_allowed_by(&list, "boss@corp.io", matcher));
    }

    #[test]
    fn empty_list_denies_everyone() {
        assert!(!is_user_allowed(&[], "alice", Match::Sensitive));
        assert!(!is_user_allowed(&[], "alice", Match::CaseInsensitive));
    }

    #[test]
    fn exact_match_case_sensitive() {
        let list = vec!["alice".to_string()];
        assert!(is_user_allowed(&list, "alice", Match::Sensitive));
        assert!(!is_user_allowed(&list, "Alice", Match::Sensitive));
    }

    #[test]
    fn exact_match_case_insensitive() {
        let list = vec!["Alice".to_string()];
        assert!(is_user_allowed(&list, "alice", Match::CaseInsensitive));
        assert!(is_user_allowed(&list, "ALICE", Match::CaseInsensitive));
    }

    // --- is_user_allowed_by (caller-provided matcher) ---------------

    #[test]
    fn by_empty_denies_and_wildcard_admits() {
        let eq = |e: &str, u: &str| e == u;
        assert!(!is_user_allowed_by(&[], "alice", eq));
        assert!(is_user_allowed_by(&["*".to_string()], "anyone", eq));
    }

    #[test]
    fn by_email_domain_class() {
        // Mirrors email_channel / gmail_push: "@host" / bare "host" match the
        // whole domain; "user@host" is a full case-insensitive address.
        let matcher = |allowed: &str, email: &str| -> bool {
            let email_lower = email.to_lowercase();
            if allowed.starts_with('@') {
                email_lower.ends_with(&allowed.to_lowercase())
            } else if allowed.contains('@') {
                allowed.eq_ignore_ascii_case(email)
            } else {
                email_lower.ends_with(&format!("@{}", allowed.to_lowercase()))
            }
        };
        let list = vec!["@example.com".to_string(), "boss@corp.io".to_string()];
        assert!(is_user_allowed_by(&list, "anyone@Example.com", matcher));
        assert!(is_user_allowed_by(&list, "BOSS@corp.io", matcher));
        assert!(!is_user_allowed_by(&list, "user@evil.com", matcher));
    }

    #[test]
    fn by_phone_e164_normalized() {
        // Mirrors whatsapp_web E.164 normalization (digits only, leading +).
        let norm = |s: &str| -> String {
            let mut out = String::new();
            let mut chars = s.chars();
            if let Some('+') = chars.clone().next() {
                out.push('+');
                chars.next();
            }
            out.extend(chars.filter(|c| c.is_ascii_digit()));
            out
        };
        let matcher = |entry: &str, phone: &str| norm(entry) == norm(phone);
        let list = vec!["+1-555-0100".to_string()];
        assert!(is_user_allowed_by(&list, "+1 555 0100", matcher));
        assert!(!is_user_allowed_by(&list, "+15550101", matcher));
    }

    #[test]
    fn by_wildcard_short_circuits_matcher() {
        let list = vec!["*".to_string()];

        assert!(is_user_allowed_by(&list, "alice", |_, _| {
            panic!("wildcard should short-circuit before custom matcher runs");
        }));
    }
}
