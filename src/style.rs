//! Text styling for every command's output, so records of every type look
//! alike: ANSI codes on a terminal that wants color, plain text otherwise.

use std::io::IsTerminal;

/// Whether output to a stream that `is_terminal` should be colored: only on a
/// terminal, and never with `NO_COLOR` set (https://no-color.org).
pub fn wanted(is_terminal: bool) -> bool {
    is_terminal && std::env::var_os("NO_COLOR").is_none()
}

/// Whether prompts and pickers, which draw on stderr, should be colored.
pub fn on_stderr() -> bool {
    wanted(std::io::stderr().is_terminal())
}

/// `s` in the SGR style `code` when `on`.
pub fn paint(on: bool, code: &str, s: &str) -> String {
    if on {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// A record's ID, e.g. `acct/prod`: a lighter gray than the name beside it.
pub fn id(on: bool, s: &str) -> String {
    paint(on, "90", s)
}

/// How long ago `then` was, at `now`, in the largest whole unit: "just now",
/// "5 minutes ago", "3 days ago", "2 years ago".
pub fn ago(then: chrono::DateTime<chrono::Utc>, now: chrono::DateTime<chrono::Utc>) -> String {
    let secs = (now - then).num_seconds();
    if secs < 0 {
        return "in the future".into();
    }
    let (n, unit) = match secs {
        0..60 => return "just now".into(),
        60..3_600 => (secs / 60, "minute"),
        3_600..86_400 => (secs / 3_600, "hour"),
        86_400..2_592_000 => (secs / 86_400, "day"),
        2_592_000..31_536_000 => (secs / 2_592_000, "month"),
        _ => (secs / 31_536_000, "year"),
    };
    format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::ago;

    #[test]
    fn ago_counts_in_the_largest_whole_unit() {
        let now: chrono::DateTime<chrono::Utc> = "2026-10-14T12:00:00Z".parse().unwrap();
        let before = |secs: i64| ago(now - chrono::Duration::seconds(secs), now);
        assert_eq!(before(30), "just now");
        assert_eq!(before(60), "1 minute ago");
        assert_eq!(before(5 * 3_600 + 59), "5 hours ago");
        assert_eq!(before(86_400), "1 day ago");
        assert_eq!(before(65 * 86_400), "2 months ago");
        assert_eq!(before(800 * 86_400), "2 years ago");
        assert_eq!(before(-10), "in the future");
    }
}
