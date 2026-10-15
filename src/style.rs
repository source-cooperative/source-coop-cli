//! Text styling for every command's output, so records of every type look
//! alike: ANSI codes on a terminal that wants color, plain text otherwise.

/// Whether output to a stream that `is_terminal` should be colored: only on a
/// terminal, and as `console` decides for stdout (never with `NO_COLOR`,
/// https://no-color.org; never with `CLICOLOR=0`).
pub fn wanted(is_terminal: bool) -> bool {
    is_terminal && console::colors_enabled()
}

/// Whether prompts and pickers, which draw on stderr, should be colored.
pub fn on_stderr() -> bool {
    console::colors_enabled_stderr()
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

/// Help text with its section headings (unindented lines ending in `:`)
/// styled like clap's own "Usage:" and "Options:". clap drops the styling
/// wherever it prints help without color.
pub fn help(text: &str) -> clap::builder::StyledStr {
    let h = clap::builder::Styles::default().get_header().to_owned();
    let lines: Vec<_> = text
        .lines()
        .map(|l| {
            if l.starts_with(' ') || !l.ends_with(':') {
                l.to_string()
            } else {
                format!("{h}{l}{h:#}")
            }
        })
        .collect();
    lines.join("\n").into()
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
