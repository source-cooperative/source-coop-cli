//! Text styling for every command's output, so records of every type look
//! alike: ANSI codes on a terminal that wants color, plain text otherwise.

use chrono::{DateTime, Utc};

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

/// A command's "Examples:" help section, a command a line.
pub fn examples(commands: &[&str]) -> clap::builder::StyledStr {
    let lines: Vec<_> = commands.iter().map(|c| format!("  {c}")).collect();
    help(&format!("Examples:\n{}", lines.join("\n")))
}

/// `at` as RFC 3339 (or just its day, when `day`, for estimates), then how
/// far it is from `now`, dimmed: "2026-10-15T05:19:03Z (14 hours ago)".
pub fn when(color: bool, at: DateTime<Utc>, now: DateTime<Utc>, day: bool) -> String {
    let stamp = match day {
        true => at.format("%Y-%m-%d").to_string(),
        false => at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };
    let rel = paint(color, "2", &format!("({})", relative(at, now)));
    format!("{stamp} {rel}")
}

/// `at` relative to `now`, in the largest whole unit: "just now",
/// "5 minutes ago", "2 years ago", or "in 29 days" while still ahead.
pub fn relative(at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let secs = (now - at).num_seconds();
    let (n, unit) = match secs.unsigned_abs() {
        0..60 if secs < 0 => return "in under a minute".into(),
        0..60 => return "just now".into(),
        s @ 60..3_600 => (s / 60, "minute"),
        s @ 3_600..86_400 => (s / 3_600, "hour"),
        s @ 86_400..2_592_000 => (s / 86_400, "day"),
        s @ 2_592_000..31_536_000 => (s / 2_592_000, "month"),
        s => (s / 31_536_000, "year"),
    };
    let plural = if n == 1 { "" } else { "s" };
    match secs < 0 {
        true => format!("in {n} {unit}{plural}"),
        false => format!("{n} {unit}{plural} ago"),
    }
}

#[cfg(test)]
mod tests {
    use super::{relative, when};

    #[test]
    fn relative_counts_in_the_largest_whole_unit() {
        let now: chrono::DateTime<chrono::Utc> = "2026-10-14T12:00:00Z".parse().unwrap();
        let before = |secs: i64| relative(now - chrono::Duration::seconds(secs), now);
        assert_eq!(before(30), "just now");
        assert_eq!(before(60), "1 minute ago");
        assert_eq!(before(5 * 3_600 + 59), "5 hours ago");
        assert_eq!(before(86_400), "1 day ago");
        assert_eq!(before(65 * 86_400), "2 months ago");
        assert_eq!(before(800 * 86_400), "2 years ago");
        assert_eq!(before(-30), "in under a minute");
        assert_eq!(before(-(29 * 86_400 + 5)), "in 29 days");
    }

    #[test]
    fn when_is_rfc_3339_then_relative() {
        let now: chrono::DateTime<chrono::Utc> = "2026-10-14T12:00:00Z".parse().unwrap();
        let at = now - chrono::Duration::hours(3);
        assert_eq!(
            when(false, at, now, false),
            "2026-10-14T09:00:00Z (3 hours ago)"
        );
        assert_eq!(when(false, at, now, true), "2026-10-14 (3 hours ago)");
        assert_eq!(
            when(true, at, now, true),
            "2026-10-14 \x1b[2m(3 hours ago)\x1b[0m"
        );
    }
}
