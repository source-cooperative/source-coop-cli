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
