//! The keyboard-driven list and screen behind `-i`, drawn on stderr.
//!
//! dialoguer's pickers take no shortcuts, so this is a small one of our own
//! on `console`, which dialoguer already brings in.

use crate::prompt::{Action, Place};
use console::{style, Key, Term};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;

/// Restores the cursor however the picker ends.
struct Visible<'a>(&'a Term);

impl Drop for Visible<'_> {
    fn drop(&mut self) {
        let _ = self.0.show_cursor();
    }
}

/// The terminal's alternate screen, as `less` and `vim` use it, held for an
/// `-i` session: each screen clears and redraws rather than piling up, and
/// dropping the guard puts back what was on the terminal before.
pub struct FullScreen;

/// Whether the alternate screen is up, for the Ctrl+C handler.
static IN_FULLSCREEN: AtomicBool = AtomicBool::new(false);

/// Put the terminal back on Ctrl+C, however it arrives. Our own prompts read
/// it as a key, but dialoguer's choices have `console` raise it as a signal,
/// and so does a Ctrl+C while a request is running: the default handler would
/// end the process with the cursor dialoguer hid still hidden, and inside the
/// alternate screen. Installed once, as a handler stays for the process.
pub fn handle_interrupts() {
    static HANDLER: Once = Once::new();
    HANDLER.call_once(|| {
        tokio::spawn(async {
            if tokio::signal::ctrl_c().await.is_ok() {
                if IN_FULLSCREEN.load(Ordering::SeqCst) {
                    eprint!("\x1b[?1049l");
                }
                eprint!("\x1b[?25h");
                say_interrupted();
                std::process::exit(130);
            }
        });
    });
}

/// Print "Interrupted." once: the handler above and the prompt whose read the
/// signal interrupted can both get there.
pub fn say_interrupted() {
    static SAID: AtomicBool = AtomicBool::new(false);
    if !SAID.swap(true, Ordering::SeqCst) {
        eprintln!("\n{}", crate::prompt::INTERRUPTED);
    }
}

impl FullScreen {
    pub fn enter() -> FullScreen {
        handle_interrupts();
        IN_FULLSCREEN.store(true, Ordering::SeqCst);
        eprint!("\x1b[?1049h\x1b[H");
        FullScreen
    }
}

impl Drop for FullScreen {
    fn drop(&mut self) {
        IN_FULLSCREEN.store(false, Ordering::SeqCst);
        eprint!("\x1b[?1049l");
    }
}

fn failed(e: std::io::Error) -> String {
    format!("Prompt failed: {e}")
}

fn interrupted() -> String {
    crate::prompt::INTERRUPTED.into()
}

/// `line` cut to `cols` columns, keeping its styling.
fn fit(line: &str, cols: u16) -> String {
    console::truncate_str(line, (cols as usize).max(1), "…").into_owned()
}

/// How close to the end of the items the highlight gets before more are asked
/// for, so they're usually there before it arrives.
const LOOKAHEAD: usize = 3;

/// Move through `items` from `place` and return what was pressed, with
/// `place.at` the highlighted item: ↑/↓ (or k/j, PgUp/PgDn) move, →/Enter/l
/// open, ←/Esc/h/q go back, `/` narrows the list by typed text, and any key in
/// `keys` comes back as `Action::Key`.
///
/// With `more`, the list pages itself: once the highlight is within
/// `LOOKAHEAD` of the last item shown (or a filter matches nothing), it shows
/// "Loading more…" and returns `Action::More`, leaving the list on screen for
/// the next call, with the extra items, to redraw in place.
pub fn browse(
    label: &str,
    items: &[String],
    place: &mut Place,
    more: bool,
    keys: &str,
    hint: &str,
) -> Result<Action, String> {
    let term = Term::stderr();
    term.hide_cursor().map_err(failed)?;
    let _visible = Visible(&term);
    let (rows, cols) = term.size();

    // Items may carry styling (a gray ID): filter on the text alone, and
    // highlight it whole rather than let an item's own reset end the cyan.
    let plain: Vec<String> = items
        .iter()
        .map(|i| console::strip_ansi_codes(i).into_owned())
        .collect();
    let mut filter = std::mem::take(&mut place.filter);
    let mut filtering = place.filtering;
    // The highlighted item, as an index into `items`.
    let mut current = place.at.min(items.len().saturating_sub(1));
    let mut drawn = place.drawn;
    let mut notice = place.notice.take();
    loop {
        let height = (rows as usize)
            .saturating_sub(3 + usize::from(notice.is_some()))
            .max(3);
        let needle = filter.to_lowercase();
        let shown: Vec<usize> = (0..items.len())
            .filter(|&i| needle.is_empty() || plain[i].to_lowercase().contains(&needle))
            .collect();
        let sel = shown.iter().position(|&i| i == current).unwrap_or(0);
        if let Some(&i) = shown.get(sel) {
            current = i;
        }
        // While a filter is typed for the server to search, wait for Enter
        // rather than page through everything loaded meanwhile.
        let near_end =
            more && !(filtering && place.server_search) && sel + LOOKAHEAD >= shown.len();
        let top = sel
            .saturating_sub(height - 1)
            .min(shown.len().saturating_sub(height));

        let mut lines = vec![match (filtering, filter.is_empty()) {
            (true, _) => format!("{} /{filter}▏", style(label).bold()),
            (false, false) => format!("{} /{filter}", style(label).bold()),
            (false, true) => style(label).bold().to_string(),
        }];
        if shown.is_empty() {
            lines.push(style("  (nothing matches)").dim().to_string());
        }
        for (row, &i) in shown.iter().enumerate().skip(top).take(height) {
            lines.push(if row == sel {
                let text = fit(&plain[i], cols.saturating_sub(2));
                format!("{} {}", style("›").cyan(), style(text).cyan())
            } else {
                format!("  {}", fit(&items[i], cols.saturating_sub(2)))
            });
        }
        if let Some(n) = &notice {
            lines.push(style(n).yellow().to_string());
        }
        lines.push(
            style(if near_end {
                "Loading more…"
            } else if filtering && place.server_search {
                "type to filter · Enter search all · ↓ done · Esc clear"
            } else if filtering {
                "type to filter · Enter/↓ done · Esc clear"
            } else {
                hint
            })
            .dim()
            .to_string(),
        );
        term.clear_last_lines(drawn).map_err(failed)?;
        for line in &lines {
            // A line that wraps takes two rows, and the next redraw would
            // clear one too few.
            term.write_line(&fit(line, cols)).map_err(failed)?;
        }
        drawn = lines.len();
        if near_end {
            place.at = current;
            place.filter = filter;
            place.filtering = filtering;
            place.drawn = drawn;
            place.notice = notice;
            return Ok(Action::More);
        }

        let key = term.read_key_raw().map_err(failed)?;
        // A notice is read once; the next key clears it.
        notice = None;
        // The item `by` rows from the highlighted one, staying in the list.
        let n = shown.len() as isize;
        let step = |by: isize| (n > 0).then(|| shown[(sel as isize + by).clamp(0, n - 1) as usize]);
        if filtering {
            match key {
                Key::Escape => {
                    filter.clear();
                    filtering = false;
                }
                Key::Enter if place.server_search && !filter.trim().is_empty() => {
                    term.clear_last_lines(drawn).map_err(failed)?;
                    place.at = current;
                    place.filter = filter;
                    place.filtering = false;
                    place.drawn = 0;
                    return Ok(Action::Search);
                }
                Key::Enter | Key::ArrowDown => filtering = false,
                Key::Backspace => {
                    filter.pop();
                }
                Key::CtrlC => return Err(interrupted()),
                Key::Char(c) if !c.is_control() => filter.push(c),
                _ => {}
            }
            continue;
        }
        let moved = match key {
            Key::ArrowUp | Key::Char('k') => step(-1),
            Key::ArrowDown | Key::Char('j') => step(1),
            Key::PageUp => step(-(height as isize)),
            Key::PageDown => step(height as isize),
            Key::Home => step(-n),
            Key::End => step(n),
            _ => None,
        };
        let action = match key {
            Key::Char('/') => {
                filtering = true;
                None
            }
            Key::ArrowLeft | Key::Escape | Key::Char('h' | 'q') => Some(Action::Back),
            Key::CtrlC => return Err(interrupted()),
            _ if shown.is_empty() => None,
            Key::Enter | Key::ArrowRight | Key::Char('l') => Some(Action::Open),
            Key::Char(c) if keys.contains(c) => Some(Action::Key(c)),
            _ => None,
        };
        if let Some(i) = moved {
            current = i;
        }
        if let Some(action) = action {
            term.clear_last_lines(drawn).map_err(failed)?;
            // The filter stays for when they come back to the list.
            place.at = current;
            place.filter = filter;
            place.filtering = false;
            place.drawn = 0;
            return Ok(action);
        }
    }
}

/// Wait for ←/Esc/h/q (back) or one of `keys`, showing
/// `hint` meanwhile.
/// The part of `text` to show in `room` columns with the cursor at `at`:
/// all of it if it fits, otherwise a window that keeps the cursor in view.
/// Returns the shown text and how many columns the cursor sits from its end.
fn window(text: &[char], at: usize, room: usize) -> (String, usize) {
    let width = |cs: &[char]| console::measure_text_width(&cs.iter().collect::<String>());
    // Start as far left as still leaves a column for the cursor.
    let mut start = 0;
    while start < at && width(&text[start..at]) + 1 > room {
        start += 1;
    }
    let mut end = at;
    while end < text.len() && width(&text[start..end + 1]) <= room {
        end += 1;
    }
    (text[start..end].iter().collect(), width(&text[at..end]))
}

#[cfg(test)]
mod tests {
    use super::window;

    fn chars(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    #[test]
    fn a_line_that_fits_is_shown_whole_with_the_cursor_where_it_is() {
        assert_eq!(window(&chars("héllo"), 5, 20), ("héllo".into(), 0));
        assert_eq!(window(&chars("héllo"), 1, 20), ("héllo".into(), 4));
    }

    #[test]
    fn a_long_line_scrolls_to_keep_the_cursor_in_view() {
        let text = chars("abcdefghij");
        // At the end: the last 4 letters and a column for the cursor.
        assert_eq!(window(&text, 10, 5), ("ghij".into(), 0));
        // At the start: the first 5 letters.
        assert_eq!(window(&text, 0, 5), ("abcde".into(), 5));
    }

    #[test]
    fn wide_characters_count_their_columns() {
        // Each emoji takes two columns.
        assert_eq!(window(&chars("🌍🌍🌍"), 3, 5), ("🌍🌍".into(), 0));
        assert_eq!(window(&chars("a🌍b"), 1, 20), ("a🌍b".into(), 3));
    }
}

/// How a `line` ended.
#[derive(Debug, PartialEq)]
pub enum Line {
    /// Enter, with what was in the line.
    Text(String),
    /// Esc.
    Cancelled,
    /// Ctrl+E, when `editor` was offered: open the person's editor instead.
    Editor,
    /// ↑, or ← at the start of the line, when `back` was offered: return to
    /// the question before.
    Back,
}

/// Leave a question for the one before it: clear this one and the line where
/// the one before was answered, so it's asked again in its place.
fn step_back(term: &Term, lines: usize) -> Result<(), String> {
    term.clear_line().map_err(failed)?;
    term.clear_last_lines(lines + 1).map_err(failed)
}

/// A line of text, as dialoguer's `Input` asks for it but cancellable: it
/// starts as `initial` to keep or edit, Enter takes it, Esc backs out. ←/→,
/// Home/End and Ctrl+A move; Backspace and Delete erase a whole character,
/// accents and emoji included. A line wider than the terminal scrolls
/// sideways rather than wrap. Empty is refused unless `allow_empty`. With
/// `editor`, Ctrl+E at the end of the line asks for the person's editor
/// instead. With `back`, ↑ (or ← at the start of the line) returns `Back`.
pub fn line(
    label: &str,
    initial: &str,
    allow_empty: bool,
    editor: bool,
    back: bool,
) -> Result<Line, String> {
    let term = Term::stderr();
    term.show_cursor().map_err(failed)?;
    let prefix = format!(
        "{} {} {} ",
        style("?").yellow().bold(),
        style(label).bold(),
        style("›").dim()
    );
    let mut text: Vec<char> = initial.chars().collect();
    let mut at = text.len();
    let done = |mark: String, value: &str| -> Result<(), String> {
        term.clear_line().map_err(failed)?;
        term.write_line(&fit(
            &format!(
                "{mark} {} {} {value}",
                style(label).bold(),
                style("·").dim()
            ),
            term.size().1,
        ))
        .map_err(failed)
    };
    loop {
        let room = (term.size().1 as usize)
            .saturating_sub(console::measure_text_width(&prefix) + 1)
            .max(1);
        let (shown, after) = window(&text, at, room);
        term.clear_line().map_err(failed)?;
        term.write_str(&format!("{prefix}{shown}"))
            .map_err(failed)?;
        if after > 0 {
            term.move_cursor_left(after).map_err(failed)?;
        }
        match term.read_key_raw().map_err(failed)? {
            Key::Escape => {
                done(style("✘").red().to_string(), "")?;
                return Ok(Line::Cancelled);
            }
            // `console` reads Ctrl+E as End (as shells do), so the two can't
            // be told apart: at the end of the line it opens the editor, and
            // elsewhere it moves there first.
            Key::End | Key::Char('\u{5}') if editor && at == text.len() => {
                done(style("✎").cyan().to_string(), "(in your editor)")?;
                return Ok(Line::Editor);
            }
            Key::CtrlC => {
                term.write_line("").map_err(failed)?;
                return Err(interrupted());
            }
            Key::ArrowUp if back => {
                step_back(&term, 0)?;
                return Ok(Line::Back);
            }
            Key::ArrowLeft if back && at == 0 => {
                step_back(&term, 0)?;
                return Ok(Line::Back);
            }
            Key::Enter => {
                let value: String = text.iter().collect();
                if value.trim().is_empty() && !allow_empty {
                    continue;
                }
                // Long text (the one with an editor) keeps what was there on
                // an empty Enter, so say that rather than show nothing.
                let shown = if editor && value.trim().is_empty() {
                    style("(no change)").dim().to_string()
                } else {
                    value.clone()
                };
                done(style("✔").green().to_string(), &shown)?;
                return Ok(Line::Text(value));
            }
            Key::Backspace if at > 0 => {
                at -= 1;
                text.remove(at);
            }
            Key::Del if at < text.len() => {
                text.remove(at);
            }
            Key::ArrowLeft if at > 0 => at -= 1,
            Key::ArrowRight if at < text.len() => at += 1,
            Key::Home | Key::Char('\u{1}') => at = 0,
            Key::End => at = text.len(),
            Key::Char(c) if !c.is_control() => {
                text.insert(at, c);
                at += 1;
            }
            _ => {}
        }
    }
}

pub fn keypress(hint: &str, keys: &str) -> Result<Action, String> {
    let term = Term::stderr();
    term.hide_cursor().map_err(failed)?;
    let _visible = Visible(&term);
    term.write_line(&fit(&style(hint).dim().to_string(), term.size().1))
        .map_err(failed)?;
    let action = loop {
        match term.read_key_raw().map_err(failed)? {
            Key::ArrowLeft | Key::Escape | Key::Char('h' | 'q') => break Action::Back,
            Key::CtrlC => return Err(interrupted()),
            Key::Char(c) if keys.contains(c) => break Action::Key(c),
            _ => {}
        }
    };
    term.clear_last_lines(1).map_err(failed)?;
    Ok(action)
}

/// One of `items`, as dialoguer's `Select` asks for it, plus going back:
/// ↑/↓ (k/j) move, Enter (or →) chooses, Esc cancels, and with `back`, ←
/// returns None to ask the question before again. `details` are shown under
/// the question while it's asked (a summary to confirm, say), and go with it.
// ponytail: no scrolling; its lists (accounts, data connections,
// visibilities) fit a screen. Window it like `browse` if one grows past that.
pub fn select(
    label: &str,
    details: &[String],
    items: &[String],
    default: usize,
    back: bool,
) -> Result<Option<usize>, String> {
    let term = Term::stderr();
    term.hide_cursor().map_err(failed)?;
    let _visible = Visible(&term);
    let cols = term.size().1;
    let hint = if back {
        "↑↓ move · Enter choose · ← back · Esc cancel"
    } else {
        "↑↓ move · Enter choose · Esc cancel"
    };
    let mut at = default.min(items.len().saturating_sub(1));
    let mut drawn = 0;
    let done = |term: &Term, drawn: usize, mark: String, value: &str| -> Result<(), String> {
        term.clear_last_lines(drawn).map_err(failed)?;
        term.write_line(&fit(
            &format!(
                "{mark} {} {} {value}",
                style(label).bold(),
                style("·").dim()
            ),
            cols,
        ))
        .map_err(failed)
    };
    loop {
        let mut lines = vec![format!(
            "{} {}",
            style("?").yellow().bold(),
            style(label).bold()
        )];
        lines.extend(details.iter().map(|d| format!("    {d}")));
        for (i, item) in items.iter().enumerate() {
            lines.push(if i == at {
                format!("{} {}", style("›").cyan(), style(item).cyan())
            } else {
                format!("  {item}")
            });
        }
        lines.push(style(hint).dim().to_string());
        term.clear_last_lines(drawn).map_err(failed)?;
        for line in &lines {
            term.write_line(&fit(line, cols)).map_err(failed)?;
        }
        drawn = lines.len();
        match term.read_key_raw().map_err(failed)? {
            Key::ArrowUp | Key::Char('k') => at = at.saturating_sub(1),
            Key::ArrowDown | Key::Char('j') => at = (at + 1).min(items.len().saturating_sub(1)),
            Key::Enter | Key::ArrowRight if !items.is_empty() => {
                done(&term, drawn, style("✔").green().to_string(), &items[at])?;
                return Ok(Some(at));
            }
            Key::ArrowLeft if back => {
                step_back(&term, drawn)?;
                return Ok(None);
            }
            Key::Escape | Key::Char('q') => {
                done(&term, drawn, style("✘").red().to_string(), "")?;
                return Err(crate::prompt::CANCELLED.into());
            }
            Key::CtrlC => return Err(interrupted()),
            _ => {}
        }
    }
}
