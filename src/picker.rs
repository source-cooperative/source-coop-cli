//! The keyboard-driven list and screen behind `-i`, drawn on stderr.
//!
//! dialoguer's pickers take no shortcuts, so this is a small one of our own
//! on `console`, which dialoguer already brings in.

use crate::prompt::{Action, Place};
use console::{style, Key, Term};

/// Restores the cursor however the picker ends.
struct Visible<'a>(&'a Term);

impl Drop for Visible<'_> {
    fn drop(&mut self) {
        let _ = self.0.show_cursor();
    }
}

fn failed(e: std::io::Error) -> String {
    format!("Prompt failed: {e}")
}

fn interrupted() -> String {
    "Interrupted.".into()
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
    let height = (rows as usize).saturating_sub(3).max(3);

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
    loop {
        let needle = filter.to_lowercase();
        let shown: Vec<usize> = (0..items.len())
            .filter(|&i| needle.is_empty() || plain[i].to_lowercase().contains(&needle))
            .collect();
        let sel = shown.iter().position(|&i| i == current).unwrap_or(0);
        if let Some(&i) = shown.get(sel) {
            current = i;
        }
        let near_end = more && sel + LOOKAHEAD >= shown.len();
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
        lines.push(
            style(if near_end {
                "Loading more…"
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
            *place = Place {
                at: current,
                filter,
                filtering,
                drawn,
            };
            return Ok(Action::More);
        }

        let key = term.read_key_raw().map_err(failed)?;
        // The item `by` rows from the highlighted one, staying in the list.
        let n = shown.len() as isize;
        let step = |by: isize| (n > 0).then(|| shown[(sel as isize + by).clamp(0, n - 1) as usize]);
        if filtering {
            match key {
                Key::Escape => {
                    filter.clear();
                    filtering = false;
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
            *place = Place {
                at: current,
                filter,
                filtering: false,
                drawn: 0,
            };
            return Ok(action);
        }
    }
}

/// Wait for ←/Esc/h/q (back) or one of `keys`, showing
/// `hint` meanwhile.
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
