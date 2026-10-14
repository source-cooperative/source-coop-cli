//! The keyboard-driven list and screen behind `-i`, drawn on stderr.
//!
//! dialoguer's pickers take no shortcuts, so this is a small one of our own
//! on `console`, which dialoguer already brings in.

use crate::prompt::Action;
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

/// Move through `items` and return the highlighted one's index with what was
/// pressed: ↑/↓ (or k/j, PgUp/PgDn) move, →/Enter/l open, ←/Esc/h/q go back,
/// `/` narrows the list by typed text, and any key in `keys` comes back as
/// `Action::Key`.
pub fn browse(
    label: &str,
    items: &[String],
    at: usize,
    keys: &str,
    hint: &str,
) -> Result<(usize, Action), String> {
    let term = Term::stderr();
    term.hide_cursor().map_err(failed)?;
    let _visible = Visible(&term);
    let (rows, cols) = term.size();
    let height = (rows as usize).saturating_sub(3).max(3);

    let mut filter = String::new();
    let mut filtering = false;
    // The highlighted item, as an index into `items`.
    let mut current = at.min(items.len().saturating_sub(1));
    let mut drawn = 0;
    loop {
        let needle = filter.to_lowercase();
        let shown: Vec<usize> = (0..items.len())
            .filter(|&i| needle.is_empty() || items[i].to_lowercase().contains(&needle))
            .collect();
        let sel = shown.iter().position(|&i| i == current).unwrap_or(0);
        if let Some(&i) = shown.get(sel) {
            current = i;
        }
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
            let text = console::truncate_str(&items[i], (cols as usize).saturating_sub(2), "…");
            lines.push(if row == sel {
                format!("{} {}", style("›").cyan(), style(text).cyan())
            } else {
                format!("  {text}")
            });
        }
        lines.push(
            style(if filtering {
                "type to filter · Enter/↓ done · Esc clear"
            } else {
                hint
            })
            .dim()
            .to_string(),
        );
        term.clear_last_lines(drawn).map_err(failed)?;
        for line in &lines {
            term.write_line(line).map_err(failed)?;
        }
        drawn = lines.len();

        let key = term.read_key().map_err(failed)?;
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
                Key::Char('\u{3}') => return Err(interrupted()),
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
            Key::Char('\u{3}') => return Err(interrupted()),
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
            return Ok((current, action));
        }
    }
}

/// Wait for ←/Esc/h/q (back), →/Enter/l (open) or one of `keys`, showing
/// `hint` meanwhile.
pub fn keypress(hint: &str, keys: &str) -> Result<Action, String> {
    let term = Term::stderr();
    term.hide_cursor().map_err(failed)?;
    let _visible = Visible(&term);
    term.write_line(&style(hint).dim().to_string())
        .map_err(failed)?;
    let action = loop {
        match term.read_key().map_err(failed)? {
            Key::ArrowLeft | Key::Escape | Key::Char('h' | 'q') => break Action::Back,
            Key::Enter | Key::ArrowRight | Key::Char('l') => break Action::Open,
            Key::Char('\u{3}') => return Err(interrupted()),
            Key::Char(c) if keys.contains(c) => break Action::Key(c),
            _ => {}
        }
    };
    term.clear_last_lines(1).map_err(failed)?;
    Ok(action)
}
