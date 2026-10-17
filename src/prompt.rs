//! Interactive prompts for whatever a command wasn't given by flag or file.
//!
//! Prompts appear only when someone is there to answer them: stdin and stderr
//! are both terminals and `SOURCE_PROMPT_DISABLED` is unset. Otherwise a
//! command sends what it was given, and the API says what's missing.

use crate::picker::Line;
use dialoguer::{theme::ColorfulTheme, Confirm, Editor, Select};
use std::io::IsTerminal;

/// What someone did in a `browse` list or at a `keypress`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Action {
    /// → or Enter: go into the highlighted item.
    Open,
    /// ← or Esc: go back (or out).
    Back,
    /// One of the shortcut keys asked for.
    Key(char),
    /// Only from `browse`, when told there's more: the highlight neared the
    /// end of the items. Load the next page and browse again from `Place`.
    More,
    /// Only from `browse` with `Place::server_search`: a filter was submitted
    /// with Enter. Search for `Place::filter` and browse the results.
    Search,
}

/// Where someone is in a `browse` list, kept between calls so loading more
/// items (`Action::More`) doesn't lose their place or their filter.
#[derive(Default)]
pub struct Place {
    /// The highlighted item.
    pub at: usize,
    pub filter: String,
    /// Typing a filter, rather than moving.
    pub filtering: bool,
    /// Lines left on screen while more load, for the next call to redraw over.
    pub drawn: usize,
    /// Whether the list can be searched on the server: Enter on a filter
    /// returns `Action::Search` instead of only narrowing what's loaded.
    pub server_search: bool,
    /// A message for the person, shown once in the list (e.g. "Deleted …").
    pub notice: Option<String>,
}

pub trait Prompter {
    /// Ask for a line of text, offering `default` (taken on a bare Enter).
    fn input(&mut self, label: &str, default: &str, allow_empty: bool) -> Result<String, String>;
    /// Ask for one of `items`, starting on `default`; returns its index.
    fn select(&mut self, label: &str, items: &[String], default: usize) -> Result<usize, String>;
    /// Let someone move through `items` from `place` and act on one: returns
    /// what they pressed, with `place.at` the item it was pressed on. With
    /// `more`, nearing the end returns `Action::More` (see
    /// `crate::picker::browse`).
    fn browse(
        &mut self,
        label: &str,
        items: &[String],
        place: &mut Place,
        more: bool,
        keys: &str,
        hint: &str,
    ) -> Result<Action, String>;
    /// Wait for back or one of `keys`, showing `hint`.
    fn keypress(&mut self, hint: &str, keys: &str) -> Result<Action, String>;
    /// Take over the screen until the returned guard is dropped (see
    /// `crate::picker::FullScreen`); None where there's no screen to take, or
    /// it's already taken (the outer guard puts it back).
    fn fullscreen(&mut self) -> Option<crate::picker::FullScreen> {
        None
    }
    /// Start a fresh screen, inside `fullscreen`.
    fn clear(&mut self) {}
    /// Ask a yes/no question.
    fn confirm(&mut self, label: &str, default: bool) -> Result<bool, String>;
    /// Ask for text that may run to paragraphs, starting from `current`: typed
    /// on one line, or written in the person's editor.
    fn long_text(&mut self, label: &str, current: &str) -> Result<String, String>;

    /// `input`, `select` and `long_text` for a question with one before it:
    /// None means the person went back to it (↑, or ← at the start of a line
    /// or in a list).
    fn input_or_back(
        &mut self,
        label: &str,
        default: &str,
        allow_empty: bool,
    ) -> Result<Option<String>, String>;
    fn select_or_back(
        &mut self,
        label: &str,
        items: &[String],
        default: usize,
    ) -> Result<Option<usize>, String>;
    fn long_text_or_back(&mut self, label: &str, current: &str) -> Result<Option<String>, String>;
    /// Show `details` (what's about to be sent) and ask `question`, yes by
    /// default. None means back to the question before.
    fn confirm_or_back(
        &mut self,
        question: &str,
        details: &[String],
    ) -> Result<Option<bool>, String>;
}

/// Prompts on the terminal, written to stderr so stdout stays clean for output.
pub struct Tty {
    theme: ColorfulTheme,
}

/// A terminal prompter, or None when no one is there to answer.
pub fn tty() -> Option<Tty> {
    let enabled = std::env::var_os("SOURCE_PROMPT_DISABLED").is_none()
        && std::io::stdin().is_terminal()
        && std::io::stderr().is_terminal();
    enabled.then(|| Tty {
        theme: ColorfulTheme::default(),
    })
}

fn failed(e: dialoguer::Error) -> String {
    match e {
        // Ctrl+C, which `console` raises as a signal, interrupting the read.
        dialoguer::Error::IO(ref io) if io.kind() == std::io::ErrorKind::Interrupted => {
            INTERRUPTED.into()
        }
        e => format!("Prompt failed: {e}"),
    }
}

/// What a prompt returns as its error when the person backs out with Esc (or
/// `q`) on a choice: the command stops, having changed nothing. dialoguer's
/// text prompts don't take Esc, so a text prompt that is the last step before
/// something irreversible says how to back out instead (see `delete`).
pub const CANCELLED: &str = "Cancelled; nothing was changed.";

/// An error as the person should see it. Backing out of a prompt isn't a
/// failure worth an "Error:", so that message stands alone.
pub fn describe(e: &str) -> String {
    if e == CANCELLED || e == INTERRUPTED {
        e.to_string()
    } else {
        format!("Error: {e}")
    }
}

/// What a prompt returns as its error on Ctrl+C. Like backing out, it's the
/// person's own doing, so it's reported without an "Error:".
pub const INTERRUPTED: &str = "Interrupted.";

/// Print an error on stderr, as `describe` puts it.
pub fn report(e: &str) {
    if e == INTERRUPTED {
        crate::picker::say_interrupted();
    } else {
        eprintln!("{}", describe(e));
    }
}

fn cancellable<T>(answer: dialoguer::Result<Option<T>>) -> Result<T, String> {
    answer.map_err(failed)?.ok_or_else(|| CANCELLED.to_string())
}

/// The last step before something irreversible, for any kind of record: the
/// person types `name` back. Enter on nothing backs out (text prompts can't
/// take Esc); anything else that isn't `name` stops with `action` undone.
pub fn confirm_by_name(ask: &mut dyn Prompter, name: &str, action: &str) -> Result<(), String> {
    let typed = ask.input(&format!("Type {name} to confirm (Esc to cancel)"), "", true)?;
    match typed.trim() {
        "" => Err(CANCELLED.into()),
        t if t == name => Ok(()),
        _ => Err(format!("Not confirmed; nothing was {action}.")),
    }
}

/// `Tty::long_text`, and None for back when `back` was offered.
fn long_text(label: &str, current: &str, back: bool) -> Result<Option<String>, String> {
    // Text of one line starts in the line to keep or edit; more than that
    // can't, so Enter on the empty line keeps it.
    let (initial, hint) = if current.contains('\n') {
        (
            "",
            format!("{label} [Enter to keep · Ctrl+E editor · Esc cancel]"),
        )
    } else if current.is_empty() {
        (
            "",
            format!("{label} [Enter to skip · Ctrl+E editor · Esc cancel]"),
        )
    } else {
        (current, format!("{label} [Ctrl+E editor · Esc cancel]"))
    };
    match crate::picker::line(&hint, initial, true, true, back)? {
        Line::Cancelled => Err(CANCELLED.into()),
        Line::Back => Ok(None),
        // An empty line keeps the text it stood for; a line that held the
        // text and was emptied clears it.
        Line::Text(typed) if typed.trim().is_empty() => Ok(Some(
            if initial.is_empty() { current } else { "" }.to_string(),
        )),
        Line::Text(typed) => Ok(Some(typed)),
        Line::Editor(typed) => {
            // The editor starts from what's in the line, or from the text an
            // empty line stood for.
            let start = if initial.is_empty() && typed.trim().is_empty() {
                current
            } else {
                &typed
            };
            let edited = Editor::new()
                .require_save(true)
                .edit(start)
                .map_err(|e| format!("Couldn't open your editor: {e}"));
            crate::picker::FullScreen::reenter();
            let edited = edited?;
            // Quitting without saving keeps what was there.
            Ok(Some(edited.map_or_else(
                || current.to_string(),
                |t| t.trim_end().to_string(),
            )))
        }
    }
}

impl Prompter for Tty {
    /// Our own line prompt rather than dialoguer's, whose text prompts ignore
    /// Esc: the default starts in the line to keep or edit, and Esc backs out.
    fn input(&mut self, label: &str, default: &str, allow_empty: bool) -> Result<String, String> {
        match crate::picker::line(label, default, allow_empty, false, false)? {
            Line::Text(text) => Ok(text),
            Line::Cancelled | Line::Editor(_) | Line::Back => Err(CANCELLED.into()),
        }
    }

    fn input_or_back(
        &mut self,
        label: &str,
        default: &str,
        allow_empty: bool,
    ) -> Result<Option<String>, String> {
        match crate::picker::line(label, default, allow_empty, false, true)? {
            Line::Text(text) => Ok(Some(text)),
            Line::Back => Ok(None),
            Line::Cancelled | Line::Editor(_) => Err(CANCELLED.into()),
        }
    }

    fn select_or_back(
        &mut self,
        label: &str,
        items: &[String],
        default: usize,
    ) -> Result<Option<usize>, String> {
        crate::picker::select(label, &[], items, default, true)
    }

    fn confirm_or_back(
        &mut self,
        question: &str,
        details: &[String],
    ) -> Result<Option<bool>, String> {
        let options = ["Yes".to_string(), "No, cancel".to_string()];
        Ok(crate::picker::select(question, details, &options, 0, true)?.map(|i| i == 0))
    }

    fn select(&mut self, label: &str, items: &[String], default: usize) -> Result<usize, String> {
        cancellable(
            Select::with_theme(&self.theme)
                .with_prompt(label)
                .items(items)
                .default(default)
                .interact_opt(),
        )
    }

    fn browse(
        &mut self,
        label: &str,
        items: &[String],
        place: &mut Place,
        more: bool,
        keys: &str,
        hint: &str,
    ) -> Result<Action, String> {
        crate::picker::browse(label, items, place, more, keys, hint)
    }

    fn keypress(&mut self, hint: &str, keys: &str) -> Result<Action, String> {
        crate::picker::keypress(hint, keys)
    }

    fn fullscreen(&mut self) -> Option<crate::picker::FullScreen> {
        crate::picker::FullScreen::enter()
    }

    fn clear(&mut self) {
        let _ = console::Term::stderr().clear_screen();
    }

    fn confirm(&mut self, label: &str, default: bool) -> Result<bool, String> {
        cancellable(
            Confirm::with_theme(&self.theme)
                .with_prompt(label)
                .default(default)
                .interact_opt(),
        )
    }

    /// Enter keeps what's there, anything typed is the new text, and Ctrl+E
    /// opens `$VISUAL` or `$EDITOR` on it, for text of several paragraphs. The
    /// line starts with the text when it's one line, and empty otherwise.
    fn long_text(&mut self, label: &str, current: &str) -> Result<String, String> {
        Ok(long_text(label, current, false)?.unwrap_or_default())
    }

    fn long_text_or_back(&mut self, label: &str, current: &str) -> Result<Option<String>, String> {
        long_text(label, current, true)
    }
}

/// Answers from a script, in order, for tests.
#[cfg(test)]
pub mod scripted {
    use super::{Action, Prompter};
    use std::collections::VecDeque;

    #[derive(Debug)]
    pub enum Answer {
        /// Take the offered default.
        Default,
        Text(&'static str),
        Pick(usize),
        Yes(bool),
        /// In a `browse` list: highlight item `.0` and press `.1`.
        Browse(usize, Action),
        /// In a `browse` list: type `/` and this, then Enter to search.
        Search(&'static str),
        /// At a `keypress`.
        Press(Action),
        /// Back out, as Esc does on a choice.
        Cancel,
        /// Go back to the question before (↑ or ←), where one may be asked.
        Back,
        /// Fail with this error, as an editor that won't open does.
        Fail(&'static str),
    }

    #[derive(Default)]
    pub struct Script {
        pub answers: VecDeque<Answer>,
        /// Every prompt asked, as `label [default]`, to check what was offered.
        pub asked: Vec<String>,
    }

    impl Script {
        pub fn new(answers: impl IntoIterator<Item = Answer>) -> Self {
            Script {
                answers: answers.into_iter().collect(),
                asked: vec![],
            }
        }

        fn next(&mut self, label: &str) -> Answer {
            self.answers
                .pop_front()
                .unwrap_or_else(|| panic!("unscripted prompt: {label}"))
        }

        /// A scripted `Back` for a question that may go back: recorded as
        /// `label (back)`. Any other answer is left for the plain prompt.
        fn went_back(&mut self, label: &str) -> bool {
            let back = matches!(self.answers.front(), Some(Answer::Back));
            if back {
                self.answers.pop_front();
                self.asked.push(format!("{label} (back)"));
            }
            back
        }
    }

    impl Prompter for Script {
        fn input_or_back(
            &mut self,
            label: &str,
            default: &str,
            allow_empty: bool,
        ) -> Result<Option<String>, String> {
            if self.went_back(label) {
                return Ok(None);
            }
            self.input(label, default, allow_empty).map(Some)
        }

        fn select_or_back(
            &mut self,
            label: &str,
            items: &[String],
            default: usize,
        ) -> Result<Option<usize>, String> {
            if self.went_back(label) {
                return Ok(None);
            }
            self.select(label, items, default).map(Some)
        }

        fn long_text_or_back(
            &mut self,
            label: &str,
            current: &str,
        ) -> Result<Option<String>, String> {
            if self.went_back(label) {
                return Ok(None);
            }
            self.long_text(label, current).map(Some)
        }

        /// Recorded as `question {detail | detail | …} [true]`.
        fn confirm_or_back(
            &mut self,
            question: &str,
            details: &[String],
        ) -> Result<Option<bool>, String> {
            let label = format!("{question} {{{}}}", details.join(" | "));
            if self.went_back(&label) {
                return Ok(None);
            }
            self.confirm(&label, true).map(Some)
        }

        fn input(&mut self, label: &str, default: &str, _: bool) -> Result<String, String> {
            self.asked.push(format!("{label} [{default}]"));
            Ok(match self.next(label) {
                Answer::Default => default.to_string(),
                Answer::Text(t) => t.to_string(),
                Answer::Cancel => return Err(super::CANCELLED.into()),
                a => panic!("{label}: expected text, scripted {a:?}"),
            })
        }

        fn select(
            &mut self,
            label: &str,
            items: &[String],
            default: usize,
        ) -> Result<usize, String> {
            self.asked.push(format!(
                "{label} [{}] of {}",
                items[default],
                items.join(" | ")
            ));
            Ok(match self.next(label) {
                Answer::Default => default,
                Answer::Pick(i) => i,
                Answer::Cancel => return Err(super::CANCELLED.into()),
                a => panic!("{label}: expected a pick, scripted {a:?}"),
            })
        }

        fn confirm(&mut self, label: &str, default: bool) -> Result<bool, String> {
            self.asked.push(format!("{label} [{default}]"));
            Ok(match self.next(label) {
                Answer::Default => default,
                Answer::Yes(y) => y,
                Answer::Cancel => return Err(super::CANCELLED.into()),
                a => panic!("{label}: expected yes/no, scripted {a:?}"),
            })
        }

        fn long_text(&mut self, label: &str, current: &str) -> Result<String, String> {
            self.asked.push(format!("{label} (long) [{current}]"));
            Ok(match self.next(label) {
                Answer::Default => current.to_string(),
                Answer::Text(t) => t.to_string(),
                Answer::Cancel => return Err(super::CANCELLED.into()),
                Answer::Fail(e) => return Err(e.into()),
                a => panic!("{label}: expected text, scripted {a:?}"),
            })
        }

        fn browse(
            &mut self,
            label: &str,
            items: &[String],
            place: &mut super::Place,
            more: bool,
            keys: &str,
            _: &str,
        ) -> Result<Action, String> {
            let more_note = if more { " (more)" } else { "" };
            // A notice is shown once, as the picker does.
            let notice = place
                .notice
                .take()
                .map_or(String::new(), |n| format!(" !{n}"));
            self.asked.push(format!(
                "{label} [{}] of {}{more_note}{notice} (keys {keys})",
                items.get(place.at).map_or("", String::as_str),
                items.join(" | ")
            ));
            match self.next(label) {
                Answer::Browse(i, action) => {
                    assert!(more || action != Action::More, "More without more");
                    // As the picker ignores keys it wasn't given.
                    if let Action::Key(c) = action {
                        assert!(keys.contains(c), "{c} isn't a key here ({keys})");
                    }
                    place.at = i;
                    Ok(action)
                }
                Answer::Search(text) => {
                    assert!(place.server_search, "Search on a list that can't");
                    place.filter = text.to_string();
                    Ok(Action::Search)
                }
                a => panic!("{label}: expected a browse, scripted {a:?}"),
            }
        }

        fn keypress(&mut self, hint: &str, keys: &str) -> Result<Action, String> {
            self.asked.push(format!("{hint} (keys {keys})"));
            Ok(match self.next(hint) {
                Answer::Press(action) => action,
                a => panic!("{hint}: expected a key, scripted {a:?}"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::scripted::{Answer::*, Script};
    use super::*;

    #[test]
    fn confirming_by_name_takes_the_name_backs_out_on_nothing_and_refuses_the_rest() {
        let confirm = |answer| confirm_by_name(&mut Script::new([answer]), "acct/thing", "deleted");
        assert_eq!(confirm(Text("acct/thing")), Ok(()));
        assert_eq!(confirm(Text("  ")), Err(CANCELLED.to_string()));
        assert_eq!(
            confirm(Text("acct/other")),
            Err("Not confirmed; nothing was deleted.".to_string())
        );
    }
}
