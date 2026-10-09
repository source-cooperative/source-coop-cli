//! Interactive prompts for whatever a command wasn't given by flag or file.
//!
//! Prompts appear only when someone is there to answer them: stdin and stderr
//! are both terminals and `SOURCE_PROMPT_DISABLED` is unset. Otherwise a
//! command sends what it was given, and the API says what's missing.

use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use std::io::IsTerminal;

pub trait Prompter {
    /// Ask for a line of text, offering `default` (taken on a bare Enter).
    fn input(&mut self, label: &str, default: &str, allow_empty: bool) -> Result<String, String>;
    /// Ask for one of `items`, starting on `default`; returns its index.
    fn select(&mut self, label: &str, items: &[String], default: usize) -> Result<usize, String>;
    /// Ask a yes/no question.
    fn confirm(&mut self, label: &str, default: bool) -> Result<bool, String>;
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
    format!("Prompt failed: {e}")
}

impl Prompter for Tty {
    fn input(&mut self, label: &str, default: &str, allow_empty: bool) -> Result<String, String> {
        let mut input = Input::<String>::with_theme(&self.theme)
            .with_prompt(label)
            .allow_empty(allow_empty);
        if !default.is_empty() {
            input = input.default(default.to_string());
        }
        input.interact_text().map_err(failed)
    }

    fn select(&mut self, label: &str, items: &[String], default: usize) -> Result<usize, String> {
        Select::with_theme(&self.theme)
            .with_prompt(label)
            .items(items)
            .default(default)
            .interact()
            .map_err(failed)
    }

    fn confirm(&mut self, label: &str, default: bool) -> Result<bool, String> {
        Confirm::with_theme(&self.theme)
            .with_prompt(label)
            .default(default)
            .interact()
            .map_err(failed)
    }
}

/// Answers from a script, in order, for tests.
#[cfg(test)]
pub mod scripted {
    use super::Prompter;
    use std::collections::VecDeque;

    #[derive(Debug)]
    pub enum Answer {
        /// Take the offered default.
        Default,
        Text(&'static str),
        Pick(usize),
        Yes(bool),
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
    }

    impl Prompter for Script {
        fn input(&mut self, label: &str, default: &str, _: bool) -> Result<String, String> {
            self.asked.push(format!("{label} [{default}]"));
            Ok(match self.next(label) {
                Answer::Default => default.to_string(),
                Answer::Text(t) => t.to_string(),
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
                a => panic!("{label}: expected a pick, scripted {a:?}"),
            })
        }

        fn confirm(&mut self, label: &str, default: bool) -> Result<bool, String> {
            self.asked.push(format!("{label} [{default}]"));
            Ok(match self.next(label) {
                Answer::Default => default,
                Answer::Yes(y) => y,
                a => panic!("{label}: expected yes/no, scripted {a:?}"),
            })
        }
    }
}
