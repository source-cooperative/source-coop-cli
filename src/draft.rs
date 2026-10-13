//! Answers someone typed for a create or edit, kept when sending them fails so
//! nothing has to be typed again. Any command that asks for fields and then
//! sends them can use one: `resume` before asking, `finish` with the result.
//!
//! Drafts are the person's own work, so they live in the OS's place for app
//! state rather than its cache, which the OS or a cleaner may empty:
//! `$XDG_STATE_HOME` (`~/.local/state`) on Linux, `~/Library/Application
//! Support` on macOS, `%LocalAppData%` on Windows.

use crate::cache;
use crate::prompt::Prompter;
use serde_json::{Map, Value};
use std::fs;
use std::path::PathBuf;

pub struct Draft {
    path: PathBuf,
}

fn dir() -> Result<PathBuf, String> {
    // Tests never touch the person's real drafts, nor each other's: each test
    // runs on its own thread, and many name the same product.
    if cfg!(test) {
        return Ok(std::env::temp_dir().join(format!(
            "source-coop-drafts-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        )));
    }
    Ok(dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .ok_or("Could not determine a directory for drafts")?
        .join("source-coop")
        .join("drafts"))
}

impl Draft {
    /// The draft for `key`, one per thing being created or edited, e.g.
    /// `product-create/acct/prod`.
    pub fn for_key(key: &str) -> Result<Draft, String> {
        let name = cache::sanitize(key, &['-', '_', '.']);
        Ok(Draft {
            path: dir()?.join(format!("{name}.json")),
        })
    }

    /// Offer the answers saved by a failed try. Taken, they fill in whatever
    /// `body` doesn't already hold, so flags and --from-file still win;
    /// declined, the draft is dropped. Returns whether they were taken.
    pub fn resume(
        &self,
        ask: &mut dyn Prompter,
        body: &mut Map<String, Value>,
    ) -> Result<bool, String> {
        let Some(saved) = self.load() else {
            return Ok(false);
        };
        if !ask.confirm("Use the answers saved from your last try?", true)? {
            self.discard();
            return Ok(false);
        }
        for (field, value) in saved {
            body.entry(field).or_insert(value);
        }
        Ok(true)
    }

    /// Drop the draft once `result` succeeded. When it failed, save `body` so
    /// the next run can offer it, and say so in the error.
    pub fn finish<T>(
        &self,
        result: Result<T, String>,
        body: &Map<String, Value>,
    ) -> Result<T, String> {
        let e = match result {
            Ok(value) => {
                self.discard();
                return Ok(value);
            }
            Err(e) => e,
        };
        let json = serde_json::to_string_pretty(body).expect("a JSON object serializes");
        Err(match cache::write_file(&self.path, &json) {
            Ok(path) => format!(
                "{e}\nYour answers are saved: run the same command again to use them, or pass --from-file {path}"
            ),
            Err(save) => format!("{e}\nYour answers couldn't be saved: {save}"),
        })
    }

    fn load(&self) -> Option<Map<String, Value>> {
        match serde_json::from_str(&fs::read_to_string(&self.path).ok()?) {
            Ok(Value::Object(fields)) => Some(fields),
            _ => None,
        }
    }

    fn discard(&self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::scripted::{Answer::*, Script};
    use serde_json::json;

    fn body(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn a_failed_send_keeps_the_answers_for_the_next_try() {
        let draft = Draft::for_key("test/kept").unwrap();
        let typed = body(json!({"title": "Typed", "description": "Long text"}));
        let err = draft
            .finish::<()>(Err("Authentication required".into()), &typed)
            .unwrap_err();
        assert!(err.starts_with("Authentication required\nYour answers are saved"));

        // Next try: a flag's value wins over the saved one, the rest is resumed.
        let mut next = body(json!({"title": "From a flag"}));
        let mut ask = Script::new([Yes(true)]);
        assert!(draft.resume(&mut ask, &mut next).unwrap());
        assert_eq!(
            Value::Object(next),
            json!({"title": "From a flag", "description": "Long text"})
        );

        draft.finish(Ok(()), &Map::new()).unwrap();
        assert!(draft.load().is_none(), "success drops the draft");
    }

    #[test]
    fn declining_a_draft_drops_it_and_no_draft_asks_nothing() {
        let draft = Draft::for_key("test/declined").unwrap();
        let _ = draft.finish::<()>(Err("boom".into()), &body(json!({"title": "T"})));

        let mut fresh = Map::new();
        assert!(!draft
            .resume(&mut Script::new([Yes(false)]), &mut fresh)
            .unwrap());
        assert!(fresh.is_empty());
        // Gone now, so nothing is offered (an unscripted prompt would panic).
        assert!(!draft.resume(&mut Script::new([]), &mut fresh).unwrap());
    }
}
