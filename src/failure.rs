//! What a command's failure means, for `--json` errors and exit codes: the
//! API's error code, status and field errors where the failure came from the
//! API, and a local code otherwise.
//!
//! ponytail: errors travel through the commands as `String`s, which drop the
//! API's structure. `remember` keeps the last API error as it's turned into
//! text, and `classify` finds it again in the text that reaches `fail`, even
//! once wrapped ("Couldn't get new credentials (…)", a saved-draft note). The
//! upgrade path is a typed error carried through `Result` instead.

use crate::api::ApiError;
use std::cell::RefCell;
use std::collections::BTreeMap;

/// A failure as scripts see it, serialized as the API's error body.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Failure {
    /// The API's error code, or a local one: `cancelled`, `interrupted`,
    /// `not_signed_in`, `error`.
    pub code: String,
    /// The whole message, as a person would read it.
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub field_errors: BTreeMap<String, Vec<String>>,
}

thread_local! {
    /// The last API error, with the text it became.
    static LAST: RefCell<Option<(String, ApiError)>> = const { RefCell::new(None) };
}

/// Keep `e`'s structure, as it becomes `text`.
pub fn remember(e: &ApiError, text: &str) {
    LAST.with(|last| *last.borrow_mut() = Some((text.to_string(), e.clone())));
}

/// What `e`, the text that reached `fail`, means.
pub fn classify(e: &str) -> Failure {
    let local = |code: &str, status: Option<u16>| Failure {
        code: code.into(),
        message: e.to_string(),
        status,
        field_errors: BTreeMap::new(),
    };
    if e == crate::prompt::CANCELLED {
        return local("cancelled", None);
    }
    if e == crate::prompt::INTERRUPTED {
        return local("interrupted", None);
    }
    if e.starts_with("Not signed in") {
        return local("not_signed_in", None);
    }
    let api = LAST
        .with(|last| last.borrow().clone())
        .filter(|(text, _)| e.contains(text));
    match api {
        Some((text, api)) => Failure {
            code: api.code.unwrap_or_else(|| "error".into()),
            // The code, status and field errors have fields of their own.
            message: e.replace(&text, &api.message),
            status: api.status.map(|s| s.as_u16()),
            field_errors: api.field_errors,
        },
        None => local("error", None),
    }
}

impl Failure {
    /// The process exit code, the same for every command.
    pub fn exit_code(&self) -> i32 {
        match (self.code.as_str(), self.status) {
            ("interrupted", _) => 130,
            ("not_signed_in", _) | (_, Some(401 | 403)) => 4,
            (_, Some(400 | 409 | 422)) => 3,
            (_, Some(404)) => 5,
            _ => 1,
        }
    }

    /// `{"error": {"code", "message", "status"?, "field_errors"?}}`, the API's
    /// own error shape.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "error": self })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;

    fn api_error(status: u16, code: &str, fields: &[(&str, &str)]) -> String {
        let body = serde_json::json!({"error": {
            "code": code, "message": "Rejected",
            "field_errors": fields.iter().map(|(f, m)| (f.to_string(), vec![m.to_string()])).collect::<BTreeMap<_, _>>(),
        }});
        ApiError::from_response(StatusCode::from_u16(status).unwrap(), &body.to_string()).into()
    }

    #[test]
    fn an_api_error_keeps_its_code_fields_and_status_even_wrapped() {
        let text = api_error(400, "invalid_input", &[("title", "must not be empty")]);
        let wrapped = format!("{text}\nYour answers are saved: run the same command again");
        let f = classify(&wrapped);
        assert_eq!(f.code, "invalid_input");
        assert_eq!(f.status, Some(400));
        assert_eq!(f.field_errors["title"], ["must not be empty"]);
        // The API's message, without what the other fields carry, still wrapped.
        assert_eq!(
            f.message,
            "Rejected\nYour answers are saved: run the same command again"
        );
        assert_eq!(f.exit_code(), 3);
        assert_eq!(
            f.to_json(),
            serde_json::json!({"error": {"code": "invalid_input", "message": f.message,
                "status": 400, "field_errors": {"title": ["must not be empty"]}}})
        );
    }

    #[test]
    fn exit_codes_say_what_kind_of_failure_it_was() {
        assert_eq!(
            classify(&api_error(401, "unauthenticated", &[])).exit_code(),
            4
        );
        assert_eq!(classify(&api_error(403, "forbidden", &[])).exit_code(), 4);
        assert_eq!(classify(&api_error(409, "conflict", &[])).exit_code(), 3);
        assert_eq!(classify(&api_error(404, "not_found", &[])).exit_code(), 5);
        assert_eq!(classify(&api_error(500, "internal", &[])).exit_code(), 1);
        assert_eq!(
            classify("Not signed in: run 'source-coop auth login'.").exit_code(),
            4
        );
        assert_eq!(classify(crate::prompt::INTERRUPTED).exit_code(), 130);
        let cancelled = classify(crate::prompt::CANCELLED);
        assert_eq!(
            (cancelled.code.as_str(), cancelled.exit_code()),
            ("cancelled", 1)
        );
    }

    #[test]
    fn a_local_error_is_just_an_error() {
        let f = classify("Couldn't read input.json: No such file");
        assert_eq!(
            (f.code.as_str(), f.status, f.exit_code()),
            ("error", None, 1)
        );
        assert_eq!(
            f.to_json(),
            serde_json::json!({"error": {"code": "error", "message": "Couldn't read input.json: No such file"}})
        );
    }
}
