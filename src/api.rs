//! A thin client for source.coop's `/api/v1`.
//!
//! The CLI validates nothing itself: the API enforces the same rules as the web
//! UI, and this module's job is to send the request and turn the API's error
//! body, an RFC 9457 problem (`application/problem+json`), into a message a
//! person can act on.

use reqwest::{Method, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// The API's error body: an RFC 9457 problem, with the API's extension
/// members `code`, `errors` and `request_id`.
#[derive(Debug, Deserialize)]
struct Problem {
    #[serde(rename = "type")]
    type_url: Option<String>,
    title: Option<String>,
    detail: Option<String>,
    code: Option<String>,
    #[serde(default)]
    errors: Vec<FieldProblem>,
    request_id: Option<String>,
}

/// One rejected field: a JSON Pointer into the request body, or a query
/// parameter.
#[derive(Debug, Deserialize)]
struct FieldProblem {
    detail: String,
    pointer: Option<String>,
    parameter: Option<String>,
}

impl FieldProblem {
    /// The field as the CLI names it everywhere else: a dotted path
    /// (`metadata.title`), as the prompts and `--json`'s `field_errors` use.
    fn field(&self) -> Option<String> {
        if let Some(p) = &self.parameter {
            return Some(p.clone());
        }
        let pointer = self.pointer.as_deref()?;
        let path = pointer.strip_prefix('#').unwrap_or(pointer);
        let path = path.strip_prefix('/')?;
        Some(
            path.split('/')
                .map(|s| s.replace("~1", "/").replace("~0", "~"))
                .collect::<Vec<_>>()
                .join("."),
        )
    }
}

/// The error body the API answered before it answered problems. Read too, so
/// the CLI works against a deploy that hasn't caught up.
#[derive(Debug, Deserialize)]
struct LegacyErrorBody {
    error: LegacyErrorDetail,
}

#[derive(Debug, Deserialize)]
struct LegacyErrorDetail {
    code: String,
    message: String,
    #[serde(default)]
    field_errors: BTreeMap<String, Vec<String>>,
}

/// Where the API's problem types live. A `type` under it ends in its code.
const PROBLEM_TYPE_BASE: &str = "https://source.coop/api/problems/";

/// A failed API call, with whatever the API said about why.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: Option<StatusCode>,
    pub code: Option<String>,
    pub message: String,
    pub field_errors: BTreeMap<String, Vec<String>>,
    /// The problem's `type`: a URL whose page explains it.
    pub type_url: Option<String>,
    /// The API's ID for the request, which finds it in source.coop's logs.
    pub request_id: Option<String>,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.code, self.status) {
            (Some(code), Some(status)) => {
                write!(f, "{} ({code}, HTTP {})", self.message, status.as_u16())?
            }
            (None, Some(status)) => write!(f, "{} (HTTP {})", self.message, status.as_u16())?,
            _ => write!(f, "{}", self.message)?,
        }
        for (field, problems) in &self.field_errors {
            for problem in problems {
                write!(f, "\n  {field}: {problem}")?;
            }
        }
        if let (Some(id), Some(true)) = (&self.request_id, self.status.map(|s| s.is_server_error()))
        {
            write!(
                f,
                "\nIf this keeps happening, report it with request ID {id}."
            )?;
        }
        if self.status == Some(StatusCode::UNAUTHORIZED) {
            write!(
                f,
                "\nThis needs you signed in: run 'source-coop auth login'."
            )?;
        }
        Ok(())
    }
}

impl From<ApiError> for String {
    fn from(e: ApiError) -> Self {
        let text = e.to_string();
        // So `--json` errors and exit codes can still give its code and fields.
        crate::failure::remember(&e, &text);
        text
    }
}

impl ApiError {
    /// A request that never got a response. reqwest's own message names only
    /// the URL; the cause (DNS, TLS, a refused connection) is further down the
    /// chain, so all of it is shown.
    fn transport(e: &reqwest::Error) -> Self {
        let causes: String = std::iter::successors(std::error::Error::source(e), |c| c.source())
            .map(|c| format!(": {c}"))
            .collect();
        Self::other(format!("API request failed: {e}{causes}"))
    }

    fn other(message: String) -> Self {
        ApiError {
            status: None,
            code: None,
            message,
            field_errors: BTreeMap::new(),
            type_url: None,
            request_id: None,
        }
    }

    /// Build the error from a non-2xx response body, which is a problem when
    /// the API produced it and anything at all when something in front of the
    /// API did.
    pub fn from_response(status: StatusCode, body: &str) -> Self {
        let unknown = || ApiError {
            status: Some(status),
            code: None,
            message: status
                .canonical_reason()
                .unwrap_or("Unexpected response")
                .to_string(),
            field_errors: BTreeMap::new(),
            type_url: None,
            request_id: None,
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
            return unknown();
        };
        if !json.is_object() {
            return unknown();
        }
        if json.get("error").is_some_and(|e| e.is_object()) {
            return match serde_json::from_value::<LegacyErrorBody>(json) {
                Ok(LegacyErrorBody { error }) => ApiError {
                    code: Some(error.code),
                    message: error.message,
                    field_errors: error.field_errors,
                    ..unknown()
                },
                Err(_) => unknown(),
            };
        }
        let Ok(p) = serde_json::from_value::<Problem>(json) else {
            return unknown();
        };
        if p.type_url.is_none() && p.title.is_none() && p.detail.is_none() {
            return unknown();
        }
        let mut field_errors = BTreeMap::<String, Vec<String>>::new();
        for e in &p.errors {
            if let Some(field) = e.field() {
                field_errors
                    .entry(field)
                    .or_default()
                    .push(e.detail.clone());
            }
        }
        let code = p.code.or_else(|| {
            p.type_url
                .as_deref()
                .and_then(|t| t.strip_prefix(PROBLEM_TYPE_BASE))
                .map(str::to_string)
        });
        let fallback = unknown();
        ApiError {
            code,
            message: p.detail.or(p.title).unwrap_or(fallback.message),
            field_errors,
            type_url: p.type_url,
            request_id: p.request_id,
            ..fallback
        }
    }
}

pub struct Client {
    base: url::Url,
    token: Option<String>,
    http: reqwest::Client,
    verbose: bool,
}

impl Client {
    /// `api_url` is the site's origin (e.g. `https://source.coop`); requests go
    /// to `{api_url}/api/v1/...`.
    pub fn new(api_url: &str, token: Option<String>, verbose: bool) -> Result<Self, String> {
        let mut base = url::Url::parse(api_url).map_err(|e| format!("Invalid API URL: {e}"))?;
        base.set_path("/api/v1/");
        Ok(Client {
            base,
            token: token.filter(|t| !t.trim().is_empty()),
            http: reqwest::Client::new(),
            verbose,
        })
    }

    /// The URL for `segments` under `/api/v1/`, each one percent-encoded.
    pub fn url(&self, segments: &[&str]) -> url::Url {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .expect("an http(s) URL has path segments")
            .pop_if_empty()
            .extend(segments);
        url
    }

    /// Send a request and return the status and body as they came, whatever
    /// the status. Only a request that gets no response at all is an error.
    pub async fn send(
        &self,
        method: Method,
        url: url::Url,
        body: Option<&impl Serialize>,
    ) -> Result<(StatusCode, String), ApiError> {
        if self.verbose {
            let auth = if self.token.is_some() {
                " (bearer)"
            } else {
                ""
            };
            eprintln!("[verbose] {method} {url}{auth}");
        }
        let mut req = self.http.request(method, url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        if let Some(body) = body {
            req = req.json(body);
        }
        let resp = req.send().await.map_err(|e| ApiError::transport(&e))?;
        let status = resp.status();
        let text = resp.text().await.map_err(|e| ApiError::transport(&e))?;
        if self.verbose {
            eprintln!("[verbose] -> HTTP {}", status.as_u16());
        }
        Ok((status, text))
    }

    /// Send a request and parse a successful response; any other status is an
    /// error carrying what the API said.
    pub async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        url: url::Url,
        body: Option<&impl Serialize>,
    ) -> Result<T, ApiError> {
        let (status, text) = self.send(method, url, body).await?;
        if !status.is_success() {
            return Err(ApiError::from_response(status, &text));
        }
        serde_json::from_str(&text)
            .map_err(|e| ApiError::other(format!("API response unreadable: {e}")))
    }

    /// Resolve a path the way `source-coop api` takes one: relative to
    /// `/api/v1/`, with or without a leading `/` or `api/v1/`, and with any
    /// query string kept.
    pub fn resolve(&self, path: &str) -> Result<url::Url, String> {
        let path = path.trim_start_matches('/');
        let path = path.strip_prefix("api/v1/").unwrap_or(path);
        let url = self
            .base
            .join(path)
            .map_err(|e| format!("Invalid API path '{path}': {e}"))?;
        // A full URL joins as itself, and the bearer must not go elsewhere;
        // `..` segments must not climb out of the API either.
        if url.origin() != self.base.origin() || !url.path().starts_with(self.base.path()) {
            return Err(format!(
                "'{path}' isn't on the API at {}; give a path under /api/v1",
                self.base.origin().ascii_serialization()
            ));
        }
        Ok(url)
    }

    pub async fn get<T: DeserializeOwned>(&self, url: url::Url) -> Result<T, ApiError> {
        self.request(Method::GET, url, None::<&()>).await
    }

    /// Fail before anyone is asked anything if changes can't be made as them:
    /// no token, or one the API refuses (expired, or for another audience).
    /// Returns the `/whoami` session, which says who they are and what they're
    /// a member of.
    pub async fn check_signed_in(&self) -> Result<serde_json::Value, ApiError> {
        if self.token.is_none() {
            return Err(ApiError::other(
                "Not signed in: run 'source-coop auth login'.".into(),
            ));
        }
        self.get(self.url(&["whoami"])).await
    }
}

/// One page of a listing.
#[derive(Debug, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encodes_segments_under_api_v1() {
        let c = Client::new("https://source.coop", None, false).unwrap();
        assert_eq!(
            c.url(&["products", "acct", "a b"]).as_str(),
            "https://source.coop/api/v1/products/acct/a%20b"
        );
        let c = Client::new("http://localhost:3000/ignored", None, false).unwrap();
        assert_eq!(
            c.url(&["products"]).as_str(),
            "http://localhost:3000/api/v1/products"
        );
    }

    #[test]
    fn resolves_api_paths() {
        let c = Client::new("https://source.coop", None, false).unwrap();
        for p in [
            "products/acct?limit=2",
            "/products/acct?limit=2",
            "/api/v1/products/acct?limit=2",
        ] {
            assert_eq!(
                c.resolve(p).unwrap().as_str(),
                "https://source.coop/api/v1/products/acct?limit=2"
            );
        }
        // The token is only ever sent to the API's own origin, and only under
        // /api/v1 there.
        assert!(c.resolve("https://example.com/steal").is_err());
        assert!(c.resolve("../../whoami").is_err());
        assert!(c.resolve("products/../../../admin").is_err());
        assert!(c.resolve("products/../whoami").is_ok());
    }

    #[tokio::test]
    async fn a_failed_connection_says_why() {
        // Nothing listens on port 9 (discard) on loopback.
        let c = Client::new("http://127.0.0.1:9", None, false).unwrap();
        let e = c.get::<()>(c.url(&["products"])).await.unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.starts_with("API request failed: error sending request"),
            "{msg}"
        );
        assert!(msg.matches(": ").count() >= 2, "no cause in: {msg}");
    }

    #[test]
    fn shows_field_errors_from_the_apis_problem() {
        let body = r##"{"type":"https://source.coop/api/problems/invalid","title":"Invalid request",
            "status":400,"detail":"A title is required","code":"invalid",
            "errors":[{"detail":"A title is required","pointer":"#/title"},
                      {"detail":"Too long","pointer":"#/metadata/a~1b"},
                      {"detail":"Too big","parameter":"limit"}]}"##;
        let e = ApiError::from_response(StatusCode::BAD_REQUEST, body);
        assert_eq!(e.code.as_deref(), Some("invalid"));
        assert_eq!(
            e.type_url.as_deref(),
            Some("https://source.coop/api/problems/invalid")
        );
        assert_eq!(
            e.to_string(),
            "A title is required (invalid, HTTP 400)\n  limit: Too big\n  metadata.a/b: Too long\n  title: A title is required"
        );
    }

    #[test]
    fn takes_the_code_from_the_type_when_the_problem_has_none() {
        let body = r#"{"type":"https://source.coop/api/problems/conflict","title":"Conflict","status":409}"#;
        let e = ApiError::from_response(StatusCode::CONFLICT, body);
        assert_eq!(e.code.as_deref(), Some("conflict"));
        assert_eq!(e.message, "Conflict");
    }

    #[test]
    fn gives_the_request_id_to_report_a_server_error() {
        let body = r#"{"type":"https://source.coop/api/problems/internal","title":"Internal server error",
            "status":500,"detail":"Internal server error","code":"internal","request_id":"iad1::abc"}"#;
        let e = ApiError::from_response(StatusCode::INTERNAL_SERVER_ERROR, body);
        assert!(e.to_string().contains("request ID iad1::abc"), "{e}");
    }

    #[test]
    fn still_reads_the_error_shape_from_before_problems() {
        let body = r#"{"error":{"code":"invalid","message":"The request is invalid.",
            "field_errors":{"title":["A title is required"]}}}"#;
        let e = ApiError::from_response(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            e.to_string(),
            "The request is invalid. (invalid, HTTP 400)\n  title: A title is required"
        );
    }

    #[test]
    fn survives_a_body_that_is_not_a_problem() {
        let e = ApiError::from_response(StatusCode::BAD_GATEWAY, "<html>oops</html>");
        assert_eq!(e.to_string(), "Bad Gateway (HTTP 502)");
        let e = ApiError::from_response(StatusCode::BAD_GATEWAY, r#"{"message":"oops"}"#);
        assert_eq!(e.to_string(), "Bad Gateway (HTTP 502)");
    }

    #[test]
    fn says_how_to_authenticate_on_401() {
        let body = r#"{"type":"https://source.coop/api/problems/unauthenticated","title":"Authentication required",
            "status":401,"detail":"Sign in first.","code":"unauthenticated"}"#;
        let e = ApiError::from_response(StatusCode::UNAUTHORIZED, body);
        assert!(e.to_string().contains("source-coop auth login"));
    }
}
