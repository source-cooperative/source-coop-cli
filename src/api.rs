//! A thin client for source.coop's `/api/v1`.
//!
//! The CLI validates nothing itself: the API enforces the same rules as the web
//! UI, and this module's job is to send the request and turn the API's error
//! body — `{"error": {"code", "message", "field_errors"?}}` — into a message a
//! person can act on.

use reqwest::{Method, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// The API's shared error shape.
#[derive(Debug, Deserialize)]
struct ErrorBody {
    error: ApiErrorDetail,
}

#[derive(Debug, Deserialize)]
struct ApiErrorDetail {
    code: String,
    message: String,
    #[serde(default)]
    field_errors: BTreeMap<String, Vec<String>>,
}

/// A failed API call, with whatever the API said about why.
#[derive(Debug)]
pub struct ApiError {
    pub status: Option<StatusCode>,
    pub code: Option<String>,
    pub message: String,
    pub field_errors: BTreeMap<String, Vec<String>>,
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
        if self.status == Some(StatusCode::UNAUTHORIZED) {
            write!(f, "\nThis needs you signed in: run 'source-coop login'.")?;
        }
        Ok(())
    }
}

impl From<ApiError> for String {
    fn from(e: ApiError) -> Self {
        e.to_string()
    }
}

impl ApiError {
    fn transport(e: impl fmt::Display) -> Self {
        ApiError {
            status: None,
            code: None,
            message: format!("API request failed: {e}"),
            field_errors: BTreeMap::new(),
        }
    }

    /// Build the error from a non-2xx response body, which is the shared error
    /// shape when the API produced it and anything at all when something in
    /// front of the API did.
    fn from_response(status: StatusCode, body: &str) -> Self {
        match serde_json::from_str::<ErrorBody>(body) {
            Ok(ErrorBody { error }) => ApiError {
                status: Some(status),
                code: Some(error.code),
                message: error.message,
                field_errors: error.field_errors,
            },
            Err(_) => ApiError {
                status: Some(status),
                code: None,
                message: status
                    .canonical_reason()
                    .unwrap_or("Unexpected response")
                    .to_string(),
                field_errors: BTreeMap::new(),
            },
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

    pub async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        url: url::Url,
        body: Option<&impl Serialize>,
    ) -> Result<T, ApiError> {
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
        let resp = req.send().await.map_err(ApiError::transport)?;
        let status = resp.status();
        let text = resp.text().await.map_err(ApiError::transport)?;
        if self.verbose {
            eprintln!("[verbose] -> HTTP {}", status.as_u16());
        }
        if !status.is_success() {
            return Err(ApiError::from_response(status, &text));
        }
        serde_json::from_str(&text)
            .map_err(|e| ApiError::transport(format!("unreadable response: {e}")))
    }

    pub async fn get<T: DeserializeOwned>(&self, url: url::Url) -> Result<T, ApiError> {
        self.request(Method::GET, url, None::<&()>).await
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
    fn shows_field_errors_from_the_api() {
        let body = r#"{"error":{"code":"invalid","message":"The request is invalid.",
            "field_errors":{"title":["A title is required"]}}}"#;
        let e = ApiError::from_response(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            e.to_string(),
            "The request is invalid. (invalid, HTTP 400)\n  title: A title is required"
        );
    }

    #[test]
    fn survives_a_body_that_is_not_the_error_shape() {
        let e = ApiError::from_response(StatusCode::BAD_GATEWAY, "<html>oops</html>");
        assert_eq!(e.to_string(), "Bad Gateway (HTTP 502)");
    }

    #[test]
    fn says_how_to_authenticate_on_401() {
        let body = r#"{"error":{"code":"unauthenticated","message":"Sign in first."}}"#;
        let e = ApiError::from_response(StatusCode::UNAUTHORIZED, body);
        assert!(e.to_string().contains("source-coop login"));
    }
}
