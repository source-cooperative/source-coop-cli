//! `source-coop api`: any `/api/v1` request, authenticated as whoever ran
//! `login`, for whatever the other commands don't cover yet. Modeled on
//! `gh api`.

use crate::api::{ApiError, Client};
use clap::Args;
use reqwest::Method;
use serde_json::{Map, Value};
use std::io::Read;

#[derive(Args)]
pub struct ApiArgs {
    /// The path under /api/v1, e.g. `products/my-org` (a query string is kept)
    path: String,

    /// HTTP method; GET, or POST when there's a body (-f or -F)
    #[arg(long, short = 'X')]
    method: Option<String>,

    /// A query parameter, `key=value`; doesn't change the method
    #[arg(long, short = 'q', value_name = "KEY=VALUE")]
    query: Vec<String>,

    /// A body field, `key=value`; a value that parses as JSON (`5`, `true`,
    /// `["a"]`) is sent as that, anything else as a string (quote it, `'"5"'`,
    /// to send a number as a string)
    #[arg(long = "field", short = 'f', value_name = "KEY=VALUE")]
    fields: Vec<String>,

    /// Read the body from a JSON file (`-` for stdin); -f fields win over its keys
    #[arg(long, short = 'F', value_name = "PATH")]
    from_file: Option<String>,
}

/// Prints the response body (pretty if JSON) to stdout, and fails on any
/// status that isn't a success, as `gh api` does, so scripts can check `$?`.
pub async fn run(args: ApiArgs, client: &Client) -> Result<(), String> {
    let mut url = client.resolve(&args.path)?;
    for q in &args.query {
        let (k, v) = split(q)?;
        url.query_pairs_mut().append_pair(&k, &v);
    }
    let body = body(args.from_file.as_deref(), &args.fields)?;
    let method = match &args.method {
        Some(m) => m
            .to_uppercase()
            .parse::<Method>()
            .map_err(|_| format!("Invalid method '{m}'"))?,
        None if body.is_some() => Method::POST,
        None => Method::GET,
    };
    if method == Method::GET && body.is_some() {
        return Err(
            "-f and -F send a request body, which a GET doesn't take: give query parameters with -q, or another method with -X"
                .into(),
        );
    }

    let (status, text) = client.send(method, url, body.as_ref()).await?;
    match serde_json::from_str::<Value>(&text) {
        Ok(json) => crate::output::json(&json),
        Err(_) if text.is_empty() => {}
        Err(_) => println!("{text}"),
    }
    if status.is_success() {
        Ok(())
    } else {
        // Through `From`, which keeps the code and status for the exit code.
        Err(ApiError::from_response(status, &text).into())
    }
}

/// The request body: `from_file`'s JSON with `fields` set over it. None when
/// neither is given.
fn body(from_file: Option<&str>, fields: &[String]) -> Result<Option<Value>, String> {
    let mut body = match from_file {
        Some(path) => read_json(path)?,
        None if fields.is_empty() => return Ok(None),
        None => Value::Object(Map::new()),
    };
    if fields.is_empty() {
        return Ok(Some(body));
    }
    let Value::Object(map) = &mut body else {
        return Err("-f fields can only be added to a JSON object from -F".into());
    };
    for f in fields {
        let (k, v) = split(f)?;
        let value = serde_json::from_str(&v).unwrap_or(Value::String(v));
        map.insert(k, value);
    }
    Ok(Some(body))
}

fn split(f: &str) -> Result<(String, String), String> {
    f.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("Expected KEY=VALUE, got '{f}'"))
}

/// The JSON in `path` (`-` for stdin).
pub(crate) fn read_json(path: &str) -> Result<Value, String> {
    let text = if path == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("Couldn't read stdin: {e}"))?;
        s
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("Couldn't read {path}: {e}"))?
    };
    serde_json::from_str(&text).map_err(|e| format!("{path} isn't JSON: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn args(path: &str) -> ApiArgs {
        ApiArgs {
            path: path.into(),
            method: None,
            query: vec![],
            fields: vec![],
            from_file: None,
        }
    }

    fn temp_json(name: &str, text: &str) -> String {
        let path = std::env::temp_dir().join(format!("api-cmd-{name}-{}.json", std::process::id()));
        std::fs::write(&path, text).unwrap();
        path.display().to_string()
    }

    #[test]
    fn fields_are_json_when_they_parse() {
        let fields = [
            "a=true",
            "b=null",
            "c=7",
            "d=x",
            "e=[\"t\"]",
            "f=\"5\"",
            "g=a=b",
        ];
        let fields: Vec<String> = fields.iter().map(|f| f.to_string()).collect();
        assert_eq!(
            body(None, &fields).unwrap(),
            Some(json!({"a": true, "b": null, "c": 7, "d": "x", "e": ["t"], "f": "5", "g": "a=b"}))
        );
        assert_eq!(body(None, &[]).unwrap(), None);
        assert!(body(None, &["nokey".into()]).is_err());
    }

    #[test]
    fn fields_win_over_the_file() {
        let path = temp_json("merge", r#"{"title": "Old", "description": "D"}"#);
        let merged = body(Some(&path), &["title=New".into()]);
        let list = temp_json("list", "[1]");
        let not_object = body(Some(&list), &["title=New".into()]);
        let _ = (std::fs::remove_file(&path), std::fs::remove_file(&list));
        assert_eq!(
            merged.unwrap(),
            Some(json!({"title": "New", "description": "D"}))
        );
        assert!(not_object.is_err());
    }

    #[tokio::test]
    async fn query_parameters_keep_a_get() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/acct"))
            .and(query_param("limit", "2"))
            .and(query_param("q", "a b"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), None, false).unwrap();
        let mut a = args("/products/acct");
        a.query = vec!["limit=2".into(), "q=a b".into()];
        run(a, &client).await.unwrap();
    }

    #[tokio::test]
    async fn fields_default_to_a_post_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/products/acct"))
            .and(body_json(json!({"product_id": "p", "title": "T"})))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), None, false).unwrap();
        let mut a = args("products/acct");
        a.fields = vec!["product_id=p".into(), "title=T".into()];
        run(a, &client).await.unwrap();
    }

    #[tokio::test]
    async fn an_error_status_fails_with_the_apis_message() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_json(
                json!({"type": "https://source.coop/api/problems/not_found", "title": "T", "status": 404,
                "detail": "No such product.", "code": "not_found"}),
            ))
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), None, false).unwrap();
        let err = run(args("products/acct/nope"), &client).await.unwrap_err();
        assert!(err.contains("No such product. (not_found, HTTP 404)"));
        // The API's code and status survive, for --json errors and exit codes.
        let failure = crate::failure::classify(&err);
        assert_eq!(
            (failure.code.as_str(), failure.status),
            ("not_found", Some(404))
        );
        assert_eq!(failure.exit_code(), 5);
    }

    #[tokio::test]
    async fn a_get_refuses_a_body() {
        let client = Client::new("http://127.0.0.1:9", None, false).unwrap();
        let mut a = args("products/acct");
        a.method = Some("GET".into());
        a.fields = vec!["limit=2".into()];
        let err = run(a, &client).await.unwrap_err();
        assert!(err.starts_with("-f and -F send a request body"), "{err}");
    }
}
