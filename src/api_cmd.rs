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

    /// HTTP method; GET, or POST when fields or --input are given
    #[arg(long, short = 'X')]
    method: Option<String>,

    /// A field, `key=value`, sent as a string; in the query string for GET
    #[arg(long = "raw-field", short = 'f', value_name = "KEY=VALUE")]
    raw_fields: Vec<String>,

    /// A field, `key=value`, where `true`, `false`, `null` and numbers are
    /// sent as JSON rather than strings
    #[arg(long = "field", short = 'F', value_name = "KEY=VALUE")]
    fields: Vec<String>,

    /// Send this file's JSON as the request body (`-` for stdin)
    #[arg(long, value_name = "PATH", conflicts_with_all = ["raw_fields", "fields"])]
    input: Option<String>,
}

/// Prints the response body (pretty if JSON) to stdout, and fails on any
/// status that isn't a success, as `gh api` does, so scripts can check `$?`.
pub async fn run(args: ApiArgs, client: &Client) -> Result<(), String> {
    let mut url = client.resolve(&args.path)?;
    let fields = parse_fields(&args.raw_fields, &args.fields)?;
    let body = match &args.input {
        Some(path) => Some(read_json(path)?),
        None => None,
    };
    let method = match &args.method {
        Some(m) => m
            .to_uppercase()
            .parse::<Method>()
            .map_err(|_| format!("Invalid method '{m}'"))?,
        None if body.is_some() || !fields.is_empty() => Method::POST,
        None => Method::GET,
    };

    let body = if method == Method::GET {
        let mut q = url.query_pairs_mut();
        for (k, v) in &fields {
            q.append_pair(k, &v.as_str().map_or_else(|| v.to_string(), String::from));
        }
        drop(q);
        body
    } else if fields.is_empty() {
        body
    } else {
        Some(Value::Object(fields))
    };

    let (status, text) = client.send(method, url, body.as_ref()).await?;
    match serde_json::from_str::<Value>(&text) {
        Ok(json) => println!("{}", serde_json::to_string_pretty(&json).unwrap()),
        Err(_) if text.is_empty() => {}
        Err(_) => println!("{text}"),
    }
    if status.is_success() {
        Ok(())
    } else {
        Err(ApiError::from_response(status, &text).to_string())
    }
}

/// `-f` values are strings; `-F` values are JSON when they parse as a
/// boolean, null or number.
fn parse_fields(raw: &[String], typed: &[String]) -> Result<Map<String, Value>, String> {
    let mut fields = Map::new();
    let split = |f: &str| {
        f.split_once('=')
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .ok_or_else(|| format!("Expected KEY=VALUE, got '{f}'"))
    };
    for f in raw {
        let (k, v) = split(f)?;
        fields.insert(k, Value::String(v));
    }
    for f in typed {
        let (k, v) = split(f)?;
        let value = match serde_json::from_str::<Value>(&v) {
            Ok(j @ (Value::Bool(_) | Value::Null | Value::Number(_))) => j,
            _ => Value::String(v),
        };
        fields.insert(k, value);
    }
    Ok(fields)
}

fn read_json(path: &str) -> Result<Value, String> {
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
            raw_fields: vec![],
            fields: vec![],
            input: None,
        }
    }

    #[test]
    fn typed_fields_become_json() {
        let f = parse_fields(
            &["n=5".into()],
            &["a=true".into(), "b=null".into(), "c=7".into(), "d=x".into()],
        )
        .unwrap();
        assert_eq!(
            Value::Object(f),
            json!({"n": "5", "a": true, "b": null, "c": 7, "d": "x"})
        );
        assert!(parse_fields(&["nokey".into()], &[]).is_err());
    }

    #[tokio::test]
    async fn get_puts_fields_in_the_query() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/acct"))
            .and(query_param("limit", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), None, false).unwrap();
        let mut a = args("/products/acct");
        a.method = Some("get".into());
        a.fields = vec!["limit=2".into()];
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
        a.raw_fields = vec!["product_id=p".into(), "title=T".into()];
        run(a, &client).await.unwrap();
    }

    #[tokio::test]
    async fn an_error_status_fails_with_the_apis_message() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_json(
                json!({"error": {"code": "not_found", "message": "No such product."}}),
            ))
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), None, false).unwrap();
        let err = run(args("products/acct/nope"), &client).await.unwrap_err();
        assert!(err.contains("No such product. (not_found, HTTP 404)"));
    }
}
