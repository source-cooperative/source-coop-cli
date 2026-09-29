use quick_xml::de::from_str as xml_from_str;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: String,
}

/// Build the STS endpoint URL from the proxy base. STS is served at the
/// proxy's `/.sts` path, never the root, so the path is set explicitly — a base
/// `proxy_url` (or any other path) always ends up targeting `/.sts`.
fn sts_url(proxy_url: &str) -> Result<url::Url, String> {
    let mut url = url::Url::parse(proxy_url).map_err(|e| format!("Invalid proxy URL: {e}"))?;
    url.set_path("/.sts");
    Ok(url)
}

/// A role as the ARN a stock SDK sends in `AWS_ROLE_ARN`: a bare name such as
/// `ReadOnly` becomes `arn:aws:iam::000000000000:role/ReadOnly`. The proxy
/// ignores the account segment, because the token names the account; an ARN
/// passes through unchanged.
fn role_arn(role: &str) -> String {
    if role.starts_with("arn:") {
        role.to_string()
    } else {
        format!("arn:aws:iam::000000000000:role/{role}")
    }
}

/// Call the proxy's STS AssumeRoleWithWebIdentity endpoint. The token travels
/// in a form-encoded POST body, never the URL: URLs end up in access logs, and
/// the proxy refuses an API key sent in one.
pub async fn assume_role(
    proxy_url: &str,
    role: &str,
    web_identity_token: &str,
    duration_seconds: Option<u64>,
    verbose: bool,
) -> Result<Credentials, String> {
    let url = sts_url(proxy_url)?;
    let role_arn = role_arn(role);
    let duration = duration_seconds.map(|d| d.to_string());
    let mut form = vec![
        ("Action", "AssumeRoleWithWebIdentity"),
        ("RoleArn", role_arn.as_str()),
        ("WebIdentityToken", web_identity_token),
    ];
    if let Some(duration) = &duration {
        form.push(("DurationSeconds", duration));
    }

    if verbose {
        eprintln!("[verbose] POST {url}");
        eprintln!("[verbose]   RoleArn={role_arn}");
    }

    let resp = reqwest::Client::new()
        .post(url)
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("STS request failed: {e}"))?;

    let status = resp.status();
    let request_id = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if verbose {
        eprintln!("[verbose] Response: {status}");
    }

    let body = resp
        .text()
        .await
        .map_err(|e| format!("Failed to read STS response: {e}"))?;

    if !status.is_success() {
        if verbose {
            eprintln!("[verbose] Response body:\n{body}");
        }
        let mut error = match xml_from_str::<StsErrorResponse>(&body) {
            Ok(err) => format!("STS error ({}): {}", err.error.code, err.error.message),
            Err(_) => format!("STS request failed (HTTP {status}): {body}"),
        };
        // Support finds the proxy's log lines by request id. A refused API key
        // carries it in the message; other failures carry it only in a header.
        if let Some(id) = request_id.filter(|id| !error.contains(id.as_str())) {
            error.push_str(&format!(" (request id {id})"));
        }
        return Err(error);
    }

    let parsed: StsResponse =
        xml_from_str(&body).map_err(|e| format!("Failed to parse STS response XML: {e}"))?;

    let creds = parsed.result.credentials;
    if verbose {
        // The success body holds the secret key and session token; don't echo it.
        eprintln!(
            "[verbose] Received credentials: AccessKeyId={}, Expiration={}",
            creds.access_key_id, creds.expiration
        );
    }
    Ok(Credentials {
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: creds.session_token,
        expiration: creds.expiration,
    })
}

// XML deserialization types matching the STS response format

#[derive(Debug, Deserialize)]
#[serde(rename = "AssumeRoleWithWebIdentityResponse")]
struct StsResponse {
    #[serde(rename = "AssumeRoleWithWebIdentityResult")]
    result: StsResult,
}

#[derive(Debug, Deserialize)]
struct StsResult {
    #[serde(rename = "Credentials")]
    credentials: StsCredentials,
}

#[derive(Debug, Deserialize)]
struct StsCredentials {
    #[serde(rename = "AccessKeyId")]
    access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: String,
    #[serde(rename = "SessionToken")]
    session_token: String,
    #[serde(rename = "Expiration")]
    expiration: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "ErrorResponse")]
struct StsErrorResponse {
    #[serde(rename = "Error")]
    error: StsError,
}

#[derive(Debug, Deserialize)]
struct StsError {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn targets_sts_path_from_base() {
        assert_eq!(
            sts_url("https://data.staging.source.coop")
                .unwrap()
                .as_str(),
            "https://data.staging.source.coop/.sts"
        );
    }

    #[test]
    fn always_targets_sts_regardless_of_input_path() {
        // trailing slash, an unrelated path, and an already-present /.sts all
        // normalize to /.sts — auth requests never hit the proxy root.
        for input in [
            "https://x.test",
            "https://x.test/",
            "https://x.test/other",
            "https://x.test/.sts",
        ] {
            assert_eq!(sts_url(input).unwrap().path(), "/.sts", "input: {input}");
        }
    }

    #[test]
    fn expands_bare_role_names_to_arns() {
        let default = "arn:aws:iam::000000000000:role/_default";
        assert_eq!(role_arn("_default"), default);
        assert_eq!(role_arn(default), default);
        assert_eq!(
            role_arn("ReadOnly"),
            "arn:aws:iam::000000000000:role/ReadOnly"
        );
    }

    /// The error `assume_role` returns when the proxy answers `status` with
    /// `body`, tagged with a request id the way the proxy tags every response.
    async fn sts_error(status: u16, body: &str) -> String {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/.sts"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("x-request-id", "a40cee47fef1c4b4")
                    .set_body_string(body),
            )
            .mount(&server)
            .await;
        assume_role(&server.uri(), "_default", "sck_x", None, false)
            .await
            .unwrap_err()
    }

    #[tokio::test]
    async fn surfaces_the_proxy_error_verbatim() {
        // The proxy's refusal of an API key, byte for byte.
        let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ErrorResponse><Error>\
            <Code>InvalidIdentityToken</Code>\
            <Message>API key was not accepted (request id a40cee47fef1c4b4)</Message>\
            </Error></ErrorResponse>";
        assert_eq!(
            sts_error(400, body).await,
            "STS error (InvalidIdentityToken): API key was not accepted (request id a40cee47fef1c4b4)"
        );
    }

    #[tokio::test]
    async fn adds_the_request_id_when_the_message_lacks_it() {
        let body = "<ErrorResponse><Error><Code>InternalError</Code>\
            <Message>internal error</Message></Error></ErrorResponse>";
        assert_eq!(
            sts_error(500, body).await,
            "STS error (InternalError): internal error (request id a40cee47fef1c4b4)"
        );
    }
}
