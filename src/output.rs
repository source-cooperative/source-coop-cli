use crate::sts::Credentials;

/// Print a command's `--json` output: one document on stdout and nothing
/// else there (see AGENTS.md, "JSON output").
pub fn json(value: &impl serde::Serialize) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("JSON output serializes")
    );
}

/// Print credentials in AWS credential_process JSON format.
pub fn print_credential_process(creds: &Credentials) {
    let json = serde_json::json!({
        "Version": 1,
        "AccessKeyId": creds.access_key_id,
        "SecretAccessKey": creds.secret_access_key,
        "SessionToken": creds.session_token,
        "Expiration": creds.expiration,
    });
    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

/// Print credentials as shell export statements.
pub fn print_env(creds: &Credentials) {
    println!("export AWS_ACCESS_KEY_ID={}", creds.access_key_id);
    println!("export AWS_SECRET_ACCESS_KEY={}", creds.secret_access_key);
    println!("export AWS_SESSION_TOKEN={}", creds.session_token);
}

/// Print credentials as an AWS credentials-file (INI) profile,
/// suitable for appending to ~/.aws/credentials.
pub fn print_aws_credentials(creds: &Credentials, profile: &str) {
    println!("[{profile}]");
    println!("# expires {}", creds.expiration);
    println!("aws_access_key_id = {}", creds.access_key_id);
    println!("aws_secret_access_key = {}", creds.secret_access_key);
    println!("aws_session_token = {}", creds.session_token);
}

/// The proxy's host, with its port when that isn't the scheme's own, and
/// whether it's served over HTTPS: DuckDB and GDAL take the endpoint without
/// a scheme.
fn endpoint(proxy_url: &str) -> Result<(String, bool), String> {
    let url =
        url::Url::parse(proxy_url).map_err(|e| format!("Invalid proxy URL {proxy_url}: {e}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| format!("Proxy URL {proxy_url} has no host"))?;
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    Ok((host, url.scheme() == "https"))
}

/// DuckDB SQL creating an S3 secret for the proxy. DuckDB ignores
/// `AWS_ENDPOINT_URL` and `endpoint_url` in `~/.aws/config`, so the secret
/// names the endpoint itself; the proxy is path-style only.
pub fn duckdb_secret(creds: &Credentials, proxy_url: &str) -> Result<String, String> {
    let (host, https) = endpoint(proxy_url)?;
    let quote = |s: &str| format!("'{}'", s.replace('\'', "''"));
    Ok(format!(
        "-- expires {}\n\
         CREATE OR REPLACE SECRET source_coop (\n    \
         TYPE s3,\n    \
         KEY_ID {},\n    \
         SECRET {},\n    \
         SESSION_TOKEN {},\n    \
         ENDPOINT {},\n    \
         URL_STYLE 'path',\n    \
         USE_SSL {https},\n    \
         REGION 'us-west-2'\n\
         );",
        creds.expiration,
        quote(&creds.access_key_id),
        quote(&creds.secret_access_key),
        quote(&creds.session_token),
        quote(&host),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(secret: &str) -> Credentials {
        Credentials {
            access_key_id: "ASIAKEY".into(),
            secret_access_key: secret.into(),
            session_token: "TOKEN".into(),
            expiration: "2026-07-13T12:00:00Z".into(),
        }
    }

    #[test]
    fn duckdb_secret_names_the_proxy_path_style() {
        let sql = duckdb_secret(&creds("SECRET"), "https://data.source.coop").unwrap();
        assert_eq!(
            sql,
            "-- expires 2026-07-13T12:00:00Z\n\
             CREATE OR REPLACE SECRET source_coop (\n    \
             TYPE s3,\n    \
             KEY_ID 'ASIAKEY',\n    \
             SECRET 'SECRET',\n    \
             SESSION_TOKEN 'TOKEN',\n    \
             ENDPOINT 'data.source.coop',\n    \
             URL_STYLE 'path',\n    \
             USE_SSL true,\n    \
             REGION 'us-west-2'\n\
             );"
        );
    }

    #[test]
    fn duckdb_secret_keeps_the_port_and_turns_ssl_off_for_http() {
        let sql = duckdb_secret(&creds("SECRET"), "http://127.0.0.1:8080/").unwrap();
        assert!(sql.contains("ENDPOINT '127.0.0.1:8080',"), "{sql}");
        assert!(sql.contains("USE_SSL false,"), "{sql}");
    }

    #[test]
    fn duckdb_secret_escapes_quotes() {
        let sql = duckdb_secret(&creds("it's"), "https://data.source.coop").unwrap();
        assert!(sql.contains("SECRET 'it''s',"), "{sql}");
    }

    #[test]
    fn duckdb_secret_refuses_a_proxy_url_it_cannot_read() {
        assert!(duckdb_secret(&creds("SECRET"), "data.source.coop").is_err());
    }
}
