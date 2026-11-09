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

/// Shell `export` statements for GDAL's `/vsis3/`. GDAL ignores
/// `AWS_ENDPOINT_URL`, so they name the proxy in its own variables; the proxy
/// is path-style only. Values are single-quoted, so `eval` reads them whole.
pub fn gdal_env(creds: &Credentials, proxy_url: &str) -> Result<String, String> {
    let (host, https) = endpoint(proxy_url)?;
    let vars = [
        ("AWS_ACCESS_KEY_ID", creds.access_key_id.as_str()),
        ("AWS_SECRET_ACCESS_KEY", &creds.secret_access_key),
        ("AWS_SESSION_TOKEN", &creds.session_token),
        ("AWS_S3_ENDPOINT", &host),
        ("AWS_VIRTUAL_HOSTING", "FALSE"),
        ("AWS_HTTPS", if https { "YES" } else { "NO" }),
        ("AWS_REGION", "us-west-2"),
    ];
    let lines: Vec<_> = vars
        .iter()
        .map(|(name, value)| format!("export {name}='{}'", value.replace('\'', r"'\''")))
        .collect();
    Ok(lines.join("\n"))
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
    fn gdal_env_names_the_proxy_path_style() {
        let env = gdal_env(&creds("SECRET"), "https://data.source.coop").unwrap();
        assert_eq!(
            env,
            "export AWS_ACCESS_KEY_ID='ASIAKEY'\n\
             export AWS_SECRET_ACCESS_KEY='SECRET'\n\
             export AWS_SESSION_TOKEN='TOKEN'\n\
             export AWS_S3_ENDPOINT='data.source.coop'\n\
             export AWS_VIRTUAL_HOSTING='FALSE'\n\
             export AWS_HTTPS='YES'\n\
             export AWS_REGION='us-west-2'"
        );
    }

    #[test]
    fn gdal_env_keeps_the_port_and_turns_https_off_for_http() {
        let env = gdal_env(&creds("SECRET"), "http://127.0.0.1:8080/").unwrap();
        assert!(
            env.contains("export AWS_S3_ENDPOINT='127.0.0.1:8080'\n"),
            "{env}"
        );
        assert!(env.contains("export AWS_HTTPS='NO'\n"), "{env}");
    }

    #[test]
    fn gdal_env_escapes_quotes() {
        let env = gdal_env(&creds("it's"), "https://data.source.coop").unwrap();
        assert!(
            env.contains(r"export AWS_SECRET_ACCESS_KEY='it'\''s'"),
            "{env}"
        );
    }

    #[test]
    fn gdal_env_refuses_a_proxy_url_it_cannot_read() {
        assert!(gdal_env(&creds("SECRET"), "data.source.coop").is_err());
    }
}
