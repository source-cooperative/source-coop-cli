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

/// The exports that point a stock AWS SDK or the AWS CLI at the data proxy:
/// S3 and STS only (a global `AWS_ENDPOINT_URL` would send IAM and every
/// other service there too), and a region, which the Rust and Go SDKs won't
/// run without and the proxy ignores.
pub fn endpoint_env(proxy: &str) -> [String; 3] {
    let proxy = proxy.trim_end_matches('/');
    [
        "export AWS_REGION=us-west-2".to_string(),
        format!("export AWS_ENDPOINT_URL_S3={proxy}"),
        format!("export AWS_ENDPOINT_URL_STS={proxy}/.sts"),
    ]
}

/// Credentials as shell export statements, with the proxy's endpoints.
fn env(creds: &Credentials, proxy: &str) -> String {
    let mut lines = vec![
        format!("export AWS_ACCESS_KEY_ID={}", creds.access_key_id),
        format!("export AWS_SECRET_ACCESS_KEY={}", creds.secret_access_key),
        format!("export AWS_SESSION_TOKEN={}", creds.session_token),
    ];
    lines.extend(endpoint_env(proxy));
    lines.join("\n")
}

/// Print credentials as shell export statements, with the proxy's endpoints.
pub fn print_env(creds: &Credentials, proxy: &str) {
    println!("{}", env(creds, proxy));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_exports_credentials_and_the_proxy_s_endpoints() {
        let creds = Credentials {
            access_key_id: "AKID".into(),
            secret_access_key: "SECRET".into(),
            session_token: "TOKEN".into(),
            expiration: "2026-07-13T12:00:00Z".into(),
        };
        let want = "export AWS_ACCESS_KEY_ID=AKID\n\
                    export AWS_SECRET_ACCESS_KEY=SECRET\n\
                    export AWS_SESSION_TOKEN=TOKEN\n\
                    export AWS_REGION=us-west-2\n\
                    export AWS_ENDPOINT_URL_S3=https://data.source.coop\n\
                    export AWS_ENDPOINT_URL_STS=https://data.source.coop/.sts";
        assert_eq!(env(&creds, "https://data.source.coop"), want);
        // A trailing slash on --proxy-url doesn't double up before /.sts.
        assert_eq!(env(&creds, "https://data.source.coop/"), want);
    }
}
