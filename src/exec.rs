//! `source-coop exec`: run any S3 tool (the AWS CLI, s5cmd, rclone, an SDK
//! script) as the signed-in user, with credentials and the data proxy's
//! endpoint in its environment, as `aws-vault exec` does for AWS.

use crate::sts::Credentials;
use std::process::Command;

/// The environment `command` runs with: the credentials, where they expire,
/// and the proxy as the S3 endpoint under the names the common tools read.
/// A region is only given when none is set, as the proxy ignores it but
/// signing needs one.
pub fn vars(creds: &Credentials, proxy_url: &str, region_set: bool) -> Vec<(&'static str, String)> {
    let endpoint = proxy_url.trim_end_matches('/').to_string();
    let mut vars = vec![
        ("AWS_ACCESS_KEY_ID", creds.access_key_id.clone()),
        ("AWS_SECRET_ACCESS_KEY", creds.secret_access_key.clone()),
        ("AWS_SESSION_TOKEN", creds.session_token.clone()),
        ("AWS_CREDENTIAL_EXPIRATION", creds.expiration.clone()),
        // The AWS CLI (v2.13+) and SDKs, for S3 alone: other services (STS,
        // KMS) a script calls keep their own endpoints.
        ("AWS_ENDPOINT_URL_S3", endpoint.clone()),
        // s5cmd.
        ("S3_ENDPOINT_URL", endpoint),
    ];
    if !region_set {
        vars.push(("AWS_REGION", "us-east-1".into()));
        vars.push(("AWS_DEFAULT_REGION", "us-east-1".into()));
    }
    vars
}

/// Run `command` with `vars` added to the environment, and leave with its
/// exit code. On Unix this process becomes the command, so signals (Ctrl+C)
/// and the exit status reach the shell as if it had been run directly.
pub fn run(command: &[String], vars: Vec<(&'static str, String)>) -> Result<(), String> {
    let (program, args) = command.split_first().ok_or("Name a command to run.")?;
    let mut cmd = Command::new(program);
    cmd.args(args).envs(vars);
    // A profile could hold other credentials or an endpoint; the env vars
    // already win, but naming one invites confusion over which applied. And
    // tools told to ignore configured endpoints would send the credentials
    // to AWS itself rather than the proxy.
    for name in [
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
    ] {
        cmd.env_remove(name);
    }
    let failed = |e: std::io::Error| format!("Couldn't run {program}: {e}");

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Only returns if the command couldn't be started.
        Err(failed(cmd.exec()))
    }
    #[cfg(not(unix))]
    {
        let status = cmd.status().map_err(failed)?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Credentials {
        Credentials {
            access_key_id: "AKID".into(),
            secret_access_key: "SECRET".into(),
            session_token: "TOKEN".into(),
            expiration: "2026-10-14T13:00:00Z".into(),
        }
    }

    #[test]
    fn the_command_gets_credentials_and_the_proxy_as_its_endpoint() {
        let vars = vars(&creds(), "https://data.staging.source.coop/", false);
        let get = |k: &str| {
            vars.iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("AWS_ACCESS_KEY_ID"), Some("AKID"));
        assert_eq!(get("AWS_SESSION_TOKEN"), Some("TOKEN"));
        assert_eq!(
            get("AWS_CREDENTIAL_EXPIRATION"),
            Some("2026-10-14T13:00:00Z")
        );
        for name in ["AWS_ENDPOINT_URL_S3", "S3_ENDPOINT_URL"] {
            assert_eq!(
                get(name),
                Some("https://data.staging.source.coop"),
                "{name}"
            );
        }
        assert_eq!(get("AWS_ENDPOINT_URL"), None, "only S3 goes to the proxy");
        assert_eq!(get("AWS_REGION"), Some("us-east-1"));
    }

    #[test]
    fn a_region_already_set_is_kept() {
        let vars = vars(&creds(), "https://data.source.coop", true);
        assert!(!vars.iter().any(|(name, _)| name.contains("REGION")));
    }

    #[test]
    fn a_missing_command_is_an_error() {
        assert_eq!(run(&[], vec![]), Err("Name a command to run.".to_string()));
    }
}
