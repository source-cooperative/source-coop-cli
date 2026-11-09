//! `source-coop exec`: run any S3 tool (the AWS CLI, s5cmd, GDAL, an SDK
//! script) with the data proxy as its endpoint, as `aws-vault exec` does for
//! AWS: as the signed-in user, with credentials in its environment, or, when
//! nobody is signed in, unsigned, which reads public products.

use crate::sts::Credentials;
use std::process::Command;

/// The region a command is given when it has none: the proxy ignores it, but
/// signing needs one. The same as `service-account usage` gives.
const REGION: &str = "us-west-2";

/// What `command` runs with: variables to set, and variables to remove.
#[derive(Debug, Default, PartialEq)]
pub struct Env {
    pub set: Vec<(&'static str, String)>,
    pub remove: Vec<&'static str>,
}

/// Removed whether signed or not. A profile could hold other credentials or
/// an endpoint; the env vars already win, but naming one invites confusion
/// over which applied. And tools told to ignore configured endpoints would
/// send requests to AWS itself rather than the proxy.
const ALWAYS_REMOVED: &[&str] = &[
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS",
];

/// Removed when running unsigned: every other way an AWS tool finds keys.
/// Keys the proxy doesn't know (anyone's real AWS keys) are refused even for
/// public data, and would be sent, if not the secret, to the proxy.
const OTHER_CREDENTIALS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_CREDENTIAL_EXPIRATION",
    "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_SESSION_NAME",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
];

/// A file that reads as empty, for the AWS config and credentials files.
#[cfg(unix)]
const EMPTY_FILE: &str = "/dev/null";
#[cfg(not(unix))]
const EMPTY_FILE: &str = "NUL";

/// The environment `command` runs with: the proxy as the S3 endpoint under
/// the names the common tools read, and either `creds` and where they expire
/// or, without them, each tool's switch to send requests unsigned. A region
/// is only given when none is set.
pub fn env(creds: Option<&Credentials>, proxy_url: &str, region_set: bool) -> Env {
    let endpoint = proxy_url.trim_end_matches('/').to_string();
    let mut set = vec![
        // The AWS CLI (v2.13+) and SDKs, for S3 alone: other services (STS,
        // KMS) a script calls keep their own endpoints.
        ("AWS_ENDPOINT_URL_S3", endpoint.clone()),
        // s5cmd.
        ("S3_ENDPOINT_URL", endpoint.clone()),
        // Rust `object_store` (obstore, Polars without boto3) before 0.13.2,
        // which doesn't read AWS_ENDPOINT_URL_S3; the AWS SDKs ignore it.
        ("AWS_ENDPOINT", endpoint),
    ];
    if let Ok(url) = url::Url::parse(proxy_url) {
        let http = url.scheme() == "http";
        if http {
            // `object_store` refuses plain HTTP (a local proxy) without it.
            set.push(("AWS_ALLOW_HTTP", "true".into()));
        }
        // GDAL's /vsis3/ (QGIS, rasterio, geopandas), which reads no AWS
        // endpoint setting: a host without the scheme for GDAL before 3.11,
        // and paths rather than bucket subdomains.
        if let Some(host) = url.host_str() {
            let host = match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            set.push(("AWS_S3_ENDPOINT", host));
            set.push(("AWS_HTTPS", if http { "NO" } else { "YES" }.into()));
            set.push(("AWS_VIRTUAL_HOSTING", "FALSE".into()));
        }
    }
    if !region_set {
        set.push(("AWS_REGION", REGION.into()));
        set.push(("AWS_DEFAULT_REGION", REGION.into()));
    }
    let mut remove = ALWAYS_REMOVED.to_vec();
    match creds {
        Some(creds) => set.extend([
            ("AWS_ACCESS_KEY_ID", creds.access_key_id.clone()),
            ("AWS_SECRET_ACCESS_KEY", creds.secret_access_key.clone()),
            ("AWS_SESSION_TOKEN", creds.session_token.clone()),
            ("AWS_CREDENTIAL_EXPIRATION", creds.expiration.clone()),
        ]),
        None => {
            remove.extend(OTHER_CREDENTIALS);
            set.extend([
                // GDAL.
                ("AWS_NO_SIGN_REQUEST", "YES".into()),
                // `object_store`.
                ("AWS_SKIP_SIGNATURE", "true".into()),
                // Keys in ~/.aws, or from an EC2 instance's role, would sign.
                ("AWS_SHARED_CREDENTIALS_FILE", EMPTY_FILE.into()),
                ("AWS_CONFIG_FILE", EMPTY_FILE.into()),
                ("AWS_EC2_METADATA_DISABLED", "true".into()),
            ]);
        }
    }
    Env { set, remove }
}

/// For a command run unsigned, how to tell it so when no variable can: the
/// AWS CLI and s5cmd sign every request unless given `--no-sign-request`,
/// and fail without credentials. None when the command has the flag, or
/// isn't one of those.
pub fn unsigned_hint(command: &[String]) -> Option<String> {
    let (program, args) = command.split_first()?;
    let name = std::path::Path::new(program).file_stem()?.to_str()?;
    if !matches!(name, "aws" | "s5cmd") || args.iter().any(|a| a == "--no-sign-request") {
        return None;
    }
    let args: Vec<_> = args.iter().map(|a| quoted(a)).collect();
    Some(format!(
        "{name} needs --no-sign-request to run unsigned: \
         source-coop exec -- {program} --no-sign-request {}",
        args.join(" ")
    ))
}

/// `arg` as a shell would need it typed: in single quotes when it holds
/// anything but the characters that need none.
fn quoted(arg: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c);
    if !arg.is_empty() && arg.chars().all(plain) {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// Run `command` in `env`, and leave with its exit code. On Unix this
/// process becomes the command, so signals (Ctrl+C) and the exit status reach
/// the shell as if it had been run directly.
pub fn run(command: &[String], env: Env) -> Result<(), String> {
    let (program, args) = command.split_first().ok_or("Name a command to run.")?;
    let mut cmd = Command::new(program);
    cmd.args(args);
    for name in env.remove {
        cmd.env_remove(name);
    }
    cmd.envs(env.set);
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

    fn get<'a>(env: &'a Env, name: &str) -> Option<&'a str> {
        env.set
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn the_command_gets_credentials_and_the_proxy_as_its_endpoint() {
        let env = env(Some(&creds()), "https://data.staging.source.coop/", false);
        assert_eq!(get(&env, "AWS_ACCESS_KEY_ID"), Some("AKID"));
        assert_eq!(get(&env, "AWS_SECRET_ACCESS_KEY"), Some("SECRET"));
        assert_eq!(get(&env, "AWS_SESSION_TOKEN"), Some("TOKEN"));
        assert_eq!(
            get(&env, "AWS_CREDENTIAL_EXPIRATION"),
            Some("2026-10-14T13:00:00Z")
        );
        for name in ["AWS_ENDPOINT_URL_S3", "S3_ENDPOINT_URL", "AWS_ENDPOINT"] {
            assert_eq!(
                get(&env, name),
                Some("https://data.staging.source.coop"),
                "{name}"
            );
        }
        assert_eq!(
            get(&env, "AWS_ENDPOINT_URL"),
            None,
            "only S3 goes to the proxy"
        );
        assert_eq!(
            get(&env, "AWS_S3_ENDPOINT"),
            Some("data.staging.source.coop")
        );
        assert_eq!(get(&env, "AWS_HTTPS"), Some("YES"));
        assert_eq!(get(&env, "AWS_VIRTUAL_HOSTING"), Some("FALSE"));
        assert_eq!(get(&env, "AWS_ALLOW_HTTP"), None);
        assert_eq!(get(&env, "AWS_REGION"), Some("us-west-2"));
        assert_eq!(get(&env, "AWS_DEFAULT_REGION"), Some("us-west-2"));
        // Signed: nothing says to skip signing, and only profiles go.
        for name in [
            "AWS_NO_SIGN_REQUEST",
            "AWS_SKIP_SIGNATURE",
            "AWS_CONFIG_FILE",
        ] {
            assert_eq!(get(&env, name), None, "{name}");
        }
        assert_eq!(env.remove, ALWAYS_REMOVED);
    }

    #[test]
    fn without_credentials_the_command_runs_unsigned_and_ignores_other_keys() {
        let env = env(None, "https://data.source.coop", false);
        assert_eq!(
            get(&env, "AWS_ENDPOINT_URL_S3"),
            Some("https://data.source.coop")
        );
        assert_eq!(get(&env, "AWS_S3_ENDPOINT"), Some("data.source.coop"));
        assert_eq!(get(&env, "AWS_REGION"), Some("us-west-2"));
        assert_eq!(get(&env, "AWS_NO_SIGN_REQUEST"), Some("YES"));
        assert_eq!(get(&env, "AWS_SKIP_SIGNATURE"), Some("true"));
        assert_eq!(get(&env, "AWS_SHARED_CREDENTIALS_FILE"), Some(EMPTY_FILE));
        assert_eq!(get(&env, "AWS_CONFIG_FILE"), Some(EMPTY_FILE));
        assert_eq!(get(&env, "AWS_EC2_METADATA_DISABLED"), Some("true"));
        for name in [
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
        ] {
            assert_eq!(get(&env, name), None, "{name} isn't set");
            assert!(env.remove.contains(&name), "{name} is removed");
        }
        for name in ["AWS_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"] {
            assert!(env.remove.contains(&name), "{name} is removed");
        }
        // Nothing is both set and removed.
        assert!(env.set.iter().all(|(n, _)| !env.remove.contains(n)));
    }

    #[test]
    fn a_local_proxy_over_http_keeps_its_port() {
        let env = env(Some(&creds()), "http://localhost:9000", false);
        assert_eq!(get(&env, "AWS_S3_ENDPOINT"), Some("localhost:9000"));
        assert_eq!(get(&env, "AWS_HTTPS"), Some("NO"));
        assert_eq!(get(&env, "AWS_ALLOW_HTTP"), Some("true"));
    }

    #[test]
    fn a_region_already_set_is_kept() {
        for creds in [Some(creds()), None] {
            let env = env(creds.as_ref(), "https://data.source.coop", true);
            assert!(!env.set.iter().any(|(name, _)| name.contains("REGION")));
        }
    }

    #[test]
    fn the_aws_cli_and_s5cmd_are_told_to_add_no_sign_request() {
        let cmd = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        assert_eq!(
            unsigned_hint(&cmd("aws s3 ls s3://acct/p/")).as_deref(),
            Some(
                "aws needs --no-sign-request to run unsigned: \
                 source-coop exec -- aws --no-sign-request s3 ls s3://acct/p/"
            )
        );
        let s5cmd = vec![
            "/usr/local/bin/s5cmd".to_string(),
            "cp".into(),
            "s3://acct/p/*.parquet".into(),
            "it's here".into(),
        ];
        assert_eq!(
            unsigned_hint(&s5cmd).as_deref(),
            Some(
                "s5cmd needs --no-sign-request to run unsigned: source-coop exec -- \
                 /usr/local/bin/s5cmd --no-sign-request cp 's3://acct/p/*.parquet' 'it'\\''s here'"
            )
        );
        assert_eq!(
            unsigned_hint(&cmd("aws --no-sign-request s3 ls s3://acct/p/")),
            None
        );
        assert_eq!(unsigned_hint(&cmd("gdalinfo /vsis3/acct/p/a.tif")), None);
    }

    #[test]
    fn a_missing_command_is_an_error() {
        assert_eq!(
            run(&[], Env::default()),
            Err("Name a command to run.".to_string())
        );
    }
}
