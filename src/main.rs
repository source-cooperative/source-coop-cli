mod cache;
mod oidc;
mod output;
mod sts;

use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(feature = "staging")]
mod defaults {
    pub const ISSUER: &str = "https://auth.staging.source.coop";
    pub const CLIENT_ID: &str = "a79c9537-be78-454a-9ea1-b96a1be811cc";
    pub const PROXY_URL: &str = "https://data.staging.source.coop";
    pub const ROLE_ARN: &str = "_default";
}

#[cfg(not(feature = "staging"))]
mod defaults {
    pub const ISSUER: &str = "https://auth.source.coop";
    pub const CLIENT_ID: &str = "197e20e7-d52d-4d1d-9e54-4b73a342034b";
    pub const PROXY_URL: &str = "https://data.source.coop";
    pub const ROLE_ARN: &str = "_default";
}

/// Parse a duration into seconds. Accepts a bare number (seconds) or a value
/// with a unit suffix: `s`, `m`, `h`, `d`. The API is always called in seconds.
fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let err = || format!("invalid duration '{s}' (use e.g. 3600, 90s, 5m, 12h, 1d)");
    let (digits, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86400),
        Some(c) if c.is_ascii_digit() => (s, 1),
        _ => return Err(err()),
    };
    digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .ok_or_else(err)
}

#[derive(Parser)]
#[command(name = "source-coop", about = "Source Cooperative CLI", version)]
struct Cli {
    /// Enable verbose output to see HTTP requests and responses
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate via OIDC and obtain temporary S3 credentials
    Login(LoginArgs),
    /// Output credentials as credential_process JSON, shell env vars, or an
    /// AWS credentials-file profile: those cached by `login` (refreshed first
    /// if expired), or ones exchanged for a service account's API key
    Creds(CredsArgs),
}

#[derive(Parser)]
struct LoginArgs {
    /// OIDC issuer URL
    #[arg(long, env = "SOURCE_OIDC_ISSUER", default_value = defaults::ISSUER)]
    issuer: String,

    /// OAuth2 client ID
    #[arg(long, env = "SOURCE_OIDC_CLIENT_ID", default_value = defaults::CLIENT_ID)]
    client_id: String,

    /// S3 proxy URL for STS
    #[arg(long, env = "SOURCE_PROXY_URL", default_value = defaults::PROXY_URL)]
    proxy_url: String,

    /// Role to assume: a role name such as `ReadOnly`, or a full role ARN
    #[arg(long, env = "SOURCE_ROLE_ARN", default_value = defaults::ROLE_ARN)]
    role_arn: String,

    /// Output format
    #[arg(long, default_value = "credential-process")]
    format: OutputFormat,

    /// Session duration, e.g. `3600`, `90s`, `5m`, `12h`, `1d` (bare number = seconds)
    #[arg(long, value_parser = parse_duration)]
    duration: Option<u64>,

    /// OAuth2 scopes (`offline_access` lets `creds` refresh expired credentials
    /// without another browser login)
    #[arg(long, default_value = "openid offline_access")]
    scope: String,

    /// Local callback port (0 for random available port)
    #[arg(long, default_value = "0")]
    port: u16,

    /// Skip caching credentials (just print to stdout)
    #[arg(long)]
    no_cache: bool,

    /// Profile name for --format aws-credentials
    #[arg(long, default_value = "source-coop")]
    profile: String,
}

#[derive(Parser)]
struct CredsArgs {
    /// Role to read cached credentials for, or with an API key to assume: a
    /// role name such as `ReadOnly`, or a full role ARN
    #[arg(long, env = "SOURCE_ROLE_ARN", default_value = defaults::ROLE_ARN)]
    role_arn: String,

    /// File holding a service account's API key (`sck_…`), exchanged for
    /// credentials without a browser. SOURCE_API_KEY may hold the key itself
    /// instead; this file wins if both are set
    #[arg(long, env = "SOURCE_API_KEY_FILE")]
    api_key_file: Option<PathBuf>,

    /// S3 proxy URL for an API key's STS exchange (`login` records its own)
    #[arg(long, env = "SOURCE_PROXY_URL", default_value = defaults::PROXY_URL)]
    proxy_url: String,

    /// Session duration for an API key's exchange, e.g. `3600`, `90s`, `5m`,
    /// `12h`, `1d` (bare number = seconds)
    #[arg(long, value_parser = parse_duration)]
    duration: Option<u64>,

    /// Output format
    #[arg(long, default_value = "credential-process")]
    format: OutputFormat,

    /// Profile name for --format aws-credentials
    #[arg(long, default_value = "source-coop")]
    profile: String,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    /// AWS credential_process JSON format
    CredentialProcess,
    /// Shell export statements
    Env,
    /// AWS credentials file (INI) profile
    AwsCredentials,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let verbose = cli.verbose;

    match cli.command {
        Commands::Login(args) => {
            if let Err(e) = run_login(args, verbose).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::Creds(args) => {
            if let Err(e) = run_creds(args, verbose).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }
}

async fn run_login(args: LoginArgs, verbose: bool) -> Result<(), String> {
    // 1. OIDC Discovery
    eprintln!("Discovering OIDC endpoints...");
    let endpoints = oidc::discover(&args.issuer, verbose).await?;

    // 2. Browser-based OIDC login
    let tokens = oidc::login(&endpoints, &args.client_id, &args.scope, args.port, verbose).await?;
    eprintln!("Authentication successful.");

    // 3. STS credential exchange
    if verbose {
        eprintln!("[verbose] Assuming role: {}", args.role_arn);
    }
    eprintln!("Exchanging token for credentials...");
    let creds = sts::assume_role(
        &args.proxy_url,
        &args.role_arn,
        &tokens.id_token,
        args.duration,
        verbose,
    )
    .await?;

    // 4. Cache, or print to stdout only with --no-cache (don't leak creds by default).
    if args.no_cache {
        eprintln!("Skipping credential cache (--no-cache)");
        match args.format {
            OutputFormat::CredentialProcess => output::print_credential_process(&creds),
            OutputFormat::Env => output::print_env(&creds),
            OutputFormat::AwsCredentials => output::print_aws_credentials(&creds, &args.profile),
        }
    } else {
        if tokens.refresh_token.is_none() {
            eprintln!(
                "No refresh token issued; run 'source-coop login' again when credentials expire."
            );
        }
        let entry = cache::CacheEntry {
            creds,
            refresh: tokens
                .refresh_token
                .map(|refresh_token| cache::RefreshState {
                    refresh_token,
                    token_endpoint: endpoints.token_endpoint,
                    client_id: args.client_id,
                    proxy_url: args.proxy_url,
                    duration: args.duration,
                }),
        };
        let location = cache::write_credentials(&args.role_arn, &entry)?;
        eprintln!("Credentials cached to {location}");
        eprintln!("Run 'source-coop creds' to print them.");
    }

    Ok(())
}

async fn run_creds(args: CredsArgs, verbose: bool) -> Result<(), String> {
    let api_key = api_key(
        args.api_key_file.as_deref(),
        std::env::var("SOURCE_API_KEY").ok(),
    )?;
    let creds = match api_key {
        Some(key) => {
            let slot = cache::api_key_slot(&key, &args.role_arn);
            // One exchange at a time per key and role: callers started together
            // (SDK threads, a batch of jobs) then read what the first one cached
            // instead of each spending an exchange against the proxy's
            // per-address rate limit.
            let _lock = cache::lock(&slot).ok();
            let load = || cache::read_credentials(&slot);
            let save = |e: &cache::CacheEntry| cache::write_credentials(&slot, e).map(drop);
            key_credentials(&args, &key, verbose, load, save).await?
        }
        None => login_credentials(&args, verbose).await?,
    };

    match args.format {
        OutputFormat::CredentialProcess => output::print_credential_process(&creds),
        OutputFormat::Env => output::print_env(&creds),
        OutputFormat::AwsCredentials => output::print_aws_credentials(&creds, &args.profile),
    }
    Ok(())
}

/// The API key to exchange, if one is configured: the contents of
/// `--api-key-file`, which wins, else `env` (SOURCE_API_KEY). No flag takes the
/// key itself, because other users on the machine can read a command line.
fn api_key(file: Option<&Path>, env: Option<String>) -> Result<Option<String>, String> {
    let (raw, source) = match (file, env) {
        (Some(path), _) => {
            let raw = fs::read_to_string(path)
                .map_err(|e| format!("Failed to read API key file {}: {e}", path.display()))?;
            (raw, path.display().to_string())
        }
        (None, Some(key)) => (key, "SOURCE_API_KEY".to_string()),
        (None, None) => return Ok(None),
    };
    let key = parse_api_key(&raw).ok_or_else(|| {
        format!("{source} does not hold a Source API key (sck_ followed by 43 characters)")
    })?;
    Ok(Some(key.to_string()))
}

/// The key, trimmed because a key file ends in a newline, if it has an API
/// key's fixed shape: `sck_` and 43 base64url characters. Anything else, such
/// as a JWT or the wrong file's contents, is never sent as a key.
fn parse_api_key(raw: &str) -> Option<&str> {
    let key = raw.trim();
    let is_key = key.len() == 47
        && key.starts_with("sck_")
        && key[4..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    is_key.then_some(key)
}

/// Credentials for a service account's API key: the cached ones until they are
/// due for refresh, otherwise a new exchange, cached for the next call. The
/// cache only saves exchanges, so one that can't be read or written costs an
/// exchange instead of failing the call: a daemon holding a key keeps getting
/// credentials.
async fn key_credentials(
    args: &CredsArgs,
    key: &str,
    verbose: bool,
    load: impl FnOnce() -> Result<Option<cache::CacheEntry>, String>,
    save: impl FnOnce(&cache::CacheEntry) -> Result<(), String>,
) -> Result<sts::Credentials, String> {
    let cached = load().ok().flatten().map(|entry| entry.creds);
    if let Some(creds) = cached
        .as_ref()
        .filter(|c| cache::needs_refresh(c, args.duration) == Ok(false))
    {
        return Ok(creds.clone());
    }
    let exchanged =
        sts::assume_role(&args.proxy_url, &args.role_arn, key, args.duration, verbose).await;
    let entry = cache::CacheEntry {
        creds: match exchanged {
            Ok(creds) => creds,
            Err(e) => return cached.and_then(|c| until_expiry(c, &e)).ok_or(e),
        },
        refresh: None,
    };
    if let Err(e) = save(&entry) {
        eprintln!("Warning: credentials were not cached: {e}");
    }
    Ok(entry.creds)
}

/// The cached credentials after refreshing them early failed with `error`, if
/// they are still valid. An SDK keeps its credentials when an advisory refresh
/// fails, and so does this: refreshing early never ends a session sooner.
fn until_expiry(cached: sts::Credentials, error: &str) -> Option<sts::Credentials> {
    if cache::is_expired(&cached) != Ok(false) {
        return None;
    }
    eprintln!("Warning: {error}; using cached credentials until they expire");
    Some(cached)
}

/// `login`'s cached credentials for the role, refreshed first when due.
async fn login_credentials(args: &CredsArgs, verbose: bool) -> Result<sts::Credentials, String> {
    const NOT_FOUND: &str = "No cached credentials found. Run 'source-coop login' first.";
    // Only a refresh token replaces credentials without a person, so without
    // one they are served until they expire rather than refreshed early.
    let due = |e: &cache::CacheEntry| match &e.refresh {
        Some(state) => cache::needs_refresh(&e.creds, state.duration),
        None => cache::is_expired(&e.creds),
    };
    let mut entry = cache::read_credentials(&args.role_arn)?.ok_or(NOT_FOUND)?;

    if due(&entry)? {
        if entry.refresh.is_none() {
            return Err(
                "Cached credentials have expired. Run 'source-coop login' to refresh.".to_string(),
            );
        }
        // Re-read under the lock: another process may have refreshed already.
        let _lock = cache::lock(&args.role_arn)?;
        entry = cache::read_credentials(&args.role_arn)?.ok_or(NOT_FOUND)?;
        if due(&entry)? {
            let cached = entry.creds.clone();
            let save =
                |e: &cache::CacheEntry| cache::write_credentials(&args.role_arn, e).map(drop);
            entry = match refresh(&args.role_arn, entry, verbose, save).await {
                Ok(entry) => entry,
                Err(e) => {
                    return until_expiry(cached, &format!("refresh failed ({e})")).ok_or_else(|| {
                        format!("Cached credentials have expired and refresh failed ({e}). Run 'source-coop login'.")
                    })
                }
            };
        }
    }
    Ok(entry.creds)
}

/// Trade the cached refresh token for a new id_token, exchange that for new STS
/// credentials, and cache the result (including the rotated refresh token) via `save`.
async fn refresh(
    role_arn: &str,
    mut entry: cache::CacheEntry,
    verbose: bool,
    mut save: impl FnMut(&cache::CacheEntry) -> Result<(), String>,
) -> Result<cache::CacheEntry, String> {
    let state = entry.refresh.as_mut().ok_or("No refresh token cached")?;
    let tokens = oidc::refresh(
        &state.token_endpoint,
        &state.client_id,
        &state.refresh_token,
        verbose,
    )
    .await?;
    if let Some(rotated) = tokens.refresh_token {
        // The old refresh token is now spent; persist the new one before STS can fail.
        state.refresh_token = rotated;
        save(&entry)?;
    }
    let state = entry.refresh.as_ref().unwrap();
    entry.creds = sts::assume_role(
        &state.proxy_url,
        role_arn,
        &tokens.id_token,
        state.duration,
        verbose,
    )
    .await?;
    save(&entry)?;
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use wiremock::matchers::{body_string_contains, header, method, path, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const STS_OK: &str = "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult>\
        <Credentials><AccessKeyId>NEWKEY</AccessKeyId><SecretAccessKey>NEWSECRET</SecretAccessKey>\
        <SessionToken>NEWSESSION</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration>\
        </Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>";

    /// An expired cache entry whose refresh state points at the mock server.
    fn expired_entry(server: &MockServer) -> cache::CacheEntry {
        cache::CacheEntry {
            creds: sts::Credentials {
                access_key_id: "OLDKEY".into(),
                secret_access_key: "OLDSECRET".into(),
                session_token: "OLDSESSION".into(),
                expiration: "2020-01-01T00:00:00Z".into(),
            },
            refresh: Some(cache::RefreshState {
                refresh_token: "old-rt".into(),
                token_endpoint: format!("{}/oauth2/token", server.uri()),
                client_id: "cid".into(),
                proxy_url: server.uri(),
                duration: Some(3600),
            }),
        }
    }

    /// Mock Ory's token endpoint: only a refresh grant carrying `old-rt` matches.
    async fn mock_token(server: &MockServer, status: u16, body: serde_json::Value) {
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=old-rt"))
            .and(body_string_contains("client_id=cid"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .expect(1)
            .mount(server)
            .await;
    }

    /// Mock the proxy's STS endpoint: only the freshly issued id_token, sent in
    /// the form body rather than the URL, matches.
    async fn mock_sts(server: &MockServer, status: u16, body: &str) {
        Mock::given(method("POST"))
            .and(path("/.sts"))
            .and(query_param_is_missing("WebIdentityToken"))
            .and(body_string_contains("WebIdentityToken=new-id-token"))
            .and(body_string_contains("DurationSeconds=3600"))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .expect(1)
            .mount(server)
            .await;
    }

    /// Run `refresh` with a `save` that records each saved entry's
    /// (refresh token, access key) so tests can check what was persisted when.
    async fn run_refresh(
        server: &MockServer,
    ) -> (Result<cache::CacheEntry, String>, Vec<(String, String)>) {
        let mut saved = vec![];
        let result = refresh("role", expired_entry(server), false, |e| {
            let rt = e.refresh.as_ref().unwrap().refresh_token.clone();
            saved.push((rt, e.creds.access_key_id.clone()));
            Ok(())
        })
        .await;
        (result, saved)
    }

    fn saved(rt: &str, key: &str) -> (String, String) {
        (rt.into(), key.into())
    }

    #[tokio::test]
    async fn refresh_rotates_token_and_fetches_new_credentials() {
        let server = MockServer::start().await;
        let tokens = serde_json::json!({"id_token": "new-id-token", "refresh_token": "new-rt"});
        mock_token(&server, 200, tokens).await;
        mock_sts(&server, 200, STS_OK).await;

        let (result, saved_entries) = run_refresh(&server).await;
        let entry = result.unwrap();

        assert_eq!(entry.creds.access_key_id, "NEWKEY");
        assert!(!cache::is_expired(&entry.creds).unwrap());
        assert_eq!(entry.refresh.unwrap().refresh_token, "new-rt");
        // Rotated token persisted first (with old creds), then the new creds.
        assert_eq!(
            saved_entries,
            [saved("new-rt", "OLDKEY"), saved("new-rt", "NEWKEY")]
        );
    }

    #[tokio::test]
    async fn refresh_keeps_token_when_not_rotated() {
        let server = MockServer::start().await;
        mock_token(
            &server,
            200,
            serde_json::json!({"id_token": "new-id-token"}),
        )
        .await;
        mock_sts(&server, 200, STS_OK).await;

        let (result, saved_entries) = run_refresh(&server).await;

        assert_eq!(result.unwrap().refresh.unwrap().refresh_token, "old-rt");
        assert_eq!(saved_entries, [saved("old-rt", "NEWKEY")]);
    }

    #[tokio::test]
    async fn refresh_persists_rotated_token_even_if_sts_fails() {
        let server = MockServer::start().await;
        let tokens = serde_json::json!({"id_token": "new-id-token", "refresh_token": "new-rt"});
        mock_token(&server, 200, tokens).await;
        let sts_err = "<ErrorResponse><Error><Code>AccessDenied</Code>\
            <Message>nope</Message></Error></ErrorResponse>";
        mock_sts(&server, 403, sts_err).await;

        let (result, saved_entries) = run_refresh(&server).await;

        assert!(result.err().unwrap().contains("AccessDenied"));
        // The spent token must not survive in the cache: the rotated one does.
        assert_eq!(saved_entries, [saved("new-rt", "OLDKEY")]);
    }

    #[tokio::test]
    async fn refresh_fails_cleanly_when_refresh_token_expired() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "error": "invalid_grant",
            "error_description": "The refresh token has expired."
        });
        mock_token(&server, 400, body).await;

        let (result, saved_entries) = run_refresh(&server).await;

        assert!(result.err().unwrap().contains("invalid_grant"));
        assert!(saved_entries.is_empty());
    }

    /// A throwaway key of the issued shape, built at run time so that secret
    /// scanners looking for `sck_` keys don't flag this file.
    fn test_key() -> String {
        format!("sck_{}", "k".repeat(43))
    }

    fn in_minutes(minutes: i64) -> String {
        (chrono::Utc::now() + chrono::Duration::minutes(minutes)).to_rfc3339()
    }

    fn cached(access_key_id: &str, expiration: &str) -> cache::CacheEntry {
        cache::CacheEntry {
            creds: sts::Credentials {
                access_key_id: access_key_id.into(),
                secret_access_key: "SECRET".into(),
                session_token: "SESSION".into(),
                expiration: expiration.into(),
            },
            refresh: None,
        }
    }

    /// Mock the proxy's STS endpoint for an API key: a form-encoded POST with
    /// exactly these parameters and nothing in the URL, the only way the proxy
    /// accepts a key.
    async fn mock_key_sts(server: &MockServer, expected_calls: u64) {
        let expected: HashMap<String, String> = HashMap::from([
            ("Action".into(), "AssumeRoleWithWebIdentity".into()),
            (
                "RoleArn".into(),
                "arn:aws:iam::000000000000:role/ReadOnly".into(),
            ),
            ("WebIdentityToken".into(), test_key()),
            ("DurationSeconds".into(), "900".into()),
        ]);
        Mock::given(method("POST"))
            .and(path("/.sts"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(move |req: &wiremock::Request| {
                let form: HashMap<String, String> = url::form_urlencoded::parse(&req.body)
                    .into_owned()
                    .collect();
                req.url.query().is_none() && form == expected
            })
            .respond_with(ResponseTemplate::new(200).set_body_string(STS_OK))
            .expect(expected_calls)
            .mount(server)
            .await;
    }

    /// Run `key_credentials` for the bare role `ReadOnly` against the mock
    /// proxy, with `load` and `save` answering as given; returns the result and
    /// the access key of each entry saved.
    async fn run_key(
        server: &MockServer,
        load: Result<Option<cache::CacheEntry>, String>,
        save: Result<(), String>,
    ) -> (Result<sts::Credentials, String>, Vec<String>) {
        let uri = server.uri();
        let args = CredsArgs::parse_from([
            "creds",
            "--role-arn",
            "ReadOnly",
            "--proxy-url",
            &uri,
            "--duration",
            "15m",
        ]);
        let mut saved = vec![];
        let result = key_credentials(
            &args,
            &test_key(),
            false,
            || load,
            |e| {
                saved.push(e.creds.access_key_id.clone());
                save
            },
        )
        .await;
        (result, saved)
    }

    #[tokio::test]
    async fn api_key_is_exchanged_again_before_credentials_expire() {
        let server = MockServer::start().await;
        mock_key_sts(&server, 1).await;

        // Five minutes left of the 15-minute session `run_key` asks for.
        let due = cached("OLDKEY", &in_minutes(5));
        let (result, saved) = run_key(&server, Ok(Some(due)), Ok(())).await;

        assert_eq!(result.unwrap().access_key_id, "NEWKEY");
        assert_eq!(saved, ["NEWKEY"]);
    }

    #[tokio::test]
    async fn failed_early_exchange_serves_cached_credentials_until_they_expire() {
        let server = MockServer::start().await; // answers every request 404

        let due = cached("OLDKEY", &in_minutes(5));
        let (result, _) = run_key(&server, Ok(Some(due)), Ok(())).await;
        assert_eq!(result.unwrap().access_key_id, "OLDKEY");

        let expired = cached("OLDKEY", "2020-01-01T00:00:00Z");
        let (result, _) = run_key(&server, Ok(Some(expired)), Ok(())).await;
        assert!(result.unwrap_err().contains("HTTP 404"));
    }

    #[tokio::test]
    async fn api_key_credentials_come_from_the_cache_while_fresh() {
        let server = MockServer::start().await;
        mock_key_sts(&server, 0).await;

        let fresh = cached("CACHEDKEY", "2099-01-01T00:00:00Z");
        let (result, saved) = run_key(&server, Ok(Some(fresh)), Ok(())).await;

        assert_eq!(result.unwrap().access_key_id, "CACHEDKEY");
        assert!(saved.is_empty());
    }

    #[tokio::test]
    async fn api_key_is_exchanged_even_when_the_cache_is_unusable() {
        let server = MockServer::start().await;
        mock_key_sts(&server, 1).await;

        let locked = "keychain is locked".to_string();
        let (result, _) = run_key(&server, Err(locked.clone()), Err(locked)).await;

        assert_eq!(result.unwrap().access_key_id, "NEWKEY");
    }

    #[test]
    fn only_a_key_shaped_token_is_sent_as_a_key() {
        let key = test_key();
        assert_eq!(parse_api_key(&format!("{key}\r\n")), Some(key.as_str()));
        for bad in [
            String::new(),
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln".to_string(),
            key[..46].to_string(),
            format!("{key}k"),
            key.replace("sck_", "SCK_"),
            format!("sck_{}!", "k".repeat(42)),
        ] {
            assert_eq!(parse_api_key(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn api_key_file_wins_over_env_and_errors_never_echo_a_key() {
        let (key, other) = (test_key(), format!("sck_{}", "o".repeat(43)));
        let file = std::env::temp_dir().join(format!("source-coop-key-{}", std::process::id()));
        fs::write(&file, format!("{key}\n")).unwrap();
        assert_eq!(api_key(Some(&file), Some(other.clone())), Ok(Some(key)));
        fs::remove_file(&file).unwrap();

        assert_eq!(api_key(None, Some(other.clone())), Ok(Some(other)));
        assert_eq!(api_key(None, None), Ok(None));
        let err = api_key(None, Some("sck_not-quite".into())).unwrap_err();
        assert!(
            err.starts_with("SOURCE_API_KEY") && !err.contains("not-quite"),
            "{err}"
        );
    }

    #[test]
    fn parses_units_and_bare_seconds() {
        assert_eq!(parse_duration("3600").unwrap(), 3600);
        assert_eq!(parse_duration("90s").unwrap(), 90);
        assert_eq!(parse_duration("5m").unwrap(), 300);
        assert_eq!(parse_duration("12h").unwrap(), 43200);
        assert_eq!(parse_duration("1d").unwrap(), 86400);
        assert_eq!(parse_duration(" 2h ").unwrap(), 7200);
    }

    #[test]
    fn rejects_junk() {
        for bad in ["", "h", "abc", "5x", "1.5h", "-5m"] {
            assert!(parse_duration(bad).is_err(), "expected error for {bad:?}");
        }
    }
}
