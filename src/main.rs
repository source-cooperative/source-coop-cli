mod api;
mod cache;
mod oidc;
mod output;
mod product;
mod prompt;
mod session;
mod sts;

use clap::{Parser, Subcommand, ValueEnum};

#[cfg(feature = "staging")]
mod defaults {
    pub const ISSUER: &str = "https://auth.staging.source.coop";
    pub const CLIENT_ID: &str = "a79c9537-be78-454a-9ea1-b96a1be811cc";
    pub const PROXY_URL: &str = "https://data.staging.source.coop";
    pub const ROLE_ARN: &str = "_default";
    pub const API_URL: &str = "https://staging.source.coop";
}

#[cfg(not(feature = "staging"))]
mod defaults {
    pub const ISSUER: &str = "https://auth.source.coop";
    pub const CLIENT_ID: &str = "197e20e7-d52d-4d1d-9e54-4b73a342034b";
    pub const PROXY_URL: &str = "https://data.source.coop";
    pub const ROLE_ARN: &str = "_default";
    pub const API_URL: &str = "https://source.coop";
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
    /// Output cached credentials as credential_process JSON, shell env vars,
    /// or an AWS credentials-file profile, refreshing them first if expired
    Creds(CredsArgs),
    /// Work with the login session
    #[command(subcommand)]
    Auth(AuthCommand),
    /// List, view, create, edit and delete products
    Product(ProductArgs),
}

/// A command that calls the source.coop API, as whoever ran `login` (see
/// `api_token`).
#[derive(Parser)]
struct ProductArgs {
    /// source.coop site URL; the API is served under its `/api/v1`
    #[arg(long, global = true, env = "SOURCE_API_URL", default_value = defaults::API_URL)]
    api_url: String,

    #[command(subcommand)]
    command: product::ProductCommand,
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Print an access token for the source.coop API, refreshing it if expired
    /// (e.g. `curl -H "Authorization: Bearer $(source-coop auth token)" ...`)
    Token,
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

    /// Role ARN to assume
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

    /// Audience for the access token the source.coop API takes; pass an empty
    /// value to request none (then only `creds` works)
    #[arg(long, env = "SOURCE_API_AUDIENCE", default_value = defaults::API_URL)]
    audience: String,

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
    /// Role ARN to read cached credentials for
    #[arg(long, env = "SOURCE_ROLE_ARN", default_value = defaults::ROLE_ARN)]
    role_arn: String,

    /// S3 proxy URL for STS, for a role with nothing cached yet
    #[arg(long, env = "SOURCE_PROXY_URL", default_value = defaults::PROXY_URL)]
    proxy_url: String,

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
        Commands::Auth(AuthCommand::Token) => {
            if let Err(e) = run_auth_token(verbose).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
        Commands::Product(args) => {
            let token = api_token(verbose).await;
            let result = match api::Client::new(&args.api_url, token, verbose) {
                Ok(client) => {
                    let mut tty = prompt::tty();
                    let prompter = tty.as_mut().map(|t| t as &mut dyn prompt::Prompter);
                    product::run(args.command, &client, &args.api_url, prompter).await
                }
                Err(e) => Err(e),
            };
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }
}

async fn run_auth_token(verbose: bool) -> Result<(), String> {
    let token = session::token(session::Want::Access, verbose)
        .await?
        .ok_or("No access token cached. Run 'source-coop login' (with an API audience).")?;
    println!("{token}");
    Ok(())
}

async fn run_login(args: LoginArgs, verbose: bool) -> Result<(), String> {
    // 1. OIDC Discovery
    eprintln!("Discovering OIDC endpoints...");
    let endpoints = oidc::discover(&args.issuer, verbose).await?;

    // 2. Browser-based OIDC login
    let audience = Some(args.audience.trim()).filter(|a| !a.is_empty());
    let tokens = oidc::login(
        &endpoints,
        &args.client_id,
        &args.scope,
        audience,
        args.port,
        verbose,
    )
    .await?;
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
        return Ok(());
    }

    if tokens.refresh_token.is_none() {
        eprintln!(
            "No refresh token issued; run 'source-coop login' again when credentials expire."
        );
    }
    if audience.is_some() && tokens.access_token.is_none() {
        eprintln!(
            "No access token issued; commands that call the source.coop API will run signed out."
        );
    }
    let session = session::Session::new(
        tokens,
        args.client_id,
        endpoints.token_endpoint,
        audience.map(String::from),
        chrono::Utc::now().timestamp(),
    );
    {
        let _lock = cache::lock_session()?;
        cache::write_session(&session)?;
    }
    let entry = cache::CacheEntry {
        creds,
        sts: Some(cache::StsSettings {
            proxy_url: args.proxy_url,
            duration: args.duration,
        }),
        refresh: None,
    };
    let location = cache::write_credentials(&args.role_arn, &entry)?;
    eprintln!("Credentials cached to {location}");
    eprintln!("Run 'source-coop creds' to print them.");
    Ok(())
}

async fn run_creds(args: CredsArgs, verbose: bool) -> Result<(), String> {
    let cached = cache::read_credentials(&args.role_arn)?;
    let entry = match cached {
        Some(entry) if !cache::is_expired(&entry.creds)? => entry,
        _ => {
            // Re-check under the lock: another process may have minted already.
            let _lock = cache::lock(&args.role_arn)?;
            match cache::read_credentials(&args.role_arn)? {
                Some(entry) if !cache::is_expired(&entry.creds)? => entry,
                stale => mint(&args, stale, verbose).await.map_err(|e| {
                    format!("Couldn't get new credentials ({e}). Run 'source-coop login'.")
                })?,
            }
        }
    };

    match args.format {
        OutputFormat::CredentialProcess => output::print_credential_process(&entry.creds),
        OutputFormat::Env => output::print_env(&entry.creds),
        OutputFormat::AwsCredentials => output::print_aws_credentials(&entry.creds, &args.profile),
    }
    Ok(())
}

/// New credentials for the role, cached before they're returned. An entry
/// from before the session was shared refreshes with its own token; anything
/// else exchanges the session's ID token, refreshing the session if need be.
async fn mint(
    args: &CredsArgs,
    stale: Option<cache::CacheEntry>,
    verbose: bool,
) -> Result<cache::CacheEntry, String> {
    let save = |e: &cache::CacheEntry| cache::write_credentials(&args.role_arn, e).map(drop);
    match stale {
        Some(entry) if entry.sts.is_none() && entry.refresh.is_some() => {
            refresh(&args.role_arn, entry, verbose, save).await
        }
        stale => {
            let sts = stale.and_then(|e| e.sts).unwrap_or(cache::StsSettings {
                proxy_url: args.proxy_url.clone(),
                duration: None,
            });
            let id_token = session::token(session::Want::Id, verbose)
                .await?
                .ok_or("not logged in")?;
            let creds = sts::assume_role(
                &sts.proxy_url,
                &args.role_arn,
                &id_token,
                sts.duration,
                verbose,
            )
            .await?;
            let entry = cache::CacheEntry {
                creds,
                sts: Some(sts),
                refresh: None,
            };
            save(&entry)?;
            Ok(entry)
        }
    }
}

/// The bearer for the source.coop API: `SOURCE_TOKEN` if set (for a token
/// obtained some other way), else the login session's access token. Without
/// either, commands run signed out, which is enough to read public products.
async fn api_token(verbose: bool) -> Option<String> {
    if let Ok(token) = std::env::var("SOURCE_TOKEN") {
        return Some(token);
    }
    match session::token(session::Want::Access, verbose).await {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Warning: continuing signed out: {e}");
            None
        }
    }
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
    use wiremock::matchers::{body_string_contains, method, path, query_param};
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
            sts: None,
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

    /// Mock the proxy's STS endpoint: only the freshly issued id_token matches.
    async fn mock_sts(server: &MockServer, status: u16, body: &str) {
        Mock::given(method("GET"))
            .and(path("/.sts"))
            .and(query_param("WebIdentityToken", "new-id-token"))
            .and(query_param("DurationSeconds", "3600"))
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
