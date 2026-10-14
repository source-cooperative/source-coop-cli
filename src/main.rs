mod api_cmd;
mod cache;
mod failure;
mod oidc;
mod output;
mod session;
mod sts;
// Reusable pieces for the commands built on them (resources such as
// products, and `auth`). Parts are unused until those land; each command PR
// removes the allowances it no longer needs.
#[allow(dead_code)]
mod api;
#[allow(dead_code)]
mod draft;
#[allow(dead_code)]
mod picker;
#[allow(dead_code)]
mod prompt;
#[allow(dead_code)]
mod style;

use clap::{Parser, Subcommand, ValueEnum};

#[cfg(feature = "staging")]
mod defaults {
    pub const ISSUER: &str = "https://auth.staging.source.coop";
    pub const CLIENT_ID: &str = "a79c9537-be78-454a-9ea1-b96a1be811cc";
    pub const PROXY_URL: &str = "https://data.staging.source.coop";
    pub const ROLE_ARN: &str = "_default";
    pub const API_URL: &str = "https://staging.source.coop";
    pub const REFRESH_TOKEN_LIFETIME: &str = "30d";
}

#[cfg(not(feature = "staging"))]
mod defaults {
    pub const ISSUER: &str = "https://auth.source.coop";
    pub const CLIENT_ID: &str = "197e20e7-d52d-4d1d-9e54-4b73a342034b";
    pub const PROXY_URL: &str = "https://data.source.coop";
    pub const ROLE_ARN: &str = "_default";
    pub const API_URL: &str = "https://source.coop";
    /// Ory's default `oauth2.ttl.refresh_token`: its refresh tokens carry no
    /// expiry and the token response gives none, so `auth status` counts from
    /// the last renewal. Overridden by `SOURCE_REFRESH_TOKEN_LIFETIME`.
    pub const REFRESH_TOKEN_LIFETIME: &str = "30d";
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
    /// Log in, see whether you are, log out, and print tokens for the source.coop API
    #[command(subcommand)]
    Auth(AuthCommand),
    /// Output cached credentials as credential_process JSON, shell env vars,
    /// or an AWS credentials-file profile, refreshing them first if expired
    Creds(CredsArgs),
    /// Log in through the browser (now `auth login`; this name still works)
    #[command(hide = true)]
    Login(LoginArgs),
    /// Make any request to the source.coop API, signed in as you
    Api(ApiCommandArgs),
}

#[derive(Parser)]
struct ApiCommandArgs {
    /// source.coop site URL; the API is served under its `/api/v1`
    #[arg(long, env = "SOURCE_API_URL", default_value = defaults::API_URL)]
    api_url: String,

    /// S3 proxy URL of the environment whose login session to use
    #[arg(long, env = "SOURCE_PROXY_URL", default_value = defaults::PROXY_URL)]
    proxy_url: String,

    #[command(flatten)]
    request: api_cmd::ApiArgs,
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Log in through the browser, keeping the session and a role's S3
    /// credentials for `creds` and the API
    Login(LoginArgs),
    /// Show the cached login session and a role's credentials, without
    /// refreshing either or going to the network
    Status(StatusArgs),
    /// Remove an environment's login session and a role's cached credentials.
    /// Other roles' credentials can't be found to remove; they stay usable
    /// until they expire, but can't be renewed without the session
    Logout(LogoutArgs),
    /// Print an access token for the source.coop API, refreshing it if expired
    /// (e.g. `curl -H "Authorization: Bearer $(source-coop auth token)" ...`)
    Token(TokenArgs),
}

#[derive(Parser)]
struct LogoutArgs {
    /// S3 proxy URL: selects the environment to log out of
    #[arg(long, env = "SOURCE_PROXY_URL", default_value = defaults::PROXY_URL)]
    proxy_url: String,

    /// Role ARN whose cached credentials to remove
    #[arg(long, env = "SOURCE_ROLE_ARN", default_value = defaults::ROLE_ARN)]
    role_arn: String,
}

#[derive(Parser)]
struct StatusArgs {
    /// S3 proxy URL: selects the environment to report on
    #[arg(long, env = "SOURCE_PROXY_URL", default_value = defaults::PROXY_URL)]
    proxy_url: String,

    /// Role ARN whose cached credentials to report on
    #[arg(long, env = "SOURCE_ROLE_ARN", default_value = defaults::ROLE_ARN)]
    role_arn: String,

    /// Print the status as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct TokenArgs {
    /// S3 proxy URL of the environment whose login session to use
    #[arg(long, env = "SOURCE_PROXY_URL", default_value = defaults::PROXY_URL)]
    proxy_url: String,
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

    /// source.coop site URL whose API names the account you logged in as,
    /// shown by `auth status`
    #[arg(long, env = "SOURCE_API_URL", default_value = defaults::API_URL)]
    api_url: String,

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

    /// S3 proxy URL: selects the environment whose cache and login session to use
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

/// Report a command's error and exit with the code for its kind (see
/// `failure::Failure::exit_code`): as JSON on stderr when the command was
/// asked for `--json`, otherwise as `prompt::report` puts it.
fn fail(e: String, json: bool) -> ! {
    let failure = failure::classify(&e);
    if json {
        eprintln!("{}", failure.to_json());
    } else {
        prompt::report(&e);
    }
    std::process::exit(failure.exit_code());
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let verbose = cli.verbose;

    match cli.command {
        Commands::Auth(AuthCommand::Login(args)) | Commands::Login(args) => {
            if let Err(e) = run_login(args, verbose).await {
                fail(e, false);
            }
        }
        Commands::Creds(args) => {
            if let Err(e) = run_creds(args, verbose).await {
                fail(e, false);
            }
        }
        Commands::Auth(AuthCommand::Status(args)) => {
            let json = args.json;
            if let Err(e) = run_status(args) {
                fail(e, json);
            }
        }
        Commands::Auth(AuthCommand::Logout(args)) => {
            if let Err(e) = run_logout(args) {
                fail(e, false);
            }
        }
        Commands::Auth(AuthCommand::Token(args)) => {
            if let Err(e) = run_auth_token(args, verbose).await {
                fail(e, false);
            }
        }
        Commands::Api(args) => {
            let token = api_token(&args.proxy_url, verbose).await;
            let result = async {
                let client = api::Client::new(&args.api_url, token, verbose)?;
                api_cmd::run(args.request, &client).await
            };
            if let Err(e) = result.await {
                fail(e, false);
            }
        }
    }
}

/// The account `access_token` acts as, from the API's `/whoami`, to keep
/// with the session. None without a token; a failed lookup is noted, not an
/// error, since the login itself worked.
async fn whoami(
    api_url: &str,
    access_token: Option<String>,
    verbose: bool,
) -> Option<session::Account> {
    let client = api::Client::new(api_url, Some(access_token?), verbose).ok()?;
    match client
        .get::<serde_json::Value>(client.url(&["whoami"]))
        .await
    {
        Ok(me) => session::Account::from_whoami(&me),
        Err(e) => {
            eprintln!("Couldn't look up your account ({e}); `auth status` won't name it.");
            None
        }
    }
}

fn run_status(args: StatusArgs) -> Result<(), String> {
    let env = cache::env(&args.proxy_url)?;
    let session = cache::read_session(env.as_deref())?;
    let entry = cache::read_credentials(env.as_deref(), &args.role_arn)?;
    let (session, creds) = (session.as_ref(), entry.as_ref().map(|e| &e.creds));
    let now = chrono::Utc::now().timestamp();
    let lifetime = refresh_lifetime()?;
    let lifetime = Some((lifetime.0, lifetime.1.as_str()));
    if args.json {
        output::json(&status_json(
            &args.proxy_url,
            env.as_deref(),
            &args.role_arn,
            session,
            creds,
            now,
            lifetime,
        ));
    } else {
        print!(
            "{}",
            status_report(
                &args.proxy_url,
                env.as_deref(),
                &args.role_arn,
                session,
                creds,
                now,
                lifetime,
                style::wanted(std::io::IsTerminal::is_terminal(&std::io::stdout())),
            )
        );
    }
    Ok(())
}

/// How long a refresh token lasts unused, in seconds, with how it was given
/// (`30d`): `SOURCE_REFRESH_TOKEN_LIFETIME`, else this build's default. The
/// provider doesn't say, so this is what `auth status` estimates from. It's
/// only for display: OAuth2 has no way to ask for a refresh token's lifetime,
/// so nothing sent at login depends on it; Ory's project config decides.
fn refresh_lifetime() -> Result<(i64, String), String> {
    let text = std::env::var("SOURCE_REFRESH_TOKEN_LIFETIME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| defaults::REFRESH_TOKEN_LIFETIME.to_string());
    let secs = parse_duration(&text).map_err(|e| format!("SOURCE_REFRESH_TOKEN_LIFETIME: {e}"))?;
    Ok((secs as i64, text.trim().to_string()))
}

/// The site a session's account lives on: the API audience it was issued
/// for (`https://source.coop`, or a staging or preview site), else this
/// build's.
fn site(s: &session::Session) -> &str {
    s.audience
        .as_deref()
        .filter(|a| !a.is_empty())
        .unwrap_or(defaults::API_URL)
        .trim_end_matches('/')
}

/// `at` relative to `now`, in the largest whole unit: "3 hours ago", or
/// "in 29 days" while still ahead.
fn relative(at: i64, now: i64) -> String {
    let Some((at_t, now_t)) =
        chrono::DateTime::from_timestamp(at, 0).zip(chrono::DateTime::from_timestamp(now, 0))
    else {
        return String::new();
    };
    if at <= now {
        return style::ago(at_t, now_t);
    }
    match style::ago(now_t, at_t).as_str() {
        "just now" => "in under a minute".into(),
        ahead => format!("in {}", ahead.trim_end_matches(" ago")),
    }
}

/// A Unix timestamp as RFC 3339, the API's date format.
fn rfc3339(t: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(t, 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// `auth status --json`: what `status_report` shows, as data. Times are RFC
/// 3339 with an `expired` flag, as of `now`; absent ones are null.
fn status_json(
    proxy_url: &str,
    env: Option<&str>,
    role_arn: &str,
    session: Option<&session::Session>,
    creds: Option<&sts::Credentials>,
    now: i64,
    refresh_lifetime: Option<(i64, &str)>,
) -> serde_json::Value {
    use serde_json::{json, Value};
    let at = |t: Option<i64>| match t {
        Some(t) => json!({"expires_at": rfc3339(t), "expired": t <= now}),
        None => json!({"expires_at": null, "expired": null}),
    };
    let login = session.map(|s| {
        let id_exp = session::jwt_exp(&s.id_token);
        let expired = s.refresh_token.is_none() && id_exp.is_some_and(|e| e <= now);
        let estimate = match (&s.refresh_token, s.refresh_token_expires_at) {
            (Some(_), None) => s
                .refresh_token_issued_at
                .zip(refresh_lifetime)
                .map(|(issued, (secs, label))| (issued + secs, label)),
            _ => None,
        };
        json!({
            "state": if expired { "expired" } else { "logged_in" },
            "account": s.account.as_ref().map(|a| json!({
                "account_id": a.account_id,
                "name": a.name,
                "profile_url": format!("{}/{}", site(s), a.account_id),
            })),
            "refresh_token": {
                "present": s.refresh_token.is_some(),
                "issued_at": s.refresh_token_issued_at.and_then(rfc3339),
                "expires_at": s.refresh_token_expires_at.and_then(rfc3339),
                // When the provider gave no expiry: the last renewal plus the
                // assumed lifetime, as `auth status` estimates it.
                "estimated_lapse_at": estimate.and_then(|(at, _)| rfc3339(at)),
                "assumed_lifetime": estimate.map(|(_, label)| label),
            },
            "id_token": at(id_exp),
            "access_token": match &s.access_token {
                None => Value::Null,
                Some(_) => {
                    let mut a = at(s.access_token_expires_at);
                    a["audience"] = json!(s.audience);
                    a
                }
            },
        })
    });
    let credentials = match creds {
        None => json!({"role_arn": role_arn, "cached": false}),
        Some(c) => {
            let exp = chrono::DateTime::parse_from_rfc3339(&c.expiration).ok();
            json!({
                "role_arn": role_arn,
                "cached": true,
                "expires_at": c.expiration,
                "expired": exp.map(|t| t.timestamp() <= now),
            })
        }
    };
    json!({
        "environment": {"name": env.unwrap_or("production"), "proxy_url": proxy_url},
        "logged_in": login.as_ref().is_some_and(|l| l["state"] == "logged_in"),
        "login": login,
        "credentials": credentials,
    })
}

/// `<expires> <time>` for a Unix timestamp, or `expired <time>` (yellow)
/// once it's past, as of `now`.
fn expiry(exp: Option<i64>, now: i64, expires: &str, color: bool) -> String {
    match exp.and_then(|t| chrono::DateTime::from_timestamp(t, 0)) {
        None => "expiry unknown".into(),
        Some(t) => {
            let when = t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            if t.timestamp() > now {
                format!("{expires} {when}")
            } else {
                style::paint(color, "33", &format!("expired {when}"))
            }
        }
    }
}

/// The `auth status` report for one environment and role, as of `now`: a
/// `Label  value` row each, labels dim and the login's state green (logged
/// in) or red (expired, not logged in) when `color`. `refresh_lifetime`, the
/// assumed lifetime and how it was given, estimates when an unused login lapses.
// Every input is a separate fact the report shows; a struct would only rename them.
#[allow(clippy::too_many_arguments)]
fn status_report(
    proxy_url: &str,
    env: Option<&str>,
    role_arn: &str,
    session: Option<&session::Session>,
    creds: Option<&sts::Credentials>,
    now: i64,
    refresh_lifetime: Option<(i64, &str)>,
    color: bool,
) -> String {
    let mut rows = vec![(
        "Environment",
        format!("{} ({proxy_url})", env.unwrap_or("production")),
    )];
    match session {
        None => rows.push(("Login", style::paint(color, "31", "not logged in"))),
        Some(s) => {
            let id_exp = session::jwt_exp(&s.id_token);
            // Without a refresh token, the session ends when its ID token does.
            let state = match (&s.refresh_token, id_exp) {
                (None, Some(exp)) if exp <= now => style::paint(color, "31", "expired"),
                _ => style::paint(color, "32", "logged in"),
            };
            rows.push(("Login", state));
            rows.push((
                "Account",
                match &s.account {
                    Some(a) => match &a.name {
                        Some(name) => format!("{name} ({})", style::id(color, &a.account_id)),
                        None => a.account_id.clone(),
                    },
                    None => style::paint(color, "2", "unknown until your next `auth login`"),
                },
            ));
            if let Some(a) = &s.account {
                rows.push((
                    "Profile",
                    style::paint(color, "4", &format!("{}/{}", site(s), a.account_id)),
                ));
            }
            // `renewed <time> (<ago>); expires <when> (<in>)`. Ory's refresh
            // tokens are opaque and its token response gives no lifetime, so
            // the expiry is the provider's where it said, and otherwise the
            // last renewal plus the configured lifetime (to the day, as it's
            // an estimate; the README says so).
            let refresh = match (&s.refresh_token, s.refresh_token_issued_at) {
                (None, _) => "none: log in again when the ID token expires".into(),
                (Some(_), None) => "yes".into(),
                (Some(_), Some(issued)) => format!(
                    "renewed {} ({})",
                    rfc3339(issued).unwrap_or_default(),
                    relative(issued, now)
                ),
            };
            let expires = match (s.refresh_token_expires_at, s.refresh_token_issued_at) {
                (Some(exp), _) => Some((exp, rfc3339(exp).unwrap_or_default())),
                (None, Some(issued)) => refresh_lifetime.map(|(secs, _)| {
                    let at = issued + secs;
                    let day = chrono::DateTime::from_timestamp(at, 0)
                        .map(|d| d.format("%Y-%m-%d").to_string())
                        .unwrap_or_default();
                    (at, day)
                }),
                _ => None,
            };
            let refresh = match expires.filter(|_| s.refresh_token.is_some()) {
                Some((at, when)) if at > now => {
                    format!("{refresh}; expires {when} ({})", relative(at, now))
                }
                Some((at, when)) => format!(
                    "{refresh}; {}",
                    style::paint(
                        color,
                        "33",
                        &format!("expired {when} ({})", relative(at, now))
                    )
                ),
                None => refresh,
            };
            rows.push(("Refresh token", refresh));
            rows.push(("ID token", expiry(id_exp, now, "expires", color)));
            rows.push((
                "Access token",
                match &s.access_token {
                    None => "none".into(),
                    Some(_) => format!(
                        "{}{}",
                        s.audience
                            .as_deref()
                            .map(|a| format!("for {a}, "))
                            .unwrap_or_default(),
                        expiry(s.access_token_expires_at, now, "expires", color)
                    ),
                },
            ));
        }
    }
    rows.push((
        "Credentials",
        match creds {
            None => format!("{role_arn}: none cached"),
            Some(c) => {
                let exp = chrono::DateTime::parse_from_rfc3339(&c.expiration).ok();
                format!(
                    "{role_arn}: {}",
                    expiry(exp.map(|t| t.timestamp()), now, "expire", color)
                )
            }
        },
    ));
    let width = rows.iter().map(|(label, _)| label.len()).max().unwrap_or(0);
    rows.iter()
        .map(|(label, value)| {
            format!(
                "{}  {value}\n",
                style::paint(color, "2", &format!("{label:<width$}"))
            )
        })
        .collect()
}

fn run_logout(args: LogoutArgs) -> Result<(), String> {
    let env = cache::env(&args.proxy_url)?;
    let name = env.as_deref().unwrap_or("production");
    // The session first: a `creds` that still had it may be minting, and the
    // role's lock makes us wait for it before removing what it caches.
    let session = cache::delete_session(env.as_deref())?;
    let creds = cache::delete_credentials(env.as_deref(), &args.role_arn)?;
    if session || creds {
        eprintln!("Logged out of {name} ({}).", args.proxy_url);
    } else {
        eprintln!("Not logged in to {name} ({}).", args.proxy_url);
    }
    Ok(())
}

async fn run_auth_token(args: TokenArgs, verbose: bool) -> Result<(), String> {
    let env = cache::env(&args.proxy_url)?;
    let token = session::token(env.as_deref(), session::Want::Access, verbose)
        .await?
        .ok_or("No access token cached. Run 'source-coop auth login' (with an API audience).")?;
    println!("{token}");
    Ok(())
}

async fn run_login(args: LoginArgs, verbose: bool) -> Result<(), String> {
    let env = cache::env(&args.proxy_url)?;

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
            "No refresh token issued; run 'source-coop auth login' again when credentials expire."
        );
    }
    if audience.is_some() && tokens.access_token.is_none() {
        eprintln!(
            "No access token issued; commands that call the source.coop API will run signed out."
        );
    }
    let mut session = session::Session::new(
        tokens,
        args.proxy_url.clone(),
        args.client_id,
        endpoints.token_endpoint,
        audience.map(String::from),
        chrono::Utc::now().timestamp(),
    );
    session.account = whoami(&args.api_url, session.access_token.clone(), verbose).await;
    {
        let _lock = cache::lock_session(env.as_deref())?;
        cache::write_session(env.as_deref(), &session)?;
    }
    let entry = cache::CacheEntry {
        creds,
        sts: Some(cache::StsSettings {
            proxy_url: args.proxy_url,
            duration: args.duration,
        }),
        refresh: None,
    };
    // Under the role's lock, so a `creds` minting from the old session can't
    // overwrite this entry afterwards.
    let _lock = cache::lock(env.as_deref(), &args.role_arn)?;
    let location = cache::write_credentials(env.as_deref(), &args.role_arn, &entry)?;
    eprintln!("Credentials cached to {location}");
    eprintln!("Run 'source-coop creds' to print them.");
    Ok(())
}

async fn run_creds(args: CredsArgs, verbose: bool) -> Result<(), String> {
    let env = cache::env(&args.proxy_url)?;
    let env = env.as_deref();
    let cached = cache::read_credentials(env, &args.role_arn)?;
    let entry = match cached {
        Some(entry) if !cache::is_expired(&entry.creds)? => entry,
        _ => {
            // Re-check under the lock: another process may have minted already.
            let _lock = cache::lock(env, &args.role_arn)?;
            match cache::read_credentials(env, &args.role_arn)? {
                Some(entry) if !cache::is_expired(&entry.creds)? => entry,
                stale => mint(&args, env, stale, verbose).await.map_err(|e| {
                    format!("Couldn't get new credentials ({e}). Run 'source-coop auth login'.")
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
    env: Option<&str>,
    stale: Option<cache::CacheEntry>,
    verbose: bool,
) -> Result<cache::CacheEntry, String> {
    let save = |e: &cache::CacheEntry| cache::write_credentials(env, &args.role_arn, e).map(drop);
    match stale {
        Some(entry) if entry.sts.is_none() && entry.refresh.is_some() => {
            refresh(&args.role_arn, entry, verbose, save).await
        }
        stale => {
            let sts = stale.and_then(|e| e.sts).unwrap_or(cache::StsSettings {
                proxy_url: args.proxy_url.clone(),
                duration: None,
            });
            let id_token = session::token(env, session::Want::Id, verbose)
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
async fn api_token(proxy_url: &str, verbose: bool) -> Option<String> {
    // Set but empty is unset, so `SOURCE_TOKEN=` doesn't skip the session.
    if let Some(token) = std::env::var("SOURCE_TOKEN")
        .ok()
        .filter(|t| !t.trim().is_empty())
    {
        return Some(token);
    }
    let token = async {
        let env = cache::env(proxy_url)?;
        session::token(env.as_deref(), session::Want::Access, verbose).await
    };
    token.await.unwrap_or_else(|e| {
        eprintln!("Warning: continuing signed out: {e}");
        None
    })
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
    use clap::CommandFactory;
    use wiremock::matchers::{body_string_contains, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Every runnable command, as its words after `source-coop`.
    fn commands(cmd: &clap::Command, path: &str, out: &mut Vec<String>) {
        // Hidden ones are old names kept working, documented under the new.
        for sub in cmd
            .get_subcommands()
            .filter(|s| s.get_name() != "help" && !s.is_hide_set())
        {
            let words = format!("{path} {}", sub.get_name()).trim().to_string();
            if sub.has_subcommands() {
                commands(sub, &words, out);
            } else {
                out.push(words);
            }
        }
    }

    fn creds(expiration: &str) -> sts::Credentials {
        sts::Credentials {
            access_key_id: "KEY".into(),
            secret_access_key: "SECRET".into(),
            session_token: "SESSION".into(),
            expiration: expiration.into(),
        }
    }

    /// An unsigned JWT that expires at `exp`; only its claims are ever read.
    fn jwt(exp: i64) -> String {
        use base64::Engine;
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::json!({ "exp": exp }).to_string());
        format!("e30.{claims}.sig")
    }

    fn live_session(now: i64, account: Option<session::Account>) -> session::Session {
        session::Session {
            proxy_url: Some("https://data.source.coop".into()),
            client_id: "cid".into(),
            token_endpoint: "https://auth.test/oauth2/token".into(),
            audience: Some("https://source.coop".into()),
            refresh_token: Some("rt".into()),
            id_token: jwt(now + 3600),
            access_token: Some("at".into()),
            access_token_expires_at: Some(now - 60),
            account,
            refresh_token_issued_at: Some(now - 3 * 3600),
            refresh_token_expires_at: None,
        }
    }

    #[test]
    fn status_names_who_is_logged_in() {
        // 2026-10-13T17:00:00Z
        let now = 1_791_910_800;
        let me = session::Account {
            account_id: "alukach".into(),
            name: Some("Anthony Lukach".into()),
        };
        let report = status_report(
            "https://data.source.coop",
            None,
            "_default",
            Some(&live_session(now, Some(me))),
            Some(&creds("2026-10-13T18:30:00Z")),
            now,
            None,
            false,
        );
        assert_eq!(
            report,
            "Environment    production (https://data.source.coop)\n\
             Login          logged in\n\
             Account        Anthony Lukach (alukach)\n\
             Profile        https://source.coop/alukach\n\
             Refresh token  renewed 2026-10-13T14:00:00Z (3 hours ago)\n\
             ID token       expires 2026-10-13T18:00:00Z\n\
             Access token   for https://source.coop, expired 2026-10-13T16:59:00Z\n\
             Credentials    _default: expire 2026-10-13T18:30:00Z\n"
        );
    }

    #[test]
    fn status_shows_the_refresh_tokens_expiry_where_the_provider_gave_one() {
        let now = 1_791_910_800;
        let mut s = live_session(now, None);
        s.refresh_token_expires_at = Some(now + 30 * 86_400);
        let report = status_report(
            "https://data.source.coop",
            None,
            "_default",
            Some(&s),
            None,
            now,
            None,
            false,
        );
        assert!(
            report.contains(
                "Refresh token  renewed 2026-10-13T14:00:00Z (3 hours ago); expires 2026-11-12T17:00:00Z (in 1 month)\n"
            ),
            "{report}"
        );
        // No Profile row without a known account.
        assert!(!report.contains("Profile"), "{report}");
    }

    #[test]
    fn status_estimates_when_an_unused_login_expires() {
        let now = 1_791_910_800; // 2026-10-13T17:00:00Z, renewed 3 hours before
        let row = |s: &session::Session, lifetime| {
            let report = status_report(
                "https://data.source.coop",
                None,
                "_default",
                Some(s),
                None,
                now,
                Some(lifetime),
                false,
            );
            report
                .lines()
                .find(|l| l.starts_with("Refresh token"))
                .unwrap()
                .to_string()
        };
        let s = live_session(now, None);
        assert_eq!(
            row(&s, (30 * 86_400, "30d")),
            "Refresh token  renewed 2026-10-13T14:00:00Z (3 hours ago); \
             expires 2026-11-12 (in 29 days)"
        );
        // Renewed longer ago than the lifetime: expired.
        assert_eq!(
            row(&s, (3600, "1h")),
            "Refresh token  renewed 2026-10-13T14:00:00Z (3 hours ago); \
             expired 2026-10-13 (2 hours ago)"
        );
        // An expiry the provider gave is exact, to the second, and beats the
        // estimate.
        let mut exact = live_session(now, None);
        exact.refresh_token_expires_at = Some(now + 86_400);
        assert!(row(&exact, (30 * 86_400, "30d"))
            .ends_with("; expires 2026-10-14T17:00:00Z (in 1 day)"));
        // Without a renewal time there's nothing to count from.
        let mut unknown = live_session(now, None);
        unknown.refresh_token_issued_at = None;
        assert_eq!(row(&unknown, (30 * 86_400, "30d")), "Refresh token  yes");
    }

    #[test]
    fn relative_times_read_ahead_and_behind() {
        let now = 1_791_910_800;
        assert_eq!(relative(now + 29 * 86_400 + 5, now), "in 29 days");
        assert_eq!(relative(now + 30, now), "in under a minute");
        assert_eq!(relative(now - 3 * 3600, now), "3 hours ago");
        assert_eq!(relative(now, now), "just now");
    }

    #[test]
    fn a_bad_refresh_lifetime_override_says_which_variable() {
        let err = parse_duration("forever").unwrap_err();
        assert!(err.contains("invalid duration"), "{err}");
        // refresh_lifetime() names SOURCE_REFRESH_TOKEN_LIFETIME around that;
        // the default must always parse.
        assert_eq!(
            parse_duration(defaults::REFRESH_TOKEN_LIFETIME),
            Ok(30 * 86_400)
        );
    }

    #[test]
    fn status_json_carries_the_same_facts_as_data() {
        let now = 1_791_910_800;
        let me = session::Account {
            account_id: "alukach".into(),
            name: Some("Anthony Lukach".into()),
        };
        let json = status_json(
            "https://data.source.coop",
            None,
            "_default",
            Some(&live_session(now, Some(me))),
            Some(&creds("2026-10-13T18:30:00Z")),
            now,
            Some((30 * 86_400, "30d")),
        );
        assert_eq!(
            json,
            serde_json::json!({
                "environment": {"name": "production", "proxy_url": "https://data.source.coop"},
                "logged_in": true,
                "login": {
                    "state": "logged_in",
                    "account": {
                        "account_id": "alukach",
                        "name": "Anthony Lukach",
                        "profile_url": "https://source.coop/alukach",
                    },
                    "refresh_token": {
                        "present": true,
                        "issued_at": "2026-10-13T14:00:00Z",
                        "expires_at": null,
                        // Estimated: the provider gave no expiry.
                        "estimated_lapse_at": "2026-11-12T14:00:00Z",
                        "assumed_lifetime": "30d",
                    },
                    "id_token": {"expires_at": "2026-10-13T18:00:00Z", "expired": false},
                    "access_token": {
                        "audience": "https://source.coop",
                        "expires_at": "2026-10-13T16:59:00Z",
                        "expired": true,
                    },
                },
                "credentials": {
                    "role_arn": "_default",
                    "cached": true,
                    "expires_at": "2026-10-13T18:30:00Z",
                    "expired": false,
                },
            })
        );
        let nobody = status_json(
            "https://data.source.coop",
            None,
            "_default",
            None,
            None,
            now,
            None,
        );
        assert_eq!(nobody["logged_in"], false);
        assert_eq!(nobody["login"], serde_json::Value::Null);
        assert_eq!(
            nobody["credentials"],
            serde_json::json!({"role_arn": "_default", "cached": false})
        );
    }

    #[test]
    fn status_says_when_the_account_is_unknown_or_nobody_is_logged_in() {
        let now = 1_791_910_800;
        let unknown = status_report(
            "https://data.source.coop",
            None,
            "_default",
            Some(&live_session(now, None)),
            None,
            now,
            None,
            false,
        );
        assert!(
            unknown.contains("Account        unknown until your next `auth login`\n"),
            "{unknown}"
        );
        assert!(
            unknown.ends_with("Credentials    _default: none cached\n"),
            "{unknown}"
        );

        let nobody = status_report(
            "https://data.staging.source.coop",
            Some("data.staging.source.coop"),
            "_default",
            None,
            None,
            0,
            None,
            false,
        );
        assert_eq!(
            nobody,
            "Environment  data.staging.source.coop (https://data.staging.source.coop)\n\
             Login        not logged in\n\
             Credentials  _default: none cached\n"
        );
    }

    #[test]
    fn status_colours_labels_and_the_login_state() {
        let now = 1_791_910_800;
        let me = session::Account {
            account_id: "alukach".into(),
            name: Some("A".into()),
        };
        let report = status_report(
            "https://data.source.coop",
            None,
            "_default",
            Some(&live_session(now, Some(me))),
            None,
            now,
            None,
            true,
        );
        assert!(
            report.contains("\x1b[2mLogin        \x1b[0m  \x1b[32mlogged in\x1b[0m"),
            "{report:?}"
        );
        // The ID in gray, and a past expiry in yellow.
        assert!(report.contains("A (\x1b[90malukach\x1b[0m)"), "{report:?}");
        assert!(
            report.contains("\x1b[33mexpired 2026-10-13T16:59:00Z\x1b[0m"),
            "{report:?}"
        );
        let nobody = status_report(
            "https://data.source.coop",
            None,
            "_default",
            None,
            None,
            now,
            None,
            true,
        );
        assert!(
            nobody.contains("\x1b[31mnot logged in\x1b[0m"),
            "{nobody:?}"
        );
    }

    #[test]
    fn the_account_comes_from_whoami() {
        let me =
            serde_json::json!({"account": {"account_id": "alukach", "name": "Anthony Lukach"}});
        assert_eq!(
            session::Account::from_whoami(&me),
            Some(session::Account {
                account_id: "alukach".into(),
                name: Some("Anthony Lukach".into())
            })
        );
        // Signed in without an account yet.
        assert_eq!(
            session::Account::from_whoami(&serde_json::json!({"account": null})),
            None
        );
    }

    #[tokio::test]
    async fn login_looks_up_the_account_only_with_an_access_token() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/whoami"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"account": {"account_id": "alukach", "name": "Anthony Lukach"}}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let found = whoami(&server.uri(), Some("at".into()), false).await;
        assert_eq!(found.map(|a| a.account_id), Some("alukach".to_string()));
        // No token, no request (the mock expects exactly one).
        assert_eq!(whoami(&server.uri(), None, false).await, None);
    }

    /// `login` moved under `auth`; the old name still works, unlisted.
    #[test]
    fn login_still_works_by_its_old_name() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["source-coop"], args].concat());
        assert!(matches!(
            parse(&["auth", "login"]).map(|c| c.command),
            Ok(Commands::Auth(AuthCommand::Login(_)))
        ));
        assert!(matches!(
            parse(&["login", "--role-arn", "r"]).map(|c| c.command),
            Ok(Commands::Login(_))
        ));
        let help = Cli::command().render_help().to_string();
        assert!(
            !help.contains("\n  login"),
            "login should be hidden:\n{help}"
        );
    }

    /// AGENTS.md: the README documents the CLI as it is, starting with every
    /// command appearing in it as `source-coop <command>`.
    #[test]
    fn every_command_is_in_the_readme() {
        let readme = include_str!("../README.md");
        let mut all = vec![];
        commands(&Cli::command(), "", &mut all);
        let missing: Vec<_> = all
            .iter()
            .filter(|c| !readme.contains(&format!("source-coop {c}")))
            .collect();
        assert!(all.len() > 5, "found too few commands: {all:?}");
        assert!(missing.is_empty(), "not in README.md: {missing:?}");
    }

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
