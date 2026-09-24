mod cache;
mod oidc;
mod output;
mod sts;

use clap::{Parser, Subcommand, ValueEnum};

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
    /// Output cached credentials as credential_process JSON or shell env vars,
    /// refreshing them first if they have expired
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

    /// Role ARN to assume
    #[arg(long, env = "SOURCE_ROLE_ARN", default_value = defaults::ROLE_ARN)]
    role_arn: String,

    /// Output format
    #[arg(long, default_value = "credential-process")]
    format: OutputFormat,

    /// Session duration in seconds
    #[arg(long)]
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
}

#[derive(Parser)]
struct CredsArgs {
    /// Role ARN to read cached credentials for
    #[arg(long, env = "SOURCE_ROLE_ARN", default_value = defaults::ROLE_ARN)]
    role_arn: String,

    /// Output format
    #[arg(long, default_value = "credential-process")]
    format: OutputFormat,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    /// AWS credential_process JSON format
    CredentialProcess,
    /// Shell export statements
    Env,
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
    const NOT_FOUND: &str = "No cached credentials found. Run 'source-coop login' first.";
    let mut entry = cache::read_credentials(&args.role_arn)?.ok_or(NOT_FOUND)?;

    if cache::is_expired(&entry.creds)? {
        if entry.refresh.is_none() {
            return Err(
                "Cached credentials have expired. Run 'source-coop login' to refresh.".to_string(),
            );
        }
        // Re-read under the lock: another process may have refreshed already.
        let _lock = cache::lock(&args.role_arn)?;
        entry = cache::read_credentials(&args.role_arn)?.ok_or(NOT_FOUND)?;
        if cache::is_expired(&entry.creds)? {
            entry = refresh(&args.role_arn, entry, verbose).await.map_err(|e| {
                format!("Cached credentials have expired and refresh failed ({e}). Run 'source-coop login'.")
            })?;
        }
    }

    match args.format {
        OutputFormat::CredentialProcess => output::print_credential_process(&entry.creds),
        OutputFormat::Env => output::print_env(&entry.creds),
    }
    Ok(())
}

/// Trade the cached refresh token for a new id_token, exchange that for new STS
/// credentials, and cache the result (including the rotated refresh token).
async fn refresh(
    role_arn: &str,
    mut entry: cache::CacheEntry,
    verbose: bool,
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
        cache::write_credentials(role_arn, &entry)?;
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
    cache::write_credentials(role_arn, &entry)?;
    Ok(entry)
}
