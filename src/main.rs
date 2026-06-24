mod cache;
mod oidc;
mod output;
mod sts;

use clap::{Parser, Subcommand, ValueEnum};

#[cfg(feature = "staging")]
mod defaults {
    pub const ISSUER: &str = "https://auth.staging.source.coop";
    pub const CLIENT_ID: &str = "c445cc61-9884-44a8-b051-8d8f7273ffc1";
    pub const PROXY_URL: &str = "https://staging.data.source.coop/.sts";
    pub const ROLE_ARN: &str = "default";
}

#[cfg(not(feature = "staging"))]
mod defaults {
    pub const ISSUER: &str = "https://auth.source.coop";
    pub const CLIENT_ID: &str = "d037d00b-09c7-4815-ac39-2a0b9fae40c6";
    pub const PROXY_URL: &str = "https://data.source.coop/.sts";
    pub const ROLE_ARN: &str = "default";
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
    /// Output cached credentials as credential_process JSON or shell env vars
    Creds(CredsArgs),
    /// Clear cached credentials and revoke refresh token
    Logout(LogoutArgs),
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

    /// Authentication flow to use
    #[arg(long, default_value = "auto")]
    flow: oidc::FlowType,

    /// OAuth2 scopes
    #[arg(long, default_value = "openid offline_access")]
    scope: String,

    /// Local callback port for auth-code flow (0 for random available port)
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

    /// Do not attempt to refresh expired credentials automatically
    #[arg(long)]
    no_refresh: bool,

    /// OIDC issuer URL (used for auto-refresh)
    #[arg(long, env = "SOURCE_OIDC_ISSUER", default_value = defaults::ISSUER)]
    issuer: String,

    /// S3 proxy URL for STS (used for auto-refresh)
    #[arg(long, env = "SOURCE_PROXY_URL", default_value = defaults::PROXY_URL)]
    proxy_url: String,
}

#[derive(Parser)]
struct LogoutArgs {
    /// OIDC issuer URL
    #[arg(long, env = "SOURCE_OIDC_ISSUER", default_value = defaults::ISSUER)]
    issuer: String,

    /// OAuth2 client ID
    #[arg(long, env = "SOURCE_OIDC_CLIENT_ID", default_value = defaults::CLIENT_ID)]
    client_id: String,

    /// Role ARN to clear cached credentials for
    #[arg(long, env = "SOURCE_ROLE_ARN", default_value = defaults::ROLE_ARN)]
    role_arn: String,
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
        Commands::Logout(args) => {
            if let Err(e) = run_logout(args, verbose).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }
}

async fn run_login(args: LoginArgs, verbose: bool) -> Result<(), String> {
    // 1. OIDC Discovery
    eprintln!("Discovering OIDC endpoints...");
    let discovery = oidc::discover(&args.issuer, verbose).await?;

    // 2. Select and execute auth flow
    // Auto defaults to auth-code because device-code requires per-client
    // grant configuration that the discovery document doesn't reflect.
    let flow = match args.flow {
        oidc::FlowType::Auto => {
            if verbose {
                eprintln!("[verbose] Auto-selected authorization code flow");
            }
            oidc::FlowType::AuthCode
        }
        explicit => explicit,
    };

    let token_response = match flow {
        oidc::FlowType::DeviceCode => {
            if !discovery.supports_device_code()
                || discovery.device_authorization_endpoint.is_none()
            {
                return Err(
                    "Provider does not support device code flow. Use --flow auth-code.".to_string(),
                );
            }
            oidc::device_code::login(&discovery, &args.client_id, &args.scope, verbose).await?
        }
        oidc::FlowType::AuthCode => {
            oidc::auth_code::login(&discovery, &args.client_id, &args.scope, args.port, verbose)
                .await?
        }
        oidc::FlowType::Auto => unreachable!(),
    };

    let id_token = token_response
        .id_token
        .ok_or("No id_token in token response")?;
    eprintln!("Authentication successful.");

    if verbose {
        // Decode and display the JWT claims (header.payload.signature)
        if let Some(payload) = id_token.split('.').nth(1) {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            match URL_SAFE_NO_PAD.decode(payload) {
                Ok(bytes) => match String::from_utf8(bytes) {
                    Ok(json) => eprintln!("[verbose] ID token claims: {json}"),
                    Err(_) => eprintln!("[verbose] Could not decode ID token payload as UTF-8"),
                },
                Err(_) => eprintln!("[verbose] Could not base64-decode ID token payload"),
            }
        }
    }

    // Cache refresh token if present
    if let Some(ref refresh_token) = token_response.refresh_token {
        let data = cache::RefreshTokenData {
            refresh_token: refresh_token.clone(),
            issuer: args.issuer.clone(),
            client_id: args.client_id.clone(),
            proxy_url: Some(args.proxy_url.clone()),
            role_arn: Some(args.role_arn.clone()),
        };
        match cache::write_refresh_token(&data) {
            Ok(location) => {
                if verbose {
                    eprintln!("[verbose] Refresh token cached to {location}");
                }
            }
            Err(e) => {
                eprintln!("Warning: could not cache refresh token: {e}");
            }
        }
    }

    // 3. STS credential exchange
    if verbose {
        eprintln!("[verbose] Assuming role: {}", args.role_arn);
    }
    eprintln!("Exchanging token for credentials...");
    let creds = sts::assume_role(
        &args.proxy_url,
        &args.role_arn,
        &id_token,
        args.duration,
        verbose,
    )
    .await?;

    // 4. Cache credentials
    if args.no_cache {
        eprintln!("Skipping credential cache (--no-cache)");
    } else {
        let location = cache::write_credentials(&args.role_arn, &creds)?;
        eprintln!("Credentials cached to {location}");
    }

    // 5. Output
    match args.format {
        OutputFormat::CredentialProcess => output::print_credential_process(&creds),
        OutputFormat::Env => output::print_env(&creds),
    }

    Ok(())
}

async fn run_creds(args: CredsArgs, verbose: bool) -> Result<(), String> {
    // Load refresh data early so we can resolve the role_arn and proxy_url
    // from the original login session (falling back to CLI args/defaults).
    let refresh_data = cache::read_refresh_token(&args.issuer)?;

    let role_arn = refresh_data
        .as_ref()
        .and_then(|r| r.role_arn.clone())
        .unwrap_or_else(|| args.role_arn.clone());
    let proxy_url = refresh_data
        .as_ref()
        .and_then(|r| r.proxy_url.clone())
        .unwrap_or_else(|| args.proxy_url.clone());

    let creds = cache::read_credentials(&role_arn)?;

    // If we have valid (non-expired) cached credentials, output them directly
    if let Some(ref c) = creds {
        if !cache::is_expired(c)? {
            match args.format {
                OutputFormat::CredentialProcess => output::print_credential_process(c),
                OutputFormat::Env => output::print_env(c),
            }
            return Ok(());
        }
    }

    // Credentials are missing or expired
    if args.no_refresh {
        return Err(
            "Cached credentials have expired. Run 'source-coop login' to refresh.".to_string(),
        );
    }

    let refresh_data = refresh_data
        .ok_or("Cached credentials have expired and no refresh token is available. Run 'source-coop login' to re-authenticate.")?;

    eprintln!("Credentials expired. Refreshing...");

    // 1. OIDC Discovery
    if verbose {
        eprintln!("[verbose] Discovering OIDC endpoints for auto-refresh...");
    }
    let discovery = oidc::discover(&refresh_data.issuer, verbose).await?;

    // 2. Refresh the token
    let token_response = oidc::refresh::refresh(
        &discovery,
        &refresh_data.client_id,
        &refresh_data.refresh_token,
        verbose,
    )
    .await?;

    let id_token = token_response
        .id_token
        .ok_or("No id_token in refresh response")?;

    // 3. Cache rotated refresh token if present
    if let Some(ref new_refresh_token) = token_response.refresh_token {
        let new_data = cache::RefreshTokenData {
            refresh_token: new_refresh_token.clone(),
            issuer: refresh_data.issuer.clone(),
            client_id: refresh_data.client_id.clone(),
            proxy_url: refresh_data.proxy_url.clone(),
            role_arn: refresh_data.role_arn.clone(),
        };
        match cache::write_refresh_token(&new_data) {
            Ok(location) => {
                if verbose {
                    eprintln!("[verbose] Rotated refresh token cached to {location}");
                }
            }
            Err(e) => {
                eprintln!("Warning: could not cache rotated refresh token: {e}");
            }
        }
    }

    // 4. STS credential exchange
    if verbose {
        eprintln!("[verbose] Assuming role: {role_arn}");
    }
    let new_creds = sts::assume_role(&proxy_url, &role_arn, &id_token, None, verbose).await?;

    // 5. Cache new credentials
    let location = cache::write_credentials(&role_arn, &new_creds)?;
    eprintln!("Credentials refreshed and cached to {location}");

    // 6. Output
    match args.format {
        OutputFormat::CredentialProcess => output::print_credential_process(&new_creds),
        OutputFormat::Env => output::print_env(&new_creds),
    }

    Ok(())
}

async fn run_logout(args: LogoutArgs, verbose: bool) -> Result<(), String> {
    // 1. Try to revoke the refresh token at the provider (best-effort)
    match cache::read_refresh_token(&args.issuer)? {
        Some(refresh_data) => match oidc::discover(&args.issuer, verbose).await {
            Ok(discovery) => {
                if let Err(e) = oidc::refresh::revoke(
                    &discovery,
                    &refresh_data.client_id,
                    &refresh_data.refresh_token,
                    verbose,
                )
                .await
                {
                    eprintln!("Warning: could not revoke refresh token: {e}");
                }
            }
            Err(e) => {
                eprintln!("Warning: could not discover OIDC endpoints for revocation: {e}");
            }
        },
        None => {
            if verbose {
                eprintln!("[verbose] No cached refresh token found; skipping revocation");
            }
        }
    }

    // 2. Delete cached refresh token
    cache::delete_refresh_token(&args.issuer)?;
    eprintln!("Refresh token cleared.");

    // 3. Delete cached AWS credentials
    cache::delete_credentials(&args.role_arn)?;
    eprintln!("Cached credentials cleared.");

    eprintln!("Logged out successfully.");
    Ok(())
}
