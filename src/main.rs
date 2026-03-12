mod cache;
mod oidc;
mod output;
mod sts;

use clap::{Parser, Subcommand, ValueEnum};

#[cfg(feature = "staging")]
mod defaults {
    pub const ISSUER: &str = "https://auth.staging.source.coop";
    pub const CLIENT_ID: &str = "c445cc61-9884-44a8-b051-8d8f7273ffc1";
    pub const PROXY_URL: &str = "https://staging.data.source.coop";
    pub const ROLE_ARN: &str = "default";
}

#[cfg(not(feature = "staging"))]
mod defaults {
    pub const ISSUER: &str = "https://auth.source.coop";
    pub const CLIENT_ID: &str = "d037d00b-09c7-4815-ac39-2a0b9fae40c6";
    pub const PROXY_URL: &str = "https://data.source.coop";
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
            if let Err(e) = run_creds(args) {
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
    let flow = match args.flow {
        oidc::FlowType::Auto => {
            if discovery.supports_device_code()
                && discovery.device_authorization_endpoint.is_some()
            {
                if verbose {
                    eprintln!("[verbose] Auto-selected device code flow");
                }
                oidc::FlowType::DeviceCode
            } else {
                if verbose {
                    eprintln!("[verbose] Auto-selected authorization code flow");
                }
                oidc::FlowType::AuthCode
            }
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
            oidc::auth_code::login(
                &discovery,
                &args.client_id,
                &args.scope,
                args.port,
                verbose,
            )
            .await?
        }
        oidc::FlowType::Auto => unreachable!(),
    };

    let id_token = token_response
        .id_token
        .ok_or("No id_token in token response")?;
    eprintln!("Authentication successful.");

    // Cache refresh token if present
    if let Some(ref refresh_token) = token_response.refresh_token {
        let data = cache::RefreshTokenData {
            refresh_token: refresh_token.clone(),
            issuer: args.issuer.clone(),
            client_id: args.client_id.clone(),
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

fn run_creds(args: CredsArgs) -> Result<(), String> {
    let creds = cache::read_credentials(&args.role_arn)?
        .ok_or("No cached credentials found. Run 'source-coop login' first.")?;

    if cache::is_expired(&creds)? {
        return Err(
            "Cached credentials have expired. Run 'source-coop login' to refresh.".to_string(),
        );
    }

    match args.format {
        OutputFormat::CredentialProcess => output::print_credential_process(&creds),
        OutputFormat::Env => output::print_env(&creds),
    }
    Ok(())
}
