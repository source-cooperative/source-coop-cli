# OIDC Discovery-Driven Auth Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace single-flow auth with a discovery-driven system supporting Authorization Code + PKCE, Device Code, and Refresh Token flows.

**Architecture:** Parse the full OIDC discovery document, select the best flow (device code preferred, auth code fallback, user override via `--flow`), execute that flow to get an id_token + optional refresh_token, then STS exchange for AWS credentials. Refresh tokens cached separately in keyring enable silent credential renewal.

**Tech Stack:** Rust, reqwest, serde, clap, keyring, tokio, sha2, base64, rand

---

### Task 1: Restructure oidc.rs into oidc/ module with expanded discovery

**Files:**
- Delete: `src/oidc.rs`
- Create: `src/oidc/mod.rs`
- Create: `src/oidc/auth_code.rs`

**Step 1: Create the oidc directory and mod.rs with expanded OidcDiscovery struct**

Create `src/oidc/mod.rs`:

```rust
pub mod auth_code;

use serde::Deserialize;

/// Parsed OIDC discovery document.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub device_authorization_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub grant_types_supported: Option<Vec<String>>,
    pub scopes_supported: Option<Vec<String>>,
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

impl OidcDiscovery {
    pub fn supports_grant_type(&self, grant_type: &str) -> bool {
        self.grant_types_supported
            .as_ref()
            .map(|types| types.iter().any(|t| t == grant_type))
            .unwrap_or(false)
    }

    pub fn supports_device_code(&self) -> bool {
        self.supports_grant_type("urn:ietf:params:oauth:grant-type:device_code")
            || self.supports_grant_type("device_code")
    }
}

/// Token response from the OIDC provider.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<u64>,
}

/// Fetch and parse the OIDC discovery document.
pub async fn discover(issuer: &str, verbose: bool) -> Result<OidcDiscovery, String> {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );

    if verbose {
        eprintln!("[verbose] GET {discovery_url}");
    }

    let resp = reqwest::get(&discovery_url)
        .await
        .map_err(|e| format!("Failed to fetch OIDC discovery document: {e}"))?;

    if verbose {
        eprintln!("[verbose] Response: {}", resp.status());
    }

    if !resp.status().is_success() {
        return Err(format!("OIDC discovery returned status {}", resp.status()));
    }

    let discovery: OidcDiscovery = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse OIDC discovery document: {e}"))?;

    if verbose {
        eprintln!("[verbose] Authorization endpoint: {}", discovery.authorization_endpoint);
        eprintln!("[verbose] Token endpoint: {}", discovery.token_endpoint);
        if let Some(ref dae) = discovery.device_authorization_endpoint {
            eprintln!("[verbose] Device authorization endpoint: {dae}");
        }
        if let Some(ref grants) = discovery.grant_types_supported {
            eprintln!("[verbose] Supported grant types: {}", grants.join(", "));
        }
    }

    Ok(discovery)
}
```

**Step 2: Move existing auth code flow into auth_code.rs**

Create `src/oidc/auth_code.rs` with the existing flow logic, adapted to use `OidcDiscovery` and return `TokenResponse`:

```rust
use super::{OidcDiscovery, TokenResponse};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use tokio::net::TcpListener;
use url::Url;

struct Pkce {
    verifier: String,
    challenge: String,
}

fn generate_pkce() -> Pkce {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let verifier = URL_SAFE_NO_PAD.encode(&bytes);

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

    Pkce {
        verifier,
        challenge,
    }
}

/// Run the Authorization Code + PKCE flow. Returns a TokenResponse.
pub async fn login(
    discovery: &OidcDiscovery,
    client_id: &str,
    scope: &str,
    port: u16,
    verbose: bool,
) -> Result<TokenResponse, String> {
    let pkce = generate_pkce();
    let state: String = URL_SAFE_NO_PAD.encode(rand::thread_rng().gen::<[u8; 16]>());

    // Bind local callback server
    let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .map_err(|e| format!("Failed to bind local server: {e}"))?;

    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("Failed to get local address: {e}"))?;
    let redirect_uri = format!("http://127.0.0.1:{}/callback", local_addr.port());

    if verbose {
        eprintln!("[verbose] Callback server listening on {local_addr}");
        eprintln!("[verbose] Redirect URI: {redirect_uri}");
    }

    // Build authorization URL
    let mut auth_url = Url::parse(&discovery.authorization_endpoint)
        .map_err(|e| format!("Invalid authorization endpoint URL: {e}"))?;
    auth_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("scope", scope)
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &state);

    if verbose {
        eprintln!("[verbose] Authorization URL: {auth_url}");
    }

    eprintln!("Opening browser for authentication...");
    if open::that(auth_url.as_str()).is_err() {
        eprintln!(
            "Could not open browser automatically. Please open this URL:\n{}",
            auth_url
        );
    }

    // Wait for callback
    let (code, received_state) = wait_for_callback(&listener).await?;

    if verbose {
        eprintln!("[verbose] Received authorization code callback");
    }

    if received_state != state {
        return Err("State mismatch — possible CSRF attack".to_string());
    }

    // Exchange code for tokens
    exchange_code(
        &discovery.token_endpoint,
        &code,
        &redirect_uri,
        client_id,
        &pkce.verifier,
        verbose,
    )
    .await
}

async fn wait_for_callback(listener: &TcpListener) -> Result<(String, String), String> {
    let (stream, _) = listener
        .accept()
        .await
        .map_err(|e| format!("Failed to accept callback connection: {e}"))?;

    let std_stream = stream
        .into_std()
        .map_err(|e| format!("Failed to convert stream: {e}"))?;
    std_stream
        .set_nonblocking(false)
        .map_err(|e| format!("Failed to set blocking: {e}"))?;

    let mut reader = BufReader::new(&std_stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| format!("Failed to read request: {e}"))?;

    let path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or("Invalid HTTP request")?;

    let url = Url::parse(&format!("http://localhost{path}"))
        .map_err(|e| format!("Failed to parse callback URL: {e}"))?;

    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();

    if let Some(error) = params.get("error") {
        let desc = params
            .get("error_description")
            .map(|d| format!(": {d}"))
            .unwrap_or_default();
        let html = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
             <html><body><h1>Authentication Failed</h1><p>{error}{desc}</p>\
             <p>You can close this tab.</p></body></html>"
        );
        let _ = (&std_stream).write_all(html.as_bytes());
        return Err(format!("Authentication error: {error}{desc}"));
    }

    let code = params
        .get("code")
        .ok_or("No authorization code in callback")?
        .clone();
    let received_state = params.get("state").ok_or("No state in callback")?.clone();

    let html = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n\
        <html><body><h1>Authentication Successful</h1>\
        <p>You can close this tab and return to your terminal.</p></body></html>";
    (&std_stream)
        .write_all(html.as_bytes())
        .map_err(|e| format!("Failed to send response: {e}"))?;

    Ok((code, received_state))
}

async fn exchange_code(
    token_endpoint: &str,
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    code_verifier: &str,
    verbose: bool,
) -> Result<TokenResponse, String> {
    if verbose {
        eprintln!("[verbose] POST {token_endpoint}");
        eprintln!("[verbose]   grant_type=authorization_code");
        eprintln!("[verbose]   redirect_uri={redirect_uri}");
        eprintln!("[verbose]   client_id={client_id}");
    }

    let client = reqwest::Client::new();
    let resp = client
        .post(token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", code_verifier),
        ])
        .send()
        .await
        .map_err(|e| format!("Token exchange request failed: {e}"))?;

    if verbose {
        eprintln!("[verbose] Response: {}", resp.status());
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Token exchange failed (HTTP {status}): {body}"));
    }

    let token_response: TokenResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse token response: {e}"))?;

    if token_response.id_token.is_none() {
        return Err("No id_token in token response".to_string());
    }

    if verbose {
        eprintln!("[verbose] Received id_token");
        if token_response.refresh_token.is_some() {
            eprintln!("[verbose] Received refresh_token");
        }
    }

    Ok(token_response)
}
```

**Step 3: Delete old oidc.rs**

```bash
rm src/oidc.rs
```

**Step 4: Update main.rs module declaration**

In `src/main.rs`, the `mod oidc;` declaration already works for both a file and a directory module. Update the `run_login` function to use the new types:

Replace lines 123-161 of `src/main.rs` with:

```rust
async fn run_login(args: LoginArgs, verbose: bool) -> Result<(), String> {
    // 1. OIDC Discovery
    eprintln!("Discovering OIDC endpoints...");
    let discovery = oidc::discover(&args.issuer, verbose).await?;

    // 2. Browser-based OIDC login
    let token_response =
        oidc::auth_code::login(&discovery, &args.client_id, &args.scope, args.port, verbose).await?;
    let id_token = token_response
        .id_token
        .ok_or("No id_token in token response")?;
    eprintln!("Authentication successful.");

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
```

**Step 5: Verify it compiles and existing behavior is preserved**

Run: `cargo build`
Expected: Compiles successfully. No functional changes yet — still uses auth code flow only.

**Step 6: Commit**

```bash
git add -A && git commit -m "refactor: restructure oidc.rs into oidc/ module with expanded discovery"
```

---

### Task 2: Add device code flow

**Files:**
- Create: `src/oidc/device_code.rs`
- Modify: `src/oidc/mod.rs` (add `pub mod device_code;`)

**Step 1: Add device_code module declaration**

In `src/oidc/mod.rs`, add after `pub mod auth_code;`:

```rust
pub mod device_code;
```

**Step 2: Create device_code.rs**

Create `src/oidc/device_code.rs`:

```rust
use super::{OidcDiscovery, TokenResponse};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    #[serde(default = "default_interval")]
    interval: u64,
    expires_in: u64,
}

fn default_interval() -> u64 {
    5
}

#[derive(Debug, Deserialize)]
struct DeviceTokenErrorResponse {
    error: String,
    error_description: Option<String>,
}

/// Run the Device Code flow (RFC 8628). Returns a TokenResponse.
pub async fn login(
    discovery: &OidcDiscovery,
    client_id: &str,
    scope: &str,
    verbose: bool,
) -> Result<TokenResponse, String> {
    let device_endpoint = discovery
        .device_authorization_endpoint
        .as_ref()
        .ok_or("Provider does not support device authorization")?;

    if verbose {
        eprintln!("[verbose] POST {device_endpoint}");
        eprintln!("[verbose]   client_id={client_id}");
        eprintln!("[verbose]   scope={scope}");
    }

    // Step 1: Request device code
    let client = reqwest::Client::new();
    let resp = client
        .post(device_endpoint)
        .form(&[("client_id", client_id), ("scope", scope)])
        .send()
        .await
        .map_err(|e| format!("Device authorization request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "Device authorization failed (HTTP {status}): {body}"
        ));
    }

    let device_resp: DeviceAuthResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse device authorization response: {e}"))?;

    if verbose {
        eprintln!("[verbose] Device code received");
        eprintln!("[verbose] User code: {}", device_resp.user_code);
        eprintln!("[verbose] Verification URI: {}", device_resp.verification_uri);
        eprintln!("[verbose] Poll interval: {}s", device_resp.interval);
        eprintln!("[verbose] Expires in: {}s", device_resp.expires_in);
    }

    // Step 2: Display instructions to user
    eprintln!();
    eprintln!("To authenticate, visit:");
    eprintln!("  {}", device_resp.verification_uri);
    eprintln!();
    eprintln!("And enter code: {}", device_resp.user_code);
    eprintln!();

    // Try to open browser with the complete URI
    if let Some(ref complete_uri) = device_resp.verification_uri_complete {
        eprintln!("Opening browser...");
        if open::that(complete_uri).is_err() {
            eprintln!("Could not open browser automatically.");
        }
    }

    // Step 3: Poll for token
    let mut interval = device_resp.interval;
    let deadline =
        tokio::time::Instant::now() + tokio::time::Duration::from_secs(device_resp.expires_in);

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;

        if tokio::time::Instant::now() > deadline {
            return Err("Device code expired. Please try again.".to_string());
        }

        if verbose {
            eprintln!("[verbose] Polling token endpoint...");
        }

        let resp = client
            .post(&discovery.token_endpoint)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", &device_resp.device_code),
                ("client_id", client_id),
            ])
            .send()
            .await
            .map_err(|e| format!("Token poll request failed: {e}"))?;

        if resp.status().is_success() {
            let token_response: TokenResponse = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse token response: {e}"))?;

            if token_response.id_token.is_none() {
                return Err("No id_token in token response".to_string());
            }

            if verbose {
                eprintln!("[verbose] Received id_token");
                if token_response.refresh_token.is_some() {
                    eprintln!("[verbose] Received refresh_token");
                }
            }

            return Ok(token_response);
        }

        // Parse error response
        let body = resp
            .text()
            .await
            .unwrap_or_default();

        let error_resp: DeviceTokenErrorResponse = serde_json::from_str(&body)
            .unwrap_or(DeviceTokenErrorResponse {
                error: "unknown".to_string(),
                error_description: Some(body.clone()),
            });

        match error_resp.error.as_str() {
            "authorization_pending" => {
                if verbose {
                    eprintln!("[verbose] Authorization pending, waiting...");
                }
                continue;
            }
            "slow_down" => {
                interval += 5;
                if verbose {
                    eprintln!("[verbose] Slowing down, new interval: {interval}s");
                }
                continue;
            }
            "expired_token" => {
                return Err("Device code expired. Please try again.".to_string());
            }
            "access_denied" => {
                return Err("Access denied by user.".to_string());
            }
            other => {
                let desc = error_resp
                    .error_description
                    .map(|d| format!(": {d}"))
                    .unwrap_or_default();
                return Err(format!("Device code error ({other}){desc}"));
            }
        }
    }
}
```

**Step 3: Verify it compiles**

Run: `cargo build`
Expected: Compiles. device_code module exists but isn't called yet.

**Step 4: Commit**

```bash
git add -A && git commit -m "feat: add device code flow (RFC 8628)"
```

---

### Task 3: Add flow selection and --flow flag to CLI

**Files:**
- Modify: `src/main.rs` (add `--flow` flag, flow selection logic)
- Modify: `src/oidc/mod.rs` (add FlowType enum)

**Step 1: Add FlowType to oidc/mod.rs**

Add at the top of `src/oidc/mod.rs` (after imports):

```rust
use clap::ValueEnum;

#[derive(Debug, Clone, ValueEnum)]
pub enum FlowType {
    /// Automatically select the best flow
    Auto,
    /// Device code flow (works everywhere including headless)
    DeviceCode,
    /// Authorization code + PKCE flow (requires browser on same machine)
    AuthCode,
}
```

**Step 2: Update LoginArgs in main.rs**

Add the `--flow` flag to `LoginArgs`:

```rust
    /// Authentication flow to use
    #[arg(long, default_value = "auto")]
    flow: oidc::FlowType,
```

Change the default scope:

```rust
    /// OAuth2 scopes
    #[arg(long, default_value = "openid offline_access")]
    scope: String,
```

**Step 3: Update run_login with flow selection**

Replace the OIDC login section (step 2) in `run_login`:

```rust
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
```

**Step 4: Verify it compiles**

Run: `cargo build`
Expected: Compiles. `source-coop login --help` shows the new `--flow` flag.

**Step 5: Verify help output**

Run: `cargo run -- login --help`
Expected: Shows `--flow <FLOW>` with auto, device-code, auth-code options.

**Step 6: Commit**

```bash
git add -A && git commit -m "feat: add --flow flag with auto-selection (device code preferred)"
```

---

### Task 4: Add refresh token storage to cache.rs

**Files:**
- Modify: `src/cache.rs`

**Step 1: Add refresh token cache functions**

Add these functions to `src/cache.rs`, after the existing `is_expired` function (before `#[cfg(test)]`):

```rust
/// Compute a short, filesystem-safe key for an issuer URL.
fn issuer_key(issuer: &str) -> String {
    sanitize_role_arn(issuer)
}

/// Full path to the refresh token cache file for a given issuer.
fn refresh_cache_path(issuer: &str) -> Result<PathBuf, String> {
    let cache_dir = dirs::cache_dir().ok_or("Could not determine cache directory")?;
    let key = issuer_key(issuer);
    Ok(cache_dir
        .join("source-coop")
        .join("refresh")
        .join(format!("{key}.json")))
}

/// Refresh token data stored in cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenData {
    pub refresh_token: String,
    pub issuer: String,
    pub client_id: String,
}

fn write_refresh_token_file(data: &RefreshTokenData) -> Result<String, String> {
    let path = refresh_cache_path(&data.issuer)?;
    let dir = path.parent().unwrap();

    fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create refresh cache directory {}: {e}", dir.display()))?;

    let json = serde_json::to_string_pretty(data)
        .map_err(|e| format!("Failed to serialize refresh token: {e}"))?;

    fs::write(&path, &json)
        .map_err(|e| format!("Failed to write refresh token cache {}: {e}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set permissions on {}: {e}", path.display()))?;
    }

    Ok(path.display().to_string())
}

fn read_refresh_token_file(issuer: &str) -> Result<Option<RefreshTokenData>, String> {
    let path = refresh_cache_path(issuer)?;
    match fs::read_to_string(&path) {
        Ok(contents) => {
            let data: RefreshTokenData = serde_json::from_str(&contents)
                .map_err(|e| format!("Failed to parse refresh token cache: {e}"))?;
            Ok(Some(data))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "Failed to read refresh token cache {}: {e}",
            path.display()
        )),
    }
}

const REFRESH_KEYRING_PREFIX: &str = "source-coop-cli:refresh";

/// Write refresh token, trying OS keyring first with file fallback.
pub fn write_refresh_token(data: &RefreshTokenData) -> Result<String, String> {
    let json = serde_json::to_string(data)
        .map_err(|e| format!("Failed to serialize refresh token: {e}"))?;

    let key = issuer_key(&data.issuer);
    let entry = keyring::Entry::new(REFRESH_KEYRING_PREFIX, &key)
        .map_err(|e| format!("Failed to create keyring entry: {e}"));

    if let Ok(entry) = entry {
        match entry.set_password(&json) {
            Ok(()) => {
                return Ok(format!("OS keyring (service: {REFRESH_KEYRING_PREFIX})"));
            }
            Err(ref e) if is_keyring_unavailable(e) => {}
            Err(e) => {
                return Err(format!("Failed to write refresh token to keyring: {e}"));
            }
        }
    }

    write_refresh_token_file(data)
}

/// Read refresh token, trying OS keyring first with file fallback.
pub fn read_refresh_token(issuer: &str) -> Result<Option<RefreshTokenData>, String> {
    let key = issuer_key(issuer);
    let entry = keyring::Entry::new(REFRESH_KEYRING_PREFIX, &key)
        .map_err(|e| format!("Failed to create keyring entry: {e}"));

    if let Ok(entry) = entry {
        match entry.get_password() {
            Ok(json) => {
                let data: RefreshTokenData = serde_json::from_str(&json)
                    .map_err(|e| format!("Failed to parse refresh token from keyring: {e}"))?;
                return Ok(Some(data));
            }
            Err(keyring::Error::NoEntry) => {}
            Err(ref e) if is_keyring_unavailable(e) => {}
            Err(e) => {
                return Err(format!("Failed to read refresh token from keyring: {e}"));
            }
        }
    }

    read_refresh_token_file(issuer)
}

/// Delete refresh token from both keyring and file cache.
pub fn delete_refresh_token(issuer: &str) -> Result<(), String> {
    let key = issuer_key(issuer);

    // Try keyring
    if let Ok(entry) = keyring::Entry::new(REFRESH_KEYRING_PREFIX, &key) {
        let _ = entry.delete_credential();
    }

    // Try file
    if let Ok(path) = refresh_cache_path(issuer) {
        let _ = fs::remove_file(path);
    }

    Ok(())
}

/// Delete AWS credentials from both keyring and file cache.
pub fn delete_credentials(role_arn: &str) -> Result<(), String> {
    // Try keyring
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, role_arn) {
        let _ = entry.delete_credential();
    }

    // Try file
    if let Ok(path) = cache_path(role_arn) {
        let _ = fs::remove_file(path);
    }

    Ok(())
}
```

Also add `use serde::Serialize;` to the imports at the top (Credentials already derives Serialize via sts.rs, but RefreshTokenData needs it for the module).

Add to the top of cache.rs:

```rust
use serde::{Deserialize, Serialize};
```

Wait — `cache.rs` doesn't import serde directly. It uses `serde_json` for serialization but the `Credentials` struct derives `Serialize`/`Deserialize` in `sts.rs`. For `RefreshTokenData`, we need the derives in cache.rs itself. Add `use serde::{Serialize, Deserialize};` at the top of `cache.rs`.

**Step 2: Verify it compiles**

Run: `cargo build`
Expected: Compiles. New functions exist but aren't called yet.

**Step 3: Commit**

```bash
git add -A && git commit -m "feat: add refresh token cache with keyring and file fallback"
```

---

### Task 5: Add refresh token flow module

**Files:**
- Create: `src/oidc/refresh.rs`
- Modify: `src/oidc/mod.rs` (add `pub mod refresh;`)

**Step 1: Add refresh module declaration**

In `src/oidc/mod.rs`, add:

```rust
pub mod refresh;
```

**Step 2: Create refresh.rs**

Create `src/oidc/refresh.rs`:

```rust
use super::{OidcDiscovery, TokenResponse};

/// Exchange a refresh token for new tokens.
pub async fn refresh(
    discovery: &OidcDiscovery,
    client_id: &str,
    refresh_token: &str,
    verbose: bool,
) -> Result<TokenResponse, String> {
    if verbose {
        eprintln!("[verbose] POST {}", discovery.token_endpoint);
        eprintln!("[verbose]   grant_type=refresh_token");
        eprintln!("[verbose]   client_id={client_id}");
    }

    let client = reqwest::Client::new();
    let resp = client
        .post(&discovery.token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ])
        .send()
        .await
        .map_err(|e| format!("Refresh token request failed: {e}"))?;

    if verbose {
        eprintln!("[verbose] Response: {}", resp.status());
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Token refresh failed (HTTP {status}): {body}"));
    }

    let token_response: TokenResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse token response: {e}"))?;

    if token_response.id_token.is_none() {
        return Err("No id_token in refresh response".to_string());
    }

    if verbose {
        eprintln!("[verbose] Received refreshed id_token");
        if token_response.refresh_token.is_some() {
            eprintln!("[verbose] Received rotated refresh_token");
        }
    }

    Ok(token_response)
}

/// Revoke a refresh token at the provider's revocation endpoint.
pub async fn revoke(
    discovery: &OidcDiscovery,
    client_id: &str,
    refresh_token: &str,
    verbose: bool,
) -> Result<(), String> {
    let revocation_endpoint = match &discovery.revocation_endpoint {
        Some(ep) => ep,
        None => {
            if verbose {
                eprintln!("[verbose] No revocation endpoint; skipping token revocation");
            }
            return Ok(());
        }
    };

    if verbose {
        eprintln!("[verbose] POST {revocation_endpoint}");
        eprintln!("[verbose]   token_type_hint=refresh_token");
        eprintln!("[verbose]   client_id={client_id}");
    }

    let client = reqwest::Client::new();
    let resp = client
        .post(revocation_endpoint)
        .form(&[
            ("token", refresh_token),
            ("token_type_hint", "refresh_token"),
            ("client_id", client_id),
        ])
        .send()
        .await
        .map_err(|e| format!("Token revocation request failed: {e}"))?;

    if verbose {
        eprintln!("[verbose] Revocation response: {}", resp.status());
    }

    // RFC 7009: revocation endpoint returns 200 even if token was already invalid
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        eprintln!("Warning: token revocation returned HTTP {status}: {body}");
    }

    Ok(())
}
```

**Step 3: Verify it compiles**

Run: `cargo build`
Expected: Compiles.

**Step 4: Commit**

```bash
git add -A && git commit -m "feat: add refresh token exchange and revocation"
```

---

### Task 6: Wire refresh token caching into login flow

**Files:**
- Modify: `src/main.rs` (cache refresh token after login)

**Step 1: Update run_login to cache refresh token**

After the "Authentication successful" line in `run_login`, add refresh token caching:

```rust
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
```

**Step 2: Verify it compiles**

Run: `cargo build`
Expected: Compiles.

**Step 3: Commit**

```bash
git add -A && git commit -m "feat: cache refresh token during login"
```

---

### Task 7: Add auto-refresh to creds command

**Files:**
- Modify: `src/main.rs` (update `CredsArgs` and `run_creds`)

**Step 1: Update CredsArgs with refresh-related fields**

```rust
#[derive(Parser)]
struct CredsArgs {
    /// Role ARN to read cached credentials for
    #[arg(long, env = "SOURCE_ROLE_ARN", default_value = defaults::ROLE_ARN)]
    role_arn: String,

    /// Output format
    #[arg(long, default_value = "credential-process")]
    format: OutputFormat,

    /// Skip automatic refresh of expired credentials
    #[arg(long)]
    no_refresh: bool,

    /// OIDC issuer URL (needed for auto-refresh)
    #[arg(long, env = "SOURCE_OIDC_ISSUER", default_value = defaults::ISSUER)]
    issuer: String,

    /// S3 proxy URL for STS (needed for auto-refresh)
    #[arg(long, env = "SOURCE_PROXY_URL", default_value = defaults::PROXY_URL)]
    proxy_url: String,
}
```

**Step 2: Make run_creds async and add auto-refresh logic**

Change `run_creds` to async:

```rust
async fn run_creds(args: CredsArgs, verbose: bool) -> Result<(), String> {
    let creds = cache::read_credentials(&args.role_arn)?
        .ok_or("No cached credentials found. Run 'source-coop login' first.")?;

    if !cache::is_expired(&creds)? {
        // Credentials still valid, output them
        match args.format {
            OutputFormat::CredentialProcess => output::print_credential_process(&creds),
            OutputFormat::Env => output::print_env(&creds),
        }
        return Ok(());
    }

    // Credentials expired — try auto-refresh
    if args.no_refresh {
        return Err(
            "Cached credentials have expired. Run 'source-coop login' to refresh.".to_string(),
        );
    }

    let refresh_data = cache::read_refresh_token(&args.issuer)?;
    let refresh_data = match refresh_data {
        Some(data) => data,
        None => {
            return Err(
                "Cached credentials have expired and no refresh token found. Run 'source-coop login'.".to_string(),
            );
        }
    };

    if verbose {
        eprintln!("[verbose] Credentials expired, attempting auto-refresh...");
    }
    eprintln!("Credentials expired. Refreshing...");

    // Discover endpoints for refresh
    let discovery = oidc::discover(&refresh_data.issuer, verbose).await?;

    // Refresh tokens
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

    // Update cached refresh token if rotated
    if let Some(ref new_refresh_token) = token_response.refresh_token {
        let new_data = cache::RefreshTokenData {
            refresh_token: new_refresh_token.clone(),
            issuer: refresh_data.issuer.clone(),
            client_id: refresh_data.client_id.clone(),
        };
        let _ = cache::write_refresh_token(&new_data);
    }

    // STS exchange
    let creds = sts::assume_role(
        &args.proxy_url,
        &args.role_arn,
        &id_token,
        None,
        verbose,
    )
    .await?;

    // Cache new credentials
    let location = cache::write_credentials(&args.role_arn, &creds)?;
    if verbose {
        eprintln!("[verbose] Refreshed credentials cached to {location}");
    }
    eprintln!("Credentials refreshed.");

    match args.format {
        OutputFormat::CredentialProcess => output::print_credential_process(&creds),
        OutputFormat::Env => output::print_env(&creds),
    }
    Ok(())
}
```

**Step 3: Update the main() match arm for Creds**

Update the `Commands::Creds` arm in `main()` to pass verbose and use `.await`:

```rust
        Commands::Creds(args) => {
            if let Err(e) = run_creds(args, verbose).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
```

**Step 4: Verify it compiles**

Run: `cargo build`
Expected: Compiles.

**Step 5: Verify help output**

Run: `cargo run -- creds --help`
Expected: Shows `--no-refresh`, `--issuer`, `--proxy-url` flags.

**Step 6: Commit**

```bash
git add -A && git commit -m "feat: add auto-refresh of expired credentials in creds command"
```

---

### Task 8: Add logout command

**Files:**
- Modify: `src/main.rs` (add Logout command)

**Step 1: Add LogoutArgs and Logout command variant**

Add to the `Commands` enum:

```rust
    /// Clear cached credentials and revoke refresh token
    Logout(LogoutArgs),
```

Add the struct:

```rust
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
```

**Step 2: Add run_logout function**

```rust
async fn run_logout(args: LogoutArgs, verbose: bool) -> Result<(), String> {
    // Revoke refresh token if we have one
    if let Some(refresh_data) = cache::read_refresh_token(&args.issuer)? {
        if verbose {
            eprintln!("[verbose] Found cached refresh token, attempting revocation...");
        }

        // Best-effort discovery + revocation
        match oidc::discover(&args.issuer, verbose).await {
            Ok(discovery) => {
                if let Err(e) = oidc::refresh::revoke(
                    &discovery,
                    &args.client_id,
                    &refresh_data.refresh_token,
                    verbose,
                )
                .await
                {
                    eprintln!("Warning: could not revoke refresh token: {e}");
                }
            }
            Err(e) => {
                eprintln!("Warning: could not discover endpoints for revocation: {e}");
            }
        }
    }

    // Delete cached refresh token
    cache::delete_refresh_token(&args.issuer)?;
    eprintln!("Refresh token cleared.");

    // Delete cached AWS credentials
    cache::delete_credentials(&args.role_arn)?;
    eprintln!("Cached credentials cleared.");

    Ok(())
}
```

**Step 3: Add the match arm in main()**

```rust
        Commands::Logout(args) => {
            if let Err(e) = run_logout(args, verbose).await {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
```

**Step 4: Verify it compiles**

Run: `cargo build`
Expected: Compiles. `source-coop logout --help` shows expected flags.

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: add logout command with token revocation"
```

---

### Task 9: Final integration verification

**Files:** None (testing only)

**Step 1: Verify full build**

Run: `cargo build`
Expected: Clean compile.

**Step 2: Verify all help output**

Run: `cargo run -- --help`
Expected: Shows login, creds, logout commands.

Run: `cargo run -- login --help`
Expected: Shows --flow, --issuer, --client-id, --scope (default "openid offline_access"), etc.

Run: `cargo run -- creds --help`
Expected: Shows --no-refresh, --issuer, --proxy-url.

Run: `cargo run -- logout --help`
Expected: Shows --issuer, --client-id, --role-arn.

**Step 3: Run existing tests**

Run: `cargo test`
Expected: All existing tests pass.

**Step 4: Commit any final adjustments**

```bash
git add -A && git commit -m "chore: final integration verification"
```

---

### Summary of all tasks

| Task | Description | Key files |
|------|-------------|-----------|
| 1 | Restructure oidc.rs → oidc/ module | oidc/mod.rs, oidc/auth_code.rs |
| 2 | Add device code flow | oidc/device_code.rs |
| 3 | Add --flow flag and flow selection | main.rs, oidc/mod.rs |
| 4 | Add refresh token cache | cache.rs |
| 5 | Add refresh token flow module | oidc/refresh.rs |
| 6 | Wire refresh caching into login | main.rs |
| 7 | Add auto-refresh to creds | main.rs |
| 8 | Add logout command | main.rs |
| 9 | Final integration verification | — |
