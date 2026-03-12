pub mod auth_code;
pub mod device_code;
pub mod refresh;

use clap::ValueEnum;
use serde::Deserialize;

#[derive(Debug, Clone, ValueEnum)]
pub enum FlowType {
    /// Automatically select the best available flow
    Auto,
    /// Device code flow (works everywhere including headless/SSH)
    DeviceCode,
    /// Authorization code + PKCE flow (requires browser on same machine)
    AuthCode,
}

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

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<u64>,
}

/// Fetch OIDC discovery document and deserialize into OidcDiscovery.
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
        eprintln!(
            "[verbose] Authorization endpoint: {}",
            discovery.authorization_endpoint
        );
        eprintln!("[verbose] Token endpoint: {}", discovery.token_endpoint);
    }

    Ok(discovery)
}
