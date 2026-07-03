use serde::Deserialize;
use std::time::{Duration, Instant};

use super::{OidcDiscovery, TokenResponse};

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

/// Run the RFC 8628 device code flow.
/// Requests a device code, prompts the user to visit a verification URL,
/// and polls the token endpoint until authentication completes or times out.
pub async fn login(
    discovery: &OidcDiscovery,
    client_id: &str,
    scope: &str,
    verbose: bool,
) -> Result<TokenResponse, String> {
    let device_endpoint = discovery
        .device_authorization_endpoint
        .as_deref()
        .ok_or("OIDC provider does not support device authorization")?;

    if verbose {
        eprintln!("[verbose] POST {device_endpoint}");
        eprintln!("[verbose]   client_id={client_id}");
        eprintln!("[verbose]   scope={scope}");
    }

    // Step 1: Request device authorization
    let client = reqwest::Client::new();
    let resp = client
        .post(device_endpoint)
        .form(&[("client_id", client_id), ("scope", scope)])
        .send()
        .await
        .map_err(|e| format!("Device authorization request failed: {e}"))?;

    if verbose {
        eprintln!("[verbose] Response: {}", resp.status());
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "Device authorization failed (HTTP {status}): {body}"
        ));
    }

    let device_auth: DeviceAuthResponse = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse device authorization response: {e}"))?;

    if verbose {
        eprintln!(
            "[verbose] Device code received, expires in {}s, poll interval {}s",
            device_auth.expires_in, device_auth.interval
        );
    }

    // Step 2: Display verification info to user
    eprintln!();
    eprintln!(
        "To sign in, open this URL in your browser:\n  {}",
        device_auth.verification_uri
    );
    eprintln!();
    eprintln!("Then enter the code:\n  {}", device_auth.user_code);
    eprintln!();

    // Step 3: Try to open browser
    let browser_url = device_auth
        .verification_uri_complete
        .as_deref()
        .unwrap_or(&device_auth.verification_uri);
    if verbose {
        eprintln!("[verbose] Opening {browser_url} in browser");
    }
    if open::that(browser_url).is_err() {
        eprintln!("Could not open browser automatically.");
    }

    eprintln!("Waiting for authentication...");

    // Step 4: Poll token endpoint
    let deadline = Instant::now() + Duration::from_secs(device_auth.expires_in);
    let mut interval = device_auth.interval;

    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;

        if Instant::now() >= deadline {
            return Err("Device code expired — please try again".to_string());
        }

        if verbose {
            eprintln!(
                "[verbose] POST {} (polling, interval={}s)",
                discovery.token_endpoint, interval
            );
        }

        let resp = client
            .post(&discovery.token_endpoint)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", &device_auth.device_code),
                ("client_id", client_id),
            ])
            .send()
            .await
            .map_err(|e| format!("Token poll request failed: {e}"))?;

        let status = resp.status();

        if verbose {
            eprintln!("[verbose] Poll response: {status}");
        }

        if status.is_success() {
            let token_response: TokenResponse = resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse token response: {e}"))?;

            if verbose {
                eprintln!(
                    "[verbose] Token response contains: id_token={}, refresh_token={}, access_token={}",
                    token_response.id_token.is_some(),
                    token_response.refresh_token.is_some(),
                    token_response.access_token.is_some(),
                );
            }

            return Ok(token_response);
        }

        // Parse the error response
        let body = resp
            .text()
            .await
            .map_err(|e| format!("Failed to read token error response: {e}"))?;

        let error_resp: DeviceTokenErrorResponse = serde_json::from_str(&body)
            .map_err(|e| format!("Failed to parse token error response: {e}"))?;

        match error_resp.error.as_str() {
            "authorization_pending" => {
                if verbose {
                    eprintln!("[verbose] Authorization pending, will retry...");
                }
            }
            "slow_down" => {
                interval += 5;
                if verbose {
                    eprintln!("[verbose] Received slow_down, increasing interval to {interval}s");
                }
            }
            "expired_token" => {
                return Err("Device code expired — please try again".to_string());
            }
            "access_denied" => {
                return Err("Access denied by user".to_string());
            }
            other => {
                let desc = error_resp
                    .error_description
                    .map(|d| format!(": {d}"))
                    .unwrap_or_default();
                return Err(format!("Token request failed ({other}){desc}"));
            }
        }
    }
}
