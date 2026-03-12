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
