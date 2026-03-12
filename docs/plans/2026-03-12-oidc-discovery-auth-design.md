# OIDC Discovery-Driven Auth Rework

## Summary

Replace the current single-flow (Authorization Code + PKCE) auth with a discovery-driven system that reads the provider's OIDC discovery document and selects the best available flow. Adds Device Code and Refresh Token flows.

## Decisions

- **Scope**: Source Coop focused. STS exchange always required. Source Coop defaults retained.
- **Flows**: Authorization Code + PKCE, Device Code (RFC 8628), Refresh Token.
- **Flow priority**: device code (if provider supports it) > auth code. Override with `--flow`.
- **Refresh token storage**: Separate keyring entry (with file fallback), keyed by issuer.
- **Auto-refresh**: `source-coop creds` silently refreshes expired AWS credentials using cached refresh token.
- **Approach**: Modular flow architecture. Each flow is a separate module returning an ID token.

## Architecture

```
source-coop login
       |
       v
  Discovery        Fetch & parse .well-known/openid-configuration
       |
       v
  Flow Select      --flow flag > device_code > auth_code
       |
       v
  Flow Execution   auth_code | device_code | refresh
       |            Each returns id_token + optional refresh_token
       v
  STS Exchange     Unchanged: id_token -> AssumeRoleWithWebIdentity
       |
       v
  Cache + Output   Store AWS creds + refresh token separately
```

## Components

### Discovery

Parse the full OIDC discovery document:

```rust
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub device_authorization_endpoint: Option<String>,
    pub revocation_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub grant_types_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
}
```

`device_authorization_endpoint` is optional since not all providers expose it. `grant_types_supported` drives flow selection.

### Flow Selection

Priority:

1. `--flow device-code` -> device code (error if unsupported)
2. `--flow auth-code` -> auth code (error if unsupported)
3. `--flow auto` (default): device code if `device_code` in `grant_types_supported` AND `device_authorization_endpoint` present, else auth code + PKCE

### Device Code Flow (RFC 8628)

1. POST `device_authorization_endpoint` with `client_id`, `scope`
2. Receive `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `interval`, `expires_in`
3. Display: "Visit {verification_uri} and enter code: {user_code}". Open `verification_uri_complete` in browser.
4. Poll `token_endpoint` every `interval` seconds with `grant_type=urn:ietf:params:oauth:grant-type:device_code`
5. Handle: `authorization_pending` (continue), `slow_down` (increase interval), `expired_token` (error), success (extract `id_token`)

### Auth Code Flow (existing, reorganized)

Existing PKCE flow moves into its own module. No functional changes.

### Refresh Token

**Storage**: Separate keyring entry keyed as `source-coop-cli:refresh:{issuer_hash}`. File fallback at `~/.cache/source-coop/refresh/{issuer_hash}.json` (0600 permissions).

**During login**: Cache `refresh_token` from token response if present.

**During `creds`**: If AWS creds expired and refresh token exists:
1. POST `token_endpoint` with `grant_type=refresh_token`, `refresh_token`, `client_id`
2. Get new `id_token` (and possibly rotated `refresh_token`)
3. STS exchange -> new AWS creds -> cache

**Scope**: Default scope becomes `openid offline_access` to request refresh tokens.

### CLI Changes

**`login` additions:**
- `--flow <auto|device-code|auth-code>` (default: `auto`)
- Default scope: `openid offline_access`

**`creds` additions:**
- Auto-refresh on expired creds (silent, using cached refresh token)
- `--no-refresh` flag to skip auto-refresh

**New `logout` command:**
- Revoke refresh token via revocation endpoint
- Clear cached AWS credentials
- Clear cached refresh token

### File Structure

```
src/
  main.rs           CLI args, command dispatch
  oidc/
    mod.rs          Discovery, flow selection, OidcDiscovery struct
    auth_code.rs    Authorization Code + PKCE flow (moved from oidc.rs)
    device_code.rs  Device Code flow (new)
    refresh.rs      Refresh token handling (new)
  sts.rs            Unchanged
  cache.rs          Extended with refresh token storage
  output.rs         Unchanged
```

## Provider Reference

Source Coop's OIDC discovery (`https://auth.source.coop/.well-known/openid-configuration`) advertises:
- `grant_types_supported`: authorization_code, implicit, client_credentials, refresh_token, device_code
- `device_authorization_endpoint`: present
- `revocation_endpoint`: present
- `scopes_supported`: openid, offline_access, offline
- `code_challenge_methods_supported`: plain, S256
