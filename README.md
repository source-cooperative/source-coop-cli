# source-coop CLI

Authenticate with the Source Cooperative data proxy and obtain temporary S3 credentials.

Uses the OAuth2 Authorization Code flow with PKCE to authenticate via browser, then exchanges the OIDC ID token at the proxy's STS endpoint for temporary AWS credentials.

## Install

### From GitHub Releases (recommended)

**macOS / Linux:**

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/source-cooperative/source-coop-cli/releases/latest/download/source-coop-cli-installer.sh | sh
```

**Windows PowerShell:**

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://github.com/source-cooperative/source-coop-cli/releases/latest/download/source-coop-cli-installer.ps1 | iex"
```

### Homebrew (macOS / Linux)

```bash
brew install source-cooperative/tap/source-coop
```

### From source

```bash
cargo install --git https://github.com/source-cooperative/source-coop-cli
```

## Usage

### Using with AWS credential_process

1. Log in once (opens browser, caches credentials to the OS keyring):

```bash
source-coop login
```

2. Configure `~/.aws/config` to use cached credentials:

```ini
[profile source-coop]
credential_process = source-coop creds
endpoint_url = https://data.source.coop
```

3. Use AWS tools normally:

```bash
aws s3 ls s3://my-bucket/ --profile source-coop
```

When credentials expire, run `source-coop login` again.

### Checking the CLI version

```bash
source-coop --version
```

### Setting credentials on the environment

After logging in, you can export cached credentials as environment variables:

```bash
eval $(source-coop creds --format env)
```

This sets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` in your current shell.

### Multiple roles

Each role's credentials are cached separately:

```bash
source-coop login --role-arn reader-role
source-coop login --role-arn admin-role
```

Use `creds` with `--role-arn` to select which role to output:

```ini
[profile source-coop]
credential_process = source-coop creds --role-arn reader-role
endpoint_url = https://data.source.coop

[profile source-coop-admin]
credential_process = source-coop creds --role-arn admin-role
endpoint_url = https://data.source.coop
```

### Login options

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--issuer` | `SOURCE_OIDC_ISSUER` | `https://auth.source.coop` | OIDC issuer URL |
| `--client-id` | `SOURCE_OIDC_CLIENT_ID` | `d037d00b-...` | OAuth2 client ID |
| `--proxy-url` | `SOURCE_PROXY_URL` | `https://data.source.coop` | S3 proxy URL for STS |
| `--role-arn` | `SOURCE_ROLE_ARN` | `source-coop-user` | Role ARN to assume |
| `--format` | | `credential-process` | Output format: `credential-process` or `env` |
| `--duration` | | | Session duration in seconds |
| `--scope` | | `openid` | OAuth2 scopes |
| `--port` | | `0` (random) | Local callback port |
| `--no-cache` | | | Skip caching credentials (just print to stdout) |

### Output formats

Both `login` and `creds` support `--format` to control output:

**credential-process** (default) — AWS credential_process JSON:

```bash
source-coop creds
```

**env** — shell export statements:

```bash
eval $(source-coop creds --format env)
```

## Credential storage

The CLI caches temporary STS credentials so that `creds` can output them without re-authenticating.

### OS keyring (default)

Credentials are stored in the OS-native keyring under the service name `source-coop-cli`, keyed by role ARN:

| Platform | Backend |
|----------|---------|
| macOS | Keychain (`security` / Keychain Access) |
| Windows | Credential Manager |
| Linux | Secret Service API (GNOME Keyring, KDE Wallet) via D-Bus |

### File fallback

When the OS keyring is unavailable (headless servers, containers, CI), the CLI falls back to JSON files in the OS cache directory with `0600` permissions on Unix:

| Platform | Path |
|----------|------|
| macOS | `~/Library/Caches/source-coop/credentials/<role>.json` |
| Linux | `~/.cache/source-coop/credentials/<role>.json` |
| Windows | `%LocalAppData%\source-coop\credentials\<role>.json` |

The fallback is automatic — no configuration is needed.

## OIDC provider setup

The CLI uses the OAuth2 Authorization Code flow with PKCE. It starts a temporary local server on `http://127.0.0.1:{port}/callback` to receive the authorization code redirect.

The OAuth2 client must have a matching redirect URI registered. There are two approaches:

### Option A: Allow any port (recommended)

Register `http://127.0.0.1/callback` as a redirect URI on the OAuth2 client. Per [RFC 8252 Section 7.3](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3), loopback redirect URIs should allow any port. Ory Network follows this convention — registering the base URI without a port permits any port.

The CLI defaults to `--port 0` (OS-assigned random available port), which works with this setup.

### Option B: Fixed port

Register a specific redirect URI (e.g. `http://127.0.0.1:8400/callback`) and run the CLI with the matching port:

```bash
source-coop login --role-arn <ARN> --port 8400
```

### Client configuration

The OAuth2 client should be configured as a **public client** (no client secret) with:

- **Grant type**: Authorization Code
- **Token endpoint auth method**: `none` (public client, PKCE used instead)
- **Allowed scopes**: `openid`
- **Redirect URIs**: `http://127.0.0.1/callback` (see above)
