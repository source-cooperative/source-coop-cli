# source-coop CLI

Authenticate with the Source Cooperative data proxy and obtain temporary S3 credentials.

Uses the OAuth2 Authorization Code flow with PKCE to authenticate via browser, then exchanges the OIDC ID token at the proxy's STS endpoint for temporary AWS credentials. Software that runs unattended can instead exchange a service account's API key, with no browser (see [Using an API key](#using-an-api-key-no-browser)).

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
aws s3 ls s3://my-account/my-product --profile source-coop
```

When credentials are about to expire, `source-coop creds` uses the cached refresh token to fetch new ones automatically. Run `source-coop login` again only when that fails (e.g. the refresh token has expired or been revoked).

`creds` replaces credentials once they have 16 minutes left, or half the session if that is shorter. AWS SDKs ask `credential_process` for new credentials 5 to 15 minutes before expiry, so they get fresh ones on the first ask instead of rerunning `creds` for every request. If replacing them fails, `creds` serves the cached credentials, with a warning, until they expire.

### Logging in on a remote server (no browser)

`login` receives the OAuth2 redirect on a local port, so on a headless machine, forward that port over SSH and complete the login in your local browser:

1. Connect with a port forward (any free port works; `8400` is used here):

```bash
ssh -L 8400:127.0.0.1:8400 user@server
```

2. On the server, log in using the forwarded port:

```bash
source-coop login --port 8400
```

3. Open the URL the CLI prints in your local browser. After you sign in, the redirect to `http://127.0.0.1:8400/callback` travels through the tunnel to the CLI on the server.

Credentials are cached on the server (see [File fallback](#file-fallback)), and `source-coop creds` refreshes them there without another browser login.

### Using an API key (no browser)

Software that runs unattended, such as a cron job, a daemon or an instrument, authenticates as a service account with an API key (`sck_…`) rather than a browser login. `creds` exchanges the key at the proxy's STS endpoint, caches the credentials as it does for `login`, and exchanges the key again before they expire, so a long-running process keeps working without a person.

1. Save the key, which is shown only once when you issue it, to a file only you can read:

```bash
mkdir -p ~/.config/source-coop
(umask 077 && cat > ~/.config/source-coop/key)   # paste the key, press Enter, then Ctrl-D
```

2. Point `credential_process` at it in `~/.aws/config`, using the full path (`~` is not expanded there):

```ini
[profile source-coop]
credential_process = source-coop creds --api-key-file /home/me/.config/source-coop/key
endpoint_url = https://data.source.coop
```

3. Use AWS tools as usual:

```bash
aws s3 ls s3://my-account/my-product --profile source-coop
```

Instead of `--api-key-file`, the environment can supply the key: `SOURCE_API_KEY_FILE` names the file, or `SOURCE_API_KEY` holds the key itself. The file wins if both are set. No flag takes the key itself, because other users on the machine can read a command line.

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--api-key-file` | `SOURCE_API_KEY_FILE` | | File holding the API key |
| | `SOURCE_API_KEY` | | The API key itself |
| `--role-arn` | `SOURCE_ROLE_ARN` | `_default` | Role to assume: a name such as `ReadOnly` (sent as `arn:aws:iam::000000000000:role/ReadOnly`) or a full ARN; see [Multiple roles](#multiple-roles) |
| `--proxy-url` | `SOURCE_PROXY_URL` | `https://data.source.coop` | Proxy whose `/.sts` exchanges the key |
| `--duration` | | | Session duration, e.g. `3600`, `90s`, `5m`, `12h`, `1d` |

If the proxy refuses the key, `creds` prints the proxy's error and exits non-zero. Quote the request id when you contact support:

```
Error: STS error (InvalidIdentityToken): API key was not accepted (request id a40cee47fef1c4b4)
```

#### GDAL

GDAL 3.12 and later run `credential_process` from the profile too. GDAL can't exchange the key on its own, because it sends its STS request as a GET with the token in the URL, and the proxy refuses a key in a URL. It gets credentials through the CLI instead. GDAL ignores the profile's `endpoint_url`, so name the proxy in `AWS_S3_ENDPOINT`:

```bash
AWS_PROFILE=source-coop AWS_S3_ENDPOINT=https://data.source.coop AWS_VIRTUAL_HOSTING=FALSE \
  gdalinfo /vsis3/my-account/my-product/image.tif
```

With an older GDAL, export credentials into the environment instead. They are not refreshed, so run this again before they expire:

```bash
eval "$(source-coop creds --api-key-file ~/.config/source-coop/key --format env)"
```

#### Without the CLI

AWS SDKs and the AWS CLI can exchange the key themselves and refresh on their own, with nothing else installed. Point `AWS_WEB_IDENTITY_TOKEN_FILE` at the key file and set four more variables:

```bash
export AWS_WEB_IDENTITY_TOKEN_FILE=$HOME/.config/source-coop/key
export AWS_ROLE_ARN=arn:aws:iam::000000000000:role/_default
export AWS_ENDPOINT_URL_STS=https://data.source.coop/.sts
export AWS_ENDPOINT_URL_S3=https://data.source.coop
export AWS_REGION=us-west-2   # required by the SDK; says nothing about where data lives
aws s3 ls s3://my-account/my-product/
```

This needs an SDK that reads `AWS_ENDPOINT_URL_STS`: the AWS CLI 2.13 or later, boto3/botocore 1.31 or later, or a current Go v2, JavaScript v3 or Java 2.x SDK. `aws --debug` prints the key, so don't share its output.

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

> [!WARNING]
> Custom roles are not yet supported within the Source Cooperative data proxy. 

A bare role name such as `reader-role` reaches the proxy as `arn:aws:iam::000000000000:role/reader-role`, the ARN form AWS SDKs send; a full ARN is sent as given. Each role's credentials are cached separately:

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
| `--role-arn` | `SOURCE_ROLE_ARN` | `_default` | Role to assume: a name such as `ReadOnly`, or a full ARN |
| `--format` | | `credential-process` | Output format: `credential-process`, `env`, or `aws-credentials` |
| `--profile` | | `source-coop` | Profile name for `--format aws-credentials` |
| `--duration` | | | Session duration, e.g. `3600`, `90s`, `5m`, `12h`, `1d` (bare number = seconds) |
| `--scope` | | `openid offline_access` | OAuth2 scopes (`offline_access` enables automatic refresh in `creds`) |
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

**aws-credentials** — an INI profile you can write directly to `~/.aws/credentials`:

```bash
source-coop creds --format aws-credentials >> ~/.aws/credentials
```

```ini
[source-coop]
# expires 2026-07-13T12:00:00Z
aws_access_key_id = ...
aws_secret_access_key = ...
aws_session_token = ...
```

Use `--profile` to change the section name.

> [!TIP]
> The credentials are temporary; re-run after expiry (appending adds a duplicate section — AWS uses the last one, but prune stale sections occasionally). We recommend the utilizing `credential-process` in `~/.aws/config` rather storing temporary credentials in `~/.aws/credentials`.

## Credential storage

The CLI caches temporary STS credentials so that `creds` can output them without re-authenticating.

### OS keyring (default)

Credentials are stored in the OS-native keyring under the service name `source-coop-cli`, keyed by role. An API key's credentials are keyed by role and a prefix of the key's SHA-256, so they never mix with a `login` session's or another key's; the key itself is never stored.

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
