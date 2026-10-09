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
aws s3 ls s3://my-account/my-product --profile source-coop
```

When credentials expire, `source-coop creds` uses the cached refresh token to fetch new ones automatically. Run `source-coop login` again only when that fails (e.g. the refresh token has expired or been revoked).

`login` keeps one session for everything: `creds` for any role exchanges its ID token at the proxy, and commands that call the source.coop API send its access token. `source-coop auth token` prints that access token, refreshed if it has expired:

```bash
curl -H "Authorization: Bearer $(source-coop auth token)" https://source.coop/api/v1/...
```

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
| `--format` | | `credential-process` | Output format: `credential-process`, `env`, or `aws-credentials` |
| `--profile` | | `source-coop` | Profile name for `--format aws-credentials` |
| `--duration` | | | Session duration, e.g. `3600`, `90s`, `5m`, `12h`, `1d` (bare number = seconds) |
| `--scope` | | `openid offline_access` | OAuth2 scopes (`offline_access` enables automatic refresh in `creds`) |
| `--audience` | `SOURCE_API_AUDIENCE` | `https://source.coop` | Audience of the access token for the source.coop API; empty to request none |
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

## Managing products

`source-coop product` lists, views, creates, edits and deletes products through the source.coop API (`/api/v1`), with the same rules as the web UI: the CLI checks nothing itself and shows the API's errors, field by field.

```bash
source-coop product list                      # public products
source-coop product list my-org --json        # one account's products, as JSON
source-coop product view my-org/my-product    # --web opens it in the browser
source-coop product create my-org/my-product  # prompts for the rest
source-coop product edit my-org/my-product --visibility unlisted
source-coop product delete my-org/my-product  # asks you to type the name back
```

`create` and `edit` take each field as a flag (`--title`, `--description`, `--visibility`, `--data-connection`), from a JSON object with `--from-file PATH` (`-` for stdin), or both, with flags winning. In a terminal, whatever is still missing is asked for, with defaults: a title made from the product ID, the data connections the account can use, and the visibilities the chosen connection allows. A description can be typed on one line, or written in your editor (`$VISUAL` or `$EDITOR`) by answering `e`. `edit` with no flags asks which fields to change and starts each from its current value. When the API rejects a field, you see why and are asked for just that field again. Without a terminal, or with `SOURCE_PROMPT_DISABLED` set, nothing is asked: the request is sent as given, and `delete` needs `--yes`.

Output is for people on a terminal and for scripts when piped: `list` prints an aligned table with a header on a terminal, and tab-separated rows without one when piped; `create` and `edit` print the product's URL on stdout and their message on stderr, so `url=$(source-coop product create ...)` works.

### Any API request

`source-coop api` sends any request to `/api/v1`, signed in as you, and prints the response. It covers what the other commands don't yet:

```bash
source-coop api products/my-org -X GET -F limit=5
source-coop api products/my-org -f product_id=new -f title="New" -f description="" \
  -f visibility=public -f data_connection_id=my-connection
source-coop api products/my-org/new -X PATCH --input changes.json
```

`-f key=value` sends a string, and `-F key=value` sends `true`, `false`, `null` and numbers as JSON. Fields go in the query string for `GET` and in a JSON body otherwise, and the method is `POST` when fields or `--input` are given. A status other than success exits non-zero.

Reading public products needs no credentials. Anything else acts as whoever ran `source-coop login`: login asks Ory for an access token meant for the API (`--audience`, default `https://source.coop`) and refreshes it as needed. `SOURCE_TOKEN`, if set, is sent instead. `--api-url` (or `SOURCE_API_URL`) points the CLI at another deployment, such as a local `http://localhost:3000`.

## Credential storage

The CLI caches the login session (the Ory refresh, ID and access tokens) and the temporary STS credentials for each role, so that `creds` and API commands work without re-authenticating. The refresh token is kept in the session only: it rotates on use, so every role and every API call refreshes through it, one at a time.

### OS keyring (default)

Credentials are stored in the OS-native keyring under the service name `source-coop-cli`, keyed by role ARN, with the session under `@session`:

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

The session sits beside them, at `source-coop/session.json`.

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
- **Allowed scopes**: `openid`, `offline_access`
- **Redirect URIs**: `http://127.0.0.1/callback` (see above)
- **Allowed audiences**: the source.coop site the API is served from (`https://source.coop`, or `https://staging.source.coop`). Without it, Ory refuses a login that asks for that audience.
- **Access token strategy**: `jwt`, so the API can verify access tokens against Ory's published keys rather than asking Ory about each one
