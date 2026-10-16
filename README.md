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
source-coop auth login
```

   `source-coop login`, its name before `auth` held it, still works.

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

When credentials expire, `source-coop creds` uses the cached refresh token to fetch new ones automatically. Run `source-coop auth login` again only when that fails (e.g. the refresh token has expired or been revoked).

`auth login` keeps one session for everything: `creds` for any role exchanges its ID token at the proxy, and commands that call the source.coop API send its access token. `source-coop auth token` prints that access token, refreshed if it has expired:

```bash
curl -H "Authorization: Bearer $(source-coop auth token)" https://source.coop/api/v1/...
```

### Logging in on a remote server (no browser)

`auth login` receives the OAuth2 redirect on a local port, so on a headless machine, forward that port over SSH and complete the login in your local browser:

1. Connect with a port forward (any free port works; `8400` is used here):

```bash
ssh -L 8400:127.0.0.1:8400 user@server
```

2. On the server, log in using the forwarded port:

```bash
source-coop auth login --port 8400
```

3. Open the URL the CLI prints in your local browser. After you sign in, the redirect to `http://127.0.0.1:8400/callback` travels through the tunnel to the CLI on the server.

Credentials are cached on the server (see [File fallback](#file-fallback)), and `source-coop creds` refreshes them there without another browser login.

### Checking the CLI version

```bash
source-coop --version
```

### Checking login status

`auth status` shows whether you're logged in and as whom, and when the cached tokens and a role's credentials expire. It works from the cache: nothing is refreshed and nothing is sent over the network. The account is the one `auth login` looked up, through the API its access token is for (`--audience`), when you logged in; for a login from before it did, `auth status` says so until you log in again. On a terminal, labels are dim and the login's state is green or red.

```bash
source-coop auth status
```

```
Environment    https://data.source.coop
Login          logged in
Account        Anthony Lukach (alukach)
Profile        https://source.coop/alukach
Refresh token  renewed 2026-10-13T14:00:00Z (3 hours ago); expires 2026-11-12 (in 29 days)
ID token       expires 2026-10-13T18:00:00Z (in 1 hour)
Access token   for https://source.coop, expires 2026-10-13T18:00:00Z (in 1 hour)
Credentials    _default: expire 2026-10-13T18:30:00Z (in 1 hour)
```

**How long until you must log in again** is set by the refresh token, which `creds` and API commands use to renew everything else, so the expiries of the ID token, access token and credentials don't force a login. source.coop's login (Ory) issues opaque refresh tokens, and its token response doesn't say how long they last: that's an Ory project setting, and each renewal starts the clock again. So `auth status` shows when the refresh token was last renewed, and when it expires if left unused: an estimate, to the day, assuming a 30-day lifetime (Ory's default). Set `SOURCE_REFRESH_TOKEN_LIFETIME` (e.g. `720h`, `14d`) if the server uses another; it only changes this estimate, since a login can't ask for a lifetime, and a value it can't read is ignored with a warning. Where a provider does give an expiry, that's shown instead. Once that expiry has passed, the login shows as expired; once only the estimate has, as likely expired (yellow), since the server's lifetime may be longer. A login from before renewals were recorded shows just `yes` until its next renewal or `auth login`. The profile link is on the site the login was for (`https://staging.source.coop` for a staging login).

`--json` prints the same as data, for scripts and agents: `logged_in` (false once the login has expired; a `likely_expired` state, past only the estimate, stays true), times in RFC 3339 with an `expired` flag, the account's `profile_url`, and, when the provider gave no refresh-token expiry, `estimated_lapse_at` with the `assumed_lifetime` it was counted from.

```bash
source-coop auth status --json | jq -r .login.refresh_token.issued_at
```

The keyring can't list its entries, so `auth status` reports on one environment and role. Pass `--proxy-url` and `--role-arn` (or set `SOURCE_PROXY_URL` and `SOURCE_ROLE_ARN`) to check others.

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
source-coop auth login --role-arn reader-role
source-coop auth login --role-arn admin-role
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

### Multiple environments (e.g. staging)

Each proxy host is its own environment, with its own login session and credentials, so production and staging logins live side by side:

```bash
source-coop auth login
( source .env.staging && source-coop auth login )
```

`creds` and `auth token` read `SOURCE_PROXY_URL` (or `--proxy-url`) to pick the environment, and without either they use production. A non-production profile must pass `--proxy-url`; one that relied on whichever environment was logged in last will now get production credentials:

```ini
[profile source-coop]
credential_process = source-coop creds
endpoint_url = https://data.source.coop

[profile source-coop-staging]
credential_process = source-coop creds --proxy-url https://data.staging.source.coop
endpoint_url = https://data.staging.source.coop
```

### Logging out

`auth logout` removes an environment's login session and one role's cached credentials, from both the keyring and the [file fallback](#file-fallback):

```bash
source-coop auth logout
source-coop auth logout --proxy-url https://data.staging.source.coop --role-arn reader-role
source-coop auth logout --json   # {"proxy_url": …, "role_arn": …, "removed": {"session": true, "credentials": true}}
```

Like `creds`, it takes `--proxy-url` (`SOURCE_PROXY_URL`) and `--role-arn` (`SOURCE_ROLE_ARN`). The keyring can't list its entries, so other roles' cached credentials stay usable until they expire, though without the session `creds` can't renew them. To remove them now, run `auth logout --role-arn <role>` for each role. Tokens aren't revoked at the identity provider.

### Login options

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--issuer` | `SOURCE_OIDC_ISSUER` | `https://auth.source.coop` | OIDC issuer URL |
| `--client-id` | `SOURCE_OIDC_CLIENT_ID` | `d037d00b-...` | OAuth2 client ID |
| `--proxy-url` | `SOURCE_PROXY_URL` | `https://data.source.coop` | S3 proxy URL for STS; also selects the environment the login is cached under |
| `--role-arn` | `SOURCE_ROLE_ARN` | `source-coop-user` | Role ARN to assume |
| `--format` | | `credential-process` | Output format: `credential-process`, `env`, or `aws-credentials` |
| `--profile` | | `source-coop` | Profile name for `--format aws-credentials` |
| `--duration` | | | Session duration, e.g. `3600`, `90s`, `5m`, `12h`, `1d` (bare number = seconds) |
| `--scope` | | `openid offline_access` | OAuth2 scopes (`offline_access` enables automatic refresh in `creds`) |
| `--audience` | `SOURCE_API_AUDIENCE` | `https://source.coop` | Audience of the access token for the source.coop API; empty to request none |
| `--port` | | `0` (random) | Local callback port |
| `--no-cache` | | | Skip caching credentials (just print to stdout) |

### Output formats

Both `auth login` and `creds` support `--format` to control output:

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

### Any API request

`source-coop api` sends any request to `/api/v1`, signed in as you, and prints the response:

```bash
source-coop api products/my-org -X GET -F limit=5
source-coop api products/my-org -f product_id=new -f title="New" -f description="" \
  -f visibility=public -f data_connection_id=my-connection
source-coop api products/my-org/new -X PATCH --input changes.json
```

`-f key=value` sends a string, and `-F key=value` sends `true`, `false`, `null` and numbers as JSON. Fields go in the query string for `GET` and in a JSON body otherwise, and the method is `POST` when fields or `--input` are given; a `GET` takes no `--input`. Paths stay under `/api/v1`. A status other than success exits non-zero, with the exit code for its kind (see "JSON output and exit codes").

Reading public data needs no credentials. Anything else acts as whoever ran `source-coop auth login`, which asks Ory for an access token meant for the API (`--audience`, default `https://source.coop`) and refreshes it as needed. `SOURCE_TOKEN`, if set, is sent instead. `--api-url` (or `SOURCE_API_URL`) points the CLI at another deployment, such as a local `http://localhost:3000`.

### JSON output and exit codes

Every command that reports information takes `--json`: `auth status`, and `product list`, `view`, `create`, `edit` and `delete` (which print the resulting record). Under `--json`, stdout holds one JSON document and nothing else, with the API's field names and RFC 3339 times; notes and progress go to stderr. Fields may be added over time, but not renamed or removed.

A failure under `--json` is JSON too, on stderr, in the API's error shape. `field_errors` names what to fix when the API rejected the input:

```json
{"error": {"code": "invalid_input", "message": "…", "status": 400, "field_errors": {"title": ["…"]}}}
```

Exit codes are the same for every command:

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Any other failure, including cancelling a prompt |
| 2 | Bad command-line usage |
| 3 | The API rejected the input (HTTP 400, 409, 422): fix the named fields and retry |
| 4 | Not signed in, or not allowed (HTTP 401, 403) |
| 5 | Not found (HTTP 404) |
| 130 | Interrupted (Ctrl+C) |

`source-coop --help` ends with a summary of this section, and each command's `--help` lists its flags with examples, so an AI agent can work out how to use the CLI from the CLI itself.

`creds` (`--format`), `auth token` (a bare token) and `api` (the API's response) already print output for machines, so they don't take `--json`. Neither does `auth login`, which signs in through the browser: `auth status --json` reports the result.

## Managing products

`source-coop product` lists, views, creates, edits and deletes products through the source.coop API (`/api/v1`), with the same rules as the web UI: the CLI checks nothing itself and shows the API's errors, field by field.

```bash
source-coop product list                      # public products
source-coop product list my-org --json        # one account's products, as JSON
source-coop product list --format table       # one row per product; tab-separated when piped
source-coop product list my-org -i            # move through the products and act on them (keys below)
source-coop product view my-org/my-product    # --web opens it in the browser
source-coop product view my-org/my-product -i # the product with shortcuts; without a product, pick one
source-coop product create my-org/my-product  # prompts for the rest
source-coop product edit my-org/my-product --visibility unlisted
source-coop product edit -i                   # pick one of your account's products to edit
source-coop product delete my-org/my-product  # asks you to type the name back
source-coop product delete -i                 # pick one of your account's products to delete
```

With `-i`, lists and products answer to keys:

| Key | In a list | On a product |
|-----|-----------|--------------|
| ↑ ↓ (`k` `j`), PgUp PgDn, Home End | move | |
| → Enter (`l`) | open the product | |
| ← Esc (`h` `q`) | quit (from search results: back to the whole list) | back to the list |
| `/` | filter by typed text (Esc clears it); among all public products, Enter searches them on the server | |
| `b` | open in the browser | open in the browser |
| `e` | | edit |
| `d` | | delete |

Editing or deleting takes opening the product first, so a stray key on a long list changes nothing. Edit and delete run exactly as `product edit` and `product delete` do, prompts included. Lists load more as you scroll, and `-i` takes the whole terminal while it runs, putting it back as it was when you leave.

`create` and `edit` take each field as a flag (`--title`, `--description`, `--visibility`, `--data-connection`), from a JSON object with `--from-file PATH` (`-` for stdin), or both, with flags winning. In a terminal, whatever is still missing is asked for, with defaults: a title made from the product ID, the data connections the account can use, and the visibilities the chosen connection allows. A description can be typed on one line, or written in your editor (`$VISUAL` or `$EDITOR`) with Ctrl+E. While `create` asks, ↑ (or ← at the start of a line, or in a list) goes back to the question before, starting from your answer there; once it has asked anything, it shows what it is about to create and asks you to confirm before sending, and ← from there goes back too. `edit` with no flags asks which fields to change and starts each from its current value, offering only the visibilities its data connection allows. When the API rejects a field, you see why and are asked for just that field again. Without a terminal, or with `SOURCE_PROMPT_DISABLED` set, nothing is asked: the request is sent as given, and `delete` needs `--yes`.

To back out of any prompt, press Esc (or `q`) on a choice; on a text prompt that guards something irreversible, like typing a product's name to delete it, press Enter on nothing. The command stops with "Cancelled; nothing was changed."

Before asking anything, `create`, `edit` and `delete` check that you're signed in, so you don't fill in a form only to be refused. If sending your answers fails anyway (a lost connection, an expired login, a server error), they're saved as a draft: run the same command again and you're offered them back, with any flags you pass taking precedence, or pass the saved file with `--from-file`. Drafts live where your OS keeps app state, not its cache: `~/.local/state/source-coop/drafts` on Linux (`$XDG_STATE_HOME`), `~/Library/Application Support/source-coop/drafts` on macOS, and `%LocalAppData%\source-coop\drafts` on Windows. A successful send removes the draft.

Output is for people on a terminal and for scripts when piped: `list` shows each product's fields (`--format table` prints an aligned table with a header on a terminal, and tab-separated rows without one when piped); `create` and `edit` print the product's URL on stdout and their message on stderr, so `url=$(source-coop product create ...)` works.

## Credential storage

The CLI caches the login session (the Ory refresh, ID and access tokens) and the temporary STS credentials for each role, so that `creds` and API commands work without re-authenticating. The refresh token is kept in the session only: it rotates on use, so every role and every API call refreshes through it, one at a time.

### OS keyring (default)

Credentials are stored in the OS-native keyring under the service name `source-coop-cli`, keyed by role ARN (e.g. `_default`), with the session under `@session`. Other environments prefix both with their proxy host (e.g. `data.staging.source.coop/_default`, `data.staging.source.coop/@session`):

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

The session sits beside them, at `source-coop/session.json`. Other environments keep the same layout under `source-coop/env/<host>/`, or `source-coop/env/<host>/<port>/` for a non-default port (e.g. `source-coop/env/data.staging.source.coop/session.json`).

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
source-coop auth login --role-arn <ARN> --port 8400
```

### Client configuration

The OAuth2 client should be configured as a **public client** (no client secret) with:

- **Grant type**: Authorization Code
- **Token endpoint auth method**: `none` (public client, PKCE used instead)
- **Allowed scopes**: `openid`, `offline_access`
- **Redirect URIs**: `http://127.0.0.1/callback` (see above)
- **Allowed audiences**: the source.coop site the API is served from (`https://source.coop`, or `https://staging.source.coop`). Without it, Ory refuses a login that asks for that audience.
- **Access token strategy**: `jwt`, so the API can verify access tokens against Ory's published keys rather than asking Ory about each one
