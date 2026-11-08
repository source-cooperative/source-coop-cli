# Contributing

How to work on this repository (conventions, tests, demos, PR descriptions) is in [AGENTS.md](AGENTS.md), for people and coding agents alike. The user guide is [README.md](README.md).

This file holds the team's own workflows: staging builds to test, and setup for whoever runs the sign-in server the CLI uses.

## Staging builds

To let the team try a branch against source.coop's staging environment without building it, run the *Staging build* workflow (Actions › Staging build › Run workflow) with the branch, tag or commit to build:

```bash
gh workflow run "Staging build" -f ref=my-branch
```

It builds `source-coop-staging` for macOS (Apple silicon and Intel) and Linux (x86_64 and arm64), with `--features staging`: it signs in to `auth.staging.source.coop` and calls `staging.source.coop` and `data.staging.source.coop` by default. Each run replaces the binaries on the [`staging` pre-release](https://github.com/source-cooperative/source-coop-cli/releases/tag/staging), whose notes name the branch and commit. To install it, or update to the latest staging build:

```bash
curl -LsSf https://github.com/source-cooperative/source-coop-cli/releases/download/staging/install.sh | sh
```

- **It sits beside the production CLI.** It installs as `source-coop-staging` in `~/.local/bin` (set `SOURCE_COOP_STAGING_DIR` for elsewhere), and keeps its own login: run `source-coop-staging auth login` once.
- **On macOS, each new build asks once for your password** to read its login from the keychain. Choose **Always Allow**.
- **TAB completion** works for `source-coop` only. Don't load `source-coop-staging completions` in your shell: its script registers for `source-coop`, so the production command's TAB would ask staging.
- **It's for testing.** The `staging` pre-release is never marked latest, so the release installers and Homebrew keep installing the real release, and neither the *Release* nor the *Docs* workflow runs for it.

On a PR that changes the workflow or `staging/install.sh`, *Staging build* only builds, without publishing.

## OIDC provider setup

The CLI uses the OAuth2 Authorization Code flow with PKCE. It starts a temporary local server at `http://127.0.0.1:{port}/callback` to receive the authorization code.

The OAuth2 client must have a redirect URI that agrees with this. Use one of these two options.

### Option A: Allow all ports (recommended)

Register `http://127.0.0.1/callback` as a redirect URI on the OAuth2 client. [RFC 8252 Section 7.3](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3) says that loopback redirect URIs must allow all ports. Ory Network does this: a URI without a port allows all ports.

The CLI's default, `--port 0`, uses a random free port. This works with option A.

### Option B: One fixed port

Register a redirect URI with a port, for example `http://127.0.0.1:8400/callback`. Then run the CLI with that port:

```bash
source-coop auth login --role-arn <ARN> --port 8400
```

### Client configuration

Configure the OAuth2 client as a **public client** (no client secret):

- **Grant type**: Authorization Code
- **Token endpoint auth method**: `none` (PKCE replaces the secret)
- **Allowed scopes**: `openid`, `offline_access`
- **Redirect URIs**: `http://127.0.0.1/callback` (see above)
- **Allowed audiences**: the source.coop site of the API (`https://source.coop` or `https://staging.source.coop`). Without it, Ory refuses a sign-in that requests that audience.
- **Access token strategy**: `jwt`. Then the API can verify access tokens with Ory's public keys, and does not need to ask Ory about each token.
