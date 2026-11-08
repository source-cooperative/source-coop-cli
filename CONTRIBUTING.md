# Contributing

How to work on this repository (conventions, tests, demos, PR descriptions) is in [AGENTS.md](AGENTS.md), for people and coding agents alike. The user guide is [README.md](README.md).

This file holds setup for whoever runs the sign-in server the CLI uses.

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
