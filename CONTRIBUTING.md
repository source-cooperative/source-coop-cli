# Contributing

How to work on this repository (conventions, tests, demos, PR descriptions) is in [AGENTS.md](AGENTS.md), for people and coding agents alike. The user guide is [README.md](README.md).

This file holds the team's own workflows: preview builds to test, and setup for whoever runs the sign-in server the CLI uses.

## Preview builds

To let the team try a branch without building it, run the *Preview build* workflow (Actions › Preview build › Run workflow), or:

```bash
gh workflow run "Preview build" -f ref=my-branch                                        # staging, as source-coop-staging
gh workflow run "Preview build" -f ref=my-branch -f name=search-ui                      # its own preview, source-coop-search-ui
gh workflow run "Preview build" -f ref=my-branch -f name=prod-check -f features=production
gh workflow run "Preview build" -f ref=my-branch -f name=search-ui -f features=both     # source-coop-search-ui and source-coop-search-ui-staging
```

- **`ref`:** the branch, tag or commit to build. It's pinned to one commit when the run starts.
- **`name`** (default `staging`): the preview's pre-release tag, and the command it installs, `source-coop-NAME`. Use up to 40 lowercase letters, digits and hyphens, not starting with a digit or with `v` and a digit, so it can't be taken for a version.
- **`features`** (a choice, default `staging`): the Cargo features to build with. `staging` signs in to `auth.staging.source.coop` and calls `staging.source.coop` and `data.staging.source.coop` by default. `production` is the release's own defaults. `both` puts a production build, `source-coop-NAME`, and a staging one, `source-coop-NAME-staging`, on the same pre-release.

It builds for macOS (Apple silicon and Intel) and Linux (x86_64 and arm64). Each run replaces the preview's binaries on its pre-release, whose title and notes name the branch, commit and features. Send the install line from those notes, which for the default preview is:

```bash
curl -LsSf https://github.com/source-cooperative/source-coop-cli/releases/download/staging/install.sh | sh
```

Running it again updates the preview. For a `both` preview, that line installs the production build; add `-s -- staging` after `sh` for the staging one.

**Every push to main that changes the code (`src/`, `Cargo.toml`, `Cargo.lock`) is published as the `next` preview** (the *Main previews* workflow): `source-coop-next` is the next release as it stands, and `source-coop-next-staging` is the same commit calling staging. Its docs go to <https://source-cooperative.github.io/source-coop-cli/next/> when the README or `docs/` changes, listed as `next` in the version menu; `latest/` stays the newest release.

```bash
curl -LsSf https://github.com/source-cooperative/source-coop-cli/releases/download/next/install.sh | sh                  # source-coop-next
curl -LsSf https://github.com/source-cooperative/source-coop-cli/releases/download/next/install.sh | sh -s -- staging    # source-coop-next-staging
```

- **It sits beside the production CLI.** It installs as `source-coop-NAME` in `~/.local/bin` (set `SOURCE_COOP_PREVIEW_DIR` for elsewhere). Previews with different names sit side by side. A staging build keeps its own login: run `source-coop-staging auth login` once.
- **On macOS, each new build asks once for your password** to read its login from the keychain. Choose **Always Allow**.
- **TAB completion** works for `source-coop` only. Don't load a preview's `completions` in your shell: its script registers for `source-coop`, so the production command's TAB would ask the preview.
- **It's for testing, not a release.** A preview's pre-release is never marked latest, so the release installers and Homebrew keep installing the real release, and neither the *Release* nor the *Docs* workflow runs for it.
- **Remove a preview you're done with:** `gh release delete NAME --cleanup-tag`, and `rm ~/.local/bin/source-coop-NAME` to uninstall it.

On a PR that changes the workflow or `.github/preview/install.sh`, *Preview build* only builds the default preview, without publishing.

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
