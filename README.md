# source-coop CLI

The command line for [Source Cooperative](https://source.coop). It does two jobs:

- **Reading and writing data.** It signs you in through your browser and hands AWS tools temporary S3 credentials for the Source Cooperative data proxy, refreshing them as they expire.
- **Managing source.coop.** It lists, views, creates, edits and deletes your products, members and service accounts through the source.coop API, with the same rules as the web UI.

Every command works the same way: prompts for what you leave out when you're at a terminal, `-i` to browse records full screen, and `--json` with stable exit codes for scripts and AI agents.

The demos in this guide run against a stand-in for the API with made-up records (`demo-org`, `demo-user`), so the `http://127.0.0.1:…` URLs in them are local, not real.

**Contents**

- [Install](#install)
- [Quick start](#quick-start)
- [Signing in](#signing-in)
- [Reading data with AWS tools](#reading-data-with-aws-tools)
- [Managing products](#managing-products)
- [Managing members](#managing-members)
- [Managing service accounts](#managing-service-accounts)
- [Prompts](#prompts)
- [Browsing with `-i`](#browsing-with--i)
- [Scripts and AI agents](#scripts-and-ai-agents)
- [Any API request](#any-api-request)
- [Configuration](#configuration)
- [Credential storage](#credential-storage)
- [OIDC provider setup](#oidc-provider-setup)

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

Check which version you have:

```bash
source-coop --version
```

### Shell completion

TAB completes commands, flags and their values, and the names of records: `source-coop product view my-org/<TAB>` offers my-org's products, and before the `/` it offers the accounts you belong to. `source-coop service-account view my<TAB>` offers whole service account IDs (`my-org--nightly-sync`) from the accounts whose service accounts you can list; a new one's ID, for `create`, isn't completed. Load it from your shell's startup file:

```bash
eval "$(source-coop completions bash)"          # ~/.bashrc
eval "$(source-coop completions zsh)"           # ~/.zshrc, after compinit
source-coop completions fish | source           # ~/.config/fish/config.fish
```

```powershell
source-coop completions powershell | Out-String | Invoke-Expression   # $PROFILE
```

`elvish` works too. The script asks `source-coop` itself on every TAB (running it with `SOURCE_COOP_COMPLETE` set), so completion always matches the installed version. Names come from the API, as you: the completer uses your cached login while its access token is unexpired (or `SOURCE_TOKEN`), and never refreshes it, so after a long break only public products complete until the next command renews the login. It reads `SOURCE_API_URL` and `SOURCE_PROXY_URL` from the environment, but not `--api-url` or `--proxy-url` typed on the line. If the API doesn't answer within 2 seconds, it offers no names (bash then falls back to file names). If macOS asks for your password to read the login from the keychain, the TAB waits up to a minute for your answer; choose **Always Allow** so it doesn't ask again (until you install a new build).

## Quick start

```bash
source-coop auth login                        # sign in through your browser, once
source-coop product list my-org               # an account's products
source-coop product create                    # asks for everything a new product needs
aws s3 ls s3://my-org/my-data --profile source-coop   # after adding the profile below
```

Every command explains itself: `source-coop --help` lists the commands, and `source-coop <command> --help` lists each one's flags with examples.

## Signing in

### Logging in

`auth login` opens your browser to sign in to source.coop, then keeps the session in your OS keyring (or a [file](#file-fallback) where there's no keyring):

```bash
source-coop auth login
```

`source-coop login`, its name before `auth` held it, still works.

`auth login` keeps one session for everything: `creds` for any role exchanges its ID token at the proxy, and commands that call the source.coop API send its access token. Sign in once, and both keep working, refreshing what expires, until the session itself lapses.

It uses the OAuth2 Authorization Code flow with PKCE, then exchanges the OIDC ID token at the proxy's STS endpoint for temporary AWS credentials. Without `offline_access` in `--scope`, nothing can be refreshed and you'll sign in again when they expire. With `--no-cache`, it prints the credentials (in `--format`) and keeps nothing.

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

### Checking login status

`auth status` shows whether you're logged in and as whom, and when the cached tokens and a role's credentials expire. It works from the cache: nothing is refreshed and nothing is sent over the network. The account is the one `auth login` looked up, through the API its access token is for (`--audience`), when you logged in; for a login from before it did, `auth status` says so until you log in again. On a terminal, labels are dim and the login's state is green or red.

```bash
source-coop auth status
```

```
Environment    https://data.source.coop
Login          logged in
Account        Demo User (demo-user)
Profile        https://source.coop/demo-user
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

### Calling the API with your login

`auth token` prints the session's access token for the source.coop API, refreshed if it has expired, for tools other than this CLI:

```bash
curl -H "Authorization: Bearer $(source-coop auth token)" https://source.coop/api/v1/...
```

To send a request through the CLI instead, see [Any API request](#any-api-request).

### Multiple environments (e.g. staging)

Each proxy host is its own environment, with its own login session and credentials, so production and staging logins live side by side:

```bash
source-coop auth login
( source .env.staging && source-coop auth login )
```

Every command reads `SOURCE_PROXY_URL` (or `--proxy-url`) to pick the environment whose login it uses, and without either it uses production. Commands that call the API also take `--api-url` (`SOURCE_API_URL`) for the site to send them to; `.env.staging` sets both. A non-production AWS profile must pass `--proxy-url`; one that relied on whichever environment was logged in last will now get production credentials:

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
| `--client-id` | `SOURCE_OIDC_CLIENT_ID` | `197e20e7-...` | OAuth2 client ID |
| `--proxy-url` | `SOURCE_PROXY_URL` | `https://data.source.coop` | S3 proxy URL for STS; also selects the environment the login is cached under |
| `--role-arn` | `SOURCE_ROLE_ARN` | `_default` | Role ARN to assume |
| `--format` | | `credential-process` | Output format: `credential-process`, `env`, or `aws-credentials` |
| `--profile` | | `source-coop` | Profile name for `--format aws-credentials` |
| `--duration` | | | Session duration, e.g. `3600`, `90s`, `5m`, `12h`, `1d` (bare number = seconds) |
| `--scope` | | `openid offline_access` | OAuth2 scopes (`offline_access` enables automatic refresh in `creds`) |
| `--audience` | `SOURCE_API_AUDIENCE` | `https://source.coop` | Audience of the access token for the source.coop API; empty to request none (then only `creds` works) |
| `--port` | | `0` (random) | Local callback port |
| `--no-cache` | | | Skip caching credentials (just print to stdout) |

## Reading data with AWS tools

### AWS `credential_process`

1. Log in once (opens your browser):

   ```bash
   source-coop auth login
   ```

2. Configure `~/.aws/config` to use the cached credentials:

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

### Output formats

`creds` (and `auth login`) print credentials in one of three formats, chosen with `--format`:

**credential-process** (default): AWS `credential_process` JSON.

```bash
source-coop creds
```

**env**: shell export statements, setting `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` in your current shell.

```bash
eval $(source-coop creds --format env)
```

**aws-credentials**: an INI profile you can write directly to `~/.aws/credentials`. `--profile` changes the section name.

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

> [!TIP]
> The credentials are temporary; re-run after expiry (appending adds a duplicate section — AWS uses the last one, but prune stale sections occasionally). We recommend `credential_process` in `~/.aws/config` rather than storing temporary credentials in `~/.aws/credentials`.

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

## Managing products

`source-coop product` lists, views, creates, edits and deletes products through the source.coop API (`/api/v1`), with the same rules as the web UI: the CLI checks nothing itself and shows the API's errors, field by field. Products are named `ACCOUNT/PRODUCT`.

### Listing and viewing

```bash
source-coop product list                      # public products
source-coop product list my-org --json        # one account's products, as JSON
source-coop product list --format table       # one row per product; tab-separated when piped
source-coop product list -q climate           # search titles, descriptions and IDs
source-coop product list --tags zarr,climate --featured   # featured products with every one of these tags
source-coop product list -L 100               # up to 100 (30 by default, or all in the pager)
source-coop product list my-org -i            # browse full screen (see "Browsing with -i")
source-coop product view my-org/my-product    # one product
source-coop product view my-org/my-product -w # open its page in the browser
source-coop product view my-org/my-product -i # the product with shortcuts; without a product, pick one
```

`list` shows each product's fields as `view` does (`--format details`), or with `--format table` an aligned table with a header on a terminal, and tab-separated rows without one when piped. On a terminal, it goes through your pager and fetches every page as you read; otherwise it stops at `--limit`, and `--cursor` continues where an earlier list stopped.

![`product list`: a table, a search, then `--json`](docs/demos/product-list.svg)

### Creating

```bash
source-coop product create                    # prompts for everything
source-coop product create my-org/my-product  # prompts for the rest
source-coop product create my-org/my-product -t "My product" -d "What's in it" \
    --visibility public --data-connection my-connection
echo '{"title": "My product"}' | source-coop product create my-org/my-product -F -
```

`create` takes each field as a flag (`--title`, `--description`, `--visibility`, `--data-connection`), from a JSON object with `--from-file PATH` (`-` for stdin), or both, with flags winning. In a terminal, whatever is still missing is asked for, with the web form's defaults: the accounts you can create products in, a title made from the product ID, the data connections the account can use, and the visibilities the chosen connection allows. A product's data connection can't be changed once it's created. See [Prompts](#prompts) for going back, the review before sending, and drafts. `create` prints the product's URL on stdout and its message on stderr, so `url=$(source-coop product create ...)` works.

![`product create` with prompts: ↑ goes back a question, then the review](docs/demos/product-create.svg)

### Editing

```bash
source-coop product edit my-org/my-product                     # a form of its fields
source-coop product edit my-org/my-product --visibility unlisted
source-coop product edit my-org/my-product -d "New description" --json
source-coop product edit my-org/my-product --disable           # --enable reactivates it (admins only)
source-coop product edit -i                                    # pick one of your account's products
```

`edit` takes the same fields as `create` (all but the data connection), as flags or from `--from-file`. With no flags, it opens a form, taking the whole terminal until you leave it, of the product's title, description and visibility as they are now: ↑/↓ moves between them, Enter changes the highlighted one starting from its current value (Esc leaves it as it was), and only the visibilities its data connection allows are offered. Changed fields are marked with what they were. `s`, or Enter on *Save changes*, shows what will change and asks you to confirm, with ← back to the form; Esc or ← on the form cancels, asking first if you've changed anything. `--disable` and `--enable` are flags only. `edit` prints the product's URL on stdout.

![`product edit`: the edit form, then a flag](docs/demos/product-edit.svg)

### Deleting

```bash
source-coop product delete my-org/my-product                  # asks you to type the name back
source-coop product delete my-org/my-product --preserve-data  # keep its objects in storage
source-coop product delete my-org/my-product --yes --json     # no questions, for scripts
source-coop product delete -i                                 # pick one of your account's products
```

`delete` asks whether to keep the product's data in storage (unless `--preserve-data` answered it), then asks you to type the product's name back. Anything else typed there deletes nothing. Without a terminal it needs `--yes`.

![`product delete`: the name typed wrong, then right, then `--yes`](docs/demos/product-delete.svg)

## Managing members

`source-coop member` manages who belongs to an organization (`ACCOUNT`) or a product (`ACCOUNT/PRODUCT`), and `source-coop invitation` answers the invitations sent to you. Members are named by their account ID; there's no inviting by email.

```bash
source-coop member list my-org                    # members and pending invitations
source-coop member list my-org/my-data --json     # a product's own members, as JSON
source-coop member list my-org --state invited    # only invitations not yet answered
source-coop member list my-org -i                 # browse the members and act on them
source-coop member view my-org alice              # one member; -i for its screen
source-coop member invite my-org alice bob --role maintainers
source-coop member invite my-org/my-data -A people.txt --role read_data
source-coop member invite my-org                  # prompts for who and which role
source-coop member edit my-org alice --role owners
source-coop member edit my-org -i                 # pick a member, then a role
source-coop member revoke my-org alice            # also withdraws a pending invitation
source-coop member leave my-org                   # give up your own membership
```

With [shell completion](#shell-completion), TAB offers the organizations you belong to and their products for `ACCOUNT` or `ACCOUNT/PRODUCT`, the members of the one you named for a member, its organization's members who aren't on a product yet for `invite`, and your own invitations and memberships for `invitation accept`/`reject` and `member leave`.

Roles, most powerful first, are `owners`, `maintainers`, `write_data` and `read_data`. Only owners can make someone an owner, or change or revoke an owner's membership; owners and maintainers handle the other roles. A product's members list holds only that product's own members: the organization's members reach its products as well, and are listed with the organization.

`invite` takes any number of account IDs, and `--accounts-file PATH` (`-A`, `-` for stdin) adds one per line, skipping blank lines and lines starting with `#`. `--from-file` reads `account_id` and `role` from a JSON object. Each account is sent as its own invitation: one the API refuses is reported and the rest are still sent, and the command fails at the end if any did. In a terminal, missing accounts and role are asked for (the role defaulting to `read_data`, and `owners` offered only if you can grant it), then shown for you to confirm; ← goes back a question. If some invitations fail, the ones not sent are saved as a draft that the next `invite` to the same place offers back. A product owner's service account is added at once rather than invited, with `read_data` or `write_data` only.

`edit` with no `--role` asks for one, starting from the current role. `revoke` asks you to confirm, and to type the organization or product back when it's your own membership; `leave` always asks you to type it back, since only an owner or maintainer can let you back in. Without a terminal both need `--yes`. An invitation's role can't be changed: revoke it and invite again.

`--json` on any of these prints the memberships as the API returns them (`membership_id`, `account_id`, `membership_account_id`, `product_id` for a product, `role`, `state`, `state_changed`); `invite --json` prints an array of the memberships it created. `create` and `delete` also work as names for `invite` and `revoke`.

![`member list`, `invite`, `edit` and `revoke`](docs/demos/members.svg)

With `-i`, `member list` answers to the same keys as `product list -i`. On a member, `e` changes the role and `d` revokes the membership (on an invitation, only `d`, which withdraws it); `b` opens their profile.

![`member list -i`: open a member and change their role](docs/demos/member-browse.svg)

### Invitations sent to you

```bash
source-coop invitation list                       # invitations waiting for you
source-coop invitation list -i                    # open one to accept (a) or reject (r) it
source-coop invitation accept my-org/my-data
source-coop invitation reject my-org
source-coop invitation accept -i                  # pick which
```

Accepting makes you a member with the role you were invited to. `--json` prints the membership as it now is.

![`invitation list -i`: accept one, then reject another](docs/demos/invitations.svg)

## Managing service accounts

A service account is an account software signs in as: a GitHub Actions workflow, or a script with an API key. It belongs to an owner (you, or an organization you own or maintain, once source.coop has let that account own service accounts), and its ID is the owner's followed by its own: `my-org--nightly-sync`. `source-coop service-account` manages them through the API, laid out as the web UI's service account page is: who it is, how it signs in, and what it can reach.

```bash
source-coop service-account list my-org             # my-org's service accounts (yours without an owner)
source-coop service-account list my-org --no-pager  # printed straight out, not through the pager
source-coop service-account list my-org -i          # browse them and act on them (keys as for products)
source-coop service-account view my-org--nightly-sync          # --json adds its `trusts`, `keys` and `memberships`
source-coop service-account view my-org--nightly-sync -w       # open its page in the browser
source-coop service-account create                  # prompts for everything, as the web form asks it
source-coop service-account create my-org--nightly-sync --name "Nightly sync" \
    --github my-org/data --branch main --access my-org/my-data=write
source-coop service-account edit my-org--nightly-sync --name "Nightly sync"
source-coop service-account edit my-org--nightly-sync            # a form of its name and the products it reaches
source-coop service-account edit my-org--nightly-sync --disable   # --enable lets it sign in again
source-coop service-account delete my-org--nightly-sync           # asks you to type its ID back
```

![`service-account list`: an owner's service accounts, then as `--json`](docs/demos/service-account/list.svg)

![`service-account view`: who it is, how it signs in, what it can reach; `--json` adds `trusts` and `memberships`](docs/demos/service-account/view.svg)

`create` takes its fields as flags (`--name`, one `--github` workflow, a `--key` with `--expires` and `--out`, `--access` repeated), from a JSON object in the API's shape with `--from-file` (`name`, `local_id`, `github_subjects`, `key`, `grants`), or both. In a terminal it asks for whatever is missing: the owner, the name, the ID (made from the name), workflows to trust and an API key, products to grant. Then it shows everything, including the condition each workflow must match, before creating it. A key issued with the account is handed over as `sign-in add` does, except that stdout keeps the account's ID: to capture the key, use `--out` or `--json`. Going back, drafts, sign-in checks and `--yes` work as they do for products. `create` and `edit` print the service account's ID on stdout, so `id=$(source-coop service-account create …)` works. Its ID is what the AWS tools name it by: `role-to-assume: arn:aws:iam::my-org--nightly-sync:role/FullAccess`.

![`service-account create` with prompts](docs/demos/service-account/create.svg)

![`service-account create` from flags, with `--json`](docs/demos/service-account/create-flags.svg)

`edit --disable` stops everything signing in as it, keeping its sign-ins and access, and `--enable` lets its workflows and unrevoked keys sign in again. `delete` removes it with its sign-ins and product access, after you type its ID back (or with `--yes`).

![`service-account edit`: `--disable`, `--enable`, then a rename in the edit form](docs/demos/service-account/edit.svg)

![`service-account delete`: typed confirmation, then `--yes --json`](docs/demos/service-account/delete.svg)

![`service-account list -i`: open one, go back, delete one from its screen](docs/demos/service-account/picker.svg)

### Signing in

A service account signs in with a GitHub Actions workflow it trusts: one repository, pinned to one branch, tag or environment. GitHub vouches for every run, so there's no secret to store. Where there's no GitHub, an API key does instead.

```bash
source-coop service-account sign-in add my-org--nightly-sync --github my-org/data --branch main
source-coop service-account sign-in add my-org--nightly-sync --github my-org/data --environment production
source-coop service-account sign-in add my-org--nightly-sync --subject repo:my-org/data:ref:refs/tags/v1
source-coop service-account sign-in remove my-org--nightly-sync repo:my-org/data:ref:refs/heads/main
source-coop service-account sign-in remove my-org--nightly-sync -i   # pick which
```

`--github OWNER/REPO` with `--branch`, `--tag` or `--environment` builds the subject GitHub's tokens carry (`repo:OWNER/REPO:ref:refs/heads/main`); `--subject` takes one as it is. The CLI asks GitHub how the repository's tokens name it, as the web UI does, since a repository whose tokens name it by ID (`owner@123/repo@456`) would never match it typed as `owner/repo`. For a private repository, set `GH_TOKEN` (or `GITHUB_TOKEN`) so GitHub answers; otherwise the CLI says it couldn't check and how to find the name yourself. Without these flags, in a terminal, `sign-in add` asks for the repository and the runs to trust, and shows the condition it will trust before adding it.

![`sign-in add` with prompts and from flags, `sign-in remove -i`, `sign-in revoke-key`](docs/demos/service-account/sign-in.svg)

An API key is for environments without GitHub's tokens, such as a cron job on a cluster. Each key has a label saying where it lives, so you know which one to revoke. It expires after 30 days, 90 (the default), a year, never, or on a date you give, at midnight UTC:

```bash
source-coop service-account sign-in add my-org--nightly-sync --key "HPC cron job" --expires 1y --out ~/.source-coop/nightly.key
key=$(source-coop service-account sign-in add my-org--nightly-sync --key "HPC cron job")   # piped: the key alone on stdout
source-coop service-account sign-in edit my-org--nightly-sync key:a1B2c3 --expires never      # a new expiry, counted from now
source-coop service-account sign-in remove my-org--nightly-sync key:a1B2c3                    # revoke it; asks you to type key:a1B2c3 back
```

A key is shown once, when it's issued, and never again. `--out PATH` writes it to a new file only you can read, which is where the AWS tools want it anyway. A file already at that path is never overwritten: the key is shown instead, as it is whenever saving it fails. Piped, the key alone goes to stdout. On a terminal, you're offered a file to save it to, or Enter shows it. `view` lists each key by its label and its last six characters, `key:a1B2c3`, which is how `sign-in edit` and `remove` name it, with when it was last used and when it expires. Revoked and expired keys are listed too, dimmed. A revoked key can't be restored. Without flags, in a terminal, `sign-in add` asks whether to add a workflow or a key, and `sign-in edit -i` and `sign-in remove -i` pick which.

![API keys: `sign-in add --key --out`, `sign-in edit -i`, and revoking one with `sign-in remove`](docs/demos/service-account/keys.svg)

If a key leaks, anyone holding it can revoke it, with no sign-in needed. The key is read from stdin so it stays out of your shell history:

```bash
source-coop service-account sign-in revoke-key < leaked-key-file
```

### Reaching products

A service account can read, or read and write, its owner's products. Each grant is an ordinary membership of the product. `create --access` grants them at the start, and `edit --access` grants one, changes its role, or takes it away (`=none`):

```bash
source-coop service-account edit my-org--nightly-sync --access my-org/my-data=write --access my-org/old-data=none
```

`edit` with no flags opens a form, taking the whole terminal until you leave it, of the account's **Name**, then the products it reaches under **Can reach**, each with its role. ↑/↓ moves, and Enter changes the highlighted row: the name from its current value, or a product's access to Read, Read and write or No access. *Grant a product…* adds one of the owner's other products. Changed rows are marked with what they were. `s`, or Enter on *Save changes*, shows what will change and asks you to confirm, with ← back to the form. Esc or ← on the form cancels, asking first if you've changed anything. Asking for a role a product already has, or taking away access it doesn't have, changes nothing, so running an edit twice is safe. `--disable` and `--enable` are flags only.

![`service-account edit --access`, then the edit form: take a product away, grant another](docs/demos/service-account/access.svg)

### Using it

Workflows and scripts sign in with stock AWS tools, not this CLI. `usage` prints what they need, the same snippets the web UI shows:

```bash
source-coop service-account usage my-org--nightly-sync --subject repo:my-org/data:ref:refs/heads/main \
    > .github/workflows/source-coop.yml   # a workflow that signs in with aws-actions/configure-aws-credentials
source-coop service-account usage my-org--nightly-sync --key   # the AWS_* variables for a key saved to a file
```

Without `--subject` or `--key`, in a terminal, `usage` asks which sign-in to show.

![`service-account usage`: pick a sign-in for its workflow, then `--key`](docs/demos/service-account/usage.svg)

## Prompts

Commands that change something ask for what you didn't give them, when you're at a terminal. They all ask the same way.

- **What wins.** Flags win over `--from-file PATH` (`-F`, `-` for stdin), which wins over prompts. Only what's still missing is asked for.
- **Signed in first.** Before asking anything, `create`, `edit` and `delete` check that you're signed in, so you don't fill in a form only to be refused.
- **Going back.** ↑ (or ← at the start of a line) on a text question, and ← on a choice, goes back to the question before, starting from your answer there; later answers are kept. Questions answered by a flag or a file are skipped.
- **Review.** Once a command has asked anything, it shows what it is about to send and asks you to confirm. ← from there goes back too.
- **Long text.** A description can be typed on one line, or written in your editor (`$VISUAL` or `$EDITOR`) with Ctrl+E. One that's already a single line starts in the line to edit, and emptying the line clears it; a longer one leaves the line empty, and Enter on it keeps the text.
- **Rejected fields.** When the API rejects a field, you see why and are asked for just that field again.
- **Backing out.** Esc (or `q` on a choice) cancels with "Cancelled; nothing was changed." and exit code 1. On a text prompt that guards something irreversible, like typing a product's name to delete it, Enter on nothing cancels too. Ctrl+C stops at once, with exit code 130.
- **Drafts.** If sending your answers fails anyway (a lost connection, an expired login, a server error), they're saved as a draft: run the same command again and you're offered them back, with any flags you pass taking precedence, or pass the saved file with `--from-file`. A successful send removes the draft.

Drafts live where your OS keeps app state, not its cache:

| Platform | Path |
|----------|------|
| Linux | `~/.local/state/source-coop/drafts` (`$XDG_STATE_HOME`) |
| macOS | `~/Library/Application Support/source-coop/drafts` |
| Windows | `%LocalAppData%\source-coop\drafts` |

Without a terminal on stdin and stderr, or with `SOURCE_PROMPT_DISABLED` set, nothing is asked: the request is sent as given and the API says what's missing. Deleting, revoking and leaving then need `--yes`.

## Browsing with `-i`

`-i` (`--interactive`) works wherever a record is named or listed: `list` browses the records full screen, `view -i` opens one record's screen, and `edit`, `delete`, `revoke` and the rest pick the record first when you leave its name out. `-i` takes the whole terminal while it runs, putting it back as it was when you leave, and shows what happened as a notice on the redrawn screen.

| Key | In a list | On a record |
|-----|-----------|-------------|
| ↑ ↓ (`k` `j`), PgUp PgDn, Home End | move | |
| → Enter (`l`) | open the record | |
| ← Esc (`h` `q`) | quit (from search results: back to the whole list) | back to the list |
| `/` | filter the loaded entries by typed text, with a count of how many match (Esc clears it); among all public products, Enter searches them all on the server, and ← leaves the results | |
| `b` | open in the browser | open in the browser |
| `e` | | edit (for a member, change the role) |
| `d` | | delete (for a member, revoke) |
| `a` `r` | | accept or reject (an invitation) |

Editing or deleting takes opening the record first, so a stray key on a long list changes nothing. The shortcuts run exactly as the commands do, prompts included. Lists load more as you scroll.

![`product list -i`: open a product, go back, filter with `/`](docs/demos/product-browse.svg)

## Scripts and AI agents

`source-coop --help` ends with a summary of this section, and each command's `--help` lists its flags with examples, so an AI agent can work out how to use the CLI from the CLI itself.

### Output

Data goes to stdout and messages to stderr, so `url=$(source-coop product create ...)` works. On a terminal, output is laid out for people: in color (unless `NO_COLOR` is set or `CLICOLOR=0`), and lists stream through your pager (`$SOURCE_PAGER`, `$PAGER`, then `less -FRX`; `--no-pager` or `SOURCE_PAGER=cat` prints straight out). Piped, it's plain and never paged. `-v` (`--verbose`) on any command prints the HTTP requests and responses on stderr.

### JSON

Every command that reports information takes `--json`: `auth status` and `auth logout`; `product list`, `view`, `create`, `edit` and `delete`; the `member` and `invitation` commands; and `service-account list`, `view`, `create`, `edit`, `delete`, `sign-in add`, `edit` and `remove` (the writes print the resulting record; `service-account edit --json` prints the account as `view --json` does). Under `--json`, stdout holds one JSON document and nothing else, with the API's field names and RFC 3339 times; notes and progress go to stderr. Fields may be added over time, but not renamed or removed.

`creds` (`--format`), `auth token` (a bare token), `api` (the API's response), `completions` (a shell script) and `service-account usage` (a workflow or shell exports) already print output for machines, so they don't take `--json`. Neither does `auth login`, which signs in through the browser: `auth status --json` reports the result.

A failure under `--json` is JSON too, on stderr. When the failure came from the API, it carries what the API's [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem said: its `code` and `status`, its `type` (a URL whose page explains the failure and what to do about it), and its `request_id`, to quote if you report it. `field_errors` names what to fix when the API rejected the input, by field path (`metadata.title`):

```json
{"error": {"code": "invalid", "message": "…", "status": 400, "field_errors": {"title": ["…"]}, "type": "https://source.coop/api/problems/invalid", "request_id": "…"}}
```

### Exit codes

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

![Errors, `--json` and exit codes, without a terminal, and `-F -`](docs/demos/scripting.svg)

### Signing in without a browser

`SOURCE_TOKEN`, if set, is sent to the API instead of the login session's access token, so a script or CI job can call the API without `auth login`.

## Any API request

`source-coop api` sends any request to `/api/v1`, signed in as you, and prints the response, for what the other commands don't cover:

```bash
source-coop api products/my-org -q limit=5
source-coop api products/my-org -f product_id=new -f title="New" -f description="" \
  -f visibility=public -f data_connection_id=my-connection
source-coop api products/my-org/new -X PATCH -F changes.json -f title="Renamed"
echo '{"title": "Renamed", "tags": ["a"]}' | source-coop api products/my-org/new -X PATCH -F -
```

`-q key=value` adds a query parameter. `-f key=value` sets a field in the JSON body: a value that parses as JSON (`5`, `true`, `null`, `["a","b"]`) is sent as that, and anything else as a string. To send something that looks like JSON as a string, quote it: `-f product_id='"2024"'`. `-F file.json` (`-` for stdin) reads the body from a file, and `-f` fields override its keys. The method is `GET`, or `POST` when there's a body; `-X` picks another, and a `GET` takes no body. Paths stay under `/api/v1`, and a query string in the path is kept. The paths and their fields are listed in the API's OpenAPI spec, at [`https://source.coop/api/openapi`](https://source.coop/api/openapi).

The response body is printed to stdout as the API sent it, so `api` takes no `--json`; a failure's problem is printed there too. A status other than success exits non-zero, with the exit code for its kind (see [Exit codes](#exit-codes)).

Reading public data needs no credentials. Anything else acts as whoever ran `source-coop auth login`, which asks Ory for an access token meant for the API (`--audience`, default `https://source.coop`) and refreshes it as needed. `SOURCE_TOKEN`, if set, is sent instead. `--api-url` (or `SOURCE_API_URL`) points the CLI at another deployment, such as a local `http://localhost:3000`.

![`api`: any request to the API](docs/demos/api.svg)

## Configuration

The CLI has no config file: flags and environment variables set everything. A flag wins over its variable.

| Env var | Flag | Default | What it sets |
|---------|------|---------|--------------|
| `SOURCE_PROXY_URL` | `--proxy-url` | `https://data.source.coop` | The environment: the data proxy, and which login session and credentials to use |
| `SOURCE_API_URL` | `--api-url` | `https://source.coop` | The source.coop site whose API (`/api/v1`) commands call |
| `SOURCE_TOKEN` | | | A bearer token for the API, sent instead of the login session's |
| `SOURCE_ROLE_ARN` | `--role-arn` | `_default` | The role whose credentials `creds`, `auth login`, `status` and `logout` use |
| `SOURCE_OIDC_ISSUER` | `--issuer` | `https://auth.source.coop` | Where `auth login` signs in |
| `SOURCE_OIDC_CLIENT_ID` | `--client-id` | source.coop's | The OAuth2 client `auth login` signs in as |
| `SOURCE_API_AUDIENCE` | `--audience` | `https://source.coop` | The audience of the API access token `auth login` asks for |
| `SOURCE_REFRESH_TOKEN_LIFETIME` | | `30d` | The refresh-token lifetime `auth status` assumes, e.g. `720h`, `14d` |
| `SOURCE_PROMPT_DISABLED` | | | Set to anything: never prompt, as without a terminal |
| `SOURCE_PAGER`, `PAGER` | `--no-pager` | `less -FRX` | The pager lists go through on a terminal |
| `VISUAL`, `EDITOR` | | | The editor Ctrl+E opens for long text |
| `GH_TOKEN`, `GITHUB_TOKEN` | | | Lets the CLI ask GitHub about a private repository's workflow subject |
| `NO_COLOR`, `CLICOLOR=0` | | | No color, even on a terminal |

`.env.staging` in this repository sets the staging environment: `source .env.staging` before a command, or run it in a subshell as in [Multiple environments](#multiple-environments-eg-staging).

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
