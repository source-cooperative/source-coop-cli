<!-- group: Get started -->

# source-coop CLI

The command line for [Source Cooperative](https://source.coop). Use it to:

- **Get data credentials.** Sign in through your browser once. AWS tools then get temporary S3 credentials for the Source Cooperative data proxy, and the CLI renews them when they expire.
- **Manage source.coop.** List, view, create, edit and delete products, members and service accounts, and create and edit organizations. The source.coop API applies the same rules as the web UI.

All commands work the same way:

- At a terminal, a command asks for the values that you do not give.
- `-i` shows records full screen, for you to move through.
- `--json` and the exit codes are stable, for scripts and AI agents.

This guide is also a website, with a page for each section and docs for each release, plus `next` for what's on main and not yet released: <https://cli.source.coop/>.

The demos in this guide use a stand-in for the API with made-up records (`demo-org`, `demo-user`), and a made-up session where they show you signed in. They show production's addresses (`source.coop`, `data.source.coop`), but `demo-org` and `demo-user` don't exist there.

### Quick start

```bash
# sign in through your browser, once
source-coop auth login

# an account's products
source-coop product list my-org

# asks for each value a new product needs
source-coop product create

# after you add the AWS profile (below)
aws s3 ls s3://my-org/my-data --profile source-coop
```

`source-coop --help` lists the commands. `source-coop <command> --help` lists the flags of a command, with examples.

![`source-coop`: an account's products, one product, then as `--json`](docs/demos/tour.svg)

**Contents**

- **Get started:** [Install](#install), [Signing in](#signing-in)
- **Work with data:** [Reading data with AWS tools](#reading-data-with-aws-tools), [Uploading data with AWS tools](#uploading-data-with-aws-tools)
- **Manage source.coop:** [Accounts](#accounts), [Products](#products), [Members](#members), [Invitations](#invitations), [Service accounts](#service-accounts)
- **How commands work:** [Prompts](#prompts), [Browsing with `-i`](#browsing-with--i), [Shell completion](#shell-completion)
- **Automate:** [Scripts and AI agents](#scripts-and-ai-agents), [Any API request](#any-api-request)
- **Reference:** [Configuration](#configuration), [Credential storage](#credential-storage), [Troubleshooting](#troubleshooting)

## Install

### Homebrew (macOS / Linux)

```bash
brew install source-cooperative/tap/source-coop
```

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

### From source

```bash
cargo install --git https://github.com/source-cooperative/source-coop-cli
```

To see the installed version:

```bash
source-coop --version
```

### Upgrade

Upgrade the way you installed:

```bash
# Homebrew
brew upgrade source-coop

# from source
cargo install --force --git https://github.com/source-cooperative/source-coop-cli
```

With the installer script, run it again. It replaces the installed version with the latest release.

The [changelog](https://github.com/source-cooperative/source-coop-cli/blob/main/CHANGELOG.md) lists what each release changes. On macOS, the first command after an upgrade that reads your session can ask for your keychain password (see [Troubleshooting](#troubleshooting)).

### Uninstall

1. Sign out, to remove the session and cached credentials from the OS keyring:

   ```bash
   source-coop auth logout
   ```

   This removes one environment and one role. Run it again with `--role-arn` or `--proxy-url` for each other one that you used.

2. Remove the CLI:

   ```bash
   # Homebrew
   brew uninstall source-coop

   # installer script or from source
   rm ~/.cargo/bin/source-coop
   ```

   On Windows, delete `source-coop.exe` from `%USERPROFILE%\.cargo\bin`.

3. Remove the files it kept: the `source-coop` folders in the [file fallback](#file-fallback) and [drafts](#prompts) locations, if they exist.

## Signing in

### Sign in

```bash
source-coop auth login
```

This opens your browser. After you sign in, the CLI keeps the session in your OS keyring, or in a [file](#file-fallback) if there is no keyring. The old name, `source-coop login`, also works.

One session is used for all commands:

- `creds` exchanges the session's ID token at the data proxy for S3 credentials, for each role.
- Commands that use the source.coop API send the session's access token.

The CLI renews expired tokens and credentials. You sign in again only when the session itself expires.

Sign-in uses the OAuth2 Authorization Code flow with PKCE. The CLI then exchanges the OIDC ID token at the proxy's STS endpoint for temporary AWS credentials. Two flags change this:

- Without `offline_access` in `--scope`, the CLI cannot renew anything. You must sign in again when the credentials expire.
- With `--no-cache`, the CLI prints the credentials (in `--format`) and keeps nothing.

### Sign in on a remote server (no browser)

`auth login` receives the browser's redirect on a local port. On a server without a browser, forward that port over SSH:

1. Connect with a port forward. Any free port is satisfactory; this example uses `8400`:

   ```bash
   ssh -L 8400:127.0.0.1:8400 user@server
   ```

2. On the server, sign in on the forwarded port:

   ```bash
   source-coop auth login --port 8400
   ```

3. Open the URL that the CLI prints in your local browser, and sign in. The redirect to `http://127.0.0.1:8400/callback` goes through the tunnel to the CLI on the server.

The session stays on the server (see [File fallback](#file-fallback)). `source-coop creds` renews the credentials there without a browser.

### See your sign-in status

```bash
source-coop auth status
```

![`auth status`, then `--json`](docs/demos/auth-status.svg)

`auth status` shows:

- If you are signed in, and the account. The CLI found the account when you signed in. A session from an older version does not have it, and `auth status` tells you to sign in again.
- When the cached tokens and the role's credentials expire.
- A profile link on the site of the session (`https://staging.source.coop` for staging).

It reads only the cache. It does not renew tokens or use the network. On a terminal, the session's state is green or red.

**When you must sign in again.** The refresh token sets this. The CLI uses it to renew the other tokens and the credentials, so their expiry times do not matter. source.coop's identity provider (Ory) does not tell the CLI how long a refresh token lasts. Thus `auth status` shows:

- When the refresh token was last renewed. Each renewal starts its lifetime again.
- An estimate, to the day, of when it expires if not used. The estimate assumes 30 days, Ory's default. If the server uses a different lifetime, set `SOURCE_REFRESH_TOKEN_LIFETIME` (for example `720h` or `14d`). This changes only the estimate. If the CLI cannot read the value, it ignores it and shows a warning.

If a provider gives an expiry time, `auth status` shows that time. After that time, the session shows as expired. After only the estimate, it shows as likely expired (yellow), because the real lifetime can be longer. A session from an older version shows `yes` until its next renewal.

With `--json`, `auth status` prints the same data:

- `logged_in` is false when the session has expired. It stays true when the session is only likely expired.
- Times are RFC 3339, each with an `expired` flag.
- The account includes its `profile_url`.
- If the provider gave no refresh-token expiry, `estimated_lapse_at` and the `assumed_lifetime` it uses are included.

```bash
source-coop auth status --json | jq -r .login.refresh_token.issued_at
```

`auth status` shows one environment and one role, because the keyring cannot list its entries. To see others, use `--proxy-url` and `--role-arn` (or `SOURCE_PROXY_URL` and `SOURCE_ROLE_ARN`).

### Sign out

`auth logout` removes the session of one environment and the credentials of one role. It removes them from the keyring and from the [file fallback](#file-fallback).

```bash
# the default environment and role
source-coop auth logout

# another environment and role
source-coop auth logout --proxy-url https://data.staging.source.coop --role-arn reader-role

# {"proxy_url": …, "role_arn": …, "removed": {"session": true, "credentials": true}}
source-coop auth logout --json
```

It uses `--proxy-url` (`SOURCE_PROXY_URL`) and `--role-arn` (`SOURCE_ROLE_ARN`), as `creds` does.

The keyring cannot list its entries, so the credentials of other roles stay. You can use them until they expire, but the CLI cannot renew them without the session. To remove them now, run `auth logout --role-arn <role>` for each role.

`auth logout` does not revoke tokens at the identity provider.

![`auth logout --json`, then `auth status` and `creds` signed out](docs/demos/auth-logout.svg)

<!-- group: Work with data -->

## Reading data with AWS tools

### AWS `credential_process`

1. Sign in once:

   ```bash
   source-coop auth login
   ```

2. Add a profile to `~/.aws/config`:

   ```ini
   [profile source-coop]
   credential_process = source-coop creds
   endpoint_url = https://data.source.coop
   ```

3. Use AWS tools with that profile:

   ```bash
   aws s3 ls s3://my-account/my-product --profile source-coop
   ```

When the credentials expire, `source-coop creds` gets new ones with the session. Run `source-coop auth login` again only if this fails, for example because the refresh token expired or was revoked.

![`aws s3 ls` through `credential_process`, then `creds --format env`](docs/demos/aws.svg)

### Output formats

`creds` and `auth login` print credentials in one of three formats. Select one with `--format`:

**credential-process** (default): JSON for AWS `credential_process`.

```bash
source-coop creds
```

**env**: shell `export` statements. They set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` in your shell.

```bash
eval $(source-coop creds --format env)
```

**aws-credentials**: an INI profile for `~/.aws/credentials`. `--profile` sets the section name.

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
> These credentials are temporary. When they expire, run the command again. Each run adds a new section, and AWS uses the last one, so remove old sections occasionally. We recommend `credential_process` in `~/.aws/config` instead.

### Multiple roles

> [!WARNING]
> The Source Cooperative data proxy does not yet support custom roles.

The CLI keeps the credentials of each role separately:

```bash
# credentials for a read-only role
source-coop auth login --role-arn reader-role

# credentials for an admin role, kept separately
source-coop auth login --role-arn admin-role
```

Use `--role-arn` with `creds` to select the role:

```ini
[profile source-coop]
credential_process = source-coop creds --role-arn reader-role
endpoint_url = https://data.source.coop

[profile source-coop-admin]
credential_process = source-coop creds --role-arn admin-role
endpoint_url = https://data.source.coop
```

## Uploading data with AWS tools

The profile from [Reading data with AWS tools](#reading-data-with-aws-tools) also writes:

```bash
# one file
aws s3 cp data.parquet s3://my-org/my-data/data.parquet --profile source-coop

# a folder, copying only new and changed files
aws s3 sync ./output s3://my-org/my-data/output/ --profile source-coop

# remove an object
aws s3 rm s3://my-org/my-data/old.parquet --profile source-coop
```

The data proxy accepts a write when all of these are true. Otherwise it answers `AccessDenied`.

- **You may write to the product:** you are a member of it, or of its organization, as `write_data`, `maintainers` or `owners` (see [Members](#members)).
- **Its data connection accepts writes.** A read-only connection refuses them, whoever writes.
- **Your role writes.** The default role does. `ReadOnly` does not.

Name the object, or end the path with `/`. `aws s3 cp data.parquet s3://my-org/my-data` has no object key, and the proxy refuses it with `Missing object key`.

To upload from a GitHub Actions workflow or a script, sign in as a [service account](#service-accounts) with write access to the product (see [Access to products](#access-to-products)). `service-account usage` prints a workflow that signs in (see [Use a service account](#use-a-service-account)). Replace its last step, `aws s3 ls`, with your `aws s3 sync`.

<!-- group: Manage source.coop -->

## Accounts

`source-coop account` shows and changes accounts: yours, and the organizations you belong to. It also creates organizations. An account's ID is the first part of its products' names and of its page, `source.coop/ID`.

### List and view

```bash
# your account, then each organization you're a member of
source-coop account list

# each one's whole record, as JSON
source-coop account list --json

# move through them full screen (see "Browsing with -i")
source-coop account list -i

# one account: its name, websites, email, bio and dates
source-coop account view my-org

# open its page in the browser
source-coop account view my-org -w
```

`list` shows one row for each account: its ID, its type (`individual` or `organization`) and its name. On a terminal, it shows them in your pager (`--no-pager` prints directly). When piped, the rows are tab-separated, with no header. A disabled organization is left out, with a note, unless you are one of its owners or maintainers: source.coop doesn't show it to its other members. `list` and `view` show only some of an account's fields. `--json` has all of them, such as its flags.

![`account list`, `view`, then `list --json`](docs/demos/account-list.svg)

### Create an organization

```bash
# prompts for the ID, name and bio, then asks you to confirm
source-coop account create

# from flags; --website can be repeated
source-coop account create my-org --name "My Org" --bio "Open climate data" --website my-org.example

# from a file or stdin; flags win
echo '{"name": "My Org", "email": "data@my-org.example"}' | source-coop account create my-org -F - --json
```

You become the organization's owner. You can create organizations only if source.coop has given your account permission. Otherwise the API refuses with exit code 4.

The name defaults to one made from the ID, as on the web: `my-org` becomes `My Org`. If the ID is taken, the CLI asks for another. Going back, drafts and the sign-in check work as for products (see [Prompts](#prompts)). `create` prints the organization's page on stdout, so `url=$(source-coop account create …)` works.

People get their accounts when they sign up on the website. To create an account for software, use [`service-account create`](#service-accounts).

![`account create`: prompts, going back, a review, then a taken ID](docs/demos/account-create.svg)

### Edit

```bash
# the edit form: name, bio and location
source-coop account edit my-org

# select the account first
source-coop account edit -i

# from flags; an empty string clears a field
source-coop account edit my-org --bio "Open climate data" --location ""
source-coop account edit my-org --website my-org.example --website docs.my-org.example   # replaces the websites
source-coop account edit my-org --email data@my-org.example --ror-id 05abc1234
source-coop account edit my-ada --orcid 0000-0002-1825-0097

# turn an organization off, or back on
source-coop account edit my-org --disable
source-coop account edit my-org --enable
```

You can edit your own account and the organizations you own or maintain. Only owners can disable or enable an organization. A disabled account can't sign in, and nothing new can be attached to it.

There is no `account delete`: source.coop never deletes people or organizations. Use `--disable`.

![`account edit`: the edit form, then flags](docs/demos/account-edit.svg)

## Products

`source-coop product` lists, views, creates, edits and deletes products through the source.coop API (`/api/v1`). The CLI does not check values itself. It shows the API's errors for each field. A product's name is `ACCOUNT/PRODUCT`.

### List and view

```bash
# public products
source-coop product list

# the products of one account, as JSON
source-coop product list my-org --json

# one row for each product; tab-separated when piped
source-coop product list --format table

# search titles, descriptions and IDs
source-coop product list -q climate

# featured products with all these tags
source-coop product list --tags zarr,climate --featured

# up to 100 (default 30, or all in the pager)
source-coop product list -L 100

# move through them full screen (see "Browsing with -i")
source-coop product list my-org -i

# one product
source-coop product view my-org/my-product

# open its page in the browser
source-coop product view my-org/my-product -w

# its screen, with shortcuts; with no name, select one first
source-coop product view my-org/my-product -i
```

`list` has two formats:

- `--format details` (default) shows the fields of each product, as `view` does.
- `--format table` shows one row for each product. On a terminal, the table is aligned and has a header. When piped, the rows are tab-separated, with no header.

On a terminal, `list` shows the products in your pager and gets more pages as you read. In other cases, it stops at `--limit`. To continue from there, give `--cursor` the cursor that the last list printed.

![`product list`: a table, a search, then `--json`](docs/demos/product-list.svg)

`list -i` and `view -i` show products full screen. [Browsing with `-i`](#browsing-with--i) lists the keys.

![`product list -i`: open a product, go back, filter with `/`](docs/demos/product-browse.svg)

### Create

```bash
# asks for all values
source-coop product create

# asks for the other values
source-coop product create my-org/my-product

# all values from flags
source-coop product create my-org/my-product -t "My product" -d "What's in it" \
    --visibility public --data-connection my-connection

# values from JSON on stdin
echo '{"title": "My product"}' | source-coop product create my-org/my-product -F -
```

Give the values as flags (`--title`, `--description`, `--visibility`, `--data-connection`), as a JSON object with `--from-file PATH` (`-` for stdin), or both. Flags take priority.

At a terminal, `create` asks for the missing values, with the web form's defaults:

- The accounts that you can create products in.
- A title made from the product ID.
- The data connections that the account can use.
- The visibilities that the selected data connection allows.

You cannot change a product's data connection after you create it. For how to go back, the review, and drafts, see [Prompts](#prompts).

`create` prints the product's URL on stdout and its message on stderr. Thus `url=$(source-coop product create ...)` works.

![`product create` with prompts: ↑ goes back a question, then the review](docs/demos/product-create.svg)

### Edit

```bash
# a form of its fields
source-coop product edit my-org/my-product

# change one field
source-coop product edit my-org/my-product --visibility unlisted

# change one field and print the result as JSON
source-coop product edit my-org/my-product -d "New description" --json

# --enable makes it active again (admins only)
source-coop product edit my-org/my-product --disable

# select one of your account's products
source-coop product edit -i
```

`edit` uses the same values as `create`, but not the data connection. Give them as flags or with `--from-file`. `--disable` and `--enable` are flags only. `edit` prints the product's URL on stdout.

With no flags, `edit` opens a full-screen form of the title, description and visibility:

- <kbd>↑</kbd> <kbd>↓</kbd> moves between the fields.
- <kbd>Enter</kbd> changes the selected field, starting from its current value. <kbd>Esc</kbd> keeps the value.
- The form shows only the visibilities that the data connection allows.
- A changed field shows its old value.
- <kbd>s</kbd>, or <kbd>Enter</kbd> on *Save changes*, shows the changes and asks you to confirm. <kbd>←</kbd> goes back to the form.
- <kbd>Esc</kbd> or <kbd>←</kbd> on the form cancels. If you changed a field, the form asks first.

![`product edit`: the edit form, then a flag](docs/demos/product-edit.svg)

### Delete

```bash
# asks you to type the name
source-coop product delete my-org/my-product

# keep its objects in storage
source-coop product delete my-org/my-product --preserve-data

# no questions, for scripts
source-coop product delete my-org/my-product --yes --json

# select one of your account's products
source-coop product delete -i
```

`delete` asks two questions:

1. Keep the product's data in storage? `--preserve-data` answers yes.
2. Type the product's name. If the text is different, nothing is deleted.

Without a terminal, `delete` needs `--yes`.

![`product delete`: the name typed wrong, then right, then `--yes`](docs/demos/product-delete.svg)

## Members

`source-coop member` manages the members of an organization (`ACCOUNT`) or a product (`ACCOUNT/PRODUCT`). [`source-coop invitation`](#invitations) answers the invitations that you receive. A member's name is their account ID. You cannot invite by email.

**Roles**, from most to least access: `owners`, `maintainers`, `write_data`, `read_data`.

- Only owners can make a member an owner, or change or revoke an owner.
- Owners and maintainers can manage the other roles.
- A product's member list shows only the product's own members. The organization's members can also use its products, and show in the organization's list.

With [shell completion](#shell-completion), TAB shows:

- For `ACCOUNT` or `ACCOUNT/PRODUCT`: your organizations and their products.
- For a member: the members of that organization or product.
- For `invite`: the organization's members who are not yet members of the product.
- For `invitation accept`, `reject` and `member leave`: your invitations and memberships.

With `--json`, these commands print the memberships as the API gives them: `membership_id`, `account_id`, `membership_account_id`, `product_id` (for a product), `role`, `state` and `state_changed`. `invite --json` prints an array of the new memberships.

`create` and `delete` are other names for `invite` and `revoke`.

### List and view

```bash
# members and open invitations
source-coop member list my-org

# the members of a product, as JSON
source-coop member list my-org/my-data --json

# only open invitations
source-coop member list my-org --state invited

# move through the members full screen
source-coop member list my-org -i

# one member; -i for its screen
source-coop member view my-org alice
```

![`member list` and `view`, then `--json`](docs/demos/member-list.svg)

`member list -i` uses the same keys as `product list -i`. On a member's screen:

- `e` changes the role.
- `d` revokes the membership. For an invitation, `d` withdraws it, and `e` is not available.
- `b` opens their profile.

![`member list -i`: open a member and change their role](docs/demos/member-browse.svg)

### Invite

```bash
# invite two accounts to an organization
source-coop member invite my-org alice bob --role maintainers

# invite each account listed in a file to a product
source-coop member invite my-org/my-data -A people.txt --role read_data

# asks who to invite, and the role
source-coop member invite my-org
```

`invite` takes account IDs as arguments.

- `--accounts-file PATH` (`-A`, `-` for stdin) adds one ID from each line. It skips empty lines and lines that start with `#`.
- `--from-file` reads `account_id` and `role` from a JSON object.
- Each account gets its own invitation. If the API refuses one, the CLI shows the error and sends the others. Then the command fails.
- At a terminal, `invite` asks for the missing accounts and role, and then asks you to confirm. The default role is `read_data`. It shows `owners` only if you can give that role. <kbd>←</kbd> goes back one question.
- If invitations fail, the CLI saves the ones not sent as a draft. The next `invite` to the same place offers them again.
- If you invite a service account of the product's owner, it becomes a member at once. Its role must be `read_data` or `write_data`.

![`member invite` with prompts, then from flags with `--json`](docs/demos/member-invite.svg)

### Edit

```bash
# give a member another role
source-coop member edit my-org alice --role owners

# select a member, then a role
source-coop member edit my-org -i
```

Without `--role`, `edit` asks for a role, starting from the current one. You cannot change the role of an invitation. Revoke it and invite again.

![`member edit`: pick a role, then `--role` with `--json`](docs/demos/member-edit.svg)

### Revoke and leave

```bash
# also withdraws an open invitation
source-coop member revoke my-org alice

# end your own membership
source-coop member leave my-org
```

`revoke` asks you to confirm. For your own membership, you must also type the organization or product name.

`leave` always asks you to type the name, because only an owner or maintainer can add you again.

Without a terminal, `revoke` and `leave` need `--yes`.

![`member revoke` an invitation, then `member leave` with the name typed wrong](docs/demos/member-revoke.svg)

## Invitations

`source-coop invitation` answers the invitations that you receive. To invite someone, see [Members](#members).

### List

```bash
# invitations that wait for your answer
source-coop invitation list

# as JSON
source-coop invitation list --json

# open one, then accept (a) or reject (r) it
source-coop invitation list -i
```

### Accept and reject

```bash
# accept an invitation to a product
source-coop invitation accept my-org/my-data

# reject an invitation to an organization
source-coop invitation reject my-org

# select an invitation
source-coop invitation accept -i
```

When you accept, you become a member with the role of the invitation. With `--json`, the command prints the membership after the change.

![`invitation list -i`: accept one, then reject another](docs/demos/invitations.svg)

## Service accounts

A service account is an account for software, such as a GitHub Actions workflow or a script with an API key. It has an owner: you, or an organization that you own or maintain. source.coop must first let that account own service accounts.

A service account's ID is the owner's ID, then `--`, then its own name: `my-org--nightly-sync`. AWS tools use this ID: `role-to-assume: arn:aws:iam::my-org--nightly-sync:role/FullAccess`.

`source-coop service-account` shows a service account as the web UI does: what it is, how it signs in, and the products it can use.

### List and view

```bash
# my-org's service accounts (yours, with no owner)
source-coop service-account list my-org

# print directly, not in the pager
source-coop service-account list my-org --no-pager

# move through them full screen (keys as for products)
source-coop service-account list my-org -i

# --json adds `trusts`, `keys` and `memberships`
source-coop service-account view my-org--nightly-sync

# open its page in the browser
source-coop service-account view my-org--nightly-sync -w
```

![`service-account list`: an owner's service accounts, then as `--json`](docs/demos/service-account-list.svg)

`view` shows who the service account is, how it signs in and the products it can reach. `--json` adds `trusts`, `keys` and `memberships`.

![`service-account view`: who it is, how it signs in, what it can reach; `--json` adds `trusts` and `memberships`](docs/demos/service-account-view.svg)

`list -i` uses the same keys as `product list -i`. On a service account's screen, `e` edits it and `d` deletes it.

![`service-account list -i`: open one, go back, delete one from its screen](docs/demos/service-account-picker.svg)

### Create

```bash
# asks for all values, as the web form does
source-coop service-account create

# all values from flags
source-coop service-account create my-org--nightly-sync --name "Nightly sync" \
    --github my-org/data --branch main --access my-org/my-data=write
```

`create` takes values as flags, as a JSON object with `--from-file`, or both:

- Flags: `--name`, one `--github` workflow, a `--key` with `--expires` and `--out`, and `--access` (one or more).
- JSON uses the API's fields: `name`, `local_id`, `github_subjects`, `key`, `grants`.

At a terminal, `create` asks for the missing values: the owner, the name, the ID (made from the name), workflows and an API key, and products. Then it shows all values, with the condition that each workflow must match, and asks you to confirm.

![`service-account create` with prompts](docs/demos/service-account-create.svg)

If `create` issues a key, it gives you the key as `sign-in add` does. But stdout gets the account's ID, not the key. To keep the key, use `--out` or `--json`.

`create` and `edit` print the service account's ID on stdout. Thus `id=$(source-coop service-account create …)` works. Going back, drafts, the sign-in check and `--yes` work as for products.

![`service-account create` from flags, with `--json`](docs/demos/service-account-create-flags.svg)

### Edit

```bash
# rename it
source-coop service-account edit my-org--nightly-sync --name "Nightly sync"

# a form of its name and products
source-coop service-account edit my-org--nightly-sync

# --enable lets it sign in again
source-coop service-account edit my-org--nightly-sync --disable
```

`--disable` stops all sign-ins as the service account. It keeps its sign-ins and products. `--enable` lets its workflows and its keys that are not revoked sign in again.

With no flags, `edit` opens a form of its name and products (see [Access to products](#access-to-products)).

![`service-account edit`: `--disable`, `--enable`, then a rename in the edit form](docs/demos/service-account-edit.svg)

### Delete

```bash
# asks you to type its ID
source-coop service-account delete my-org--nightly-sync
```

`delete` removes the service account, its sign-ins and its access to products. Type its ID to confirm, or use `--yes`.

![`service-account delete`: typed confirmation, then `--yes --json`](docs/demos/service-account-delete.svg)

### Access to products

A service account can read, or read and write, its owner's products. Each grant is a usual membership of the product.

- `create --access` gives access when you create the service account.
- `edit --access` gives access, changes the role, or removes access (`=none`).

```bash
source-coop service-account edit my-org--nightly-sync --access my-org/my-data=write --access my-org/old-data=none
```

If the product already has that role, or has no access to remove, nothing changes. Thus you can run an edit two times safely.

With no flags, `edit` opens a full-screen form with **Name**, then the products under **Can reach**, each with its role:

- <kbd>↑</kbd> <kbd>↓</kbd> moves. <kbd>Enter</kbd> changes the selected row: the name, or the access to a product (Read, Read and write, or No access).
- *Grant a product…* adds one of the owner's other products.
- A changed row shows its old value.
- <kbd>s</kbd>, or <kbd>Enter</kbd> on *Save changes*, shows the changes and asks you to confirm. <kbd>←</kbd> goes back to the form.
- <kbd>Esc</kbd> or <kbd>←</kbd> on the form cancels. If you changed a row, the form asks first.

`--disable` and `--enable` are flags only.

![`service-account edit --access`, then the edit form: take a product away, grant another](docs/demos/service-account-access.svg)

### Sign-ins

A service account signs in in one of two ways:

- **A GitHub Actions workflow** that it trusts. The trust is for one repository and one branch, tag or environment. GitHub vouches for each run, so there is no secret to keep.
- **An API key**, where GitHub is not available.

```bash
# trust runs on a branch
source-coop service-account sign-in add my-org--nightly-sync --github my-org/data --branch main

# trust runs in a GitHub environment
source-coop service-account sign-in add my-org--nightly-sync --github my-org/data --environment production

# trust a subject as it is
source-coop service-account sign-in add my-org--nightly-sync --subject repo:my-org/data:ref:refs/tags/v1

# remove a trust by its subject
source-coop service-account sign-in remove my-org--nightly-sync repo:my-org/data:ref:refs/heads/main

# select a sign-in
source-coop service-account sign-in remove my-org--nightly-sync -i
```

- `--github OWNER/REPO` with `--branch`, `--tag` or `--environment` makes the subject that GitHub's tokens contain, such as `repo:OWNER/REPO:ref:refs/heads/main`.
- `--subject` takes a subject as it is.

The CLI asks GitHub how the repository's tokens name it, as the web UI does. Some repositories use IDs (`owner@123/repo@456`), which never match `owner/repo`. For a private repository, set `GH_TOKEN` (or `GITHUB_TOKEN`). If GitHub does not answer, the CLI tells you how to find the name.

At a terminal, without these flags, `sign-in add` asks for the repository and the runs to trust. Then it shows the condition and asks you to confirm.

![`sign-in add` with prompts and from flags, `sign-in remove -i`, `sign-in revoke-key`](docs/demos/service-account-sign-in.svg)

**API keys** are for places without GitHub's tokens, such as a cron job on a cluster.

- Each key has a label that tells where it is used. Use it to find the key to revoke.
- A key expires after 30 days, 90 days (default), one year, never, or on a date (at midnight UTC).

```bash
# issue a key that expires in a year, and save it to a file
source-coop service-account sign-in add my-org--nightly-sync --key "HPC cron job" --expires 1y --out ~/.source-coop/nightly.key

# piped: only the key on stdout
key=$(source-coop service-account sign-in add my-org--nightly-sync --key "HPC cron job")

# a new expiry, from now
source-coop service-account sign-in edit my-org--nightly-sync key:a1B2c3 --expires never

# revoke it; asks you to type key:a1B2c3
source-coop service-account sign-in remove my-org--nightly-sync key:a1B2c3
```

The CLI shows a key one time only, when it issues the key:

- `--out PATH` writes the key to a new file that only you can read. AWS tools read the key from a file.
- If a file is already at that path, the CLI does not overwrite it. It shows the key. It also shows the key if it cannot write the file.
- When piped, stdout gets only the key.
- On a terminal, the CLI asks for a file name. Press <kbd>Enter</kbd> to show the key instead.

`view` lists each key by its label and its last six characters, such as `key:a1B2c3`. `sign-in edit` and `sign-in remove` use this name. `view` also shows when the key was last used and when it expires. It shows revoked and expired keys dimmed. You cannot restore a revoked key.

At a terminal, without flags, `sign-in add` asks if you want a workflow or a key. `sign-in edit -i` and `sign-in remove -i` let you select one.

![`sign-in add --key --out`, `sign-in edit -i` and `sign-in remove`: issue an API key, give it a new expiry, then revoke it](docs/demos/service-account-keys.svg)

If a key leaks, anyone with the key can revoke it, without signing in. The command reads the key from stdin, so the key is not in your shell history:

```bash
source-coop service-account sign-in revoke-key < leaked-key-file
```

### Use a service account

Workflows and scripts sign in with standard AWS tools, not with this CLI. `usage` prints what they need, as the web UI does:

```bash
# a workflow that uses aws-actions/configure-aws-credentials
source-coop service-account usage my-org--nightly-sync --subject repo:my-org/data:ref:refs/heads/main \
    > .github/workflows/source-coop.yml

# the AWS_* variables for a key in a file
source-coop service-account usage my-org--nightly-sync --key
```

At a terminal, without `--subject` or `--key`, `usage` asks which sign-in to show.

![`service-account usage`: pick a sign-in for its workflow, then `--key`](docs/demos/service-account-usage.svg)

<!-- group: How commands work -->

## Prompts

At a terminal, commands that change data ask for the values that you do not give. All commands ask in the same way.

- **Priority.** Flags take priority over `--from-file PATH` (`-F`, `-` for stdin). The file takes priority over prompts. The CLI asks only for the missing values.
- **Sign-in check.** Before the first question, `create`, `edit` and `delete` make sure that you are signed in.
- **Go back.** To go back to the previous question, press <kbd>↑</kbd> in a text question (or <kbd>←</kbd> at the start of the line), or <kbd>←</kbd> in a list. The previous answer stays as the start value. Later answers stay. The CLI skips questions that a flag or file answered.
- **Review.** After it asks a question, the command shows what it will send and asks you to confirm. <kbd>←</kbd> goes back.
- **Long text.** Type a description on one line, or press <kbd>Ctrl</kbd>+<kbd>E</kbd> to write it in your editor (`$VISUAL` or `$EDITOR`). A one-line description shows in the line for you to edit. An empty line removes it. A longer description is not shown in the line. Press <kbd>Enter</kbd> on the empty line to keep it.
- **Errors.** If the API refuses a value that you typed (HTTP 400), the CLI shows the reason and asks for that value again.
- **Cancel.** Press <kbd>Esc</kbd> (or <kbd>q</kbd> in a list). The CLI shows "Cancelled; nothing was changed." and exits with code 1. When you must type a name to confirm, <kbd>Enter</kbd> on an empty line also cancels. <kbd>Ctrl</kbd>+<kbd>C</kbd> stops at once, with exit code 130.
- **Drafts.** If the send fails in another way (for example, the ID is taken, there is no connection, the session has expired or the server fails), the CLI saves your answers as a draft. Run the same command again to use them. Flags take priority over the draft. You can also give the draft file with `--from-file`. After a successful send, the CLI deletes the draft.

Drafts are in your OS's application state folder:

| Platform | Path |
|----------|------|
| Linux | `~/.local/state/source-coop/drafts` (`$XDG_STATE_HOME`) |
| macOS | `~/Library/Application Support/source-coop/drafts` |
| Windows | `%LocalAppData%\source-coop\drafts` |

The CLI does not ask questions if stdin or stderr is not a terminal, or if `SOURCE_PROMPT_DISABLED` is set. It sends the values that it has, and the API tells you which ones are missing. Then delete, revoke and leave need `--yes`.

![Prompts: a refused ID asked again, a draft kept after a failure, then Esc](docs/demos/prompts.svg)

## Browsing with `-i`

`-i` (`--interactive`) is available where a command names or lists records:

- `list -i` shows the records full screen.
- `view -i` shows the screen of one record.
- `edit`, `delete`, `revoke` and the other commands let you select the record if you do not name it.

`-i` uses the full terminal. When you exit, the terminal is as before. Results show as a notice on the screen.

| Key | In a list | On a record |
|-----|-----------|-------------|
| <kbd>↑</kbd> <kbd>↓</kbd> or <kbd>k</kbd> <kbd>j</kbd>, <kbd>PgUp</kbd> <kbd>PgDn</kbd>, <kbd>Home</kbd> <kbd>End</kbd> | move | |
| <kbd>→</kbd> <kbd>Enter</kbd> or <kbd>l</kbd> | open the record | |
| <kbd>←</kbd> <kbd>Esc</kbd> or <kbd>h</kbd> <kbd>q</kbd> | exit (in search results: go back to the full list) | go back to the list |
| <kbd>/</kbd> | filter the loaded records by text, with the number of matches (<kbd>Esc</kbd> clears the filter). In all public products, <kbd>Enter</kbd> searches the server, and <kbd>←</kbd> exits the results. | |
| <kbd>b</kbd> | open in the browser | open in the browser |
| <kbd>e</kbd> | | edit (for a member: change the role) |
| <kbd>d</kbd> | | delete (for a member: revoke) |
| <kbd>a</kbd> <kbd>r</kbd> | | accept or reject (an invitation) |

To edit or delete, you must open the record first. Thus a wrong key in a list changes nothing. The shortcuts do the same as the commands, with the same questions. Lists get more records as you move down.

![`product list -i`: open a product, go back, filter with `/`](docs/demos/product-browse.svg)

## Shell completion

Add the line for your shell to its startup file:

```text
# bash: ~/.bashrc
eval "$(source-coop completions bash)"

# zsh: ~/.zshrc, after compinit
eval "$(source-coop completions zsh)"

# fish: ~/.config/fish/config.fish
source-coop completions fish | source

# elvish: ~/.config/elvish/rc.elv
eval (source-coop completions elvish | slurp)

# PowerShell: $PROFILE
source-coop completions powershell | Out-String | Invoke-Expression
```

TAB then completes commands, flags, flag values and record names:

- `source-coop product view my-org/<TAB>` shows the products of `my-org`. Before the `/`, it shows the accounts that you are a member of.
- `source-coop account view <TAB>` shows your account and the organizations that you are a member of.
- `source-coop service-account view my<TAB>` shows full service account IDs, such as `my-org--nightly-sync`. It does not complete the ID of a new service account for `create`.

![Shell completion: TAB lists products and service accounts from the API](docs/demos/completion.svg)

How completion works:

- **It always matches the installed version.** On each TAB, the script runs `source-coop` with `SOURCE_COOP_COMPLETE` set.
- **Names come from the API, as you.** Completion uses your session's access token (or `SOURCE_TOKEN`) and never renews it. When the token has expired, only public products complete. The next command that you run renews it.
- **It reads the environment only.** It uses `SOURCE_API_URL` and `SOURCE_PROXY_URL`. It ignores `--api-url` and `--proxy-url` on the command line.
- **It waits 2 seconds for the API.** After that, it shows no names, and bash shows file names.
- **On macOS, the keychain can ask for your password.** TAB waits up to one minute for you. Select **Always Allow** so that it does not ask again until you install a new build.

<!-- group: Automate -->

## Scripts and AI agents

`source-coop --help` ends with a summary of this section. The `--help` of each command shows its flags and examples. Thus an AI agent can learn the CLI from the CLI.

### Output

- **Data goes to stdout. Messages go to stderr.** Thus `url=$(source-coop product create ...)` works.
- **On a terminal, output is for people.** It has color, unless `NO_COLOR` is set or `CLICOLOR=0`. Lists show in your pager: `$SOURCE_PAGER`, `$PAGER`, then `less -FRX`. `--no-pager` or `SOURCE_PAGER=cat` prints directly.
- **When piped, output is plain**, with no pager.
- **`-v` (`--verbose`)** prints the HTTP requests and responses on stderr.

### JSON

These commands accept `--json`:

- `auth status` and `auth logout`.
- All `account` commands.
- `product list`, `view`, `create`, `edit` and `delete`.
- All `member` and `invitation` commands.
- `service-account list`, `view`, `create`, `edit` and `delete`, and `sign-in add`, `edit` and `remove`.

Commands that change data print the record after the change. `service-account edit --json` prints the account as `view --json` does.

With `--json`:

- stdout contains one JSON document and nothing else. Notes and progress go to stderr.
- Field names are the API's. Times are RFC 3339.
- New fields can be added. Fields are not renamed or removed.

These commands do not accept `--json`, because their output is already for machines: `creds` (`--format`), `auth token` (a token), `api` (the API's response), `completions` (a shell script) and `service-account usage` (a workflow or shell exports). `auth login` does not accept it either, because it uses the browser. Use `auth status --json` after it.

With `--json`, an error is also JSON, on stderr. If the error came from the API, it contains the data of the API's [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem:

- `code` and `status`.
- `type`: a URL to a page that explains the error and what to do.
- `request_id`: give it if you report the error.
- `field_errors`: if the API refused the input, the fields to correct, by path (`metadata.title`).

```json
{"error": {"code": "invalid", "message": "…", "status": 400, "field_errors": {"title": ["…"]}, "type": "https://source.coop/api/problems/invalid", "request_id": "…"}}
```

### Exit codes

All commands use the same exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Other failure, including a cancelled prompt |
| 2 | Incorrect command-line usage |
| 3 | The API refused the input (HTTP 400, 409, 422). Correct the named fields and try again. |
| 4 | Not signed in, or not allowed (HTTP 401, 403) |
| 5 | Not found (HTTP 404) |
| 130 | Interrupted (<kbd>Ctrl</kbd>+<kbd>C</kbd>) |

![Without a terminal: errors, `--json`, exit codes and `-F -`](docs/demos/scripting.svg)

### Use the API without signing in

If `SOURCE_TOKEN` is set, the CLI sends it to the API instead of the session's access token. Thus a script or CI job can use the API without `auth login`.

### Use your session with other tools

`auth token` prints the session's access token for the source.coop API. If the token has expired, it renews it first.

```bash
curl -H "Authorization: Bearer $(source-coop auth token)" https://source.coop/api/v1/...
```

![`auth token`: the session's access token, for `curl`](docs/demos/auth-token.svg)

To send a request through the CLI, see [Any API request](#any-api-request).

## Any API request

`source-coop api` sends a request to `/api/v1` as you, and prints the response. Use it for what the other commands do not do.

```bash
# GET, with a query parameter
source-coop api products/my-org -q limit=5

# POST, with fields from flags
source-coop api products/my-org -f product_id=new -f title="New" -f description="" \
  -f visibility=public -f data_connection_id=my-connection

# PATCH, with fields from a file and a flag (the flag wins)
source-coop api products/my-org/new -X PATCH -F changes.json -f title="Renamed"

# PATCH, with the body from stdin
echo '{"title": "Renamed", "tags": ["a"]}' | source-coop api products/my-org/new -X PATCH -F -
```

| Flag | Does |
|------|------|
| `-q key=value` | Adds a query parameter. |
| `-f key=value` | Sets a field in the JSON body. A value that is valid JSON (`5`, `true`, `null`, `["a","b"]`) is sent as JSON. Other values are strings. To send a JSON-like value as a string, quote it: `-f product_id='"2024"'`. |
| `-F file.json` | Reads the body from a file (`-` for stdin). `-f` fields replace its keys. |
| `-X METHOD` | Sets the method. The default is `GET`, or `POST` with a body. A `GET` has no body. |

The path is always under `/api/v1`. A query string in the path is kept. The API's OpenAPI spec at [`https://source.coop/api/openapi`](https://source.coop/api/openapi) lists the paths and their fields.

`api` prints the response body on stdout as the API sent it, so it does not accept `--json`. It also prints error responses there. If the status is not a success, the exit code shows the type of error (see [Exit codes](#exit-codes)).

Public data needs no sign-in. Other requests use the session from `source-coop auth login`, with an access token for the API (`--audience`, default `https://source.coop`). The CLI renews this token when necessary. If `SOURCE_TOKEN` is set, the CLI sends it instead. To use a different deployment, such as `http://localhost:3000`, set `--api-url` (or `SOURCE_API_URL`).

![`api`: any request to the API](docs/demos/api.svg)

<!-- group: Reference -->

## Configuration

The CLI has no configuration file. Flags and environment variables set all values. A flag takes priority over its variable.

| Env var | Flag | Default | Sets |
|---------|------|---------|------|
| `SOURCE_PROXY_URL` | `--proxy-url` | `https://data.source.coop` | The environment: the data proxy, and the session and credentials to use |
| `SOURCE_API_URL` | `--api-url` | `https://source.coop` | The source.coop site whose API (`/api/v1`) commands use |
| `SOURCE_TOKEN` | | | A bearer token for the API, used instead of the session's |
| `SOURCE_ROLE_ARN` | `--role-arn` | `_default` | The role for `creds`, `auth login`, `status` and `logout` |
| `SOURCE_OIDC_ISSUER` | `--issuer` | `https://auth.source.coop` | Where `auth login` signs in |
| `SOURCE_OIDC_CLIENT_ID` | `--client-id` | source.coop's | The OAuth2 client for `auth login` |
| `SOURCE_API_AUDIENCE` | `--audience` | `https://source.coop` | The audience of the API access token that `auth login` requests |
| `SOURCE_REFRESH_TOKEN_LIFETIME` | | `30d` | The refresh-token lifetime that `auth status` assumes, for example `720h` or `14d` |
| `SOURCE_PROMPT_DISABLED` | | | If set to any value, the CLI never asks questions |
| `SOURCE_PAGER`, `PAGER` | `--no-pager` | `less -FRX` | The pager for lists on a terminal |
| `VISUAL`, `EDITOR` | | | The editor that <kbd>Ctrl</kbd>+<kbd>E</kbd> opens for long text |
| `GH_TOKEN`, `GITHUB_TOKEN` | | | Lets the CLI ask GitHub about the workflows of a private repository |
| `NO_COLOR`, `CLICOLOR=0` | | | No color, also on a terminal |

`.env.staging` in this repository sets the values for staging. Run `source .env.staging` before a command, or use a subshell as in [Multiple environments](#multiple-environments-for-example-staging).

To set up the OAuth2 client for another deployment of source.coop, see [CONTRIBUTING.md](CONTRIBUTING.md#oidc-provider-setup).

### Multiple environments (for example, staging)

Each proxy host is a different environment, with its own session and credentials. Thus you can be signed in to production and staging at the same time:

```bash
# sign in to production
source-coop auth login

# sign in to staging, in a subshell
( source .env.staging && source-coop auth login )
```

- `--proxy-url` (or `SOURCE_PROXY_URL`) selects the environment for all commands. The default is production.
- `--api-url` (or `SOURCE_API_URL`) selects the site for commands that use the API. `.env.staging` sets both.

An AWS profile for a different environment must use `--proxy-url`. If it does not, it gets production credentials:

```ini
[profile source-coop]
credential_process = source-coop creds
endpoint_url = https://data.source.coop

[profile source-coop-staging]
credential_process = source-coop creds --proxy-url https://data.staging.source.coop
endpoint_url = https://data.staging.source.coop
```

### Sign-in options

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--issuer` | `SOURCE_OIDC_ISSUER` | `https://auth.source.coop` | OIDC issuer URL |
| `--client-id` | `SOURCE_OIDC_CLIENT_ID` | `197e20e7-...` | OAuth2 client ID |
| `--proxy-url` | `SOURCE_PROXY_URL` | `https://data.source.coop` | S3 proxy URL for STS. Also selects the environment of the session. |
| `--role-arn` | `SOURCE_ROLE_ARN` | `_default` | Role ARN to assume |
| `--format` | | `credential-process` | Output format: `credential-process`, `env` or `aws-credentials` |
| `--profile` | | `source-coop` | Profile name for `--format aws-credentials` |
| `--duration` | | | Session duration, for example `3600`, `90s`, `5m`, `12h`, `1d` (a number alone is seconds) |
| `--scope` | | `openid offline_access` | OAuth2 scopes. `offline_access` lets `creds` renew credentials. |
| `--audience` | `SOURCE_API_AUDIENCE` | `https://source.coop` | Audience of the API access token. If empty, the CLI requests none, and only `creds` works. |
| `--port` | | `0` (random) | Local callback port |
| `--no-cache` | | | Print the credentials and keep nothing |

## Credential storage

The CLI keeps the session (the Ory refresh, ID and access tokens) and the temporary STS credentials of each role. Thus `creds` and the API commands work without a new sign-in.

Only the session keeps the refresh token. The refresh token changes each time it is used. Thus all roles and all API calls renew through the session, one at a time.

### OS keyring (default)

The CLI keeps credentials in the OS keyring, with the service name `source-coop-cli`:

- The key of each role's credentials is its role ARN, for example `_default`.
- The key of the session is `@session`.
- For environments other than production, both keys start with the proxy host, for example `data.staging.source.coop/_default` and `data.staging.source.coop/@session`.

| Platform | Backend |
|----------|---------|
| macOS | Keychain (`security` / Keychain Access) |
| Windows | Credential Manager |
| Linux | Secret Service API (GNOME Keyring, KDE Wallet) via D-Bus |

### File fallback

If there is no OS keyring (for example on servers, in containers and in CI), the CLI uses JSON files in the OS cache folder. On Unix, the files have `0600` permissions. You do not need to configure this.

| Platform | Path |
|----------|------|
| macOS | `~/Library/Caches/source-coop/credentials/<role>.json` |
| Linux | `~/.cache/source-coop/credentials/<role>.json` |
| Windows | `%LocalAppData%\source-coop\credentials\<role>.json` |

The session is in `source-coop/session.json`. Other environments use the same layout in `source-coop/env/<host>/`, or in `source-coop/env/<host>/<port>/` if the port is not the default. For example: `source-coop/env/data.staging.source.coop/session.json`.

## Troubleshooting

**`Your login has expired. Run 'source-coop auth login'.`** The session's refresh token expired or was revoked. Sign in again. `source-coop auth status` estimates when it expires.

**`Couldn't get new credentials (…). Run 'source-coop auth login'.`** `creds` could not renew a role's credentials. AWS tools show this message as their own error. The reason is in the brackets. Usually the session has expired, so sign in again.

**macOS asks for your keychain password.** macOS asks the first time a new build reads the `source-coop-cli` keychain items, for example after an upgrade. Select **Always Allow** so that it does not ask again until the next upgrade.

**`AccessDenied` from AWS tools.** The data proxy refused the request. To read a product that is not public, or to write to any product, you must be a member with a role that allows it. Writes have more conditions, in [Uploading data](#uploading-data-with-aws-tools). Check your role with `source-coop member list ACCOUNT` (the organization) or `ACCOUNT/PRODUCT`.

**Exit code 4 or 5.** A command exits with 4 when you are not signed in or not allowed, and 5 when the record does not exist. With `--json`, the error on stderr gives the HTTP `status` and, if the API sent one, a `request_id`. See [Exit codes](#exit-codes).

**A GitHub workflow cannot sign in as a service account.** The trusted subject must match what GitHub puts in the workflow's token, character for character. See [Sign-ins](#sign-ins) for how the CLI finds the repository's subject.

**Reporting a problem.** [Open an issue](https://github.com/source-cooperative/source-coop-cli/issues) with `source-coop --version`, the command, and the `request_id` from the error if there is one.
