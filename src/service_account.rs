//! `source-coop service-account`: the accounts software signs in as, through
//! `/api/v1/accounts/{owner}/service-accounts`, how they sign in (`sign-in`:
//! the GitHub Actions workflows they trust, through `/trusts`) and what they
//! reach (`access`: memberships of their owner's products). Laid out as the
//! web UI's service account page is: "Who it is", "Signs in with", "Can
//! reach".

use crate::api::{ApiError, Client, Page};
use crate::draft::Draft;
use crate::product::{read_fields, str_field, ProductRef, NEEDS_TERMINAL};
use crate::prompt::{Action, Place, Prompter};
use clap::{Args, Subcommand, ValueEnum};
use reqwest::{Method, StatusCode};
use serde_json::{json, Map, Value};
use std::io::IsTerminal;

/// Where GitHub's Actions tokens come from: a trust's `issuer`.
pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// Where to ask how a repository's tokens name it.
const GITHUB_API: &str = "https://api.github.com";

#[derive(Subcommand)]
pub enum ServiceAccountCommand {
    /// List an account's service accounts
    #[command(after_help = crate::style::examples(&["source-coop service-account list my-org --json"]))]
    List(ListArgs),
    /// Show a service account: who it is, how it signs in and what it can reach
    #[command(after_help = crate::style::examples(&["source-coop service-account view my-org--nightly-sync --json"]))]
    View(ViewArgs),
    /// Create a service account, optionally trusting a GitHub workflow and
    /// granting it products
    #[command(
        after_help = crate::style::examples(&[
            "source-coop service-account create my-org--nightly-sync --name \"Nightly sync\" --github my-org/data --branch main --access my-org/my-data=write --json",
            "echo '{\"name\": \"Nightly sync\"}' | source-coop service-account create my-org--nightly-sync -F - --json",
        ])
    )]
    Create(CreateArgs),
    /// Rename, disable or enable a service account
    #[command(
        after_help = crate::style::examples(&[
            "source-coop service-account edit my-org--nightly-sync --name \"Nightly sync\" --json",
            "source-coop service-account edit my-org--nightly-sync --disable --json",
        ])
    )]
    Edit(EditArgs),
    /// Delete a service account, with its sign-ins and product access
    #[command(after_help = crate::style::examples(&["source-coop service-account delete my-org--nightly-sync --yes --json"]))]
    Delete(DeleteArgs),
    /// Add or remove the ways software signs in as a service account
    #[command(subcommand)]
    SignIn(SignInCommand),
    /// Grant, change or remove a service account's access to products
    #[command(subcommand)]
    Access(AccessCommand),
    /// Print what a workflow or script needs to sign in as a service account:
    /// a GitHub Actions workflow, or the environment for an API key
    #[command(
        after_help = crate::style::examples(&[
            "source-coop service-account usage my-org--nightly-sync --subject repo:my-org/data:ref:refs/heads/main",
            "source-coop service-account usage my-org--nightly-sync --key",
        ])
    )]
    Usage(UsageArgs),
}

#[derive(Subcommand)]
pub enum SignInCommand {
    /// Trust a GitHub Actions workflow to sign in as the service account
    #[command(
        after_help = crate::style::examples(&[
            "source-coop service-account sign-in add my-org--nightly-sync --github my-org/data --branch main --json",
            "source-coop service-account sign-in add my-org--nightly-sync --github my-org/data --environment production --json",
            "source-coop service-account sign-in add my-org--nightly-sync --subject repo:my-org/data:ref:refs/tags/v1 --json",
        ])
    )]
    Add(SignInAddArgs),
    /// Stop a workflow signing in as the service account
    #[command(
        after_help = crate::style::examples(&[
            "source-coop service-account sign-in remove my-org--nightly-sync repo:my-org/data:ref:refs/heads/main --yes --json",
        ])
    )]
    Remove(SignInRemoveArgs),
    /// Revoke an API key, read from stdin, wherever it was found; needs no sign-in
    #[command(after_help = crate::style::examples(&["source-coop service-account sign-in revoke-key"]))]
    RevokeKey(RevokeKeyArgs),
}

#[derive(Subcommand)]
pub enum AccessCommand {
    /// Grant the service account one of its owner's products, or change its role
    #[command(
        after_help = crate::style::examples(&[
            "source-coop service-account access set my-org--nightly-sync my-org/my-data --role write --json",
        ])
    )]
    Set(AccessSetArgs),
    /// Take away the service account's access to a product
    #[command(
        after_help = crate::style::examples(&[
            "source-coop service-account access remove my-org--nightly-sync my-org/my-data --json",
        ])
    )]
    Remove(AccessRemoveArgs),
}

impl ServiceAccountCommand {
    /// Whether `--json` was asked for, so a failure is reported as JSON too.
    pub fn wants_json(&self) -> bool {
        match self {
            Self::List(a) => a.json,
            Self::View(a) => a.json,
            Self::Create(a) => a.json,
            Self::Edit(a) => a.json,
            Self::Delete(a) => a.json,
            Self::SignIn(SignInCommand::Add(a)) => a.json,
            Self::SignIn(SignInCommand::Remove(a)) => a.json,
            Self::SignIn(SignInCommand::RevokeKey(_)) => false,
            Self::Access(AccessCommand::Set(a)) => a.json,
            Self::Access(AccessCommand::Remove(a)) => a.json,
            Self::Usage(_) => false,
        }
    }
}

#[derive(Args)]
pub struct ListArgs {
    /// The owner whose service accounts to list (yours when omitted)
    owner: Option<String>,

    /// Print the service accounts as JSON
    #[arg(long)]
    json: bool,

    /// Pick a service account from the list, then view, open, edit or delete it
    #[arg(long, short = 'i', conflicts_with = "json")]
    interactive: bool,

    /// Print straight to the terminal instead of through $SOURCE_PAGER,
    /// $PAGER or `less -FRX`
    #[arg(long)]
    no_pager: bool,
}

#[derive(Args)]
pub struct ViewArgs {
    /// The service account, as OWNER--NAME (with -i, picked when omitted)
    #[arg(required_unless_present = "interactive", value_parser = parse_id)]
    account: Option<String>,

    /// Show the service account with shortcuts: b browser, e edit, d delete, ← back
    #[arg(long, short = 'i', conflicts_with_all = ["web", "json"])]
    interactive: bool,

    /// Open the service account's page in the browser instead
    #[arg(long, short = 'w')]
    web: bool,

    /// Print the service account as JSON, with its `trusts` and `memberships`
    #[arg(long)]
    json: bool,
}

/// One GitHub Actions workflow to trust: a repository and the branch, tag or
/// environment its runs sign in from, or the token subject itself.
#[derive(Args, Default, Clone)]
pub struct GithubArgs {
    /// Trust a GitHub Actions workflow in this repository, as OWNER/REPO (or
    /// OWNER@ID/REPO@ID); name its --branch, --tag or --environment too
    #[arg(long, value_name = "OWNER/REPO")]
    github: Option<String>,

    /// With --github: trust runs on this branch
    #[arg(long, requires = "github", conflicts_with_all = ["tag", "environment"])]
    branch: Option<String>,

    /// With --github: trust runs on this tag
    #[arg(long, requires = "github", conflicts_with = "environment")]
    tag: Option<String>,

    /// With --github: trust jobs that run in this GitHub environment
    #[arg(long, requires = "github")]
    environment: Option<String>,

    /// Trust the GitHub Actions token subject given as it is, e.g.
    /// repo:OWNER/REPO:ref:refs/heads/main
    #[arg(long, conflicts_with = "github")]
    subject: Option<String>,
}

#[derive(Args)]
pub struct CreateArgs {
    /// The new service account, as OWNER--NAME (prompted for when omitted)
    #[arg(value_parser = parse_id)]
    account: Option<String>,

    /// Its name, as people see it
    #[arg(long, short = 'n')]
    name: Option<String>,

    #[command(flatten)]
    github: GithubArgs,

    /// Grant one of the owner's products, as ACCOUNT/PRODUCT=read or =write
    /// (repeatable)
    #[arg(long, value_name = "PRODUCT=ROLE")]
    access: Vec<String>,

    /// Read fields from a JSON object in this file (`-` for stdin), as the
    /// API takes them; flags win
    #[arg(long, short = 'F', value_name = "PATH")]
    from_file: Option<String>,

    /// Print the new service account as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct EditArgs {
    /// The service account, as OWNER--NAME (with -i, picked when omitted)
    #[arg(required_unless_present = "interactive", value_parser = parse_id)]
    account: Option<String>,

    /// Pick the service account when it isn't named
    #[arg(long, short = 'i')]
    interactive: bool,

    /// A new name
    #[arg(long, short = 'n')]
    name: Option<String>,

    /// Stop everything signing in as it; its sign-ins and access are kept
    #[arg(long, conflicts_with = "enable")]
    disable: bool,

    /// Let its workflows and unrevoked keys sign in again
    #[arg(long)]
    enable: bool,

    /// Read fields from a JSON object in this file (`-` for stdin); flags win
    #[arg(long, short = 'F', value_name = "PATH")]
    from_file: Option<String>,

    /// Print the edited service account as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct DeleteArgs {
    /// The service account, as OWNER--NAME (with -i, picked when omitted)
    #[arg(required_unless_present = "interactive", value_parser = parse_id)]
    account: Option<String>,

    /// Pick the service account when it isn't named
    #[arg(long, short = 'i', conflicts_with = "yes")]
    interactive: bool,

    /// Skip the confirmation prompt
    #[arg(long, short = 'y')]
    yes: bool,

    /// Print the deleted service account as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct SignInAddArgs {
    /// The service account, as OWNER--NAME
    #[arg(value_parser = parse_id)]
    account: String,

    #[command(flatten)]
    github: GithubArgs,

    /// Print the new trust as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct SignInRemoveArgs {
    /// The service account, as OWNER--NAME
    #[arg(value_parser = parse_id)]
    account: String,

    /// The trusted subject to remove, as `view` lists it (with -i, picked
    /// when omitted)
    #[arg(required_unless_present = "interactive")]
    subject: Option<String>,

    /// Pick the sign-in to remove when it isn't named
    #[arg(long, short = 'i', conflicts_with = "yes")]
    interactive: bool,

    /// Skip the confirmation prompt
    #[arg(long, short = 'y')]
    yes: bool,

    /// Print the removed trust as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct RevokeKeyArgs {}

/// What a service account may do with a product's data.
#[derive(Clone, Copy, Debug, PartialEq, ValueEnum)]
pub enum Role {
    /// Read its data
    Read,
    /// Read and write its data
    Write,
}

impl Role {
    fn api(self) -> &'static str {
        match self {
            Role::Read => "read_data",
            Role::Write => "write_data",
        }
    }
}

#[derive(Args)]
pub struct AccessSetArgs {
    /// The service account, as OWNER--NAME
    #[arg(value_parser = parse_id)]
    account: String,

    /// One of its owner's products, as ACCOUNT/PRODUCT
    product: ProductRef,

    /// What it may do with the product's data
    #[arg(long, value_enum, default_value_t = Role::Read)]
    role: Role,

    /// Print the membership as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct AccessRemoveArgs {
    /// The service account, as OWNER--NAME
    #[arg(value_parser = parse_id)]
    account: String,

    /// The product to take away, as ACCOUNT/PRODUCT (with -i, picked when omitted)
    #[arg(required_unless_present = "interactive")]
    product: Option<ProductRef>,

    /// Pick the product when it isn't named
    #[arg(long, short = 'i')]
    interactive: bool,

    /// Print the ended membership as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct UsageArgs {
    /// The service account, as OWNER--NAME (with -i, picked when omitted)
    #[arg(required_unless_present = "interactive", value_parser = parse_id)]
    account: Option<String>,

    /// Pick the service account, and the sign-in, when they aren't named
    #[arg(long, short = 'i')]
    interactive: bool,

    /// The GitHub workflow's trusted subject: prints a workflow to save under
    /// .github/workflows/
    #[arg(long, conflicts_with = "key")]
    subject: Option<String>,

    /// Print the environment an AWS SDK or the AWS CLI needs to sign in with
    /// an API key saved to a file
    #[arg(long)]
    key: bool,
}

/// What every subcommand needs to reach the API and the proxy, and to name
/// pages on the site.
pub struct Ctx<'a> {
    pub client: &'a Client,
    pub site: &'a str,
    /// The data proxy software signs in to: the audience GitHub's tokens must
    /// carry, and the endpoint in the usage snippets.
    pub proxy: &'a str,
    /// GitHub's API, asked how a repository's tokens name it.
    pub github_api: &'a str,
}

impl<'a> Ctx<'a> {
    pub fn new(client: &'a Client, site: &'a str, proxy: &'a str) -> Self {
        Ctx {
            client,
            site,
            proxy,
            github_api: GITHUB_API,
        }
    }
}

pub async fn run(
    cmd: ServiceAccountCommand,
    ctx: &Ctx<'_>,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    use ServiceAccountCommand as C;
    match cmd {
        C::List(args) if args.interactive => {
            let ask = prompter.ok_or(NEEDS_TERMINAL)?;
            let owner = match args.owner {
                Some(o) => o,
                None => own_account(ctx.client).await?,
            };
            browse(ctx, ask, &owner, false).await.map(drop)
        }
        C::List(args) => list(args, ctx).await,
        C::View(args) => view(args, ctx, prompter).await,
        C::Create(args) => create(args, ctx, prompter).await,
        // Without an account, clap has required -i: choose one, then carry on
        // as if it had been named.
        C::Edit(mut args) if args.account.is_none() => {
            let ask = prompter.ok_or(NEEDS_TERMINAL)?;
            let Some(id) = choose(ctx, &mut *ask).await? else {
                return Ok(());
            };
            args.account = Some(id);
            edit(args, ctx, Some(ask)).await
        }
        C::Edit(args) => edit(args, ctx, prompter).await,
        C::Delete(mut args) if args.account.is_none() => {
            let ask = prompter.ok_or(NEEDS_TERMINAL)?;
            let Some(id) = choose(ctx, &mut *ask).await? else {
                return Ok(());
            };
            args.account = Some(id);
            delete(args, ctx, Some(ask)).await
        }
        C::Delete(args) => delete(args, ctx, prompter).await,
        C::SignIn(SignInCommand::Add(args)) => sign_in_add(args, ctx, prompter).await,
        C::SignIn(SignInCommand::Remove(args)) => sign_in_remove(args, ctx, prompter).await,
        C::SignIn(SignInCommand::RevokeKey(_)) => revoke_key(ctx.client).await,
        C::Access(AccessCommand::Set(args)) => access_set(args, ctx).await,
        C::Access(AccessCommand::Remove(args)) => access_remove(args, ctx, prompter).await,
        C::Usage(args) => usage(args, ctx, prompter).await,
    }
}

/// A service account's ID as clap checks it, so a malformed one is bad usage.
fn parse_id(s: &str) -> Result<String, String> {
    split_id(s).map(|_| s.to_string())
}

/// `OWNER--NAME` split at its `--`: the owner, and the name under it.
fn split_id(id: &str) -> Result<(&str, &str), String> {
    match id.split_once("--") {
        Some((owner, local)) if !owner.is_empty() && !local.is_empty() => Ok((owner, local)),
        _ => Err(format!(
            "expected a service account as OWNER--NAME, got '{id}'"
        )),
    }
}

/// The service account's page on the site, where it's managed.
fn web_url(site: &str, id: &str) -> String {
    let owner = id.split_once("--").map_or(id, |(o, _)| o);
    format!(
        "{}/edit/account/{owner}/service-accounts/{id}",
        site.trim_end_matches('/')
    )
}

/// The signed-in account, for a list or picker given no owner.
async fn own_account(client: &Client) -> Result<String, String> {
    let me: Value = client.get(client.url(&["whoami"])).await?;
    me.pointer("/account/account_id")
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| "Couldn't tell which account you're signed in as.".into())
}

fn not_found(message: String) -> String {
    let body = json!({"error": {"code": "not_found", "message": message}});
    ApiError::from_response(StatusCode::NOT_FOUND, &body.to_string()).into()
}

/// Every item of a listing, following its cursor to the end.
async fn all(client: &Client, url: url::Url) -> Result<Vec<Value>, String> {
    let mut items = vec![];
    let mut cursor: Option<String> = None;
    loop {
        let mut page_url = url.clone();
        page_url.query_pairs_mut().append_pair("limit", "100");
        if let Some(c) = &cursor {
            page_url.query_pairs_mut().append_pair("cursor", c);
        }
        let page: Page<Value> = client.get(page_url).await?;
        items.extend(page.items);
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Ok(items);
        }
    }
}

/// One service account. ponytail: found in its owner's listing, since
/// `GET /accounts/{id}` answers 404 for a service account to anyone but an
/// admin; fetch it directly once its managers may read it there.
async fn fetch(client: &Client, id: &str) -> Result<Value, String> {
    let (owner, _) = split_id(id)?;
    all(client, client.url(&["accounts", owner, "service-accounts"]))
        .await?
        .into_iter()
        .find(|a| str_field(a, "account_id") == id)
        .ok_or_else(|| not_found(format!("No service account {id}")))
}

async fn trusts(client: &Client, id: &str) -> Result<Vec<Value>, String> {
    all(client, client.url(&["accounts", id, "trusts"])).await
}

/// The service account's live product memberships.
async fn memberships(client: &Client, id: &str) -> Result<Vec<Value>, String> {
    let mut url = client.url(&["memberships"]);
    url.query_pairs_mut()
        .append_pair("account_id", id)
        .append_pair("state", "member");
    Ok(all(client, url)
        .await?
        .into_iter()
        .filter(|m| !str_field(m, "product_id").is_empty())
        .collect())
}

/// The service account with what `view` shows of it: its `trusts` and its
/// `memberships`, under those names.
async fn fetch_whole(client: &Client, id: &str) -> Result<Value, String> {
    let mut account = fetch(client, id).await?;
    let (t, m) = tokio::join!(trusts(client, id), memberships(client, id));
    account["trusts"] = Value::Array(t?);
    account["memberships"] = Value::Array(m?);
    Ok(account)
}

async fn list(args: ListArgs, ctx: &Ctx<'_>) -> Result<(), String> {
    let owner = match args.owner {
        Some(o) => o,
        None => own_account(ctx.client).await?,
    };
    let url = ctx.client.url(&["accounts", &owner, "service-accounts"]);
    let items = all(ctx.client, url).await?;
    if args.json {
        crate::output::json(&items);
        return Ok(());
    }
    if items.is_empty() {
        eprintln!("No service accounts found.");
        return Ok(());
    }
    let terminal = std::io::stdout().is_terminal();
    let rows = labels(&items, crate::style::wanted(terminal));
    let pager = (terminal && !args.no_pager)
        .then(crate::product::Pager::spawn)
        .flatten();
    match pager {
        // The user quitting the pager early is not an error.
        Some(mut p) => drop(p.write(&rows)),
        None => rows.iter().for_each(|r| println!("{r}")),
    }
    Ok(())
}

/// `id  Name  disabled`, one service account a row, the ID gray.
fn labels(items: &[Value], color: bool) -> Vec<String> {
    let width = items
        .iter()
        .map(|a| str_field(a, "account_id").len())
        .max()
        .unwrap_or(0);
    items
        .iter()
        .map(|a| {
            let id = format!("{:<width$}", str_field(a, "account_id"));
            let disabled = if disabled(a) {
                crate::style::paint(color, "31", "disabled")
            } else {
                String::new()
            };
            format!(
                "{}  {}  {disabled}",
                crate::style::id(color, &id),
                str_field(a, "name")
            )
            .trim_end()
            .to_string()
        })
        .collect()
}

fn disabled(a: &Value) -> bool {
    a.get("disabled").and_then(Value::as_bool) == Some(true)
}

/// A trusted subject as people read it: `GitHub Actions · acme/data · branch
/// main`. Anything not shaped like GitHub's default is shown as it is.
pub fn sign_in_label(issuer: &str, subject: &str) -> String {
    if issuer != GITHUB_ISSUER {
        return format!("{issuer} · {subject}");
    }
    let Some(rest) = subject.strip_prefix("repo:") else {
        return format!("GitHub Actions · {subject}");
    };
    let (repo, context) = match (rest.split_once(":ref:"), rest.split_once(":environment:")) {
        (Some((repo, r)), _) => match (r.strip_prefix("refs/heads/"), r.strip_prefix("refs/tags/"))
        {
            (Some(b), _) => (repo, format!("branch {b}")),
            (_, Some(t)) => (repo, format!("tag {t}")),
            _ => (repo, format!("ref {r}")),
        },
        (_, Some((repo, e))) => (repo, format!("environment {e}")),
        _ => return format!("GitHub Actions · {subject}"),
    };
    format!("GitHub Actions · {repo} · {context}")
}

fn role_label(role: &str) -> &str {
    match role {
        "read_data" => "Read",
        "write_data" => "Read and write",
        r => r,
    }
}

/// The name, then "Who it is" as `Label  value` rows, then "Signs in with"
/// and "Can reach", as the web UI's page has them.
fn account_lines(a: &Value, site: &str, color: bool) -> Vec<String> {
    let now = chrono::Utc::now();
    let paint = |code: &str, s: &str| crate::style::paint(color, code, s);
    let id = str_field(a, "account_id");
    let date = |key: &str| {
        chrono::DateTime::parse_from_rfc3339(str_field(a, key))
            .map(|d| crate::style::when(color, d.with_timezone(&chrono::Utc), now, false))
            .unwrap_or_default()
    };
    let rows = [
        ("Service account", crate::style::id(color, id)),
        ("Owner", str_field(a, "owner_account_id").to_string()),
        (
            "Disabled",
            if disabled(a) {
                paint("31", "yes")
            } else {
                "no".into()
            },
        ),
        ("Created", date("created_at")),
        ("Updated", date("updated_at")),
        ("URL", paint("4", &web_url(site, id))),
    ];
    let mut lines = vec![paint("1", str_field(a, "name")), String::new()];
    for (label, value) in rows.iter().filter(|(_, v)| !v.is_empty()) {
        lines.push(format!("{}  {value}", paint("2", &format!("{label:<15}"))));
    }
    let none = || format!("  {}", paint("2", "(none)"));
    let items = |key: &str| {
        a.get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };

    lines.extend([String::new(), paint("1", "Signs in with")]);
    let trusts = items("trusts");
    if trusts.is_empty() {
        lines.push(none());
    }
    for t in &trusts {
        lines.push(format!(
            "  {}",
            sign_in_label(str_field(t, "issuer"), str_field(t, "subject"))
        ));
        lines.push(format!(
            "    {}",
            crate::style::id(color, str_field(t, "subject"))
        ));
    }

    lines.extend([String::new(), paint("1", "Can reach")]);
    let access = items("memberships");
    if access.is_empty() {
        lines.push(none());
    }
    for m in &access {
        let product = format!(
            "{}/{}",
            str_field(m, "membership_account_id"),
            str_field(m, "product_id")
        );
        lines.push(format!("  {product}  {}", role_label(str_field(m, "role"))));
    }
    lines
}

fn print_account(a: &Value, site: &str) {
    let color = crate::style::wanted(std::io::stdout().is_terminal());
    for line in account_lines(a, site, color) {
        println!("{line}");
    }
}

async fn view(
    args: ViewArgs,
    ctx: &Ctx<'_>,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    if args.interactive {
        let ask = prompter.ok_or(NEEDS_TERMINAL)?;
        let id = match args.account {
            Some(id) => id,
            None => match choose(ctx, &mut *ask).await? {
                Some(id) => id,
                None => return Ok(()),
            },
        };
        let mut account = fetch_whole(ctx.client, &id).await?;
        let _screen = ask.fullscreen();
        screen(&mut account, ctx, ask).await?;
        return Ok(());
    }
    let id = args.account.expect("clap requires it without -i");
    split_id(&id)?;
    if args.web {
        let url = web_url(ctx.site, &id);
        eprintln!("Opening {url} in your browser.");
        return open::that(&url).map_err(|e| format!("Couldn't open a browser: {e}"));
    }
    let account = fetch_whole(ctx.client, &id).await?;
    if args.json {
        crate::output::json(&account);
    } else {
        print_account(&account, ctx.site);
    }
    Ok(())
}

const LIST_HINT: &str = "↑↓ move · → open to edit or delete · b browser · / filter · ← quit";
const CHOOSE_HINT: &str = "↑↓ move · → choose · / filter · ← quit";
const SCREEN_HINT: &str = "b browser · e edit · d delete · ← back";

/// Pick one of the service accounts of an owner you manage: the owner first,
/// when there's more than one.
async fn choose(ctx: &Ctx<'_>, ask: &mut dyn Prompter) -> Result<Option<String>, String> {
    let me = ctx.client.check_signed_in().await?;
    let owners = owners(&me);
    let owner = match owners.as_slice() {
        [] => own_account(ctx.client).await?,
        [only] => only.clone(),
        _ => owners[ask.select("Owner", &owners, 0)?].clone(),
    };
    browse(ctx, ask, &owner, true).await
}

/// Move through `owner`'s service accounts until they back out (None). From
/// `list -i`, opening one shows it as `view` does and the shortcuts act on
/// it; when `choosing`, opening one returns its ID.
async fn browse(
    ctx: &Ctx<'_>,
    ask: &mut dyn Prompter,
    owner: &str,
    choosing: bool,
) -> Result<Option<String>, String> {
    let (keys, hint) = if choosing {
        ("", CHOOSE_HINT)
    } else {
        ("b", LIST_HINT)
    };
    let url = ctx.client.url(&["accounts", owner, "service-accounts"]);
    let mut items = all(ctx.client, url).await?;
    if items.is_empty() {
        eprintln!("No service accounts found.");
        return Ok(None);
    }
    let mut place = Place::default();
    let _screen = ask.fullscreen();
    loop {
        ask.clear();
        let label = format!("Service accounts of {owner}");
        let action = ask.browse(
            &label,
            &labels(&items, crate::style::on_stderr()),
            &mut place,
            false,
            keys,
            hint,
        )?;
        let i = place.at;
        let id = str_field(&items[i], "account_id").to_string();
        let (after, notice) = match action {
            Action::Back => return Ok(None),
            Action::Open if choosing => return Ok(Some(id)),
            Action::Open => {
                let mut whole = fetch_whole(ctx.client, &id).await?;
                let done = screen(&mut whole, ctx, ask).await?;
                items[i] = whole;
                done
            }
            Action::Key(key) => act(key, &mut items[i], ctx, ask).await?,
            // Every page is loaded up front, and the listing takes no search.
            Action::More | Action::Search => continue,
        };
        if after == After::Deleted {
            items.remove(i);
            if items.is_empty() {
                return Ok(None);
            }
            place.at = place.at.min(items.len() - 1);
        }
        place.notice = notice;
    }
}

#[derive(PartialEq)]
enum After {
    Kept,
    Deleted,
}

/// One service account as `view` shows it, with the shortcuts, until back.
async fn screen(
    account: &mut Value,
    ctx: &Ctx<'_>,
    ask: &mut dyn Prompter,
) -> Result<(After, Option<String>), String> {
    let color = crate::style::wanted(std::io::stdout().is_terminal());
    let mut notice: Option<String> = None;
    loop {
        ask.clear();
        for line in account_lines(account, ctx.site, color) {
            println!("{line}");
        }
        println!();
        if let Some(n) = notice.take() {
            eprintln!("{}", crate::style::paint(color, "33", &n));
        }
        match ask.keypress(SCREEN_HINT, "bed")? {
            Action::Key(key) => match act(key, account, ctx, ask).await? {
                (After::Deleted, said) => return Ok((After::Deleted, said)),
                (After::Kept, said) => notice = said,
            },
            _ => return Ok((After::Kept, None)),
        }
    }
}

/// Run a shortcut with the commands' own code: `b` opens the page in the
/// browser, `e` edits (then fetches the account as it now is), `d` deletes.
async fn act(
    key: char,
    account: &mut Value,
    ctx: &Ctx<'_>,
    ask: &mut dyn Prompter,
) -> Result<(After, Option<String>), String> {
    let id = str_field(account, "account_id").to_string();
    let told = |e: String| Some(crate::prompt::describe(&e));
    let notice = match key {
        'b' => {
            let url = web_url(ctx.site, &id);
            match open::that(&url) {
                Ok(()) => Some(format!("Opened {url} in your browser.")),
                Err(e) => Some(format!("Couldn't open a browser: {e}")),
            }
        }
        'e' => {
            let args = EditArgs {
                account: Some(id.clone()),
                interactive: false,
                name: None,
                disable: false,
                enable: false,
                from_file: None,
                json: false,
            };
            let refetched = match edit(args, ctx, Some(&mut *ask)).await {
                Ok(()) => fetch_whole(ctx.client, &id).await,
                Err(e) => Err(e),
            };
            match refetched {
                Ok(now) if now == *account => Some(format!("No changes to {id}.")),
                Ok(now) => {
                    *account = now;
                    Some(format!("Edited {id}."))
                }
                Err(e) => told(e),
            }
        }
        'd' => {
            let args = DeleteArgs {
                account: Some(id.clone()),
                interactive: false,
                yes: false,
                json: false,
            };
            match delete(args, ctx, Some(&mut *ask)).await {
                Ok(()) => return Ok((After::Deleted, Some(format!("Deleted {id}.")))),
                Err(e) => told(e),
            }
        }
        _ => None,
    };
    Ok((After::Kept, notice))
}

/// The accounts `me`, a `/whoami` session, might own service accounts under:
/// their own, then each organization they own or maintain. Whether each may
/// is the owner's `create_service_accounts` flag, which `/whoami` doesn't
/// show for organizations, so the API decides; this only chooses what to offer.
fn owners(me: &Value) -> Vec<String> {
    let account = me.get("account").unwrap_or(&Value::Null);
    if disabled(account) || str_field(account, "type") == "service" {
        return vec![];
    }
    let mut owners: Vec<String> = vec![];
    let own = str_field(account, "account_id");
    if !own.is_empty() {
        owners.push(own.into());
    }
    let orgs = me
        .get("memberships")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|m| {
            str_field(m, "state") == "member"
                && m.get("product_id").is_none_or(Value::is_null)
                && matches!(str_field(m, "role"), "owners" | "maintainers")
        })
        .map(|m| str_field(m, "membership_account_id").to_string());
    for org in orgs {
        if !org.is_empty() && !owners.contains(&org) {
            owners.push(org);
        }
    }
    owners
}

/// The workflow `GithubArgs` names, as its token's subject. A repository
/// typed as `owner/repo` is looked up with GitHub, since one whose tokens name
/// it by ID (`owner@1/repo@2`) would never match it as typed.
async fn github_subject(g: &GithubArgs, github_api: &str) -> Result<Option<String>, String> {
    if let Some(s) = &g.subject {
        return Ok(Some(s.clone()));
    }
    let Some(repo) = &g.github else {
        return Ok(None);
    };
    let context = match (&g.branch, &g.tag, &g.environment) {
        (Some(b), _, _) => Context::Branch(b.clone()),
        (_, Some(t), _) => Context::Tag(t.clone()),
        (_, _, Some(e)) => Context::Environment(e.clone()),
        _ => {
            return Err(
                "With --github, name the runs to trust: --branch, --tag or --environment.".into(),
            )
        }
    };
    let repo = token_repository(github_api, repo.trim().trim_start_matches("repo:")).await;
    Ok(Some(subject(&repo, &context)))
}

/// Which of a repository's runs a trust lets in.
#[derive(Clone)]
enum Context {
    Branch(String),
    Tag(String),
    Environment(String),
}

/// GitHub's `sub` claim for runs of `repository` in `context`, as its tokens
/// carry it. A full `refs/…` ref is taken as it is.
fn subject(repository: &str, context: &Context) -> String {
    let refd = |prefix: &str, v: &str| {
        if v.starts_with("refs/") {
            format!("ref:{v}")
        } else {
            format!("ref:{prefix}{v}")
        }
    };
    let context = match context {
        Context::Branch(b) => refd("refs/heads/", b),
        Context::Tag(t) => refd("refs/tags/", t),
        Context::Environment(e) => format!("environment:{e}"),
    };
    format!("repo:{repository}:{context}")
}

/// How GitHub's tokens name `repository`, from its public API (with
/// `GH_TOKEN` or `GITHUB_TOKEN`, a private one too), as the web UI asks:
/// `owner/repo`, or `owner@id/repo@id` once it signs with IDs. Whatever
/// GitHub says, or can't, is told on stderr; the repository is then used as
/// typed and the API judges the subject.
async fn token_repository(github_api: &str, repository: &str) -> String {
    let short = repository.split_once('/').is_some_and(|(o, r)| {
        let ok = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
        };
        ok(o) && ok(r)
    });
    if !short {
        return repository.to_string();
    }
    let url = format!("{github_api}/repos/{repository}/actions/oidc/customization/sub");
    let mut req = reqwest::Client::new()
        .get(&url)
        .header("User-Agent", "source-coop-cli")
        .header("Accept", "application/vnd.github+json");
    if let Ok(token) = std::env::var("GH_TOKEN").or_else(|_| std::env::var("GITHUB_TOKEN")) {
        req = req.bearer_auth(token);
    }
    let hint = format!(
        "  Its admins see its default subject claim prefix at https://github.com/{repository}/settings/actions/oidc-configuration,\n  \
         or run: gh api repos/{repository}/actions/oidc/customization/sub --jq .sub_claim_prefix\n  \
         Then pass the repository as that prefix, without `repo:`."
    );
    let answer = match req.send().await {
        Ok(r) if r.status() == StatusCode::NOT_FOUND => {
            eprintln!(
                "GitHub can't show {repository}: it's private (set GH_TOKEN to look it up) or doesn't exist.\n{hint}"
            );
            return repository.to_string();
        }
        Ok(r) if r.status().is_success() => r.json::<Value>().await.ok(),
        _ => None,
    };
    let Some(answer) = answer else {
        eprintln!(
            "Couldn't check {repository} with GitHub just now; it may be rate-limiting.\n{hint}"
        );
        return repository.to_string();
    };
    let Some(prefix) = answer.get("sub_claim_prefix").and_then(Value::as_str) else {
        return repository.to_string();
    };
    let named = prefix.trim_start_matches("repo:").to_string();
    // A template of exactly these claims, in this order, builds the default's shape.
    let standard = answer.get("use_default").and_then(Value::as_bool) == Some(true)
        || answer.get("include_claim_keys") == Some(&json!(["repo", "context"]));
    if standard {
        eprintln!("Confirmed via GitHub: {repository}'s tokens name it repo:{named}");
    } else {
        eprintln!(
            "{repository} customizes its subject claim, so its tokens won't carry the subject trusted here; \
             only subjects shaped like GitHub's default can be trusted. An admin can choose \
             \"Use default template\" at https://github.com/{repository}/settings/actions/oidc-configuration"
        );
    }
    named
}

/// The trust as the AWS-style condition the web UI shows: the subject, and
/// the audience the proxy requires of every GitHub token, its own origin.
fn condition(subject: &str, proxy: &str) -> Vec<String> {
    let host = GITHUB_ISSUER.trim_start_matches("https://");
    let condition = json!({"StringEquals": {
        format!("{host}:aud"): proxy.trim_end_matches('/'),
        format!("{host}:sub"): subject,
    }});
    serde_json::to_string_pretty(&condition)
        .expect("JSON serializes")
        .lines()
        .map(String::from)
        .collect()
}

/// Ask for one workflow to trust: its repository, which runs, and the
/// branch, tag or environment. None is back, to whatever came before.
async fn ask_github(ask: &mut dyn Prompter, github_api: &str) -> Result<Option<String>, String> {
    const KINDS: [&str; 3] = ["Branch", "Tag", "Environment"];
    let (mut repo, mut kind, mut value) = (String::new(), 0, "main".to_string());
    let mut step = 0;
    loop {
        step = match step {
            0 => match ask.input_or_back("Repository (OWNER/REPO)", &repo, false)? {
                None => return Ok(None),
                Some(r) => {
                    repo = r.trim().trim_start_matches("repo:").to_string();
                    1
                }
            },
            1 => match ask.select_or_back("Allow runs from", &KINDS.map(String::from), kind)? {
                None => 0,
                Some(k) => {
                    if k != kind {
                        value = if k == 0 { "main".into() } else { String::new() };
                    }
                    kind = k;
                    2
                }
            },
            _ => match ask.input_or_back(KINDS[kind], &value, false)? {
                None => 1,
                Some(v) => {
                    value = v.trim().to_string();
                    let context = match kind {
                        0 => Context::Branch(value),
                        1 => Context::Tag(value),
                        _ => Context::Environment(value),
                    };
                    let repo = token_repository(github_api, &repo).await;
                    return Ok(Some(subject(&repo, &context)));
                }
            },
        }
    }
}

/// `ACCOUNT/PRODUCT=read|write`, as `create --access` takes it, as a grant
/// in the create body. The product must be the owner's, where the API takes
/// only its ID.
fn grant(spec: &str, owner: &str) -> Result<Value, String> {
    let bad = || format!("expected --access ACCOUNT/PRODUCT=read or =write, got '{spec}'");
    let (product, role) = spec.rsplit_once('=').ok_or_else(bad)?;
    let product: ProductRef = product.parse()?;
    let role = Role::from_str(role, true).map_err(|_| bad())?;
    if product.account_id != owner {
        return Err(format!(
            "A service account can only be granted its owner's products: {product} isn't {owner}'s."
        ));
    }
    Ok(json!({"product_id": product.product_id, "role": role.api()}))
}

/// Append `value` to the array at `key`, unless it's there already.
fn push_unique(body: &mut Map<String, Value>, key: &str, value: Value) {
    let list = body.entry(key).or_insert_with(|| json!([]));
    if let Some(list) = list.as_array_mut() {
        if !list.contains(&value) {
            list.push(value);
        }
    }
}

/// `my-nightly sync!` → `my-nightly-sync`: an ID made from a name, as the web
/// UI makes one.
fn slugify(name: &str) -> String {
    let mut id = String::new();
    for c in name.trim().to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            id.push(c);
        } else if !id.ends_with('-') && !id.is_empty() {
            id.push('-');
        }
    }
    id.trim_end_matches('-').to_string()
}

/// What `create` is about to send, as `Label  value` rows.
fn review_lines(id: &str, body: &Map<String, Value>, proxy: &str) -> Vec<String> {
    let mut rows = vec![
        ("Service account".to_string(), id.to_string()),
        (
            "Name".into(),
            str_field(&Value::Object(body.clone()), "name").to_string(),
        ),
    ];
    let list = |key: &str| {
        body.get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let subjects = list("github_subjects");
    if subjects.is_empty() {
        rows.push(("Signs in with".into(), "(nothing yet)".into()));
    }
    for (i, s) in subjects.iter().enumerate() {
        let s = s.as_str().unwrap_or_default();
        let label = if i == 0 { "Signs in with" } else { "" };
        rows.push((label.into(), sign_in_label(GITHUB_ISSUER, s)));
        rows.extend(
            condition(s, proxy)
                .into_iter()
                .map(|l| (String::new(), format!("  {l}"))),
        );
    }
    let grants = list("grants");
    if grants.is_empty() {
        rows.push(("Can reach".into(), "(nothing yet)".into()));
    }
    let owner = id.split_once("--").map_or("", |(o, _)| o);
    for (i, g) in grants.iter().enumerate() {
        let label = if i == 0 { "Can reach" } else { "" };
        rows.push((
            label.into(),
            format!(
                "{owner}/{}  {}",
                str_field(g, "product_id"),
                role_label(str_field(g, "role"))
            ),
        ));
    }
    rows.into_iter()
        .map(|(label, value)| format!("{label:<15}  {value}"))
        .collect()
}

#[derive(Clone, Copy)]
enum Step {
    Owner,
    Name,
    Id,
    SignIns,
    Access,
    Review,
}

enum Next {
    Asked(Option<Step>),
    Skipped(Option<Step>),
    Back,
}

/// Ask for what a new service account still needs, in the web form's order:
/// the owner (from the ones you manage) and name and ID unless `named`, then
/// workflows to trust and products to grant, then a last look. ↑ or ← goes
/// back a question, keeping later answers; fields from a flag, a file or a
/// resumed draft aren't asked. Returns the ID and its draft.
async fn ask_create(
    ask: &mut dyn Prompter,
    ctx: &Ctx<'_>,
    me: &Value,
    named: Option<String>,
    body: &mut Map<String, Value>,
) -> Result<(String, Draft), String> {
    const CONTINUE: &str = "Continue";
    let owners = owners(me);
    let mut owner = named
        .as_ref()
        .map(|id| id.split_once("--").map_or("", |(o, _)| o).to_string());
    if owner.is_none() {
        match owners.as_slice() {
            [] => {
                return Err(
                    "Service accounts can't be created as a service account or a disabled one."
                        .into(),
                )
            }
            [only] => {
                eprintln!("Creating under {only}, the only account you manage.");
                owner = Some(only.clone());
            }
            _ => {}
        }
    }
    let choose_owner = owner.is_none();
    let mut local = named
        .as_ref()
        .and_then(|id| id.split_once("--").map(|(_, l)| l.to_string()))
        .unwrap_or_default();
    let mut given: Vec<String> = body.keys().cloned().collect();
    let mut draft: Option<(String, Draft)> = None;
    let mut products: Option<(String, Vec<String>)> = None;
    let current = |body: &Map<String, Value>, key: &str| {
        body.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };

    let mut asked: Vec<Step> = vec![];
    let mut step = Some(Step::Owner);
    while let Some(now) = step {
        let next = match now {
            Step::Owner if !choose_owner => Next::Skipped(Some(Step::Name)),
            Step::Owner => {
                let at = owners
                    .iter()
                    .position(|o| Some(o) == owner.as_ref())
                    .unwrap_or(0);
                match ask.select_or_back("Owner", &owners, at)? {
                    None => Next::Back,
                    Some(i) => {
                        owner = Some(owners[i].clone());
                        Next::Asked(Some(Step::Name))
                    }
                }
            }
            Step::Name if given.iter().any(|k| k == "name") => Next::Skipped(Some(Step::Id)),
            Step::Name => match ask.input_or_back("Name", &current(body, "name"), false)? {
                None => Next::Back,
                Some(n) => {
                    body.insert("name".into(), json!(n.trim()));
                    Next::Asked(Some(Step::Id))
                }
            },
            Step::Id => {
                let next = if named.is_some() {
                    Next::Skipped(Some(Step::SignIns))
                } else {
                    let was = match &local {
                        l if l.is_empty() => slugify(&current(body, "name")),
                        l => l.clone(),
                    };
                    let label = format!("ID (after {}--)", owner.as_deref().unwrap_or(""));
                    match ask.input_or_back(&label, &was, false)? {
                        None => Next::Back,
                        Some(id) => {
                            local = id.trim().to_string();
                            Next::Asked(Some(Step::SignIns))
                        }
                    }
                };
                // Offer a saved draft once per account named, as soon as it is.
                if !matches!(next, Next::Back) {
                    let key = format!(
                        "service-account-create/{}--{local}",
                        owner.as_deref().unwrap_or("")
                    );
                    if draft.as_ref().map(|(k, _)| k) != Some(&key) {
                        let saved = Draft::for_key(&key)?;
                        saved.resume(ask, body)?;
                        for k in body.keys() {
                            if !given.contains(k) {
                                given.push(k.clone());
                            }
                        }
                        draft = Some((key, saved));
                    }
                }
                next
            }
            Step::SignIns if given.iter().any(|k| k == "github_subjects") => {
                Next::Skipped(Some(Step::Access))
            }
            Step::SignIns => {
                let options = ["GitHub workflow…".to_string(), CONTINUE.to_string()];
                let count = body
                    .get("github_subjects")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                let label = match count {
                    0 => "Signs in with: add a sign-in?".to_string(),
                    n => format!("Signs in with: {n} added; another?"),
                };
                match ask.select_or_back(&label, &options, 1)? {
                    None => Next::Back,
                    Some(1) => Next::Asked(Some(Step::Access)),
                    Some(_) => {
                        if let Some(s) = ask_github(ask, ctx.github_api).await? {
                            push_unique(body, "github_subjects", json!(s));
                        }
                        // The menu again, for another or to continue.
                        continue;
                    }
                }
            }
            Step::Access if given.iter().any(|k| k == "grants") => {
                Next::Skipped(Some(Step::Review))
            }
            Step::Access => {
                let owner_id = owner.clone().unwrap_or_default();
                if products.as_ref().map(|(o, _)| o) != Some(&owner_id) {
                    let ids = all(ctx.client, ctx.client.url(&["products", &owner_id]))
                        .await
                        .unwrap_or_default()
                        .iter()
                        .map(|p| str_field(p, "product_id").to_string())
                        .collect();
                    products = Some((owner_id.clone(), ids));
                }
                let granted: Vec<String> = body
                    .get("grants")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|g| str_field(g, "product_id").to_string())
                    .collect();
                let mut options: Vec<String> = products
                    .as_ref()
                    .expect("just listed")
                    .1
                    .iter()
                    .filter(|p| !granted.contains(p))
                    .map(|p| format!("{owner_id}/{p}"))
                    .collect();
                options.push(CONTINUE.into());
                let label = match granted.len() {
                    0 => "Can reach: grant a product?".to_string(),
                    n => format!("Can reach: {n} granted; another?"),
                };
                match ask.select_or_back(&label, &options, options.len() - 1)? {
                    None => Next::Back,
                    Some(i) if i == options.len() - 1 => Next::Asked(Some(Step::Review)),
                    Some(i) => {
                        let roles = ["Read".to_string(), "Read and write".to_string()];
                        if let Some(r) = ask.select_or_back("Access", &roles, 0)? {
                            let role = [Role::Read, Role::Write][r];
                            let product = options[i].split_once('/').map_or("", |(_, p)| p);
                            push_unique(
                                body,
                                "grants",
                                json!({"product_id": product, "role": role.api()}),
                            );
                        }
                        continue;
                    }
                }
            }
            Step::Review if asked.is_empty() => Next::Skipped(None),
            Step::Review => {
                let id = format!("{}--{local}", owner.as_deref().unwrap_or(""));
                match ask.confirm_or_back(
                    "Create this service account?",
                    &review_lines(&id, body, ctx.proxy),
                )? {
                    None => Next::Back,
                    Some(true) => Next::Asked(None),
                    Some(false) => return Err(crate::prompt::CANCELLED.into()),
                }
            }
        };
        step = match next {
            Next::Asked(then) => {
                asked.push(now);
                then
            }
            Next::Skipped(then) => then,
            Next::Back => asked.pop().or(Some(now)),
        };
    }
    let id = format!("{}--{local}", owner.unwrap_or_default());
    let (_, draft) = draft.expect("the ID step always opens one");
    Ok((id, draft))
}

async fn create(
    args: CreateArgs,
    ctx: &Ctx<'_>,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    let mut body = read_fields(args.from_file.as_deref())?;
    if let Some(n) = args.name {
        body.insert("name".into(), json!(n));
    }
    if let Some(id) = &args.account {
        split_id(id)?;
    }
    // Before the first question or lookup, so nobody types an account only to be refused.
    let me = match prompter {
        Some(_) => Some(ctx.client.check_signed_in().await?),
        None => None,
    };
    if let Some(s) = github_subject(&args.github, ctx.github_api).await? {
        push_unique(&mut body, "github_subjects", json!(s));
    }
    if !args.access.is_empty() {
        let owner = match &args.account {
            Some(id) => split_id(id)?.0.to_string(),
            None => {
                return Err(
                    "Name the service account, as OWNER--NAME, to grant it --access.".into(),
                )
            }
        };
        for spec in &args.access {
            push_unique(&mut body, "grants", grant(spec, &owner)?);
        }
    }
    let (id, draft) = match (prompter.as_deref_mut(), &me) {
        (Some(ask), Some(me)) => {
            let (id, draft) = ask_create(ask, ctx, me, args.account, &mut body).await?;
            (id, Some(draft))
        }
        _ => match args.account {
            Some(id) => (id, None),
            None => return Err("Name the service account to create, as OWNER--NAME.".into()),
        },
    };
    let (owner, local) = split_id(&id)?;
    body.insert("local_id".into(), json!(local));
    let url = ctx.client.url(&["accounts", owner, "service-accounts"]);
    let sent = send_until_accepted(ctx.client, Method::POST, url, &mut body, prompter).await;
    let created = match &draft {
        Some(draft) => draft.finish(sent, &body)?,
        None => sent?,
    };
    report(&created, args.json, "Created");
    let id = str_field(&created, "account_id");
    for s in body
        .get("github_subjects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let s = s.as_str().unwrap_or_default();
        eprintln!(
            "To sign in from that workflow: source-coop service-account usage {id} --subject {s}"
        );
    }
    Ok(())
}

/// The fields a person can be asked for again when the API rejects them.
const REASKABLE: [&str; 2] = ["name", "local_id"];

/// Send `body`, and when the API rejects only fields a person can answer
/// again and someone is there, show why and ask for just those. The API
/// stays the only judge.
async fn send_until_accepted(
    client: &Client,
    method: Method,
    url: url::Url,
    body: &mut Map<String, Value>,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<Value, String> {
    loop {
        let e = match client
            .request::<Value>(method.clone(), url.clone(), Some(&*body))
            .await
        {
            Ok(v) => return Ok(v),
            Err(e) => e,
        };
        let reaskable = e.status == Some(StatusCode::BAD_REQUEST)
            && !e.field_errors.is_empty()
            && e.field_errors
                .keys()
                .all(|f| REASKABLE.contains(&f.as_str()));
        match prompter.as_deref_mut() {
            Some(ask) if reaskable => {
                eprintln!("{e}");
                for field in e.field_errors.keys() {
                    let label = if field == "name" { "Name" } else { "ID" };
                    let was = body
                        .get(field)
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let answer = ask.input(label, &was, false)?;
                    body.insert(field.clone(), json!(answer.trim()));
                }
            }
            _ => return Err(e.into()),
        }
    }
}

/// The service account as JSON, or a line on stderr for the person and its
/// ID on stdout for a script: `id=$(source-coop service-account create …)`.
fn report(account: &Value, as_json: bool, verb: &str) {
    if as_json {
        crate::output::json(account);
    } else {
        let id = str_field(account, "account_id");
        eprintln!("{verb} {id}");
        println!("{id}");
    }
}

async fn edit(
    args: EditArgs,
    ctx: &Ctx<'_>,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    let id = args.account.clone().expect("run fills it in for -i");
    split_id(&id)?;
    let mut body = read_fields(args.from_file.as_deref())?;
    if let Some(n) = args.name {
        body.insert("name".into(), json!(n));
    }
    if args.disable || args.enable {
        body.insert("disabled".into(), json!(args.disable));
    }
    let key = format!("service-account-edit/{id}");
    let mut draft = None;
    if body.is_empty() {
        let Some(ask) = prompter.as_deref_mut() else {
            return Err(
                "Nothing to change: pass --name, --disable, --enable or --from-file.".into(),
            );
        };
        ctx.client.check_signed_in().await?;
        let saved = Draft::for_key(&key)?;
        if !saved.resume(ask, &mut body)? {
            let current = fetch(ctx.client, &id).await?;
            prompt_edits(ask, &current, &mut body)?;
        }
        if body.is_empty() {
            eprintln!("No changes to {id}.");
            return Ok(());
        }
        draft = Some(saved);
    }
    let url = ctx.client.url(&["accounts", &id]);
    let sent = send_until_accepted(ctx.client, Method::PATCH, url, &mut body, prompter).await;
    let edited = match &draft {
        Some(draft) => draft.finish(sent, &body)?,
        None => sent?,
    };
    report(&edited, args.json, "Edited");
    Ok(())
}

/// What disabling and enabling do, as the web UI's confirmation says it.
const DISABLE_SAYS: &str = "Nothing can sign in as it, by workflow or by API key, and within five \
    minutes credentials already generated are cut back to public data. Its workflows, keys and \
    product access are kept.";
const ENABLE_SAYS: &str =
    "Its trusted workflows and unrevoked API keys can sign in again, so revoke any key that leaked first.";

/// Ask which fields to change, then for each, from its current value.
fn prompt_edits(
    ask: &mut dyn Prompter,
    current: &Value,
    body: &mut Map<String, Value>,
) -> Result<(), String> {
    let was_disabled = disabled(current);
    let toggle = if was_disabled {
        "Enable it"
    } else {
        "Disable it"
    };
    let fields = ["Name".to_string(), toggle.to_string()];
    for picked in ask.multi_select("What do you want to change?", &fields)? {
        if picked == 0 {
            let name = ask.input("Name", str_field(current, "name"), false)?;
            if name != str_field(current, "name") {
                body.insert("name".into(), json!(name));
            }
        } else {
            eprintln!(
                "{}",
                if was_disabled {
                    ENABLE_SAYS
                } else {
                    DISABLE_SAYS
                }
            );
            if ask.confirm(&format!("{toggle}?"), false)? {
                body.insert("disabled".into(), json!(!was_disabled));
            }
        }
    }
    Ok(())
}

async fn delete(
    args: DeleteArgs,
    ctx: &Ctx<'_>,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    let id = args.account.clone().expect("run fills it in for -i");
    split_id(&id)?;
    if !args.yes {
        let Some(ask) = prompter else {
            return Err(format!(
                "Refusing to delete {id} without confirmation: pass --yes."
            ));
        };
        ctx.client.check_signed_in().await?;
        let (t, m) = tokio::join!(trusts(ctx.client, &id), memberships(ctx.client, &id));
        let (t, m) = (t?.len(), m?.len());
        eprintln!(
            "This deletes {id} with its API keys, {t} trusted workflow{} and access to {m} product{}; \
             anything signing in as it stops working. To stop it for now instead, disable it with \
             `source-coop service-account edit {id} --disable`.",
            if t == 1 { "" } else { "s" },
            if m == 1 { "" } else { "s" },
        );
        crate::prompt::confirm_by_name(ask, &id, "deleted")?;
    }
    let url = ctx.client.url(&["accounts", &id]);
    let deleted: Value = ctx.client.request(Method::DELETE, url, None::<&()>).await?;
    if args.json {
        crate::output::json(&deleted);
    } else {
        eprintln!("Deleted {}", str_field(&deleted, "account_id"));
    }
    Ok(())
}

async fn sign_in_add(
    args: SignInAddArgs,
    ctx: &Ctx<'_>,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    split_id(&args.account)?;
    let subject = match (github_subject(&args.github, ctx.github_api).await?, prompter) {
        (Some(s), _) => s,
        (None, Some(ask)) => {
            ctx.client.check_signed_in().await?;
            loop {
                let Some(s) = ask_github(ask, ctx.github_api).await? else {
                    return Err(crate::prompt::CANCELLED.into());
                };
                let mut details = vec![sign_in_label(GITHUB_ISSUER, &s), "Trusts tokens matching".into()];
                details.extend(condition(&s, ctx.proxy));
                match ask.confirm_or_back("Trust this workflow?", &details)? {
                    None => continue,
                    Some(true) => break s,
                    Some(false) => return Err(crate::prompt::CANCELLED.into()),
                }
            }
        }
        (None, None) => {
            return Err("Name the workflow: --github OWNER/REPO with --branch, --tag or --environment, or --subject.".into())
        }
    };
    let url = ctx.client.url(&["accounts", &args.account, "trusts"]);
    let trust: Value = ctx
        .client
        .request(Method::POST, url, Some(&json!({"subject": subject})))
        .await?;
    if args.json {
        crate::output::json(&trust);
    } else {
        eprintln!(
            "{} can now sign in as {}",
            sign_in_label(GITHUB_ISSUER, &subject),
            args.account
        );
        eprintln!(
            "To sign in from it: source-coop service-account usage {} --subject {subject}",
            args.account
        );
    }
    Ok(())
}

async fn sign_in_remove(
    args: SignInRemoveArgs,
    ctx: &Ctx<'_>,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    split_id(&args.account)?;
    let (issuer, subject) = match args.subject {
        Some(s) => (GITHUB_ISSUER.to_string(), s),
        None => {
            let ask = prompter.as_deref_mut().ok_or(NEEDS_TERMINAL)?;
            let all = trusts(ctx.client, &args.account).await?;
            if all.is_empty() {
                eprintln!("{} has no sign-ins to remove.", args.account);
                return Ok(());
            }
            let labels: Vec<String> = all
                .iter()
                .map(|t| {
                    format!(
                        "{}  ({})",
                        sign_in_label(str_field(t, "issuer"), str_field(t, "subject")),
                        str_field(t, "subject")
                    )
                })
                .collect();
            let t = &all[ask.select("Remove which sign-in?", &labels, 0)?];
            (
                str_field(t, "issuer").to_string(),
                str_field(t, "subject").to_string(),
            )
        }
    };
    if !args.yes {
        let Some(ask) = prompter else {
            return Err(format!(
                "Refusing to remove {subject} without confirmation: pass --yes."
            ));
        };
        ctx.client.check_signed_in().await?;
        let label = format!(
            "Stop {} signing in as {}?",
            sign_in_label(&issuer, &subject),
            args.account
        );
        if !ask.confirm(&label, false)? {
            return Err(crate::prompt::CANCELLED.into());
        }
    }
    let mut url = ctx.client.url(&["accounts", &args.account, "trusts"]);
    url.query_pairs_mut()
        .append_pair("issuer", &issuer)
        .append_pair("subject", &subject);
    let removed: Value = ctx.client.request(Method::DELETE, url, None::<&()>).await?;
    if args.json {
        crate::output::json(&removed);
    } else {
        eprintln!(
            "{} can no longer sign in as {}",
            sign_in_label(&issuer, &subject),
            args.account
        );
    }
    Ok(())
}

/// Revoke a key read from stdin, never from the command line, where shell
/// history and `ps` would keep it. The API answers the same whether or not
/// the key existed, so this can't test one.
async fn revoke_key(client: &Client) -> Result<(), String> {
    if std::io::stdin().is_terminal() {
        eprintln!("Paste the API key, then Enter:");
    }
    let mut key = String::new();
    std::io::stdin()
        .read_line(&mut key)
        .map_err(|e| format!("Couldn't read the key: {e}"))?;
    let key = key.trim();
    if key.is_empty() {
        return Err("No key given: pipe it in, e.g. `source-coop service-account sign-in revoke-key < key-file`.".into());
    }
    let url = client.url(&["service-account-keys", "revocations"]);
    let (status, text) = client
        .send(Method::POST, url, Some(&json!({"key": key})))
        .await?;
    if !status.is_success() {
        return Err(ApiError::from_response(status, &text).into());
    }
    eprintln!("Revoked, if it was a key: within a minute, nothing can sign in with it.");
    Ok(())
}

/// The service account's live membership of `product`, if it has one.
async fn membership(
    client: &Client,
    id: &str,
    product: &ProductRef,
) -> Result<Option<Value>, String> {
    Ok(memberships(client, id).await?.into_iter().find(|m| {
        str_field(m, "membership_account_id") == product.account_id
            && str_field(m, "product_id") == product.product_id
    }))
}

async fn access_set(args: AccessSetArgs, ctx: &Ctx<'_>) -> Result<(), String> {
    split_id(&args.account)?;
    let client = ctx.client;
    let role = args.role.api();
    let result: Value = match membership(client, &args.account, &args.product).await? {
        Some(m) if str_field(&m, "role") == role => m,
        Some(m) => {
            let url = client.url(&["memberships", str_field(&m, "membership_id")]);
            client
                .request(Method::PATCH, url, Some(&json!({"role": role})))
                .await?
        }
        None => {
            let body = json!({
                "membership_account_id": args.product.account_id,
                "product_id": args.product.product_id,
                "account_id": args.account,
                "role": role,
            });
            client
                .request(Method::POST, client.url(&["memberships"]), Some(&body))
                .await?
        }
    };
    if args.json {
        crate::output::json(&result);
    } else {
        eprintln!(
            "{} can {} {}",
            args.account,
            match args.role {
                Role::Read => "read",
                Role::Write => "read and write",
            },
            args.product
        );
    }
    Ok(())
}

async fn access_remove(
    args: AccessRemoveArgs,
    ctx: &Ctx<'_>,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    split_id(&args.account)?;
    let client = ctx.client;
    let m = match &args.product {
        Some(p) => membership(client, &args.account, p)
            .await?
            .ok_or_else(|| not_found(format!("{} has no access to {p}", args.account)))?,
        None => {
            let ask = prompter.ok_or(NEEDS_TERMINAL)?;
            let mut all = memberships(client, &args.account).await?;
            if all.is_empty() {
                eprintln!("{} can't reach any products.", args.account);
                return Ok(());
            }
            let labels: Vec<String> = all
                .iter()
                .map(|m| {
                    format!(
                        "{}/{}  {}",
                        str_field(m, "membership_account_id"),
                        str_field(m, "product_id"),
                        role_label(str_field(m, "role"))
                    )
                })
                .collect();
            all.swap_remove(ask.select("Remove access to which product?", &labels, 0)?)
        }
    };
    let url = client.url(&["memberships", str_field(&m, "membership_id")]);
    let ended: Value = client
        .request(Method::PATCH, url, Some(&json!({"state": "revoked"})))
        .await?;
    if args.json {
        crate::output::json(&ended);
    } else {
        eprintln!(
            "{} can no longer reach {}/{}",
            args.account,
            str_field(&m, "membership_account_id"),
            str_field(&m, "product_id")
        );
    }
    Ok(())
}

async fn usage(
    args: UsageArgs,
    ctx: &Ctx<'_>,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    let id = match args.account {
        Some(id) => id,
        None => {
            let ask = prompter.as_deref_mut().ok_or(NEEDS_TERMINAL)?;
            match choose(ctx, ask).await? {
                Some(id) => id,
                None => return Ok(()),
            }
        }
    };
    split_id(&id)?;
    let subject = match (args.subject, args.key) {
        (Some(s), _) => Some(s),
        (None, true) => None,
        (None, false) => {
            let Some(ask) = prompter else {
                return Err(
                    "Say which sign-in: --subject SUBJECT (as `view` lists it) or --key.".into(),
                );
            };
            let trusts = trusts(ctx.client, &id).await?;
            let mut options: Vec<String> = trusts
                .iter()
                .map(|t| sign_in_label(str_field(t, "issuer"), str_field(t, "subject")))
                .collect();
            options.push("An API key".into());
            let i = ask.select("Sign in with", &options, 0)?;
            trusts.get(i).map(|t| str_field(t, "subject").to_string())
        }
    };
    let proxy = ctx.proxy.trim_end_matches('/');
    match subject {
        Some(s) => {
            eprintln!("Customize and save this workflow to a file under .github/workflows/:");
            println!("{}", github_workflow(proxy, &id, &s));
        }
        None => {
            eprintln!("Save the API key to a file and set these variables:");
            println!("{}", api_key_environment(proxy, &id));
        }
    }
    Ok(())
}

/// The `aws-actions/configure-aws-credentials` step that signs a job in as
/// the service account: the web UI's `signInStep`.
fn sign_in_step(id: &str) -> [String; 7] {
    [
        format!("- name: Sign in to Source Cooperative as {id}"),
        "  uses: aws-actions/configure-aws-credentials@v6".into(),
        "  with:".into(),
        format!("    role-to-assume: arn:aws:iam::{id}:role/FullAccess"),
        "    audience: ${{ env.AWS_ENDPOINT_URL }}".into(),
        "    sts-endpoint: ${{ env.AWS_ENDPOINT_URL }}/.sts".into(),
        "    aws-region: us-west-2".into(),
    ]
}

/// A whole GitHub Actions workflow that acts as the service account, for the
/// trusted `subject`: the web UI's `githubWorkflow`, line for line, so the
/// two show the same thing.
fn github_workflow(proxy: &str, id: &str, subject: &str) -> String {
    let environment = subject.split_once(":environment:").map(|(_, e)| e);
    let branch = subject
        .split_once(":ref:")
        .map(|(_, r)| r.strip_prefix("refs/heads/").unwrap_or(r));
    let mut lines: Vec<String> = vec![
        "name: Source Cooperative".into(),
        "on:".into(),
        "  schedule:".into(),
        match branch {
            Some(b) => format!("    # Nightly @ 2am UTC; works only if {b} is the default branch"),
            None => "    # Nightly @ 2am UTC; GitHub runs schedules on the default branch".into(),
        },
        "    - cron: \"0 2 * * *\"".into(),
        "  workflow_dispatch:  # and by hand, from the Actions tab".into(),
        "env:".into(),
        "  # Configures AWS CLI/SDKs to use Source Cooperative's data proxy.".into(),
        format!("  AWS_ENDPOINT_URL: {proxy}"),
        String::new(),
        "jobs:".into(),
        "  data:".into(),
        "    runs-on: ubuntu-latest".into(),
    ];
    if let Some(e) = environment {
        lines.push(format!(
            "    environment: {}  # Must run on {e} as per Service Account \"{id}\" trust policy.",
            json!(e)
        ));
    }
    lines.extend([
        "    permissions:".to_string(),
        "      id-token: write  # required for aws-actions/configure-aws-credentials".into(),
        "      contents: read".into(),
        "    steps:".into(),
        "      # Any setup of your own (checkout, installing tools) can come first.".into(),
        String::new(),
    ]);
    lines.extend(sign_in_step(id).iter().map(|l| format!("      {l}")));
    let owner = id.split_once("--").map_or(id, |(o, _)| o);
    lines.extend([
        String::new(),
        format!("      # From here on, any AWS SDK/CLI acts as {id}."),
        format!("      - run: aws s3 ls s3://{owner}/"),
    ]);
    lines.join("\n")
}

/// What a stock AWS SDK or the AWS CLI needs to sign in with an API key saved
/// to a file: the web UI's `apiKeyEnvironment`.
fn api_key_environment(proxy: &str, id: &str) -> String {
    [
        "export AWS_REGION=us-west-2".to_string(),
        format!("export AWS_ENDPOINT_URL_S3={proxy}"),
        format!("export AWS_ENDPOINT_URL_STS={proxy}/.sts"),
        format!("export AWS_ROLE_ARN=arn:aws:iam::{id}:role/FullAccess"),
        "export AWS_WEB_IDENTITY_TOKEN_FILE=/path/to/the/saved/key".into(),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::scripted::{Answer::*, Script};
    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SITE: &str = "https://source.coop";
    const PROXY: &str = "https://data.source.coop";

    fn ctx<'a>(client: &'a Client, github: &'a MockServer) -> Ctx<'a> {
        Ctx {
            client,
            site: SITE,
            proxy: PROXY,
            github_api: Box::leak(github.uri().into_boxed_str()),
        }
    }

    fn account(id: &str) -> Value {
        json!({"account_id": id, "type": "service", "name": "Nightly sync",
               "owner_account_id": id.split_once("--").unwrap().0, "disabled": false,
               "created_at": "2026-10-01T00:00:00Z", "updated_at": "2026-10-01T00:00:00Z"})
    }

    /// A stand-in API that knows the caller: "acct", a maintainer of "org".
    async fn api_server() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/whoami"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "account": {"account_id": "acct", "type": "individual", "flags": []},
                "memberships": [{"account_id": "acct", "membership_account_id": "org",
                                 "role": "maintainers", "state": "member"}]
            })))
            .mount(&server)
            .await;
        server
    }

    /// GitHub's answer for a repository whose tokens name it by ID.
    async fn github_server() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/org/data/actions/oidc/customization/sub"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"use_default": true, "sub_claim_prefix": "repo:org@1/data@2"}),
            ))
            .mount(&server)
            .await;
        server
    }

    fn page(items: Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({"items": items, "next_cursor": null}))
    }

    #[test]
    fn subjects_are_github_s_claims_and_read_back_as_people_say_them() {
        let branch = subject("acme/data", &Context::Branch("main".into()));
        assert_eq!(branch, "repo:acme/data:ref:refs/heads/main");
        assert_eq!(
            subject("acme/data", &Context::Tag("refs/tags/v1".into())),
            "repo:acme/data:ref:refs/tags/v1"
        );
        let env = subject("acme@1/data@2", &Context::Environment("prod".into()));
        assert_eq!(env, "repo:acme@1/data@2:environment:prod");

        assert_eq!(
            sign_in_label(GITHUB_ISSUER, &branch),
            "GitHub Actions · acme/data · branch main"
        );
        assert_eq!(
            sign_in_label(GITHUB_ISSUER, "repo:a/b:ref:refs/tags/v1"),
            "GitHub Actions · a/b · tag v1"
        );
        assert_eq!(
            sign_in_label(GITHUB_ISSUER, &env),
            "GitHub Actions · acme@1/data@2 · environment prod"
        );
        assert_eq!(sign_in_label("https://other", "x"), "https://other · x");
        assert_eq!(slugify("  Nightly sync! v2 "), "nightly-sync-v2");
    }

    #[test]
    fn usage_is_the_web_ui_s_snippets() {
        let workflow = github_workflow(
            PROXY,
            "acme--nightly-sync",
            "repo:acme/data:ref:refs/heads/main",
        );
        assert!(workflow.starts_with("name: Source Cooperative\non:\n  schedule:\n    # Nightly @ 2am UTC; works only if main is the default branch\n"), "{workflow}");
        assert!(workflow.contains("\nenv:\n  # Configures AWS CLI/SDKs to use Source Cooperative's data proxy.\n  AWS_ENDPOINT_URL: https://data.source.coop\n"));
        assert!(workflow.contains("\njobs:\n  data:\n    runs-on: ubuntu-latest\n    permissions:\n      id-token: write  # required for aws-actions/configure-aws-credentials\n"));
        assert!(workflow.contains("\n      - name: Sign in to Source Cooperative as acme--nightly-sync\n        uses: aws-actions/configure-aws-credentials@v6\n        with:\n          role-to-assume: arn:aws:iam::acme--nightly-sync:role/FullAccess\n          audience: ${{ env.AWS_ENDPOINT_URL }}\n          sts-endpoint: ${{ env.AWS_ENDPOINT_URL }}/.sts\n          aws-region: us-west-2\n"));
        assert!(workflow.ends_with("\n      - run: aws s3 ls s3://acme/"));
        assert!(!workflow.contains("environment:"));

        let pinned = github_workflow(
            PROXY,
            "acme--nightly-sync",
            "repo:acme@1/data@2:environment:production",
        );
        assert!(pinned.contains("\n    runs-on: ubuntu-latest\n    environment: \"production\"  # Must run on production as per Service Account \"acme--nightly-sync\" trust policy.\n"));
        assert!(pinned
            .contains("    # Nightly @ 2am UTC; GitHub runs schedules on the default branch\n"));

        assert_eq!(
            api_key_environment(PROXY, "nightly-sync"),
            "export AWS_REGION=us-west-2\nexport AWS_ENDPOINT_URL_S3=https://data.source.coop\nexport AWS_ENDPOINT_URL_STS=https://data.source.coop/.sts\nexport AWS_ROLE_ARN=arn:aws:iam::nightly-sync:role/FullAccess\nexport AWS_WEB_IDENTITY_TOKEN_FILE=/path/to/the/saved/key"
        );
    }

    #[tokio::test]
    async fn create_from_flags_sends_the_workflow_as_github_names_it_and_the_grants() {
        let server = api_server().await;
        let github = github_server().await;
        let expected = json!({"name": "Nightly sync", "local_id": "nightly-sync",
            "github_subjects": ["repo:org@1/data@2:ref:refs/heads/main"],
            "grants": [{"product_id": "data", "role": "write_data"}]});
        Mock::given(method("POST"))
            .and(path("/api/v1/accounts/org/service-accounts"))
            .and(body_json(&expected))
            .respond_with(ResponseTemplate::new(201).set_body_json(account("org--nightly-sync")))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let args = CreateArgs {
            account: Some("org--nightly-sync".into()),
            name: Some("Nightly sync".into()),
            github: GithubArgs {
                github: Some("org/data".into()),
                branch: Some("main".into()),
                ..GithubArgs::default()
            },
            access: vec!["org/data=write".into()],
            from_file: None,
            json: true,
        };
        create(args, &ctx(&client, &github), None).await.unwrap();
    }

    #[tokio::test]
    async fn create_refuses_to_grant_another_account_s_product() {
        let server = api_server().await;
        let github = github_server().await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let args = CreateArgs {
            account: Some("org--nightly-sync".into()),
            name: None,
            github: GithubArgs::default(),
            access: vec!["other/data=read".into()],
            from_file: None,
            json: false,
        };
        let err = create(args, &ctx(&client, &github), None)
            .await
            .unwrap_err();
        assert!(
            err.contains("only be granted its owner's products"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn create_asks_the_web_form_s_questions_in_its_order() {
        let server = api_server().await;
        let github = github_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/org"))
            .respond_with(page(json!([{"account_id": "org", "product_id": "data"},
                                      {"account_id": "org", "product_id": "other"}])))
            .mount(&server)
            .await;
        let expected = json!({"name": "Nightly sync", "local_id": "nightly-sync",
            "github_subjects": ["repo:org@1/data@2:environment:prod"],
            "grants": [{"product_id": "data", "role": "write_data"}]});
        Mock::given(method("POST"))
            .and(path("/api/v1/accounts/org/service-accounts"))
            .and(body_json(&expected))
            .respond_with(ResponseTemplate::new(201).set_body_json(account("org--nightly-sync")))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([
            Pick(1),              // Owner: org
            Text("Nightly sync"), // Name
            Default,              // ID, made from the name
            Pick(0),              // Add a GitHub workflow
            Text("org/data"),     // Repository
            Pick(2),              // Environment
            Text("prod"),         // its name
            Default,              // Continue
            Pick(0),              // Grant org/data
            Pick(1),              // Read and write
            Default,              // Continue
            Yes(true),            // Create
        ]);
        let args = CreateArgs {
            account: None,
            name: None,
            github: GithubArgs::default(),
            access: vec![],
            from_file: None,
            json: true,
        };
        create(args, &ctx(&client, &github), Some(&mut ask))
            .await
            .unwrap();
        assert_eq!(
            ask.asked,
            [
                "Owner [acct] of acct | org",
                "Name []",
                "ID (after org--) [nightly-sync]",
                "Signs in with: add a sign-in? [Continue] of GitHub workflow… | Continue",
                "Repository (OWNER/REPO) []",
                "Allow runs from [Branch] of Branch | Tag | Environment",
                "Environment []",
                "Signs in with: 1 added; another? [Continue] of GitHub workflow… | Continue",
                "Can reach: grant a product? [Continue] of org/data | org/other | Continue",
                "Access [Read] of Read | Read and write",
                "Can reach: 1 granted; another? [Continue] of org/other | Continue",
                "Create this service account? {Service account  org--nightly-sync | Name             Nightly sync | Signs in with    GitHub Actions · org@1/data@2 · environment prod |                    { |                      \"StringEquals\": { |                        \"token.actions.githubusercontent.com:aud\": \"https://data.source.coop\", |                        \"token.actions.githubusercontent.com:sub\": \"repo:org@1/data@2:environment:prod\" |                      } |                    } | Can reach        org/data  Read and write} [true]",
            ]
        );
    }

    #[tokio::test]
    async fn view_finds_the_account_with_its_trusts_and_memberships() {
        let server = api_server().await;
        let github = github_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/accounts/org/service-accounts"))
            .respond_with(page(json!([
                account("org--other"),
                account("org--nightly-sync")
            ])))
            .mount(&server)
            .await;
        let trust = json!({"account_id": "org--nightly-sync", "issuer": GITHUB_ISSUER,
                           "subject": "repo:org/data:ref:refs/heads/main"});
        Mock::given(method("GET"))
            .and(path("/api/v1/accounts/org--nightly-sync/trusts"))
            .respond_with(page(json!([trust])))
            .mount(&server)
            .await;
        let grant = json!({"membership_id": "m1", "account_id": "org--nightly-sync",
                           "membership_account_id": "org", "product_id": "data",
                           "role": "write_data", "state": "member"});
        Mock::given(method("GET"))
            .and(path("/api/v1/memberships"))
            .and(query_param("account_id", "org--nightly-sync"))
            .respond_with(page(json!([grant])))
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();

        let whole = fetch_whole(&client, "org--nightly-sync").await.unwrap();
        assert_eq!(whole["trusts"], json!([trust]));
        assert_eq!(whole["memberships"], json!([grant]));
        let lines = account_lines(&whole, SITE, false);
        assert_eq!(lines[0], "Nightly sync");
        assert!(lines.contains(&"URL              https://source.coop/edit/account/org/service-accounts/org--nightly-sync".to_string()), "{lines:#?}");
        let tail: Vec<&str> = lines
            .iter()
            .map(String::as_str)
            .skip_while(|l| *l != "Signs in with")
            .collect();
        assert_eq!(
            tail,
            [
                "Signs in with",
                "  GitHub Actions · org/data · branch main",
                "    repo:org/data:ref:refs/heads/main",
                "",
                "Can reach",
                "  org/data  Read and write",
            ]
        );

        let args = ViewArgs {
            account: Some("org--missing".into()),
            interactive: false,
            web: false,
            json: true,
        };
        let err = view(args, &ctx(&client, &github), None).await.unwrap_err();
        assert_eq!(crate::failure::classify(&err).exit_code(), 5, "{err}");
    }

    #[tokio::test]
    async fn access_set_grants_once_and_changes_the_role_after() {
        let server = api_server().await;
        let github = github_server().await;
        let existing = json!({"membership_id": "m1", "account_id": "org--sa",
                              "membership_account_id": "org", "product_id": "data",
                              "role": "read_data", "state": "member"});
        Mock::given(method("GET"))
            .and(path("/api/v1/memberships"))
            .respond_with(page(json!([existing])))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/memberships/m1"))
            .and(body_json(json!({"role": "write_data"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(&existing))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/memberships"))
            .and(body_json(
                json!({"membership_account_id": "org", "product_id": "new",
                                  "account_id": "org--sa", "role": "read_data"}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(&existing))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let ctx = ctx(&client, &github);
        let set = |product: &str, role| AccessSetArgs {
            account: "org--sa".into(),
            product: product.parse().unwrap(),
            role,
            json: true,
        };
        access_set(set("org/data", Role::Write), &ctx)
            .await
            .unwrap();
        access_set(set("org/new", Role::Read), &ctx).await.unwrap();
        // Already so: nothing sent.
        access_set(set("org/data", Role::Read), &ctx).await.unwrap();
    }

    #[tokio::test]
    async fn sign_in_remove_names_the_issuer_and_subject_and_needs_yes_unasked() {
        let server = api_server().await;
        let github = github_server().await;
        let subject = "repo:org/data:ref:refs/heads/main";
        Mock::given(method("DELETE"))
            .and(path("/api/v1/accounts/org--sa/trusts"))
            .and(query_param("issuer", GITHUB_ISSUER))
            .and(query_param("subject", subject))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"subject": subject})))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let ctx = ctx(&client, &github);
        let args = |yes| SignInRemoveArgs {
            account: "org--sa".into(),
            subject: Some(subject.into()),
            interactive: false,
            yes,
            json: true,
        };
        let err = sign_in_remove(args(false), &ctx, None).await.unwrap_err();
        assert!(err.contains("pass --yes"), "{err}");
        sign_in_remove(args(true), &ctx, None).await.unwrap();
    }

    #[tokio::test]
    async fn delete_without_a_terminal_needs_yes() {
        let server = api_server().await;
        let github = github_server().await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let args = DeleteArgs {
            account: Some("org--sa".into()),
            interactive: false,
            yes: false,
            json: false,
        };
        let err = delete(args, &ctx(&client, &github), None)
            .await
            .unwrap_err();
        assert!(err.contains("pass --yes"), "{err}");
    }
}
