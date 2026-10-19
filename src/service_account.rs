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
use clap_complete::engine::ArgValueCompleter;
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
    /// Rename a service account, change what it can reach, or disable or
    /// enable it
    #[command(
        after_help = crate::style::examples(&[
            "source-coop service-account edit my-org--nightly-sync --name \"Nightly sync\" --json",
            "source-coop service-account edit my-org--nightly-sync --access my-org/my-data=write --access my-org/old=none --json",
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
    /// Trust a GitHub Actions workflow to sign in as the service account, or
    /// issue it an API key
    #[command(
        after_help = crate::style::examples(&[
            "source-coop service-account sign-in add my-org--nightly-sync --github my-org/data --branch main --json",
            "source-coop service-account sign-in add my-org--nightly-sync --github my-org/data --environment production --json",
            "source-coop service-account sign-in add my-org--nightly-sync --subject repo:my-org/data:ref:refs/tags/v1 --json",
            "source-coop service-account sign-in add my-org--nightly-sync --key \"HPC cron job\" --expires 90d --out nightly.key --json",
        ])
    )]
    Add(SignInAddArgs),
    /// Change when an API key expires
    #[command(
        after_help = crate::style::examples(&[
            "source-coop service-account sign-in edit my-org--nightly-sync key:a1B2c3 --expires 1y --json",
            "source-coop service-account sign-in edit my-org--nightly-sync key:a1B2c3 --expires never --json",
        ])
    )]
    Edit(SignInEditArgs),
    /// Stop a workflow signing in as the service account, or revoke one of its
    /// API keys
    #[command(
        after_help = crate::style::examples(&[
            "source-coop service-account sign-in remove my-org--nightly-sync repo:my-org/data:ref:refs/heads/main --yes --json",
            "source-coop service-account sign-in remove my-org--nightly-sync key:a1B2c3 --yes --json",
        ])
    )]
    Remove(SignInRemoveArgs),
    /// Revoke an API key, read from stdin, wherever it was found; needs no sign-in
    #[command(after_help = crate::style::examples(&["source-coop service-account sign-in revoke-key"]))]
    RevokeKey(RevokeKeyArgs),
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
            Self::SignIn(SignInCommand::Edit(a)) => a.json,
            Self::SignIn(SignInCommand::Remove(a)) => a.json,
            Self::SignIn(SignInCommand::RevokeKey(_)) => false,
            Self::Usage(_) => false,
        }
    }
}

#[derive(Args)]
pub struct ListArgs {
    /// The owner whose service accounts to list (yours when omitted)
    #[arg(add = ArgValueCompleter::new(crate::complete::account))]
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
    #[arg(
        required_unless_present = "interactive",
        value_parser = parse_id,
        add = ArgValueCompleter::new(crate::complete::service_account)
    )]
    account: Option<String>,

    /// Show the service account with shortcuts: b browser, e edit, d delete, ← back
    #[arg(long, short = 'i', conflicts_with_all = ["web", "json"])]
    interactive: bool,

    /// Open the service account's page in the browser instead
    #[arg(long, short = 'w')]
    web: bool,

    /// Print the service account as JSON, with its `trusts`, `keys` and
    /// `memberships`
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

/// An API key to issue: what it's for, when it stops working, and where the
/// key goes, since it is shown only once.
#[derive(Args, Default, Clone)]
pub struct KeyArgs {
    /// Issue an API key, labelled with where it will live, so you know which
    /// to revoke (e.g. "HPC cron job")
    #[arg(long = "key", value_name = "LABEL")]
    key: Option<String>,

    /// With --key: when it stops working: 30d, 90d, 1y, never, or a date
    /// (2027-01-31) [default: 90d]
    #[arg(long, requires = "key", value_parser = parse_expiry)]
    expires: Option<Value>,

    /// With --key: write the key to this file, readable only by you, instead
    /// of showing it
    #[arg(long, requires = "key", value_name = "PATH")]
    out: Option<String>,
}

#[derive(Args)]
pub struct CreateArgs {
    /// The new service account, as OWNER--NAME (prompted for when omitted)
    #[arg(value_parser = parse_id, add = ArgValueCompleter::new(crate::complete::new_service_account))]
    account: Option<String>,

    /// Its name, as people see it
    #[arg(long, short = 'n')]
    name: Option<String>,

    #[command(flatten)]
    github: GithubArgs,

    #[command(flatten)]
    key: KeyArgs,

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
    #[arg(
        required_unless_present = "interactive",
        value_parser = parse_id,
        add = ArgValueCompleter::new(crate::complete::service_account)
    )]
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

    /// Grant one of the owner's products, change its role, or take it away,
    /// as ACCOUNT/PRODUCT=read, =write or =none (repeatable)
    #[arg(long, value_name = "PRODUCT=ROLE")]
    access: Vec<String>,

    /// Read fields from a JSON object in this file (`-` for stdin); flags win
    #[arg(long, short = 'F', value_name = "PATH")]
    from_file: Option<String>,

    /// Print the edited service account as JSON, as `view --json` does
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct DeleteArgs {
    /// The service account, as OWNER--NAME (with -i, picked when omitted)
    #[arg(
        required_unless_present = "interactive",
        value_parser = parse_id,
        add = ArgValueCompleter::new(crate::complete::service_account)
    )]
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
    #[arg(value_parser = parse_id, add = ArgValueCompleter::new(crate::complete::service_account))]
    account: String,

    #[command(flatten)]
    github: GithubArgs,

    #[command(flatten)]
    key: KeyArgs,

    /// Print the new trust, or the new key's record, as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct SignInEditArgs {
    /// The service account, as OWNER--NAME
    #[arg(value_parser = parse_id, add = ArgValueCompleter::new(crate::complete::service_account))]
    account: String,

    /// The API key, as key:HINT (its last six characters, as `view` shows
    /// them) or key:KEY_ID (with -i, picked when omitted)
    #[arg(required_unless_present = "interactive")]
    key: Option<String>,

    /// Pick the key when it isn't named
    #[arg(long, short = 'i')]
    interactive: bool,

    /// When it stops working, counted from now: 30d, 90d, 1y, never, or a
    /// date (2027-01-31) (asked for when omitted)
    #[arg(long, value_parser = parse_expiry)]
    expires: Option<Value>,

    /// Print the key's record as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct SignInRemoveArgs {
    /// The service account, as OWNER--NAME
    #[arg(value_parser = parse_id, add = ArgValueCompleter::new(crate::complete::service_account))]
    account: String,

    /// The sign-in to remove, as `view` lists it: a trusted subject, or an
    /// API key as key:HINT or key:KEY_ID (with -i, picked when omitted)
    #[arg(required_unless_present = "interactive")]
    subject: Option<String>,

    /// Pick the sign-in to remove when it isn't named
    #[arg(long, short = 'i', conflicts_with = "yes")]
    interactive: bool,

    /// Skip the confirmation prompt
    #[arg(long, short = 'y')]
    yes: bool,

    /// Print the removed trust, or the revoked key's record, as JSON
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

    fn from_api(role: &str) -> Option<Role> {
        match role {
            "read_data" => Some(Role::Read),
            "write_data" => Some(Role::Write),
            _ => None,
        }
    }

    /// What it lets the account do, after "can": `read`, `read and write`.
    fn verb(self) -> &'static str {
        match self {
            Role::Read => "read",
            Role::Write => "read and write",
        }
    }
}

#[derive(Args)]
pub struct UsageArgs {
    /// The service account, as OWNER--NAME (with -i, picked when omitted)
    #[arg(
        required_unless_present = "interactive",
        value_parser = parse_id,
        add = ArgValueCompleter::new(crate::complete::service_account)
    )]
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
        C::SignIn(SignInCommand::Edit(args)) => sign_in_edit(args, ctx, prompter).await,
        C::SignIn(SignInCommand::Remove(args)) => sign_in_remove(args, ctx, prompter).await,
        C::SignIn(SignInCommand::RevokeKey(_)) => revoke_key(ctx.client).await,
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

/// Every API key issued to the service account, revoked and expired ones too.
async fn keys(client: &Client, id: &str) -> Result<Vec<Value>, String> {
    all(client, client.url(&["accounts", id, "keys"])).await
}

/// The service account with what `view` shows of it: its `trusts`, `keys`
/// and `memberships`, under those names.
async fn fetch_whole(client: &Client, id: &str) -> Result<Value, String> {
    let mut account = fetch(client, id).await?;
    let (t, k, m) = tokio::join!(
        trusts(client, id),
        keys(client, id),
        memberships(client, id)
    );
    account["trusts"] = Value::Array(t?);
    account["keys"] = Value::Array(k?);
    account["memberships"] = Value::Array(m?);
    Ok(account)
}

fn time(v: &Value, key: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(str_field(v, key))
        .ok()
        .map(|d| d.with_timezone(&chrono::Utc))
}

/// Whether a key still signs in: not revoked, and not past its expiry.
fn key_live(k: &Value, now: chrono::DateTime<chrono::Utc>) -> bool {
    k.get("revoked_at").is_none_or(Value::is_null) && time(k, "expires_at").is_none_or(|e| e > now)
}

/// An API key as people tell it apart: `API key · HPC cron job · key:a1B2c3`,
/// naming it as `sign-in edit` and `remove` take it.
fn key_label(k: &Value) -> String {
    format!(
        "API key · {} · key:{}",
        str_field(k, "label"),
        str_field(k, "hint")
    )
}

/// How a key has been used and when it ends, as the web UI's row says it:
/// `used 3 days ago · expires in 2 months`.
fn key_status(k: &Value, now: chrono::DateTime<chrono::Utc>) -> String {
    let rel = |at| crate::style::relative(at, now);
    let used = match time(k, "last_used_at") {
        Some(at) => format!("used {}", rel(at)),
        None => "never used".into(),
    };
    let end = match (time(k, "revoked_at"), time(k, "expires_at")) {
        (Some(at), _) => {
            let by = match str_field(k, "revoked_via") {
                "holder" => " by someone holding it",
                "github" => " by GitHub, which found it in public",
                _ => "",
            };
            format!("revoked {}{by}", rel(at))
        }
        (None, None) => "never expires".into(),
        (None, Some(at)) if at <= now => format!("expired {}", rel(at)),
        (None, Some(at)) => format!("expires {}", rel(at)),
    };
    format!("{used} · {end}")
}

/// `--expires` as the API takes it: `never` is null; `30d`, `90d` or `1y`
/// count from now; anything else is a date or time, sent as it is.
fn parse_expiry(s: &str) -> Result<Value, String> {
    let s = s.trim();
    if s == "never" {
        return Ok(Value::Null);
    }
    let bad = || format!("expected 30d, 90d, 1y, never, or a date like 2027-01-31, got '{s}'");
    let days = match (s.strip_suffix('d'), s.strip_suffix('y')) {
        (Some(n), _) => Some(n.parse::<i64>().ok()),
        (_, Some(n)) => Some(n.parse::<i64>().ok().and_then(|y| y.checked_mul(365))),
        _ => None,
    };
    if let Some(days) = days {
        // Checked, so a count too big for a date is an error, not a panic.
        let at = days
            .and_then(chrono::Duration::try_days)
            .and_then(|d| chrono::Utc::now().checked_add_signed(d))
            .ok_or_else(bad)?;
        return Ok(json!(at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)));
    }
    if chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok() {
        return Ok(json!(format!("{s}T00:00:00Z")));
    }
    if chrono::DateTime::parse_from_rfc3339(s).is_ok() {
        return Ok(json!(s));
    }
    Err(bad())
}

/// The expiries the web UI offers, the second (90 days) by default.
const EXPIRIES: [(&str, &str); 4] = [
    ("30 days", "30d"),
    ("90 days", "90d"),
    ("A year", "1y"),
    ("Never — until revoked", "never"),
];

/// Ask when a key should stop working, as the web UI's choice does. None is back.
fn ask_expiry(ask: &mut dyn Prompter, label: &str) -> Result<Option<Value>, String> {
    let options: Vec<String> = EXPIRIES.iter().map(|(l, _)| l.to_string()).collect();
    Ok(ask
        .select_or_back(label, &options, 1)?
        .map(|i| parse_expiry(EXPIRIES[i].1).expect("each is valid")))
}

/// When a key's `expires_at` ends it, for a review: `expires in 3 months`,
/// or never.
fn expiry_label(expires_at: &Value) -> String {
    match time(&json!({"expires_at": expires_at}), "expires_at") {
        Some(at) => format!("expires {}", crate::style::relative(at, chrono::Utc::now())),
        None => "never expires".into(),
    }
}

/// Hand over a key just issued, which nothing will show again: into `out`, a
/// file only you can read; else, with someone there, into a file they name
/// or onto the screen; else onto stdout, alone, for a script. Returns the
/// file it went to.
fn deliver_key(
    key: &str,
    out: Option<&str>,
    prompter: Option<&mut (dyn Prompter + '_)>,
    stdout: bool,
) -> Result<Option<String>, String> {
    let path = match (out, prompter) {
        (Some(p), _) => Some(p.to_string()),
        // Piped, the key goes to stdout for the script reading it.
        (None, Some(ask)) if std::io::stdout().is_terminal() => {
            let p = ask.input(
                "Save the key to a file (Enter to show it here instead)",
                "",
                true,
            )?;
            Some(p.trim().to_string()).filter(|p| !p.is_empty())
        }
        _ => None,
    };
    if let Some(p) = &path {
        // The key exists nowhere else, so a failed save shows it instead of
        // losing it.
        match crate::cache::write_file(std::path::Path::new(p), &format!("{key}\n")) {
            Ok(written) => {
                eprintln!(
                    "Saved the API key to {written}, readable only by you. It won't be shown again."
                );
                return Ok(Some(written));
            }
            Err(e) => eprintln!("Couldn't save the API key there ({e}), so here it is instead."),
        }
    }
    eprintln!("This is the only time the API key is shown. Store it now:");
    if stdout {
        println!("{key}");
    } else {
        eprintln!("{key}");
    }
    Ok(None)
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
    if trusts.is_empty() && items("keys").is_empty() {
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
    // Live keys first, then the ones that no longer work, dimmed.
    let mut keys = items("keys");
    keys.sort_by_key(|k| !key_live(k, now));
    for k in &keys {
        let (head, status) = (key_label(k), key_status(k, now));
        if key_live(k, now) {
            lines.push(format!("  {head}"));
            lines.push(format!("    {}", paint("2", &status)));
        } else {
            lines.push(format!("  {}", paint("2", &head)));
            lines.push(format!("    {}", paint("2", &status)));
        }
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
                access: vec![],
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
    let (product, role) = parse_access(spec)?;
    let role = role.ok_or_else(|| format!("{product}=none grants nothing: use read or write"))?;
    if product.account_id != owner {
        return Err(format!(
            "A service account can only be granted its owner's products: {product} isn't {owner}'s."
        ));
    }
    Ok(json!({"product_id": product.product_id, "role": role.api()}))
}

/// `ACCOUNT/PRODUCT=read|write|none`, as `--access` takes it: the product,
/// and its role, or None to take it away.
fn parse_access(spec: &str) -> Result<(ProductRef, Option<Role>), String> {
    let bad = || format!("expected --access ACCOUNT/PRODUCT=read, =write or =none, got '{spec}'");
    let (product, role) = spec.rsplit_once('=').ok_or_else(bad)?;
    let product: ProductRef = product.parse()?;
    let role = match role {
        "none" => None,
        r => Some(Role::from_str(r, true).map_err(|_| bad())?),
    };
    Ok((product, role))
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
    let key = body.get("key").filter(|k| k.is_object());
    if subjects.is_empty() && key.is_none() {
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
    if let Some(k) = key {
        let label = if subjects.is_empty() {
            "Signs in with"
        } else {
            ""
        };
        let expires = expiry_label(k.get("expires_at").unwrap_or(&Value::Null));
        rows.push((
            label.into(),
            format!("API key · {} · {expires}", str_field(k, "label")),
        ));
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
            Step::SignIns if given.iter().any(|k| k == "github_subjects" || k == "key") => {
                Next::Skipped(Some(Step::Access))
            }
            Step::SignIns => {
                // One key at creation, as the web form allows; the account's
                // own `sign-in add` issues more.
                let has_key = body.contains_key("key");
                let mut options = vec!["GitHub workflow…".to_string()];
                if !has_key {
                    options.push("API key…".into());
                }
                options.push(CONTINUE.into());
                let count = body
                    .get("github_subjects")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len)
                    + usize::from(has_key);
                let label = match count {
                    0 => "Signs in with: add a sign-in?".to_string(),
                    n => format!("Signs in with: {n} added; another?"),
                };
                match ask.select_or_back(&label, &options, options.len() - 1)? {
                    None => Next::Back,
                    Some(i) if i == options.len() - 1 => Next::Asked(Some(Step::Access)),
                    Some(0) => {
                        if let Some(s) = ask_github(ask, ctx.github_api).await? {
                            push_unique(body, "github_subjects", json!(s));
                        }
                        // The menu again, for another or to continue.
                        continue;
                    }
                    Some(_) => {
                        if let Some((label, expires_at)) = ask_key(ask)? {
                            body.insert(
                                "key".into(),
                                json!({"label": label, "expires_at": expires_at}),
                            );
                        }
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
    if let Some(label) = &args.key.key {
        let expires_at = args.key.expires.clone().unwrap_or_else(default_expiry);
        body.insert(
            "key".into(),
            json!({"label": label, "expires_at": expires_at}),
        );
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
    let sent = send_until_accepted(
        ctx.client,
        Method::POST,
        url,
        &mut body,
        prompter.as_deref_mut(),
    )
    .await;
    let mut created = match &draft {
        Some(draft) => draft.finish(sent, &body)?,
        None => sent?,
    };
    // The key issued with it, which nothing will show again.
    let key = created
        .pointer("/key/key")
        .and_then(Value::as_str)
        .map(String::from);
    if let (Some(k), true) = (&key, args.json) {
        created["key"] = key_record(created["key"].take(), k, args.key.out.as_deref());
    }
    report(&created, args.json, "Created");
    let id = str_field(&created, "account_id");
    if let (Some(k), false) = (&key, args.json) {
        // stdout holds the account's ID, for `id=$(…)`; a script wanting the
        // key passes --out or --json.
        deliver_key(k, args.key.out.as_deref(), prompter, false)?;
        eprintln!("To sign in with it: source-coop service-account usage {id} --key");
    }
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
    mut prompter: Option<&mut (dyn Prompter + '_)>,
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
    // Access changes ride in the body, so a draft keeps them, but go to
    // /memberships rather than in the PATCH.
    for spec in &args.access {
        let (product, role) = parse_access(spec)?;
        let reach = body.entry("access").or_insert_with(|| json!({}));
        reach[product.to_string()] = role.map_or(Value::Null, |r| json!(r.api()));
    }
    let key = format!("service-account-edit/{id}");
    let mut draft = None;
    if body.is_empty() {
        let Some(ask) = prompter.as_deref_mut() else {
            return Err(
                "Nothing to change: pass --name, --access, --disable, --enable or --from-file."
                    .into(),
            );
        };
        ctx.client.check_signed_in().await?;
        let saved = Draft::for_key(&key)?;
        if !saved.resume(ask, &mut body)? {
            let current = fetch_whole(ctx.client, &id).await?;
            edit_form(ask, ctx, &current, &mut body).await?;
        }
        if body.is_empty() {
            eprintln!("No changes to {id}.");
            return Ok(());
        }
        draft = Some(saved);
    }

    let mut fields = body.clone();
    let reach = fields.remove("access");
    let mut said = vec![];
    let sent = async {
        if !fields.is_empty() {
            let url = ctx.client.url(&["accounts", &id]);
            send_until_accepted(ctx.client, Method::PATCH, url, &mut fields, prompter).await?;
        }
        for (product, role) in reach.iter().flat_map(|r| r.as_object()).flatten() {
            let product: ProductRef = product.parse()?;
            let role = role.as_str().and_then(Role::from_api);
            said.push(set_access(ctx.client, &id, &product, role).await?);
        }
        Ok(())
    }
    .await;
    // Fields asked for again count as answers, for the draft.
    body.extend(fields);
    match &draft {
        Some(draft) => draft.finish(sent, &body)?,
        None => sent?,
    }
    if args.json {
        crate::output::json(&fetch_whole(ctx.client, &id).await?);
        return Ok(());
    }
    eprintln!("Edited {id}");
    for line in said {
        eprintln!("{line}");
    }
    println!("{id}");
    // What disabling or enabling does, as the web UI's confirmation says it.
    if args.disable || args.enable {
        eprintln!(
            "{}",
            if args.disable {
                DISABLE_SAYS
            } else {
                ENABLE_SAYS
            }
        );
    }
    Ok(())
}

/// Give the service account `role` on `product`, or take its access away
/// (None), through its membership: a new one, a changed role, or ended.
/// Already so is fine, so a draft sent twice does no harm. Returns what
/// changed, as a sentence.
async fn set_access(
    client: &Client,
    id: &str,
    product: &ProductRef,
    role: Option<Role>,
) -> Result<String, String> {
    let membership = membership(client, id, product).await?;
    let id_role = |m: &Value| str_field(m, "role").to_string();
    match (membership, role) {
        (None, None) => Ok(format!("{id} already can't reach {product}")),
        (Some(m), None) => {
            let url = client.url(&["memberships", str_field(&m, "membership_id")]);
            client
                .request::<Value>(Method::PATCH, url, Some(&json!({"state": "revoked"})))
                .await?;
            Ok(format!("{id} can no longer reach {product}"))
        }
        (Some(m), Some(r)) if id_role(&m) == r.api() => {
            Ok(format!("{id} already can {} {product}", r.verb()))
        }
        (Some(m), Some(r)) => {
            let url = client.url(&["memberships", str_field(&m, "membership_id")]);
            client
                .request::<Value>(Method::PATCH, url, Some(&json!({"role": r.api()})))
                .await?;
            Ok(format!("{id} can now {} {product}", r.verb()))
        }
        (None, Some(r)) => {
            let body = json!({
                "membership_account_id": product.account_id,
                "product_id": product.product_id,
                "account_id": id,
                "role": r.api(),
            });
            client
                .request::<Value>(Method::POST, client.url(&["memberships"]), Some(&body))
                .await?;
            Ok(format!("{id} can now {} {product}", r.verb()))
        }
    }
}

/// `edit`'s keys, as `product edit`'s form has them.
const EDIT_HINT: &str = "↑/↓ move · Enter change · s save · Esc cancel";

/// The choices for one product's access in the edit form.
const ACCESS_CHOICES: [&str; 3] = ["Read", "Read and write", "No access"];

/// A role as the form shows it, or "No access".
fn reach_label(role: Option<&str>) -> &str {
    role.map_or("No access", role_label)
}

/// The edit form, as `product edit` has one: the name and each product the
/// account reaches, as they are now, then "Grant a product…" and "Save
/// changes". Enter changes the highlighted row, `s` or Save shows what will
/// change and asks to confirm; Esc or ← cancels, asking first if anything
/// changed. Puts the changes in `body`: `name`, and `access` as
/// `{"ACCOUNT/PRODUCT": "read_data" | "write_data" | null}`.
async fn edit_form(
    ask: &mut dyn Prompter,
    ctx: &Ctx<'_>,
    current: &Value,
    body: &mut Map<String, Value>,
) -> Result<(), String> {
    let id = str_field(current, "account_id").to_string();
    let owner = str_field(current, "owner_account_id").to_string();
    let was_name = str_field(current, "name").to_string();
    let was: std::collections::BTreeMap<String, String> = current
        .get("memberships")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|m| {
            let product = format!(
                "{}/{}",
                str_field(m, "membership_account_id"),
                str_field(m, "product_id")
            );
            (product, str_field(m, "role").to_string())
        })
        .collect();
    let mut name = was_name.clone();
    let mut reach: std::collections::BTreeMap<String, Option<String>> = was
        .iter()
        .map(|(p, r)| (p.clone(), Some(r.clone())))
        .collect();
    let mut owned: Option<Vec<String>> = None;
    let mut place = Place::default();
    let _screen = ask.fullscreen();
    loop {
        let changed: Vec<String> = reach
            .iter()
            .filter(|(p, r)| r.as_deref() != was.get(*p).map(String::as_str))
            .map(|(p, _)| p.clone())
            .collect();
        let count = changed.len() + usize::from(name != was_name);
        let products: Vec<String> = reach.keys().cloned().collect();
        let width = products.iter().map(String::len).max().unwrap_or(0).max(12);
        let mut rows = vec![if name != was_name {
            format!("{:<width$} ● {name}   (was: {was_name})", "Name")
        } else {
            format!("{:<width$}   {name}", "Name")
        }];
        for p in &products {
            let now = reach_label(reach[p].as_deref());
            rows.push(if changed.contains(p) {
                let before = reach_label(was.get(p).map(String::as_str));
                format!("{p:<width$} ● {now}   (was: {before})")
            } else {
                format!("{p:<width$}   {now}")
            });
        }
        rows.push("Grant a product…".into());
        rows.push(match count {
            0 => "Save changes (nothing changed yet)".into(),
            1 => "Save changes (1 change)".into(),
            n => format!("Save changes ({n} changes)"),
        });
        ask.clear();
        let action = ask.browse(
            &format!("Edit {id}"),
            &rows,
            &mut place,
            false,
            "s",
            EDIT_HINT,
        )?;
        let at = place.at;
        // Esc or ↑ on a question leaves its row as it was.
        let kept = |e: &String| e == crate::prompt::CANCELLED;
        match action {
            Action::Back if count == 0 => return Err(crate::prompt::CANCELLED.into()),
            Action::Back => {
                ask.clear();
                match ask.confirm(&format!("Discard your changes to {id}?"), false) {
                    Ok(true) => return Err(crate::prompt::CANCELLED.into()),
                    Err(e) if !kept(&e) => return Err(e),
                    _ => continue,
                }
            }
            Action::Open if at == 0 => match ask.input_or_back("Name", &name, false) {
                Ok(Some(n)) => name = n.trim().to_string(),
                Ok(None) => {}
                Err(e) if kept(&e) => {}
                Err(e) => return Err(e),
            },
            Action::Open if at <= products.len() => {
                let p = &products[at - 1];
                let options = ACCESS_CHOICES.map(String::from);
                let now = match reach[p].as_deref() {
                    Some("read_data") => 0,
                    Some(_) => 1,
                    None => 2,
                };
                match ask.select_or_back(&format!("Access to {p}"), &options, now) {
                    Ok(Some(i)) => {
                        let role = [Some(Role::Read), Some(Role::Write), None][i];
                        reach.insert(p.clone(), role.map(|r| r.api().to_string()));
                    }
                    Ok(None) => {}
                    Err(e) if kept(&e) => {}
                    Err(e) => return Err(e),
                }
            }
            Action::Open if at == products.len() + 1 => {
                if owned.is_none() {
                    let listed = all(ctx.client, ctx.client.url(&["products", &owner]))
                        .await
                        .unwrap_or_default();
                    owned = Some(
                        listed
                            .iter()
                            .map(|p| format!("{owner}/{}", str_field(p, "product_id")))
                            .collect(),
                    );
                }
                let options: Vec<String> = owned
                    .iter()
                    .flatten()
                    .filter(|p| !reach.contains_key(*p))
                    .cloned()
                    .collect();
                if options.is_empty() {
                    place.notice = Some(format!("It already lists every product of {owner}."));
                    continue;
                }
                let Ok(Some(i)) = ask.select_or_back("Grant which product?", &options, 0) else {
                    continue;
                };
                let roles = ACCESS_CHOICES[..2]
                    .iter()
                    .map(|r| r.to_string())
                    .collect::<Vec<_>>();
                if let Ok(Some(r)) = ask.select_or_back("Access", &roles, 0) {
                    let role = [Role::Read, Role::Write][r];
                    reach.insert(options[i].clone(), Some(role.api().into()));
                }
            }
            _ if count == 0 => return Ok(()),
            _ => {
                let mut review = vec![];
                if name != was_name {
                    review.push(format!("{:<width$}  {was_name}  →  {name}", "Name"));
                }
                for p in &changed {
                    let before = reach_label(was.get(p).map(String::as_str));
                    let now = reach_label(reach[p].as_deref());
                    review.push(format!("{p:<width$}  {before}  →  {now}"));
                }
                ask.clear();
                match ask.confirm_or_back(&format!("Save these changes to {id}?"), &review)? {
                    None => continue,
                    Some(false) => return Err(crate::prompt::CANCELLED.into()),
                    Some(true) => {
                        if name != was_name {
                            body.insert("name".into(), json!(name));
                        }
                        if !changed.is_empty() {
                            let access: Map<String, Value> = changed
                                .iter()
                                .map(|p| {
                                    (p.clone(), reach[p].clone().map_or(Value::Null, Value::from))
                                })
                                .collect();
                            body.insert("access".into(), Value::Object(access));
                        }
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// What disabling and enabling do, as the web UI's confirmation says it.
const DISABLE_SAYS: &str = "Nothing can sign in as it, by workflow or by API key, and within five \
    minutes credentials already generated are cut back to public data. Its workflows, keys and \
    product access are kept.";
const ENABLE_SAYS: &str =
    "Its trusted workflows and unrevoked API keys can sign in again, so revoke any key that leaked first.";

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

/// A sign-in to add: a workflow by its subject, or a key by its label and
/// expiry.
enum Adding {
    Github(String),
    Key(String, Value),
}

/// A key's default expiry, the web UI's: 90 days from now.
fn default_expiry() -> Value {
    parse_expiry("90d").expect("90d is valid")
}

/// Ask what a new key is for and when it should expire. None is back.
fn ask_key(ask: &mut dyn Prompter) -> Result<Option<(String, Value)>, String> {
    let mut label = String::new();
    loop {
        match ask.input_or_back(
            "Label (where the key will live, e.g. HPC cron job)",
            &label,
            false,
        )? {
            None => return Ok(None),
            Some(l) => label = l.trim().to_string(),
        }
        if let Some(expires) = ask_expiry(ask, "Expires")? {
            return Ok(Some((label, expires)));
        }
    }
}

/// Ask which kind of sign-in to add, then for it, then to confirm, as the web
/// UI's "Add sign-in" menu does.
async fn ask_sign_in(ask: &mut dyn Prompter, ctx: &Ctx<'_>) -> Result<Adding, String> {
    let kinds = ["GitHub workflow".to_string(), "API key".to_string()];
    let mut kind = 0;
    loop {
        kind = ask.select("Sign in with", &kinds, kind)?;
        let adding = if kind == 0 {
            match ask_github(ask, ctx.github_api).await? {
                Some(s) => Adding::Github(s),
                None => continue,
            }
        } else {
            match ask_key(ask)? {
                Some((label, expires)) => Adding::Key(label, expires),
                None => continue,
            }
        };
        let (question, details) = match &adding {
            Adding::Github(s) => {
                let mut details = vec![
                    sign_in_label(GITHUB_ISSUER, s),
                    "Trusts tokens matching".into(),
                ];
                details.extend(condition(s, ctx.proxy));
                ("Trust this workflow?", details)
            }
            Adding::Key(label, expires) => (
                "Issue this key?",
                vec![format!("API key · {label}"), expiry_label(expires)],
            ),
        };
        match ask.confirm_or_back(question, &details)? {
            None => continue,
            Some(true) => return Ok(adding),
            Some(false) => return Err(crate::prompt::CANCELLED.into()),
        }
    }
}

async fn sign_in_add(
    args: SignInAddArgs,
    ctx: &Ctx<'_>,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    split_id(&args.account)?;
    let workflow = args.github.github.is_some() || args.github.subject.is_some();
    if args.key.key.is_some() && workflow {
        return Err(
            "Add one sign-in at a time: a workflow (--github or --subject) or a key (--key)."
                .into(),
        );
    }
    let adding = if let Some(label) = &args.key.key {
        let expires = args.key.expires.clone().unwrap_or_else(default_expiry);
        Adding::Key(label.clone(), expires)
    } else if let Some(s) = github_subject(&args.github, ctx.github_api).await? {
        Adding::Github(s)
    } else {
        let ask = prompter.as_deref_mut().ok_or(
            "Name the sign-in: --github OWNER/REPO with --branch, --tag or --environment, \
             --subject, or --key LABEL.",
        )?;
        ctx.client.check_signed_in().await?;
        ask_sign_in(ask, ctx).await?
    };
    let id = &args.account;
    match adding {
        Adding::Github(subject) => {
            let url = ctx.client.url(&["accounts", id, "trusts"]);
            let trust: Value = ctx
                .client
                .request(Method::POST, url, Some(&json!({"subject": subject})))
                .await?;
            if args.json {
                crate::output::json(&trust);
            } else {
                let label = sign_in_label(GITHUB_ISSUER, &subject);
                eprintln!("{label} can now sign in as {id}");
                eprintln!(
                    "To sign in from it: source-coop service-account usage {id} --subject {subject}"
                );
            }
        }
        Adding::Key(label, expires_at) => {
            let url = ctx.client.url(&["accounts", id, "keys"]);
            let body = json!({"label": label, "expires_at": expires_at});
            let issued: Value = ctx.client.request(Method::POST, url, Some(&body)).await?;
            let key = str_field(&issued, "key").to_string();
            if args.json {
                crate::output::json(&key_record(issued, &key, args.key.out.as_deref()));
            } else {
                eprintln!("Issued {} for {id}", key_label(&issued));
                deliver_key(&key, args.key.out.as_deref(), prompter, true)?;
                eprintln!("To sign in with it: source-coop service-account usage {id} --key");
            }
        }
    }
    Ok(())
}

/// A key just issued, for `--json`: as the API returned it, key and all, or,
/// with `out`, the key written there instead and named as `key_file`, unless
/// writing it fails.
fn key_record(mut issued: Value, key: &str, out: Option<&str>) -> Value {
    if let (Some(out), Some(record)) = (out, issued.as_object_mut()) {
        // The key exists nowhere else: if it can't be saved, the record keeps it.
        match crate::cache::write_file(std::path::Path::new(out), &format!("{key}\n")) {
            Ok(written) => {
                record.remove("key");
                record.insert("key_file".into(), json!(written));
            }
            Err(e) => {
                eprintln!("Couldn't save the API key to {out} ({e}); it's in the JSON instead.")
            }
        }
    }
    issued
}

/// The service account's key named as `key:HINT` or `key:KEY_ID` (the
/// `key:` optional), preferring one that still works when hints repeat.
async fn find_key(client: &Client, id: &str, named: &str) -> Result<Value, String> {
    let named = named.strip_prefix("key:").unwrap_or(named);
    let now = chrono::Utc::now();
    let mut matching: Vec<Value> = keys(client, id)
        .await?
        .into_iter()
        .filter(|k| str_field(k, "key_id") == named || str_field(k, "hint") == named)
        .collect();
    matching.sort_by_key(|k| !key_live(k, now));
    matching
        .into_iter()
        .next()
        .ok_or_else(|| not_found(format!("{id} has no API key key:{named}")))
}

/// Pick one of the service account's working keys. None when it has none.
async fn choose_key(
    client: &Client,
    id: &str,
    ask: &mut dyn Prompter,
    question: &str,
) -> Result<Option<Value>, String> {
    let now = chrono::Utc::now();
    let live: Vec<Value> = keys(client, id)
        .await?
        .into_iter()
        .filter(|k| key_live(k, now))
        .collect();
    if live.is_empty() {
        eprintln!("{id} has no API keys that still work.");
        return Ok(None);
    }
    let labels: Vec<String> = live
        .iter()
        .map(|k| format!("{}  ({})", key_label(k), key_status(k, now)))
        .collect();
    let i = ask.select(question, &labels, 0)?;
    Ok(live.into_iter().nth(i))
}

async fn sign_in_edit(
    args: SignInEditArgs,
    ctx: &Ctx<'_>,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    let id = &args.account;
    split_id(id)?;
    let key = match &args.key {
        Some(named) => find_key(ctx.client, id, named).await?,
        None => {
            let ask = prompter.as_deref_mut().ok_or(NEEDS_TERMINAL)?;
            ctx.client.check_signed_in().await?;
            match choose_key(ctx.client, id, ask, "Change which key's expiry?").await? {
                Some(k) => k,
                None => return Ok(()),
            }
        }
    };
    let expires_at = match (args.expires, prompter) {
        (Some(e), _) => e,
        (None, Some(ask)) => {
            ctx.client.check_signed_in().await?;
            let question = format!("When should {} expire?", key_label(&key));
            ask_expiry(ask, &question)?.ok_or(crate::prompt::CANCELLED)?
        }
        (None, None) => {
            return Err(
                "Say when it should expire: --expires 30d, 90d, 1y, never or a date.".into(),
            )
        }
    };
    let url = ctx
        .client
        .url(&["accounts", id, "keys", str_field(&key, "key_id")]);
    let changed: Value = ctx
        .client
        .request(Method::PATCH, url, Some(&json!({"expires_at": expires_at})))
        .await?;
    if args.json {
        crate::output::json(&changed);
    } else {
        eprintln!("{} now {}", key_label(&changed), expiry_label(&expires_at));
    }
    Ok(())
}

/// A sign-in to remove: a trust, by issuer and subject, or a key's record.
enum Removing {
    Trust(String, String),
    Key(Value),
}

async fn sign_in_remove(
    args: SignInRemoveArgs,
    ctx: &Ctx<'_>,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    let id = &args.account;
    split_id(id)?;
    let removing = match &args.subject {
        Some(k) if k.starts_with("key:") => Removing::Key(find_key(ctx.client, id, k).await?),
        Some(s) => Removing::Trust(GITHUB_ISSUER.to_string(), s.clone()),
        None => {
            let ask = prompter.as_deref_mut().ok_or(NEEDS_TERMINAL)?;
            let now = chrono::Utc::now();
            let (t, k) = tokio::join!(trusts(ctx.client, id), keys(ctx.client, id));
            let mut options: Vec<(String, Removing)> = t?
                .iter()
                .map(|t| {
                    let (issuer, subject) = (str_field(t, "issuer"), str_field(t, "subject"));
                    (
                        format!("{}  ({subject})", sign_in_label(issuer, subject)),
                        Removing::Trust(issuer.to_string(), subject.to_string()),
                    )
                })
                .collect();
            options.extend(k?.into_iter().filter(|k| key_live(k, now)).map(|k| {
                (
                    format!("{}  ({})", key_label(&k), key_status(&k, now)),
                    Removing::Key(k),
                )
            }));
            if options.is_empty() {
                eprintln!("{id} has no sign-ins to remove.");
                return Ok(());
            }
            let labels: Vec<String> = options.iter().map(|(l, _)| l.clone()).collect();
            let i = ask.select("Remove which sign-in?", &labels, 0)?;
            options.swap_remove(i).1
        }
    };
    let named = match &removing {
        Removing::Trust(_, subject) => subject.clone(),
        Removing::Key(k) => format!("key:{}", str_field(k, "hint")),
    };
    if !args.yes {
        let Some(ask) = prompter else {
            return Err(format!(
                "Refusing to remove {named} without confirmation: pass --yes."
            ));
        };
        ctx.client.check_signed_in().await?;
        match &removing {
            Removing::Trust(issuer, subject) => {
                let label = format!(
                    "Stop {} signing in as {id}?",
                    sign_in_label(issuer, subject)
                );
                if !ask.confirm(&label, false)? {
                    return Err(crate::prompt::CANCELLED.into());
                }
            }
            // A revoked key can't be restored, so it's confirmed by name.
            Removing::Key(k) => {
                eprintln!(
                    "Revoking {} can't be undone: within a minute, nothing can sign in with it.",
                    key_label(k)
                );
                crate::prompt::confirm_by_name(ask, &named, "revoked")?;
            }
        }
    }
    let (removed, said) = match &removing {
        Removing::Trust(issuer, subject) => {
            let mut url = ctx.client.url(&["accounts", id, "trusts"]);
            url.query_pairs_mut()
                .append_pair("issuer", issuer)
                .append_pair("subject", subject);
            let removed: Value = ctx.client.request(Method::DELETE, url, None::<&()>).await?;
            let said = format!(
                "{} can no longer sign in as {id}",
                sign_in_label(issuer, subject)
            );
            (removed, said)
        }
        Removing::Key(k) => {
            let url = ctx
                .client
                .url(&["accounts", id, "keys", str_field(k, "key_id")]);
            let revoked: Value = ctx
                .client
                .request(Method::PATCH, url, Some(&json!({"revoked": true})))
                .await?;
            let said = format!("Revoked {}", key_label(&revoked));
            (revoked, said)
        }
    };
    if args.json {
        crate::output::json(&removed);
    } else {
        eprintln!("{said}");
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
    use wiremock::matchers::{body_json, body_partial_json, method, path, query_param};
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
            key: KeyArgs::default(),
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
            key: KeyArgs::default(),
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
        // The key's expiry is counted from when it's asked, so only its label is matched.
        let expected = json!({"name": "Nightly sync", "local_id": "nightly-sync",
            "github_subjects": ["repo:org@1/data@2:environment:prod"],
            "key": {"label": "HPC cron job"},
            "grants": [{"product_id": "data", "role": "write_data"}]});
        let mut created = account("org--nightly-sync");
        created["key"] = json!({"key_id": "k1", "label": "HPC cron job", "hint": "a1B2c3",
                                "key": "sck_secret", "expires_at": null});
        Mock::given(method("POST"))
            .and(path("/api/v1/accounts/org/service-accounts"))
            .and(body_partial_json(&expected))
            .respond_with(ResponseTemplate::new(201).set_body_json(created))
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
            Pick(1),              // Add an API key
            Text("HPC cron job"), // Label
            Default,              // Expires in 90 days
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
            key: KeyArgs::default(),
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
                "Signs in with: add a sign-in? [Continue] of GitHub workflow… | API key… | Continue",
                "Repository (OWNER/REPO) []",
                "Allow runs from [Branch] of Branch | Tag | Environment",
                "Environment []",
                "Signs in with: 1 added; another? [Continue] of GitHub workflow… | API key… | Continue",
                "Label (where the key will live, e.g. HPC cron job) []",
                "Expires [90 days] of 30 days | 90 days | A year | Never — until revoked",
                "Signs in with: 2 added; another? [Continue] of GitHub workflow… | Continue",
                "Can reach: grant a product? [Continue] of org/data | org/other | Continue",
                "Access [Read] of Read | Read and write",
                "Can reach: 1 granted; another? [Continue] of org/other | Continue",
                "Create this service account? {Service account  org--nightly-sync | Name             Nightly sync | Signs in with    GitHub Actions · org@1/data@2 · environment prod |                    { |                      \"StringEquals\": { |                        \"token.actions.githubusercontent.com:aud\": \"https://data.source.coop\", |                        \"token.actions.githubusercontent.com:sub\": \"repo:org@1/data@2:environment:prod\" |                      } |                    } |                  API key · HPC cron job · expires in 2 months | Can reach        org/data  Read and write} [true]",
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
        let ago = |days| (chrono::Utc::now() - chrono::Duration::days(days)).to_rfc3339();
        let live = json!({"key_id": "k1", "label": "HPC cron job", "hint": "a1B2c3",
                          "last_used_at": ago(3), "expires_at": null});
        let revoked = json!({"key_id": "k0", "label": "Old laptop", "hint": "zZ9yY8",
                             "expires_at": null, "revoked_at": ago(40), "revoked_via": "github"});
        Mock::given(method("GET"))
            .and(path("/api/v1/accounts/org--nightly-sync/keys"))
            .respond_with(page(json!([revoked, live])))
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();

        let whole = fetch_whole(&client, "org--nightly-sync").await.unwrap();
        assert_eq!(whole["trusts"], json!([trust]));
        assert_eq!(whole["keys"], json!([revoked, live]));
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
                "  API key · HPC cron job · key:a1B2c3",
                "    used 3 days ago · never expires",
                "  API key · Old laptop · key:zZ9yY8",
                "    never used · revoked 1 month ago by GitHub, which found it in public",
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

    fn edit_args(access: &[&str]) -> EditArgs {
        EditArgs {
            account: Some("org--sa".into()),
            interactive: false,
            name: None,
            disable: false,
            enable: false,
            access: access.iter().map(|a| a.to_string()).collect(),
            from_file: None,
            json: false,
        }
    }

    #[tokio::test]
    async fn edit_access_grants_changes_and_takes_away_once_each() {
        let server = api_server().await;
        let github = github_server().await;
        let reads = json!({"membership_id": "m1", "account_id": "org--sa",
                           "membership_account_id": "org", "product_id": "data",
                           "role": "read_data", "state": "member"});
        let old = json!({"membership_id": "m2", "account_id": "org--sa",
                         "membership_account_id": "org", "product_id": "old",
                         "role": "write_data", "state": "member"});
        Mock::given(method("GET"))
            .and(path("/api/v1/memberships"))
            .respond_with(page(json!([reads, old])))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/memberships/m1"))
            .and(body_json(json!({"role": "write_data"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(&reads))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/memberships/m2"))
            .and(body_json(json!({"state": "revoked"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(&old))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/memberships"))
            .and(body_json(
                json!({"membership_account_id": "org", "product_id": "new",
                                  "account_id": "org--sa", "role": "read_data"}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(&reads))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let ctx = ctx(&client, &github);
        let args = edit_args(&["org/data=write", "org/old=none", "org/new=read"]);
        edit(args, &ctx, None).await.unwrap();
        // Already so, both ways: nothing sent (each mock above expects one call).
        edit(edit_args(&["org/old=write", "org/gone=none"]), &ctx, None)
            .await
            .unwrap();

        let err = edit(edit_args(&["org/data=admin"]), &ctx, None)
            .await
            .unwrap_err();
        assert!(err.contains("=read, =write or =none"), "{err}");
    }

    #[tokio::test]
    async fn the_edit_form_changes_the_name_and_access_after_a_review() {
        let server = api_server().await;
        let github = github_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/accounts/org/service-accounts"))
            .respond_with(page(json!([account("org--sa")])))
            .mount(&server)
            .await;
        for empty in ["trusts", "keys"] {
            Mock::given(method("GET"))
                .and(path(format!("/api/v1/accounts/org--sa/{empty}")))
                .respond_with(page(json!([])))
                .mount(&server)
                .await;
        }
        let reads = json!({"membership_id": "m1", "account_id": "org--sa",
                           "membership_account_id": "org", "product_id": "data",
                           "role": "read_data", "state": "member"});
        Mock::given(method("GET"))
            .and(path("/api/v1/memberships"))
            .respond_with(page(json!([reads])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/org"))
            .respond_with(page(
                json!([{"product_id": "data"}, {"product_id": "other"}]),
            ))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/accounts/org--sa"))
            .and(body_json(json!({"name": "Renamed"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(account("org--sa")))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/memberships/m1"))
            .and(body_json(json!({"state": "revoked"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(&reads))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/memberships"))
            .and(body_json(
                json!({"membership_account_id": "org", "product_id": "other",
                                  "account_id": "org--sa", "role": "write_data"}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(&reads))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([
            Browse(0, Action::Open), // Name
            Text("Renamed"),
            Browse(1, Action::Open), // org/data
            Pick(2),                 // No access
            Browse(2, Action::Open), // Grant a product…
            Pick(0),                 // org/other
            Pick(1),                 // Read and write
            Browse(0, Action::Key('s')),
            Yes(true),
        ]);
        edit(edit_args(&[]), &ctx(&client, &github), Some(&mut ask))
            .await
            .unwrap();
        assert_eq!(
            ask.asked,
            [
                "Edit org--sa [Name           Nightly sync] of Name           Nightly sync | org/data       Read | Grant a product… | Save changes (nothing changed yet) (keys s)",
                "Name [Nightly sync]",
                "Edit org--sa [Name         ● Renamed   (was: Nightly sync)] of Name         ● Renamed   (was: Nightly sync) | org/data       Read | Grant a product… | Save changes (1 change) (keys s)",
                "Access to org/data [Read] of Read | Read and write | No access",
                "Edit org--sa [org/data     ● No access   (was: Read)] of Name         ● Renamed   (was: Nightly sync) | org/data     ● No access   (was: Read) | Grant a product… | Save changes (2 changes) (keys s)",
                "Grant which product? [org/other] of org/other",
                "Access [Read] of Read | Read and write",
                "Edit org--sa [org/other    ● Read and write   (was: No access)] of Name         ● Renamed   (was: Nightly sync) | org/data     ● No access   (was: Read) | org/other    ● Read and write   (was: No access) | Grant a product… | Save changes (3 changes) (keys s)",
                "Save these changes to org--sa? {Name          Nightly sync  →  Renamed | org/data      Read  →  No access | org/other     No access  →  Read and write} [true]",
            ]
        );
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

    #[test]
    fn expiries_are_counted_from_now_or_given_as_dates() {
        assert_eq!(parse_expiry("never").unwrap(), Value::Null);
        assert_eq!(
            parse_expiry("2027-01-31").unwrap(),
            json!("2027-01-31T00:00:00Z")
        );
        assert_eq!(
            parse_expiry("2027-01-31T12:00:00Z").unwrap(),
            json!("2027-01-31T12:00:00Z")
        );
        let in_a_year = parse_expiry("1y").unwrap();
        let at = chrono::DateTime::parse_from_rfc3339(in_a_year.as_str().unwrap()).unwrap();
        let days = (at.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_days();
        assert!((364..=365).contains(&days), "{days}");
        assert!(parse_expiry("soon").is_err());
        // Too far away for a date: an error, not a panic.
        assert!(parse_expiry("99999999999d").is_err());
        assert!(parse_expiry("99999999999999999y").is_err());
    }

    #[test]
    fn a_key_that_cant_be_saved_is_kept_rather_than_lost() {
        // A directory can't be written as a file.
        let dir = std::env::temp_dir().join(format!("sa-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let at = dir.display().to_string();
        let issued = json!({"key_id": "k1", "hint": "a1B2c3", "key": "sck_secret"});
        let record = key_record(issued, "sck_secret", Some(&at));
        assert_eq!(record["key"], json!("sck_secret"));
        assert!(record.get("key_file").is_none(), "{record}");
        // Not saved anywhere, so it was shown.
        assert_eq!(
            deliver_key("sck_secret", Some(&at), None, false).unwrap(),
            None
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The key's record for the next three tests.
    fn key(revoked: bool) -> Value {
        let mut k = json!({"key_id": "k1", "account_id": "org--sa", "label": "HPC cron job",
                           "hint": "a1B2c3", "expires_at": null});
        if revoked {
            k["revoked_at"] = json!(chrono::Utc::now().to_rfc3339());
        }
        k
    }

    #[tokio::test]
    async fn sign_in_add_issues_a_key_and_writes_it_only_where_asked() {
        let server = api_server().await;
        let github = github_server().await;
        let mut issued = key(false);
        issued["key"] = json!("sck_secret");
        Mock::given(method("POST"))
            .and(path("/api/v1/accounts/org--sa/keys"))
            .and(body_json(
                json!({"label": "HPC cron job", "expires_at": null}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(&issued))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let dir = std::env::temp_dir().join(format!("sa-key-{}", std::process::id()));
        let out = dir.join("sa.key");
        let args = SignInAddArgs {
            account: "org--sa".into(),
            github: GithubArgs::default(),
            key: KeyArgs {
                key: Some("HPC cron job".into()),
                expires: Some(Value::Null),
                out: Some(out.display().to_string()),
            },
            json: true,
        };
        sign_in_add(args, &ctx(&client, &github), None)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "sck_secret\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&out).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let record = key_record(issued, "sck_secret", Some(&out.display().to_string()));
        assert!(record.get("key").is_none(), "{record}");
        assert_eq!(record["key_file"], json!(out.display().to_string()));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn sign_in_add_takes_one_sign_in_at_a_time() {
        let server = api_server().await;
        let github = github_server().await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let args = SignInAddArgs {
            account: "org--sa".into(),
            github: GithubArgs {
                subject: Some("repo:org/data:ref:refs/heads/main".into()),
                ..GithubArgs::default()
            },
            key: KeyArgs {
                key: Some("x".into()),
                ..KeyArgs::default()
            },
            json: false,
        };
        let err = sign_in_add(args, &ctx(&client, &github), None)
            .await
            .unwrap_err();
        assert!(err.contains("one sign-in at a time"), "{err}");
    }

    #[tokio::test]
    async fn keys_are_found_by_hint_given_new_expiries_and_revoked() {
        let server = api_server().await;
        let github = github_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/accounts/org--sa/keys"))
            .respond_with(page(json!([key(false)])))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/accounts/org--sa/keys/k1"))
            .and(body_json(json!({"expires_at": "2027-01-31T00:00:00Z"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(key(false)))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/accounts/org--sa/keys/k1"))
            .and(body_json(json!({"revoked": true})))
            .respond_with(ResponseTemplate::new(200).set_body_json(key(true)))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let ctx = ctx(&client, &github);
        let edit = SignInEditArgs {
            account: "org--sa".into(),
            key: Some("key:a1B2c3".into()),
            interactive: false,
            expires: Some(json!("2027-01-31T00:00:00Z")),
            json: true,
        };
        sign_in_edit(edit, &ctx, None).await.unwrap();

        let remove = |yes| SignInRemoveArgs {
            account: "org--sa".into(),
            subject: Some("key:a1B2c3".into()),
            interactive: false,
            yes,
            json: true,
        };
        let err = sign_in_remove(remove(false), &ctx, None).await.unwrap_err();
        assert!(
            err.contains("key:a1B2c3") && err.contains("pass --yes"),
            "{err}"
        );
        sign_in_remove(remove(true), &ctx, None).await.unwrap();

        let missing = SignInRemoveArgs {
            subject: Some("key:nope00".into()),
            ..remove(true)
        };
        let err = sign_in_remove(missing, &ctx, None).await.unwrap_err();
        assert_eq!(crate::failure::classify(&err).exit_code(), 5, "{err}");
    }

    #[tokio::test]
    async fn revoking_a_key_from_a_prompt_takes_its_name_typed_back() {
        let server = api_server().await;
        let github = github_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/accounts/org--sa/keys"))
            .respond_with(page(json!([key(false)])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/accounts/org--sa/trusts"))
            .respond_with(page(json!([])))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/accounts/org--sa/keys/k1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(key(true)))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([Pick(0), Text("key:a1B2c3")]);
        let args = SignInRemoveArgs {
            account: "org--sa".into(),
            subject: None,
            interactive: true,
            yes: false,
            json: false,
        };
        sign_in_remove(args, &ctx(&client, &github), Some(&mut ask))
            .await
            .unwrap();
        assert_eq!(
            ask.asked,
            [
                "Remove which sign-in? [API key · HPC cron job · key:a1B2c3  (never used · never expires)] of API key · HPC cron job · key:a1B2c3  (never used · never expires)",
                "Type key:a1B2c3 to confirm (Esc to cancel) []",
            ]
        );
    }
}
