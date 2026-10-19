//! `source-coop member` and `source-coop invitation`: who belongs to an
//! organization or a product, through `/api/v1/accounts/{account}/members`,
//! `/api/v1/products/{account}/{product}/members` and `/api/v1/memberships`.
//!
//! Members are named by where they belong (`ACCOUNT` or `ACCOUNT/PRODUCT`)
//! and their account ID, never by membership ID: the CLI finds the membership
//! by listing, as the API has no GET for a single one.

use crate::api::{ApiError, Client};
use crate::draft::Draft;
use crate::product::{read_fields, str_field, Pager, NEEDS_TERMINAL};
use crate::prompt::{Action, Place, Prompter};
use clap::{Args, Subcommand};
use clap_complete::engine::ArgValueCompleter;
use reqwest::{Method, StatusCode};
use serde_json::{json, Map, Value};
use std::io::IsTerminal;

#[derive(Subcommand)]
pub enum MemberCommand {
    /// List an organization's or a product's members and pending invitations
    #[command(
        after_help = crate::style::examples(&[
            "source-coop member list my-org --json",
            "source-coop member list my-org/my-data --state invited",
        ])
    )]
    List(ListArgs),
    /// Show one member
    #[command(after_help = crate::style::examples(&["source-coop member view my-org alice --json"]))]
    View(ViewArgs),
    /// Invite accounts to an organization or a product
    #[command(
        alias = "create",
        after_help = crate::style::examples(&[
            "source-coop member invite my-org alice bob --role maintainers --json",
            "source-coop member invite my-org/my-data --accounts-file people.txt --role read_data --json",
            "echo '{\"account_id\": \"alice\", \"role\": \"read_data\"}' | source-coop member invite my-org -F - --json",
        ])
    )]
    Invite(InviteArgs),
    /// Change a member's role
    #[command(after_help = crate::style::examples(&["source-coop member edit my-org alice --role owners --json"]))]
    Edit(EditArgs),
    /// Remove a member, or withdraw an invitation
    #[command(
        alias = "delete",
        after_help = crate::style::examples(&["source-coop member revoke my-org alice --yes --json"])
    )]
    Revoke(RevokeArgs),
    /// Give up your own membership of an organization or a product
    #[command(after_help = crate::style::examples(&["source-coop member leave my-org --yes --json"]))]
    Leave(LeaveArgs),
}

impl MemberCommand {
    /// Whether `--json` was asked for, so a failure is reported as JSON too.
    pub fn wants_json(&self) -> bool {
        match self {
            MemberCommand::List(a) => a.json,
            MemberCommand::View(a) => a.json,
            MemberCommand::Invite(a) => a.json,
            MemberCommand::Edit(a) => a.json,
            MemberCommand::Revoke(a) => a.json,
            MemberCommand::Leave(a) => a.json,
        }
    }
}

#[derive(Subcommand)]
pub enum InvitationCommand {
    /// List the invitations waiting for your answer
    #[command(after_help = crate::style::examples(&["source-coop invitation list --json"]))]
    List(InvitationListArgs),
    /// Accept an invitation, becoming a member
    #[command(after_help = crate::style::examples(&["source-coop invitation accept my-org/my-data --json"]))]
    Accept(AnswerArgs),
    /// Turn down an invitation
    #[command(after_help = crate::style::examples(&["source-coop invitation reject my-org --json"]))]
    Reject(AnswerArgs),
}

impl InvitationCommand {
    pub fn wants_json(&self) -> bool {
        match self {
            InvitationCommand::List(a) => a.json,
            InvitationCommand::Accept(a) | InvitationCommand::Reject(a) => a.json,
        }
    }
}

#[derive(Args)]
pub struct ListArgs {
    /// The organization, as ACCOUNT, or the product, as ACCOUNT/PRODUCT
    #[arg(add = ArgValueCompleter::new(crate::complete::scope))]
    scope: Scope,

    /// Only members in this state
    #[arg(long, value_parser = ["member", "invited"])]
    state: Option<String>,

    /// Print the members as JSON
    #[arg(long)]
    json: bool,

    /// Pick a member from the list, then view, edit or revoke it
    #[arg(long, short = 'i', conflicts_with = "json")]
    interactive: bool,

    /// Print straight to the terminal instead of through $SOURCE_PAGER,
    /// $PAGER or `less -FRX`
    #[arg(long)]
    no_pager: bool,
}

#[derive(Args)]
pub struct ViewArgs {
    /// The organization, as ACCOUNT, or the product, as ACCOUNT/PRODUCT
    #[arg(add = ArgValueCompleter::new(crate::complete::scope))]
    scope: Scope,

    /// The member's account ID (with -i, picked from the members when omitted)
    #[arg(
        required_unless_present = "interactive",
        add = ArgValueCompleter::new(crate::complete::member)
    )]
    member: Option<String>,

    /// Show the member with shortcuts: b browser, e edit, d revoke, ← back
    #[arg(long, short = 'i', conflicts_with = "json")]
    interactive: bool,

    /// Print the membership as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct InviteArgs {
    /// The organization, as ACCOUNT, or the product, as ACCOUNT/PRODUCT
    #[arg(add = ArgValueCompleter::new(crate::complete::scope))]
    scope: Scope,

    /// The account IDs to invite (prompted for when none are given)
    #[arg(add = ArgValueCompleter::new(crate::complete::invitee))]
    accounts: Vec<String>,

    /// Also invite the account IDs in this file, one per line (`-` for
    /// stdin); blank lines and lines starting with # are skipped
    #[arg(long, short = 'A', value_name = "PATH")]
    accounts_file: Option<String>,

    /// owners, maintainers, write_data or read_data
    #[arg(long, short = 'r')]
    role: Option<String>,

    /// Read `account_id` and `role` from a JSON object in this file (`-` for
    /// stdin); flags win
    #[arg(long, short = 'F', value_name = "PATH")]
    from_file: Option<String>,

    /// Print the new memberships as a JSON array
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct EditArgs {
    /// The organization, as ACCOUNT, or the product, as ACCOUNT/PRODUCT
    #[arg(add = ArgValueCompleter::new(crate::complete::scope))]
    scope: Scope,

    /// The member's account ID (with -i, picked from the members when omitted)
    #[arg(
        required_unless_present = "interactive",
        add = ArgValueCompleter::new(crate::complete::member)
    )]
    member: Option<String>,

    /// Pick the member when it isn't named
    #[arg(long, short = 'i')]
    interactive: bool,

    /// The new role: owners, maintainers, write_data or read_data
    #[arg(long, short = 'r')]
    role: Option<String>,

    /// Read `role` from a JSON object in this file (`-` for stdin); flags win
    #[arg(long, short = 'F', value_name = "PATH")]
    from_file: Option<String>,

    /// Print the changed membership as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct RevokeArgs {
    /// The organization, as ACCOUNT, or the product, as ACCOUNT/PRODUCT
    #[arg(add = ArgValueCompleter::new(crate::complete::scope))]
    scope: Scope,

    /// The member's account ID (with -i, picked from the members when omitted)
    #[arg(
        required_unless_present = "interactive",
        add = ArgValueCompleter::new(crate::complete::member)
    )]
    member: Option<String>,

    /// Pick the member when it isn't named
    #[arg(long, short = 'i', conflicts_with = "yes")]
    interactive: bool,

    /// Skip the confirmation prompt
    #[arg(long, short = 'y')]
    yes: bool,

    /// Print the revoked membership as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct LeaveArgs {
    /// The organization, as ACCOUNT, or the product, as ACCOUNT/PRODUCT (with
    /// -i, picked from your memberships when omitted)
    #[arg(
        required_unless_present = "interactive",
        add = ArgValueCompleter::new(crate::complete::membership)
    )]
    scope: Option<Scope>,

    /// Pick the membership when it isn't named
    #[arg(long, short = 'i', conflicts_with = "yes")]
    interactive: bool,

    /// Skip the confirmation prompt
    #[arg(long, short = 'y')]
    yes: bool,

    /// Print the revoked membership as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct InvitationListArgs {
    /// Print the invitations as JSON
    #[arg(long)]
    json: bool,

    /// Pick an invitation from the list, then accept or reject it
    #[arg(long, short = 'i', conflicts_with = "json")]
    interactive: bool,
}

#[derive(Args)]
pub struct AnswerArgs {
    /// Where you're invited: ACCOUNT, or ACCOUNT/PRODUCT (with -i, picked
    /// from your invitations when omitted)
    #[arg(
        required_unless_present = "interactive",
        add = ArgValueCompleter::new(crate::complete::invitation)
    )]
    scope: Option<Scope>,

    /// Pick the invitation when it isn't named
    #[arg(long, short = 'i')]
    interactive: bool,

    /// Print the membership as JSON
    #[arg(long)]
    json: bool,
}

/// Where a membership belongs: an organization (`ACCOUNT`) or one of its
/// products (`ACCOUNT/PRODUCT`).
#[derive(Clone, Debug, PartialEq)]
pub struct Scope {
    pub account_id: String,
    pub product_id: Option<String>,
}

impl std::str::FromStr for Scope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.trim_matches('/').split('/').collect();
        match parts.as_slice() {
            [a] if !a.is_empty() => Ok(Scope {
                account_id: a.to_string(),
                product_id: None,
            }),
            [a, p] if !a.is_empty() && !p.is_empty() => Ok(Scope {
                account_id: a.to_string(),
                product_id: Some(p.to_string()),
            }),
            _ => Err(format!("expected ACCOUNT or ACCOUNT/PRODUCT, got '{s}'")),
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.product_id {
            Some(p) => write!(f, "{}/{p}", self.account_id),
            None => write!(f, "{}", self.account_id),
        }
    }
}

impl Scope {
    /// Where a membership `m` belongs.
    pub(crate) fn of(m: &Value) -> Scope {
        Scope {
            account_id: str_field(m, "membership_account_id").to_string(),
            product_id: product_of(m).map(String::from),
        }
    }

    fn members_url(&self, client: &Client) -> url::Url {
        match &self.product_id {
            Some(p) => client.url(&["products", &self.account_id, p, "members"]),
            None => client.url(&["accounts", &self.account_id, "members"]),
        }
    }

    fn web_url(&self, site: &str) -> String {
        format!("{}/{self}", site.trim_end_matches('/'))
    }
}

/// A product-scoped membership's product: `repository_id`, or `product_id`
/// on servers that have renamed it.
fn product_of(m: &Value) -> Option<&str> {
    ["product_id", "repository_id"]
        .iter()
        .find_map(|k| m.get(*k).and_then(Value::as_str))
        .filter(|p| !p.is_empty())
}

/// The roles, most powerful first.
const ROLES: [&str; 4] = ["owners", "maintainers", "write_data", "read_data"];

pub async fn run_member(
    cmd: MemberCommand,
    client: &Client,
    site: &str,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    match cmd {
        MemberCommand::List(args) if args.interactive => {
            let ask = prompter.ok_or(NEEDS_TERMINAL)?;
            browse_members(&args.scope, args.state.as_deref(), client, site, ask, false)
                .await
                .map(drop)
        }
        MemberCommand::List(args) => list(args, client).await,
        MemberCommand::View(args) if args.interactive => {
            let ask = prompter.ok_or(NEEDS_TERMINAL)?;
            let chosen = match &args.member {
                None => browse_members(&args.scope, None, client, site, &mut *ask, true).await?,
                Some(member) => Some(find(client, &args.scope, member).await?),
            };
            let Some(mut m) = chosen else { return Ok(()) };
            member_screen(&mut m, client, site, ask).await.map(drop)
        }
        MemberCommand::View(args) => {
            let m = find(client, &args.scope, &named(&args.member)?).await?;
            if args.json {
                crate::output::json(&m);
            } else {
                let color = crate::style::wanted(std::io::stdout().is_terminal());
                for line in member_lines(&m, color) {
                    println!("{line}");
                }
            }
            Ok(())
        }
        MemberCommand::Invite(args) => invite(args, client, prompter).await,
        MemberCommand::Edit(mut args) => {
            let mut prompter = prompter;
            if args.member.is_none() {
                let ask = prompter.as_deref_mut().ok_or(NEEDS_TERMINAL)?;
                let Some(member) = pick_member(&args.scope, client, site, ask).await? else {
                    return Ok(());
                };
                args.member = Some(member);
            }
            let json = args.json;
            if let Some(m) = edit(args, client, prompter).await? {
                report(&m, json, |who, at, role| {
                    format!("{who} is now {role} in {at}")
                });
            }
            Ok(())
        }
        MemberCommand::Revoke(mut args) => {
            let mut prompter = prompter;
            if args.member.is_none() {
                let ask = prompter.as_deref_mut().ok_or(NEEDS_TERMINAL)?;
                let Some(member) = pick_member(&args.scope, client, site, ask).await? else {
                    return Ok(());
                };
                args.member = Some(member);
            }
            let json = args.json;
            let m = revoke(args, client, prompter).await?;
            report(&m, json, |who, at, _| {
                format!("Revoked {who}'s membership of {at}")
            });
            Ok(())
        }
        MemberCommand::Leave(mut args) => {
            let mut prompter = prompter;
            if args.scope.is_none() {
                let ask = prompter.as_deref_mut().ok_or(NEEDS_TERMINAL)?;
                let mine = my_memberships(client, "member").await?;
                let Some(m) = browse_mine(mine, "Your memberships", ask).await? else {
                    return Ok(());
                };
                args.scope = Some(Scope::of(&m));
            }
            let json = args.json;
            let m = leave(args, client, prompter).await?;
            report(&m, json, |_, at, role| format!("Left {at} ({role})"));
            Ok(())
        }
    }
}

pub async fn run_invitation(
    cmd: InvitationCommand,
    client: &Client,
    site: &str,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    let (args, verb) = match cmd {
        InvitationCommand::List(args) if args.interactive => {
            let ask = prompter.ok_or(NEEDS_TERMINAL)?;
            let invitations = my_memberships(client, "invited").await?;
            return browse_invitations(invitations, client, site, ask).await;
        }
        InvitationCommand::List(args) => {
            let invitations = my_memberships(client, "invited").await?;
            if args.json {
                crate::output::json(&invitations);
            } else if invitations.is_empty() {
                eprintln!("No invitations waiting for you.");
            } else {
                let rows = invitations.iter().map(invitation_row).collect();
                print_table(["WHERE", "ROLE", "INVITED"], rows, false);
            }
            return Ok(());
        }
        InvitationCommand::Accept(args) => (args, "accept"),
        InvitationCommand::Reject(args) => (args, "reject"),
    };
    let json = args.json;
    let scope = match args.scope {
        Some(scope) => scope,
        None => {
            let ask = prompter.ok_or(NEEDS_TERMINAL)?;
            let invitations = my_memberships(client, "invited").await?;
            let Some(m) = browse_mine(invitations, "Your invitations", ask).await? else {
                return Ok(());
            };
            Scope::of(&m)
        }
    };
    let m = answer(client, &scope, verb).await?;
    report(&m, json, |_, at, role| match verb {
        "accept" => format!("You're now a member of {at} ({role})"),
        _ => format!("Turned down the invitation to {at}"),
    });
    Ok(())
}

/// For `edit -i` and `revoke -i` without a member: one picked from
/// `scope`'s members, by account ID. None when they backed out.
async fn pick_member(
    scope: &Scope,
    client: &Client,
    site: &str,
    ask: &mut dyn Prompter,
) -> Result<Option<String>, String> {
    let picked = browse_members(scope, None, client, site, ask, true).await?;
    Ok(picked.map(|m| str_field(&m, "account_id").to_string()))
}

/// The member a command was given; `run_member` fills it in for `-i`.
fn named(member: &Option<String>) -> Result<String, String> {
    member
        .clone()
        .ok_or_else(|| "Name the member's account ID, or pass -i to pick it.".into())
}

/// A failure scripts can tell apart, as the API's own 404 would be (exit 5).
fn not_found(message: String) -> String {
    ApiError {
        status: Some(StatusCode::NOT_FOUND),
        code: Some("not_found".into()),
        message,
        field_errors: Default::default(),
    }
    .into()
}

/// `scope`'s memberships the caller may see, invitations first, then members
/// by role. An organization's listing also carries its products' members,
/// which belong to those products, so they're left out.
pub(crate) async fn members(client: &Client, scope: &Scope) -> Result<Vec<Value>, String> {
    let all: Vec<Value> = client.get(scope.members_url(client)).await?;
    let mut ms: Vec<Value> = all.into_iter().filter(|m| Scope::of(m) == *scope).collect();
    ms.sort_by_key(|m| {
        let state = match str_field(m, "state") {
            "invited" => 0,
            "member" => 1,
            _ => 2,
        };
        let role = ROLES.iter().position(|r| *r == str_field(m, "role"));
        (state, role, str_field(m, "account_id").to_string())
    });
    Ok(ms)
}

/// `member`'s membership of `scope`, pending or current.
async fn find(client: &Client, scope: &Scope, member: &str) -> Result<Value, String> {
    members(client, scope)
        .await?
        .into_iter()
        .find(|m| str_field(m, "account_id") == member && str_field(m, "state") != "revoked")
        .ok_or_else(|| {
            not_found(format!(
                "{member} isn't a member of {scope}, or invited to it."
            ))
        })
}

/// The caller's own memberships in `state` (`member` or `invited`).
pub(crate) async fn my_memberships(client: &Client, state: &str) -> Result<Vec<Value>, String> {
    let mut url = client.url(&["memberships"]);
    url.query_pairs_mut().append_pair("state", state);
    Ok(client.get(url).await?)
}

/// `POST /memberships/{id}/{verb}`: accept, reject or revoke.
async fn act_on(client: &Client, m: &Value, verb: &str) -> Result<Value, String> {
    let url = client.url(&["memberships", str_field(m, "membership_id"), verb]);
    Ok(client.request(Method::POST, url, None::<&()>).await?)
}

async fn list(args: ListArgs, client: &Client) -> Result<(), String> {
    let mut ms = members(client, &args.scope).await?;
    if let Some(state) = &args.state {
        ms.retain(|m| str_field(m, "state") == state);
    }
    if args.json {
        crate::output::json(&ms);
    } else if ms.is_empty() {
        eprintln!("No members found.");
    } else {
        let rows = ms.iter().map(member_row).collect();
        print_table(["MEMBER", "ROLE", "STATE", "SINCE"], rows, args.no_pager);
    }
    Ok(())
}

/// `MEMBER  ROLE  STATE  SINCE`: since when, as RFC 3339 and how long ago on
/// a terminal, and as the API gave it when piped.
fn member_row(m: &Value) -> Vec<String> {
    ["account_id", "role", "state"]
        .iter()
        .map(|k| str_field(m, k).to_string())
        .chain([since(m)])
        .collect()
}

fn invitation_row(m: &Value) -> Vec<String> {
    vec![
        Scope::of(m).to_string(),
        str_field(m, "role").to_string(),
        since(m),
    ]
}

fn since(m: &Value) -> String {
    let at = str_field(m, "state_changed");
    match chrono::DateTime::parse_from_rfc3339(at) {
        Ok(d) if std::io::stdout().is_terminal() => crate::style::when(
            false,
            d.with_timezone(&chrono::Utc),
            chrono::Utc::now(),
            false,
        ),
        _ => at.to_string(),
    }
}

/// On a terminal, padded under a header and through the pager; piped,
/// tab-separated without one, for `cut` and `awk`.
fn print_table<const N: usize>(header: [&str; N], rows: Vec<Vec<String>>, no_pager: bool) {
    if !std::io::stdout().is_terminal() {
        for row in rows {
            println!("{}", row.join("\t"));
        }
        return;
    }
    let mut all = vec![header.map(String::from).to_vec()];
    all.extend(rows);
    let mut widths = [0; N];
    for row in &all {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let lines: Vec<String> = all
        .iter()
        .map(|row| {
            row.iter()
                .zip(widths)
                .map(|(cell, w)| format!("{cell:<w$}"))
                .collect::<Vec<_>>()
                .join("  ")
                .trim_end()
                .to_string()
        })
        .collect();
    match (!no_pager).then(Pager::spawn).flatten() {
        // A pager the person quit early has nothing left to show.
        Some(mut pager) => drop(pager.write(&lines)),
        None => lines.iter().for_each(|l| println!("{l}")),
    }
}

/// The member's account, then one `Label  value` row per field.
fn member_lines(m: &Value, color: bool) -> Vec<String> {
    let paint = |code: &str, s: &str| crate::style::paint(color, code, s);
    let state = str_field(m, "state");
    let since = chrono::DateTime::parse_from_rfc3339(str_field(m, "state_changed"))
        .map(|d| {
            crate::style::when(
                color,
                d.with_timezone(&chrono::Utc),
                chrono::Utc::now(),
                false,
            )
        })
        .unwrap_or_default();
    let rows = [
        ("Of", Scope::of(m).to_string()),
        ("Role", str_field(m, "role").to_string()),
        ("State", state_label(color, state)),
        ("Since", since),
        (
            "Membership",
            crate::style::id(color, str_field(m, "membership_id")),
        ),
    ];
    let mut lines = vec![paint("1", str_field(m, "account_id")), String::new()];
    lines.extend(
        rows.iter()
            .map(|(label, value)| format!("{}  {value}", paint("2", &format!("{label:<10}")))),
    );
    lines
}

/// A member in green, a pending invitation in yellow.
fn state_label(color: bool, state: &str) -> String {
    match state {
        "member" => crate::style::paint(color, "32", state),
        "invited" => crate::style::paint(color, "33", state),
        s => s.to_string(),
    }
}

/// A change's result: the membership as JSON, or a line for the person.
/// `said` is given the member, where, and the role.
fn report(m: &Value, as_json: bool, said: impl Fn(&str, Scope, &str) -> String) {
    if as_json {
        crate::output::json(m);
    } else {
        let (who, role) = (str_field(m, "account_id"), str_field(m, "role"));
        eprintln!("{}", said(who, Scope::of(m), role));
    }
}

/// The roles `me`, a `/whoami` session, could give in `scope`, as
/// source.coop's `grantors` decides: only owners may grant `owners`, and
/// owners and maintainers the rest. Admins and the account itself may grant
/// any. The API still decides; this only chooses what to offer.
fn grantable_roles(me: &Value, scope: &Scope) -> Vec<String> {
    let account = me.get("account").unwrap_or(&Value::Null);
    let admin = account
        .get("flags")
        .and_then(Value::as_array)
        .is_some_and(|fs| fs.iter().any(|f| f.as_str() == Some("admin")));
    let owner = me
        .get("memberships")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|m| {
            str_field(m, "state") == "member"
                && str_field(m, "role") == "owners"
                && str_field(m, "membership_account_id") == scope.account_id
                && (product_of(m).is_none() || product_of(m) == scope.product_id.as_deref())
        });
    let all = admin || owner || str_field(account, "account_id") == scope.account_id;
    let skip = if all { 0 } else { 1 };
    ROLES.iter().skip(skip).map(|r| r.to_string()).collect()
}

/// The account IDs in `path` (`-` for stdin), one per line.
fn read_accounts(path: &str) -> Result<Vec<String>, String> {
    let text = if path == "-" {
        std::io::read_to_string(std::io::stdin())
            .map_err(|e| format!("Couldn't read stdin: {e}"))?
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("Couldn't read {path}: {e}"))?
    };
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}

/// Account IDs typed at a prompt: separated by spaces or commas.
fn split_accounts(typed: &str) -> Vec<String> {
    typed
        .split([' ', ','])
        .filter(|a| !a.is_empty())
        .map(String::from)
        .collect()
}

/// `invite`'s questions, in the order they're asked.
#[derive(Clone, Copy)]
enum Step {
    Accounts,
    Role,
    Review,
}

/// Where a step leads: on to the next (None once all are answered), having
/// asked or not, or back to the question before.
enum Next {
    Asked(Option<Step>),
    Skipped(Option<Step>),
    Back,
}

/// Ask for whatever an invitation still needs: who (unless `accounts` has
/// them) and the role (unless `body` has one, from a flag, file or draft),
/// then show it all before sending: answers resumed from a draft are shown
/// too, though nothing else was asked. ↑ or ← goes back a question.
fn ask_invite(
    ask: &mut dyn Prompter,
    me: &Value,
    scope: &Scope,
    accounts: &mut Vec<String>,
    body: &mut Map<String, Value>,
    resumed: bool,
) -> Result<(), String> {
    let roles = grantable_roles(me, scope);
    let given_accounts = !accounts.is_empty();
    let given_role = body.contains_key("role");
    let mut asked: Vec<Step> = vec![];
    let mut step = Some(Step::Accounts);
    while let Some(now) = step {
        let next = match now {
            Step::Accounts if given_accounts => Next::Skipped(Some(Step::Role)),
            Step::Accounts => {
                let label = "Account IDs to invite (separated by spaces)";
                match ask.input_or_back(label, &accounts.join(" "), false)? {
                    None => Next::Back,
                    Some(typed) => {
                        *accounts = split_accounts(&typed);
                        Next::Asked(Some(Step::Role))
                    }
                }
            }
            Step::Role if given_role => Next::Skipped(Some(Step::Review)),
            Step::Role => {
                // The web form's default: the least access.
                let was = body
                    .get("role")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let at = roles
                    .iter()
                    .position(|r| *r == was)
                    .or_else(|| roles.iter().position(|r| r == "read_data"))
                    .unwrap_or(0);
                match ask.select_or_back("Role", &roles, at)? {
                    None => Next::Back,
                    Some(i) => {
                        body.insert("role".into(), json!(roles[i]));
                        Next::Asked(Some(Step::Review))
                    }
                }
            }
            Step::Review if asked.is_empty() && !resumed => Next::Skipped(None),
            Step::Review => {
                let lines = [
                    format!("{:<6}  {}", "Invite", accounts.join(", ")),
                    format!("{:<6}  {scope}", "To"),
                    format!(
                        "{:<6}  {}",
                        "Role",
                        body.get("role").and_then(Value::as_str).unwrap_or_default()
                    ),
                ];
                match ask.confirm_or_back("Send these invitations?", &lines)? {
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
    Ok(())
}

/// Invite each account in turn, carrying on past any the API refuses, and
/// report every one. The API takes one invitation at a time; this is the
/// bulk form of it. Failing any fails the command, after the rest are sent.
async fn invite(
    args: InviteArgs,
    client: &Client,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    if args.from_file.as_deref() == Some("-") && args.accounts_file.as_deref() == Some("-") {
        return Err("Only one of --from-file and --accounts-file can read stdin.".into());
    }
    let mut body = read_fields(args.from_file.as_deref())?;
    let mut accounts = args.accounts;
    if let Some(path) = &args.accounts_file {
        accounts.extend(read_accounts(path)?);
    }
    // A file's account_id is one more, unless accounts were named.
    match body.remove("account_id") {
        Some(Value::String(a)) if accounts.is_empty() => accounts.push(a),
        Some(Value::String(_)) | None => {}
        Some(other) => {
            let file = args.from_file.as_deref().unwrap_or_default();
            return Err(format!(
                "account_id in {file} must be a string, not {other}"
            ));
        }
    }
    if let Some(role) = args.role {
        body.insert("role".into(), json!(role));
    }

    // Drafts keep the accounts not yet invited, so a rerun sends only those.
    let (mut draft, mut me) = (None, None);
    if let Some(ask) = prompter.as_deref_mut() {
        if accounts.is_empty() || !body.contains_key("role") {
            let signed_in = me.insert(client.check_signed_in().await?);
            let saved = Draft::for_key(&format!("member-invite/{}", args.scope))?;
            if !accounts.is_empty() {
                body.insert("account_ids".into(), json!(accounts));
            }
            let resumed = saved.resume(ask, &mut body)?;
            if let Some(Value::Array(ids)) = body.remove("account_ids") {
                accounts = ids
                    .iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect();
            }
            let scope = &args.scope;
            ask_invite(ask, signed_in, scope, &mut accounts, &mut body, resumed)?;
            draft = Some(saved);
        }
    }
    if accounts.is_empty() {
        return Err("Name the account IDs to invite, or pass --accounts-file.".into());
    }

    let url = args.scope.members_url(client);
    let total = accounts.len();
    let (mut sent, mut failed, mut last) = (vec![], vec![], String::new());
    for mut account in accounts {
        // Until it's sent or refused; a rejected role or account is asked
        // for again and retried.
        loop {
            let mut one = body.clone();
            one.insert("account_id".into(), json!(account));
            match client
                .request::<Value>(Method::POST, url.clone(), Some(&one))
                .await
            {
                Ok(m) => {
                    if !args.json {
                        // A product owner's service account is added at once.
                        let verb = match str_field(&m, "state") {
                            "member" => "Added",
                            _ => "Invited",
                        };
                        let role = str_field(&m, "role");
                        eprintln!("{verb} {account} to {} ({role})", args.scope);
                    }
                    sent.push(m);
                    break;
                }
                Err(e) => match prompter.as_deref_mut() {
                    Some(ask) if reaskable(&e) => {
                        eprintln!("{e}");
                        let signed_in = match &me {
                            Some(me) => me,
                            None => me.insert(client.check_signed_in().await?),
                        };
                        let roles = grantable_roles(signed_in, &args.scope);
                        account = reask(ask, &e, &account, &mut body, &roles)?;
                    }
                    _ => {
                        last = String::from(e);
                        eprintln!("{}", crate::prompt::describe(&format!("{account}: {last}")));
                        failed.push(account);
                        break;
                    }
                },
            }
        }
    }
    if args.json && !sent.is_empty() {
        crate::output::json(&sent);
    }

    let result = match failed.len() {
        0 => Ok(()),
        _ if total == 1 => Err(last),
        n => Err(format!(
            "{n} of {total} invitations failed. The last: {last}"
        )),
    };
    body.insert("account_ids".into(), json!(failed));
    match draft {
        Some(draft) => draft.finish(result, &body),
        None => result,
    }
}

/// A 400 naming only `account_id` or `role`.
fn reaskable(e: &ApiError) -> bool {
    e.status == Some(StatusCode::BAD_REQUEST)
        && !e.field_errors.is_empty()
        && e.field_errors
            .keys()
            .all(|f| f == "account_id" || f == "role")
}

/// Ask again for the fields the API rejected, offering `roles`; returns the
/// account to retry.
fn reask(
    ask: &mut dyn Prompter,
    e: &ApiError,
    account: &str,
    body: &mut Map<String, Value>,
    roles: &[String],
) -> Result<String, String> {
    let mut account = account.to_string();
    if e.field_errors.contains_key("account_id") {
        account = ask.input("Account ID", &account, false)?.trim().to_string();
    }
    if e.field_errors.contains_key("role") {
        let was = body
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let at = roles.iter().position(|r| *r == was).unwrap_or(0);
        body.insert("role".into(), json!(roles[ask.select("Role", roles, at)?]));
    }
    Ok(account)
}

/// Change a member's role; None when the person kept the one it had.
async fn edit(
    args: EditArgs,
    client: &Client,
    prompter: Option<&mut dyn Prompter>,
) -> Result<Option<Value>, String> {
    let member = named(&args.member)?;
    let mut body = read_fields(args.from_file.as_deref())?;
    if let Some(role) = args.role {
        body.insert("role".into(), json!(role));
    }
    // ponytail: no draft. The only answer is one pick from four roles.
    let current = if body.is_empty() {
        let Some(ask) = prompter else {
            return Err("Nothing to change: pass --role or --from-file.".into());
        };
        let me = client.check_signed_in().await?;
        let current = find(client, &args.scope, &member).await?;
        let roles = grantable_roles(&me, &args.scope);
        let was = str_field(&current, "role");
        let at = roles.iter().position(|r| r == was).unwrap_or(0);
        let role = roles[ask.select(&format!("Role for {member}"), &roles, at)?].clone();
        if role == was {
            eprintln!("No changes to {member}.");
            return Ok(None);
        }
        body.insert("role".into(), json!(role));
        current
    } else {
        find(client, &args.scope, &member).await?
    };
    let url = client.url(&["memberships", str_field(&current, "membership_id")]);
    Ok(Some(client.request(Method::PATCH, url, Some(&body)).await?))
}

async fn revoke(
    args: RevokeArgs,
    client: &Client,
    prompter: Option<&mut dyn Prompter>,
) -> Result<Value, String> {
    let member = named(&args.member)?;
    let scope = &args.scope;
    if !args.yes {
        let Some(ask) = prompter else {
            return Err(format!(
                "Refusing to revoke {member}'s membership of {scope} without confirmation: pass --yes."
            ));
        };
        let me = client.check_signed_in().await?;
        let m = find(client, scope, &member).await?;
        if me.pointer("/account/account_id").and_then(Value::as_str) == Some(&member) {
            eprintln!("This removes your own access to {scope}.");
            crate::prompt::confirm_by_name(ask, &scope.to_string(), "revoked")?;
        } else {
            let question = match str_field(&m, "state") {
                "invited" => format!("Withdraw {member}'s invitation to {scope}?"),
                _ => format!("Remove {member} from {scope}?"),
            };
            if !ask.confirm(&question, false)? {
                return Err(crate::prompt::CANCELLED.into());
            }
        }
        return act_on(client, &m, "revoke").await;
    }
    let m = find(client, scope, &member).await?;
    act_on(client, &m, "revoke").await
}

async fn leave(
    args: LeaveArgs,
    client: &Client,
    prompter: Option<&mut dyn Prompter>,
) -> Result<Value, String> {
    let scope = args
        .scope
        .ok_or("Name what to leave, as ACCOUNT or ACCOUNT/PRODUCT, or pass -i to pick it.")?;
    if !args.yes && prompter.is_none() {
        return Err(format!(
            "Refusing to leave {scope} without confirmation: pass --yes."
        ));
    }
    let m = my_memberships(client, "member")
        .await?
        .into_iter()
        .find(|m| Scope::of(m) == scope)
        .ok_or_else(|| not_found(format!("You aren't a member of {scope}.")))?;
    if let (false, Some(ask)) = (args.yes, prompter) {
        eprintln!("This removes your access to {scope}; only its owners or maintainers can invite you back.");
        crate::prompt::confirm_by_name(ask, &scope.to_string(), "changed")?;
    }
    act_on(client, &m, "revoke").await
}

/// Accept or reject (`verb`) the caller's invitation to `scope`.
async fn answer(client: &Client, scope: &Scope, verb: &str) -> Result<Value, String> {
    let m = my_memberships(client, "invited")
        .await?
        .into_iter()
        .find(|m| Scope::of(m) == *scope)
        .ok_or_else(|| not_found(format!("You have no invitation to {scope}.")))?;
    act_on(client, &m, verb).await
}

/// Whether an action left the membership in its list.
#[derive(PartialEq)]
enum After {
    Kept,
    Gone,
}

/// The shortcuts on a highlighted member: only harmless ones. Changing a
/// membership takes opening it first.
const LIST_KEYS: &str = "b";
const LIST_HINT: &str = "↑↓ move · → open to edit or revoke · b browser · / filter · ← quit";
const CHOOSE_HINT: &str = "↑↓ move · → choose · / filter · ← quit";
/// On an opened member, and on an invitation, whose role the API won't change.
const MEMBER_KEYS: &str = "bed";
const MEMBER_HINT: &str = "b browser · e change role · d revoke · ← back";
const INVITED_KEYS: &str = "bd";
const INVITED_HINT: &str = "b browser · d withdraw the invitation · ← back";

/// `alice  maintainers  member  3 days ago`, the account ID gray.
fn member_label(m: &Value) -> String {
    let color = crate::style::on_stderr();
    let ago = chrono::DateTime::parse_from_rfc3339(str_field(m, "state_changed"))
        .map(|d| crate::style::relative(d.with_timezone(&chrono::Utc), chrono::Utc::now()))
        .unwrap_or_default();
    format!(
        "{}  {}  {}  {ago}",
        crate::style::id(color, str_field(m, "account_id")),
        str_field(m, "role"),
        state_label(color, str_field(m, "state")),
    )
    .trim_end()
    .to_string()
}

/// Move through `scope`'s members until they back out (None). For `list -i`,
/// opening one shows it and the shortcuts act on it; when `choosing`
/// (`view|edit|revoke -i` without a member), opening one returns it.
async fn browse_members(
    scope: &Scope,
    state: Option<&str>,
    client: &Client,
    site: &str,
    ask: &mut dyn Prompter,
    choosing: bool,
) -> Result<Option<Value>, String> {
    let (keys, hint) = if choosing {
        ("", CHOOSE_HINT)
    } else {
        (LIST_KEYS, LIST_HINT)
    };
    let mut items = members(client, scope).await?;
    if let Some(state) = state {
        items.retain(|m| str_field(m, "state") == state);
    }
    let mut place = Place::default();
    let _screen = ask.fullscreen();
    while !items.is_empty() {
        ask.clear();
        let labels: Vec<String> = items.iter().map(member_label).collect();
        let action = ask.browse(
            &format!("Members of {scope}"),
            &labels,
            &mut place,
            false,
            keys,
            hint,
        )?;
        let i = place.at;
        let (after, notice) = match action {
            Action::Open if choosing => return Ok(Some(items.swap_remove(i))),
            Action::Open => member_screen(&mut items[i], client, site, ask).await?,
            Action::Key(key) => act(key, &mut items[i], client, site, ask).await?,
            // Lists of members come whole; there's nothing more to load.
            Action::Back | Action::More | Action::Search => return Ok(None),
        };
        if after == After::Gone {
            items.remove(i);
            place.at = place.at.min(items.len().saturating_sub(1));
        }
        place.notice = notice;
    }
    eprintln!("No members found.");
    Ok(None)
}

/// One member as `view` shows it, with the shortcuts, until back.
async fn member_screen(
    m: &mut Value,
    client: &Client,
    site: &str,
    ask: &mut dyn Prompter,
) -> Result<(After, Option<String>), String> {
    let color = crate::style::wanted(std::io::stdout().is_terminal());
    let mut notice: Option<String> = None;
    loop {
        ask.clear();
        for line in member_lines(m, color) {
            println!("{line}");
        }
        println!();
        if let Some(n) = notice.take() {
            eprintln!("{}", crate::style::paint(color, "33", &n));
        }
        let (keys, hint) = match str_field(m, "state") {
            "invited" => (INVITED_KEYS, INVITED_HINT),
            _ => (MEMBER_KEYS, MEMBER_HINT),
        };
        match ask.keypress(hint, keys)? {
            Action::Back | Action::Open | Action::More | Action::Search => {
                return Ok((After::Kept, None))
            }
            Action::Key(key) => match act(key, m, client, site, ask).await? {
                (After::Gone, said) => return Ok((After::Gone, said)),
                (After::Kept, said) => notice = said,
            },
        }
    }
}

/// Run a shortcut on member `m` with the commands' own code: `b` opens their
/// profile, `e` changes the role, `d` revokes. A failure is told, not
/// returned, so the screen it came from carries on.
async fn act(
    key: char,
    m: &mut Value,
    client: &Client,
    site: &str,
    ask: &mut dyn Prompter,
) -> Result<(After, Option<String>), String> {
    let scope = Scope::of(m);
    let member = str_field(m, "account_id").to_string();
    let told = |e: String| Some(crate::prompt::describe(&e));
    let notice = match key {
        'b' => {
            let url = format!("{}/{member}", site.trim_end_matches('/'));
            match open::that(&url) {
                Ok(()) => Some(format!("Opened {url} in your browser.")),
                Err(e) => Some(format!("Couldn't open a browser: {e}")),
            }
        }
        'e' => {
            let args = EditArgs {
                scope,
                member: Some(member.clone()),
                interactive: false,
                role: None,
                from_file: None,
                json: false,
            };
            match edit(args, client, Some(ask)).await {
                Ok(Some(now)) => {
                    *m = now;
                    Some(format!("{member} is now {}.", str_field(m, "role")))
                }
                Ok(None) => Some(format!("No changes to {member}.")),
                Err(e) => told(e),
            }
        }
        'd' => {
            let args = RevokeArgs {
                scope,
                member: Some(member.clone()),
                interactive: false,
                yes: false,
                json: false,
            };
            match revoke(args, client, Some(ask)).await {
                Ok(_) => return Ok((After::Gone, Some(format!("Revoked {member}.")))),
                Err(e) => told(e),
            }
        }
        _ => None,
    };
    Ok((After::Kept, notice))
}

/// `my-org/my-data  maintainers  3 days ago`.
fn mine_label(m: &Value) -> String {
    let ago = chrono::DateTime::parse_from_rfc3339(str_field(m, "state_changed"))
        .map(|d| crate::style::relative(d.with_timezone(&chrono::Utc), chrono::Utc::now()))
        .unwrap_or_default();
    format!(
        "{}  {}  {ago}",
        crate::style::id(crate::style::on_stderr(), &Scope::of(m).to_string()),
        str_field(m, "role")
    )
}

/// Pick one of the caller's own memberships or invitations.
async fn browse_mine(
    items: Vec<Value>,
    label: &str,
    ask: &mut dyn Prompter,
) -> Result<Option<Value>, String> {
    if items.is_empty() {
        eprintln!("Nothing to pick from.");
        return Ok(None);
    }
    let labels: Vec<String> = items.iter().map(mine_label).collect();
    let mut place = Place::default();
    let _screen = ask.fullscreen();
    ask.clear();
    match ask.browse(label, &labels, &mut place, false, "", CHOOSE_HINT)? {
        Action::Open => Ok(items.into_iter().nth(place.at)),
        _ => Ok(None),
    }
}

const INVITATION_KEYS: &str = "abr";
const INVITATION_HINT: &str = "a accept · r reject · b browser · ← back";
const INVITATIONS_HINT: &str =
    "↑↓ move · → open to accept or reject · b browser · / filter · ← quit";

/// `invitation list -i`: move through the caller's invitations; open one to
/// accept or reject it.
async fn browse_invitations(
    mut items: Vec<Value>,
    client: &Client,
    site: &str,
    ask: &mut dyn Prompter,
) -> Result<(), String> {
    let color = crate::style::wanted(std::io::stdout().is_terminal());
    let mut place = Place::default();
    let _screen = ask.fullscreen();
    while !items.is_empty() {
        ask.clear();
        let labels: Vec<String> = items.iter().map(mine_label).collect();
        let i = match ask.browse(
            "Your invitations",
            &labels,
            &mut place,
            false,
            "b",
            INVITATIONS_HINT,
        )? {
            Action::Open => place.at,
            Action::Key('b') => {
                place.notice = open_scope(&Scope::of(&items[place.at]), site);
                continue;
            }
            _ => return Ok(()),
        };
        // The invitation's screen, until it's answered or they go back.
        let mut notice: Option<String> = None;
        loop {
            ask.clear();
            // Titled with where they're invited, not with themselves.
            let mut lines = member_lines(&items[i], color);
            lines[0] = crate::style::paint(color, "1", &Scope::of(&items[i]).to_string());
            for line in lines {
                println!("{line}");
            }
            println!();
            if let Some(n) = notice.take() {
                eprintln!("{}", crate::style::paint(color, "33", &n));
            }
            let verb = match ask.keypress(INVITATION_HINT, INVITATION_KEYS)? {
                Action::Key('a') => "accept",
                Action::Key('r') => "reject",
                Action::Key('b') => {
                    notice = open_scope(&Scope::of(&items[i]), site);
                    continue;
                }
                _ => break,
            };
            let scope = Scope::of(&items[i]);
            match act_on(client, &items[i], verb).await {
                Ok(_) => {
                    items.remove(i);
                    place.at = place.at.min(items.len().saturating_sub(1));
                    let done = if verb == "accept" {
                        "Accepted"
                    } else {
                        "Rejected"
                    };
                    place.notice = Some(format!("{done} the invitation to {scope}."));
                    break;
                }
                Err(e) => notice = Some(crate::prompt::describe(&e)),
            }
        }
    }
    eprintln!("No invitations waiting for you.");
    Ok(())
}

fn open_scope(scope: &Scope, site: &str) -> Option<String> {
    let url = scope.web_url(site);
    Some(match open::that(&url) {
        Ok(()) => format!("Opened {url} in your browser."),
        Err(e) => format!("Couldn't open a browser: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::scripted::{Answer::*, Script};
    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SITE: &str = "https://source.coop";

    /// A membership of `of` (`ORG` or `ORG/PRODUCT`), with no date so labels
    /// don't drift with the clock.
    fn ms(id: &str, account: &str, of: &str, role: &str, state: &str) -> Value {
        let scope: Scope = of.parse().unwrap();
        let mut m = json!({"membership_id": id, "account_id": account,
                           "membership_account_id": scope.account_id,
                           "role": role, "state": state, "state_changed": ""});
        if let Some(p) = scope.product_id {
            m["repository_id"] = json!(p);
        }
        m
    }

    /// A stand-in API whose caller, `acct`, maintains the org `org`.
    async fn api_server() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/whoami"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "account": {"account_id": "acct", "type": "individual"},
                "memberships": [ms("m0", "acct", "org", "maintainers", "member")]
            })))
            .mount(&server)
            .await;
        server
    }

    async fn org_members(server: &MockServer, members: Value) {
        Mock::given(method("GET"))
            .and(path("/api/v1/accounts/org/members"))
            .respond_with(ResponseTemplate::new(200).set_body_json(members))
            .mount(server)
            .await;
    }

    async fn expect_post(server: &MockServer, at: &str, reply: Value, times: u64) {
        Mock::given(method("POST"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_json(reply))
            .expect(times)
            .mount(server)
            .await;
    }

    fn client(server: &MockServer) -> Client {
        Client::new(&server.uri(), Some("tkn".into()), false).unwrap()
    }

    fn invite_args(accounts: &[&str]) -> InviteArgs {
        InviteArgs {
            scope: "org".parse().unwrap(),
            accounts: accounts.iter().map(|a| a.to_string()).collect(),
            accounts_file: None,
            role: None,
            from_file: None,
            json: false,
        }
    }

    #[test]
    fn scopes_are_an_account_or_a_product() {
        let org: Scope = "org".parse().unwrap();
        assert_eq!(org.product_id, None);
        let product: Scope = "/org/data/".parse().unwrap();
        assert_eq!(product.to_string(), "org/data");
        assert!("org/data/more".parse::<Scope>().is_err());
        assert!("".parse::<Scope>().is_err());
        // A membership names its product `repository_id`, or `product_id`.
        let renamed = json!({"membership_account_id": "org", "product_id": "data"});
        assert_eq!(Scope::of(&renamed), product);
    }

    #[test]
    fn an_accounts_file_has_one_account_per_line() {
        let file = std::env::temp_dir().join(format!("accounts-{}.txt", std::process::id()));
        std::fs::write(&file, "alice\n\n  bob  \n# carol is away\ndave\n").unwrap();
        let accounts = read_accounts(file.to_str().unwrap()).unwrap();
        std::fs::remove_file(&file).unwrap();
        assert_eq!(accounts, ["alice", "bob", "dave"]);
        assert_eq!(
            split_accounts("alice, bob  carol"),
            ["alice", "bob", "carol"]
        );
    }

    #[tokio::test]
    async fn an_org_s_members_leave_out_its_products_and_list_invitations_first() {
        let server = api_server().await;
        org_members(
            &server,
            json!([
                ms("1", "zed", "org", "read_data", "member"),
                ms("2", "amy", "org", "owners", "member"),
                ms("3", "pat", "org/data", "owners", "member"),
                ms("4", "bob", "org", "read_data", "invited"),
            ]),
        )
        .await;
        let listed = members(&client(&server), &"org".parse().unwrap())
            .await
            .unwrap();
        let ids: Vec<&str> = listed.iter().map(|m| str_field(m, "account_id")).collect();
        assert_eq!(ids, ["bob", "amy", "zed"]);
    }

    #[test]
    fn owners_are_offered_only_to_those_who_can_grant_it() {
        let scope: Scope = "org".parse().unwrap();
        let me = |role: &str, of: &str| {
            json!({"account": {"account_id": "acct"},
                   "memberships": [ms("m", "acct", of, role, "member")]})
        };
        let all = ROLES.map(String::from).to_vec();
        assert_eq!(grantable_roles(&me("owners", "org"), &scope), all);
        assert_eq!(grantable_roles(&me("maintainers", "org"), &scope), all[1..]);
        // An owner of the org owns its products too; one product's doesn't.
        let product: Scope = "org/data".parse().unwrap();
        assert_eq!(grantable_roles(&me("owners", "org"), &product), all);
        assert_eq!(
            grantable_roles(&me("owners", "org/other"), &product),
            all[1..]
        );
    }

    #[tokio::test]
    async fn invite_sends_each_account_and_carries_on_past_a_refusal() {
        let server = api_server().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/accounts/org/members"))
            .and(body_json(
                json!({"account_id": "alice", "role": "read_data"}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(ms(
                "1",
                "alice",
                "org",
                "read_data",
                "invited",
            )))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/accounts/org/members"))
            .and(body_json(json!({"account_id": "bob", "role": "read_data"})))
            .respond_with(ResponseTemplate::new(409).set_body_json(
                json!({"error": {"code": "conflict", "message": "bob is already a member"}}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let file = std::env::temp_dir().join(format!("invitees-{}.txt", std::process::id()));
        std::fs::write(&file, "# from the sign-up sheet\nbob\n").unwrap();
        let mut args = invite_args(&["alice"]);
        args.accounts_file = Some(file.to_str().unwrap().into());
        args.role = Some("read_data".into());

        let err = invite(args, &client(&server), None).await.unwrap_err();
        std::fs::remove_file(&file).unwrap();
        assert!(err.starts_with("1 of 2 invitations failed"), "{err}");
        // Scripts see the API's reason and exit code.
        let failure = crate::failure::classify(&err);
        assert_eq!(
            (failure.code.as_str(), failure.exit_code()),
            ("conflict", 3)
        );
    }

    #[tokio::test]
    async fn invite_asks_who_and_which_role_then_shows_it_all() {
        let server = api_server().await;
        expect_post(
            &server,
            "/api/v1/accounts/org/members",
            ms("1", "x", "org", "read_data", "invited"),
            2,
        )
        .await;
        let mut ask = Script::new([
            Text("alice bob"),
            Pick(0), // maintainers…
            Back,    // …no: back from the review, to the role
            Pick(2), // starting from maintainers, the answer given: read_data
            Yes(true),
        ]);
        invite(invite_args(&[]), &client(&server), Some(&mut ask))
            .await
            .unwrap();
        let review =
            "Send these invitations? {Invite  alice, bob | To      org | Role    maintainers}";
        assert_eq!(
            ask.asked,
            [
                "Account IDs to invite (separated by spaces) []".to_string(),
                // A maintainer can't make owners, so isn't offered it.
                "Role [read_data] of maintainers | write_data | read_data".into(),
                format!("{review} (back)"),
                "Role [maintainers] of maintainers | write_data | read_data".into(),
                review.replace("maintainers}", "read_data}") + " [true]",
            ]
        );
    }

    #[tokio::test]
    async fn edit_finds_the_membership_and_changes_its_role() {
        let server = api_server().await;
        org_members(
            &server,
            json!([ms("m1", "bob", "org", "read_data", "member")]),
        )
        .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/memberships/m1"))
            .and(body_json(json!({"role": "write_data"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(ms(
                "m1",
                "bob",
                "org",
                "write_data",
                "member",
            )))
            .expect(1)
            .mount(&server)
            .await;
        let args = EditArgs {
            scope: "org".parse().unwrap(),
            member: Some("bob".into()),
            interactive: false,
            role: None,
            from_file: None,
            json: false,
        };
        let mut ask = Script::new([Pick(1)]);
        let changed = edit(args, &client(&server), Some(&mut ask)).await.unwrap();
        assert_eq!(str_field(&changed.unwrap(), "role"), "write_data");
        assert_eq!(
            ask.asked,
            ["Role for bob [read_data] of maintainers | write_data | read_data"]
        );
    }

    #[tokio::test]
    async fn a_member_who_isn_t_there_is_not_found() {
        let server = api_server().await;
        org_members(
            &server,
            json!([ms("m1", "bob", "org", "read_data", "revoked")]),
        )
        .await;
        let err = find(&client(&server), &"org".parse().unwrap(), "bob")
            .await
            .unwrap_err();
        assert_eq!(crate::failure::classify(&err).exit_code(), 5);
    }

    fn revoke_args(member: &str, yes: bool) -> RevokeArgs {
        RevokeArgs {
            scope: "org".parse().unwrap(),
            member: Some(member.into()),
            interactive: false,
            yes,
            json: false,
        }
    }

    #[tokio::test]
    async fn revoke_without_a_terminal_needs_yes() {
        let server = api_server().await;
        let err = revoke(revoke_args("bob", false), &client(&server), None)
            .await
            .unwrap_err();
        assert!(err.contains("pass --yes"), "{err}");

        org_members(
            &server,
            json!([ms("m1", "bob", "org", "read_data", "invited")]),
        )
        .await;
        expect_post(&server, "/api/v1/memberships/m1/revoke", json!({}), 1).await;
        revoke(revoke_args("bob", true), &client(&server), None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn revoking_yourself_takes_typing_the_name() {
        let server = api_server().await;
        org_members(
            &server,
            json!([ms("m0", "acct", "org", "maintainers", "member")]),
        )
        .await;
        expect_post(&server, "/api/v1/memberships/m0/revoke", json!({}), 0).await;
        let mut ask = Script::new([Text("not-org")]);
        let err = revoke(revoke_args("acct", false), &client(&server), Some(&mut ask))
            .await
            .unwrap_err();
        assert_eq!(err, "Not confirmed; nothing was revoked.");
        assert_eq!(ask.asked, ["Type org to confirm (Esc to cancel) []"]);
    }

    #[tokio::test]
    async fn leave_revokes_your_own_membership() {
        let server = api_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/memberships"))
            .and(query_param("state", "member"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                ms("m9", "acct", "org/data", "read_data", "member"),
                ms("m0", "acct", "org", "maintainers", "member"),
            ])))
            .mount(&server)
            .await;
        expect_post(&server, "/api/v1/memberships/m0/revoke", json!({}), 1).await;
        let args = LeaveArgs {
            scope: Some("org".parse().unwrap()),
            interactive: false,
            yes: false,
            json: false,
        };
        let mut ask = Script::new([Text("org")]);
        leave(args, &client(&server), Some(&mut ask)).await.unwrap();
    }

    #[tokio::test]
    async fn invitations_are_answered_by_where_they_re_to() {
        let server = api_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/memberships"))
            .and(query_param("state", "invited"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([ms(
                "i1",
                "acct",
                "org/data",
                "write_data",
                "invited"
            )])))
            .mount(&server)
            .await;
        expect_post(&server, "/api/v1/memberships/i1/accept", json!({}), 1).await;
        let c = client(&server);
        answer(&c, &"org/data".parse().unwrap(), "accept")
            .await
            .unwrap();
        let err = answer(&c, &"org".parse().unwrap(), "accept")
            .await
            .unwrap_err();
        assert_eq!(
            err.lines().next().unwrap(),
            "You have no invitation to org. (not_found, HTTP 404)"
        );
    }

    #[tokio::test]
    async fn list_i_edits_and_revokes_from_a_member_s_screen() {
        let server = api_server().await;
        org_members(
            &server,
            json!([
                ms("m1", "bob", "org", "read_data", "member"),
                ms("m2", "cy", "org", "read_data", "invited"),
            ]),
        )
        .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/memberships/m1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ms(
                "m1",
                "bob",
                "org",
                "write_data",
                "member",
            )))
            .expect(1)
            .mount(&server)
            .await;
        expect_post(&server, "/api/v1/memberships/m2/revoke", json!({}), 1).await;
        let mut ask = Script::new([
            Browse(1, Action::Open), // bob: invitations come first
            Press(Action::Key('e')),
            Pick(1), // write_data
            Press(Action::Back),
            Browse(0, Action::Open), // cy's invitation
            Press(Action::Key('d')),
            Yes(true),
            Browse(0, Action::Back),
        ]);
        browse_members(
            &"org".parse().unwrap(),
            None,
            &client(&server),
            SITE,
            &mut ask,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            ask.asked[0],
            "Members of org [cy  read_data  invited] of cy  read_data  invited | bob  read_data  member (keys b)"
        );
        assert_eq!(ask.asked[1], format!("{MEMBER_HINT} (keys bed)"));
        // The screen says what changed as it redraws.
        assert_eq!(ask.asked[3], format!("{MEMBER_HINT} (keys bed)"));
        // An invitation's role can't change: only withdrawing it is offered.
        assert_eq!(ask.asked[5], format!("{INVITED_HINT} (keys bd)"));
        assert_eq!(ask.asked[6], "Withdraw cy's invitation to org? [false]");
        assert_eq!(
            ask.asked[7],
            "Members of org [bob  write_data  member] of bob  write_data  member !Revoked cy. (keys b)"
        );
    }

    #[tokio::test]
    async fn answers_resumed_from_a_draft_are_shown_before_sending() {
        let server = api_server().await;
        expect_post(
            &server,
            "/api/v1/accounts/org/members",
            ms("1", "alice", "org", "read_data", "invited"),
            1,
        )
        .await;
        let saved = Draft::for_key("member-invite/org").unwrap();
        let body = json!({"account_ids": ["alice"], "role": "read_data"});
        let _ = saved.finish::<()>(Err("lost".into()), body.as_object().unwrap());

        let mut ask = Script::new([Yes(true), Yes(true)]);
        invite(invite_args(&[]), &client(&server), Some(&mut ask))
            .await
            .unwrap();
        assert_eq!(
            ask.asked,
            [
                "Use the answers saved from your last try? [true]",
                "Send these invitations? {Invite  alice | To      org | Role    read_data} [true]",
            ]
        );
    }

    #[tokio::test]
    async fn an_account_id_that_isn_t_text_is_refused_not_dropped() {
        let server = api_server().await;
        let file = std::env::temp_dir().join(format!("invite-{}.json", std::process::id()));
        std::fs::write(&file, r#"{"account_id": 42, "role": "read_data"}"#).unwrap();
        let mut args = invite_args(&[]);
        args.from_file = Some(file.to_str().unwrap().into());
        let err = invite(args, &client(&server), None).await.unwrap_err();
        std::fs::remove_file(&file).unwrap();
        assert!(
            err.contains("account_id in") && err.ends_with("must be a string, not 42"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_rejected_role_is_asked_again_from_the_roles_you_can_grant() {
        let server = api_server().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/accounts/org/members"))
            .and(body_json(json!({"account_id": "bob", "role": "owners"})))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": {
                "code": "validation_error", "message": "Invalid request",
                "field_errors": {"role": ["You can't grant owners"]}}})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/accounts/org/members"))
            .and(body_json(
                json!({"account_id": "bob", "role": "maintainers"}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(ms(
                "1",
                "bob",
                "org",
                "maintainers",
                "invited",
            )))
            .expect(1)
            .mount(&server)
            .await;
        let mut args = invite_args(&["bob"]);
        args.role = Some("owners".into());
        let mut ask = Script::new([Pick(0)]);
        invite(args, &client(&server), Some(&mut ask))
            .await
            .unwrap();
        // `acct` maintains `org`, so owners isn't offered again.
        assert_eq!(
            ask.asked,
            ["Role [maintainers] of maintainers | write_data | read_data"]
        );
    }

    #[tokio::test]
    async fn list_i_shows_only_the_state_asked_for() {
        let server = api_server().await;
        org_members(
            &server,
            json!([
                ms("m1", "bob", "org", "read_data", "member"),
                ms("m2", "cy", "org", "read_data", "invited"),
            ]),
        )
        .await;
        let mut ask = Script::new([Browse(0, Action::Back)]);
        let scope = "org".parse().unwrap();
        browse_members(
            &scope,
            Some("invited"),
            &client(&server),
            SITE,
            &mut ask,
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            ask.asked,
            ["Members of org [cy  read_data  invited] of cy  read_data  invited (keys b)"]
        );
    }
}
