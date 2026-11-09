//! `source-coop account`: list, view, create and edit accounts through
//! `/api/v1/accounts`. `create` makes organizations, the only accounts the
//! API creates this way; people sign up on the website, and service accounts
//! are `service-account create`'s. The API never deletes a person or an
//! organization, so there's no `delete`: `edit --disable` turns one off.

use crate::api::Client;
use crate::draft::Draft;
use crate::product::{one_line, read_fields, str_field, Pager, NEEDS_TERMINAL};
use crate::prompt::{send_until_accepted, Action, Place, Prompter, Question};
use clap::{Args, Subcommand};
use clap_complete::engine::ArgValueCompleter;
use reqwest::Method;
use serde_json::{json, Map, Value};
use std::io::IsTerminal;

#[derive(Subcommand)]
pub enum AccountCommand {
    /// List your own account and the organizations you belong to
    #[command(after_help = crate::style::examples(&["source-coop account list --json"]))]
    List(ListArgs),
    /// Show one account: a person's or an organization's profile
    #[command(after_help = crate::style::examples(&["source-coop account view my-org --json"]))]
    View(ViewArgs),
    /// Create an organization, with you as its owner
    #[command(
        after_help = crate::style::examples(&[
            "source-coop account create my-org --name \"My Org\" --json",
            "echo '{\"name\": \"My Org\", \"bio\": \"Open data\"}' | source-coop account create my-org -F - --json",
        ])
    )]
    Create(CreateArgs),
    /// Change an account's name or profile, or disable or enable it
    #[command(
        after_help = crate::style::examples(&[
            "source-coop account edit my-org --bio \"Open climate data\" --website example.org --json",
            "source-coop account edit my-org --disable --json",
            "echo '{\"location\": \"Lisbon\"}' | source-coop account edit my-org -F - --json",
        ])
    )]
    Edit(EditArgs),
}

impl AccountCommand {
    /// Whether `--json` was asked for, so a failure is reported as JSON too.
    pub fn wants_json(&self) -> bool {
        match self {
            AccountCommand::List(a) => a.json,
            AccountCommand::View(a) => a.json,
            AccountCommand::Create(a) => a.json,
            AccountCommand::Edit(a) => a.json,
        }
    }
}

#[derive(Args)]
pub struct ListArgs {
    /// Print the accounts as JSON: each one's whole record
    #[arg(long)]
    json: bool,

    /// Pick an account from the list, then view, open or edit it
    #[arg(long, short = 'i', conflicts_with = "json")]
    interactive: bool,

    /// Print straight to the terminal instead of through $SOURCE_PAGER,
    /// $PAGER or `less -FRX`
    #[arg(long)]
    no_pager: bool,
}

#[derive(Args)]
pub struct ViewArgs {
    /// The account's ID (with -i, picked from yours when omitted)
    #[arg(
        required_unless_present = "interactive",
        add = ArgValueCompleter::new(crate::complete::account)
    )]
    account: Option<String>,

    /// Show the account with shortcuts: b browser, e edit, ← back
    #[arg(long, short = 'i', conflicts_with_all = ["web", "json"])]
    interactive: bool,

    /// Open the account's page in the browser instead
    #[arg(long, short = 'w')]
    web: bool,

    /// Print the account as JSON
    #[arg(long)]
    json: bool,
}

/// The profile fields `account create` and `account edit` both take.
#[derive(Args, Default)]
pub struct Fields {
    /// The account's display name
    #[arg(long, short = 'n')]
    name: Option<String>,

    /// A short description (an empty string clears it)
    #[arg(long)]
    bio: Option<String>,

    /// A website; repeat for several. Replaces the account's websites
    #[arg(long = "website", value_name = "URL")]
    websites: Vec<String>,

    /// An organization's contact email (an empty string clears it)
    #[arg(long)]
    email: Option<String>,

    /// Read fields from a JSON object in this file (`-` for stdin); flags win
    #[arg(long, short = 'F', value_name = "PATH")]
    from_file: Option<String>,
}

impl Fields {
    /// The JSON body these fields make, on top of `--from-file`'s.
    fn body(&self) -> Result<Map<String, Value>, String> {
        let mut body = read_fields(self.from_file.as_deref())?;
        insert_some(&mut body, "name", &self.name);
        insert_some(&mut body, "bio", &self.bio);
        insert_some(&mut body, "email", &self.email);
        if !self.websites.is_empty() {
            body.insert("websites".into(), json!(self.websites));
        }
        Ok(body)
    }
}

#[derive(Args)]
pub struct CreateArgs {
    /// The new organization's ID, as in source.coop/ID (prompted for when
    /// omitted)
    #[arg(add = ArgValueCompleter::new(crate::complete::new_account))]
    account: Option<String>,

    #[command(flatten)]
    fields: Fields,

    /// Print the new organization as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct EditArgs {
    /// The account's ID (with -i, picked from yours when omitted)
    #[arg(
        required_unless_present = "interactive",
        add = ArgValueCompleter::new(crate::complete::account)
    )]
    account: Option<String>,

    /// Pick the account from yours when it isn't named
    #[arg(long, short = 'i')]
    interactive: bool,

    #[command(flatten)]
    fields: Fields,

    /// Where the account is (an empty string clears it)
    #[arg(long)]
    location: Option<String>,

    /// An organization's ROR ID (an empty string clears it)
    #[arg(long)]
    ror_id: Option<String>,

    /// A person's ORCID iD (an empty string clears it)
    #[arg(long)]
    orcid: Option<String>,

    /// Disable the account: it can't sign in, and nothing new may be
    /// attached to it
    #[arg(long, conflicts_with = "enable")]
    disable: bool,

    /// Enable a disabled account
    #[arg(long)]
    enable: bool,

    /// Print the edited account as JSON
    #[arg(long)]
    json: bool,
}

pub async fn run(
    cmd: AccountCommand,
    client: &Client,
    site: &str,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    match cmd {
        AccountCommand::List(args) if args.interactive => {
            let ask = prompter.ok_or(NEEDS_TERMINAL)?;
            browse(client, site, ask, false).await.map(drop)
        }
        AccountCommand::List(args) => list(args, client).await,
        AccountCommand::View(args) => view(args, client, site, prompter).await,
        AccountCommand::Create(args) => create(args, client, site, prompter).await,
        // Without an account, clap has required -i: choose one, then carry on
        // as if it had been named.
        AccountCommand::Edit(mut args) if args.account.is_none() => {
            let ask = prompter.ok_or(NEEDS_TERMINAL)?;
            let Some(a) = browse(client, site, &mut *ask, true).await? else {
                return Ok(());
            };
            args.account = Some(a);
            edit(args, client, site, Some(ask)).await
        }
        AccountCommand::Edit(args) => edit(args, client, site, prompter).await,
    }
}

/// Your own account, then each account you're a member of, as `/whoami`
/// tells them; completion offers the same.
pub(crate) async fn yours(client: &Client) -> Result<Vec<String>, String> {
    let me: Value = client.get(client.url(&["whoami"])).await?;
    let own = me.pointer("/account/account_id").and_then(Value::as_str);
    let orgs = me
        .get("memberships")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|m| str_field(m, "state") == "member")
        .map(|m| str_field(m, "membership_account_id"));
    let mut all: Vec<String> = vec![];
    for a in own.into_iter().chain(orgs) {
        if !a.is_empty() && !all.iter().any(|x| x == a) {
            all.push(a.to_string());
        }
    }
    Ok(all)
}

/// Each of your accounts' records, in `yours`' order. An account the API
/// doesn't show you is left out, with a note: `/whoami` still lists your
/// membership of a disabled organization, which only its owners and
/// maintainers can read (404 for everyone else).
/// ponytail: one request per account, in turn. People belong to a handful;
/// fetch them together if someone's list gets slow.
async fn your_records(client: &Client) -> Result<Vec<Value>, String> {
    let mut records = vec![];
    for id in yours(client).await? {
        match client.get(account_url(client, &id)).await {
            Ok(a) => records.push(a),
            Err(e) if e.status == Some(reqwest::StatusCode::NOT_FOUND) => {
                eprintln!("Left out {id}: source.coop doesn't show it to you. It may be disabled.")
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(records)
}

async fn list(args: ListArgs, client: &Client) -> Result<(), String> {
    let records = your_records(client).await?;
    if args.json {
        crate::output::json(&records);
        return Ok(());
    }
    if records.is_empty() {
        eprintln!("No accounts found.");
        return Ok(());
    }
    let rows: Vec<[&str; 3]> = records
        .iter()
        .map(|a| {
            [
                str_field(a, "account_id"),
                str_field(a, "type"),
                str_field(a, "name"),
            ]
        })
        .collect();
    if !std::io::stdout().is_terminal() {
        // Piped: tab-separated with no header, for `cut` and `awk`.
        for r in rows {
            println!("{}", r.join("\t"));
        }
        return Ok(());
    }
    let color = crate::style::wanted(true);
    let width = |i: usize| rows.iter().map(|r| r[i].len()).max().unwrap_or(0).max(4);
    let (w0, w1) = (width(0), width(1));
    let mut lines = vec![format!("{:<w0$}  {:<w1$}  NAME", "ID", "TYPE")];
    for [id, kind, name] in rows {
        let id = crate::style::id(color, &format!("{id:<w0$}"));
        lines.push(format!("{id}  {kind:<w1$}  {name}"));
    }
    match (!args.no_pager).then(Pager::spawn).flatten() {
        // A pager quit before the end has nothing left to show.
        Some(mut pager) => drop(pager.write(&lines)),
        None => lines.iter().for_each(|l| println!("{l}")),
    }
    Ok(())
}

const LIST_HINT: &str = "↑↓ move · → open to edit · b browser · / filter · ← quit";
const CHOOSE_HINT: &str = "↑↓ move · → choose · / filter · ← quit";
const SCREEN_HINT: &str = "b browser · e edit · ← back";

/// Move through your accounts until they back out (None). For `list -i`,
/// opening one shows it as `view` does and the shortcuts act on it; when
/// `choosing` (`view|edit -i` without an account), opening one returns it.
async fn browse(
    client: &Client,
    site: &str,
    ask: &mut dyn Prompter,
    choosing: bool,
) -> Result<Option<String>, String> {
    let (keys, hint) = if choosing {
        ("", CHOOSE_HINT)
    } else {
        ("b", LIST_HINT)
    };
    let mut records = your_records(client).await?;
    if records.is_empty() {
        eprintln!("No accounts found.");
        return Ok(None);
    }
    let mut place = Place::default();
    let _screen = ask.fullscreen();
    loop {
        ask.clear();
        let color = crate::style::on_stderr();
        let labels: Vec<String> = records
            .iter()
            .map(|a| {
                let id = crate::style::id(color, str_field(a, "account_id"));
                format!("{id}  {}  {}", str_field(a, "name"), str_field(a, "type"))
            })
            .collect();
        let action = ask.browse("Your accounts", &labels, &mut place, false, keys, hint)?;
        let i = place.at;
        let id = str_field(&records[i], "account_id").to_string();
        place.notice = match action {
            Action::Back => return Ok(None),
            Action::Open if choosing => return Ok(Some(id)),
            Action::Open => screen(&mut records[i], client, site, ask).await?,
            Action::Key(key) => act(key, &mut records[i], client, site, ask).await?,
            // Never asked for: the list is whole and filtered as loaded.
            Action::More | Action::Search => None,
        };
    }
}

/// One account as `view` shows it, with the shortcuts, until back. Returns
/// anything to tell the list about.
async fn screen(
    account: &mut Value,
    client: &Client,
    site: &str,
    ask: &mut dyn Prompter,
) -> Result<Option<String>, String> {
    let color = crate::style::wanted(std::io::stdout().is_terminal());
    let mut notice: Option<String> = None;
    loop {
        ask.clear();
        for line in account_lines(account, site, color, chrono::Utc::now()) {
            println!("{line}");
        }
        println!();
        if let Some(n) = notice.take() {
            eprintln!("{}", crate::style::paint(color, "33", &n));
        }
        match ask.keypress(SCREEN_HINT, "be")? {
            Action::Key(key) => notice = act(key, account, client, site, ask).await?,
            _ => return Ok(None),
        }
    }
}

/// Run a shortcut on `account` with the same code as the commands: `b` opens
/// it in the browser, `e` edits it (then fetches it as it now is). Returns
/// what to tell the person; a failed action is told, not returned.
async fn act(
    key: char,
    account: &mut Value,
    client: &Client,
    site: &str,
    ask: &mut dyn Prompter,
) -> Result<Option<String>, String> {
    let id = str_field(account, "account_id").to_string();
    Ok(match key {
        'b' => {
            let url = web_url(site, &id);
            match open::that(&url) {
                Ok(()) => Some(format!("Opened {url} in your browser.")),
                Err(e) => Some(format!("Couldn't open a browser: {e}")),
            }
        }
        'e' => {
            let args = EditArgs {
                account: Some(id.clone()),
                interactive: false,
                fields: Fields::default(),
                location: None,
                ror_id: None,
                orcid: None,
                disable: false,
                enable: false,
                json: false,
            };
            let refetched = match edit(args, client, site, Some(&mut *ask)).await {
                Ok(()) => client
                    .get(account_url(client, &id))
                    .await
                    .map_err(String::from),
                Err(e) => Err(e),
            };
            match refetched {
                Ok(now) if now == *account => Some(format!("No changes to {id}.")),
                Ok(now) => {
                    *account = now;
                    Some(format!("Edited {id}."))
                }
                Err(e) => Some(crate::prompt::describe(&e)),
            }
        }
        _ => None,
    })
}

async fn view(
    args: ViewArgs,
    client: &Client,
    site: &str,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    if args.interactive {
        let ask = prompter.ok_or(NEEDS_TERMINAL)?;
        let chosen = match args.account {
            None => browse(client, site, ask, true).await?,
            named => named,
        };
        let Some(id) = chosen else { return Ok(()) };
        let mut account: Value = client.get(account_url(client, &id)).await?;
        let _screen = ask.fullscreen();
        screen(&mut account, client, site, ask).await?;
        return Ok(());
    }
    let id = named(&args.account)?;
    if args.web {
        let url = web_url(site, &id);
        eprintln!("Opening {url} in your browser.");
        return open::that(&url).map_err(|e| format!("Couldn't open a browser: {e}"));
    }
    let account: Value = client.get(account_url(client, &id)).await?;
    if args.json {
        crate::output::json(&account);
    } else {
        let color = crate::style::wanted(std::io::stdout().is_terminal());
        for line in account_lines(&account, site, color, chrono::Utc::now()) {
            println!("{line}");
        }
    }
    Ok(())
}

/// `create`'s questions, in the order they're asked.
#[derive(Clone, Copy)]
enum Step {
    Id,
    Name,
    Bio,
    Review,
}

/// Ask for what a new organization still needs: its ID unless `named`, then
/// its name (offered from the ID, as the web form does) and bio unless
/// given. ↑ or ← goes back to the question before; a field from a flag, a
/// file or a resumed draft isn't asked. Returns the ID and its draft.
fn ask_create(
    ask: &mut dyn Prompter,
    named: Option<String>,
    body: &mut Map<String, Value>,
) -> Result<(String, Draft), String> {
    let mut id = named.clone().unwrap_or_default();
    let mut given: Vec<String> = body.keys().cloned().collect();
    let mut draft: Option<(String, Draft)> = None;
    let current = |body: &Map<String, Value>, key: &str| str_field_map(body, key);
    let mut asked: Vec<Step> = vec![];
    let mut step = Some(Step::Id);
    while let Some(now) = step {
        // (where to go, whether a question was asked)
        let next: Option<(Option<Step>, bool)> = match now {
            Step::Id => {
                let went = if named.is_some() {
                    Some((Some(Step::Name), false))
                } else {
                    ask.input_or_back("Organization ID", &id, false)?.map(|a| {
                        id = a.trim().to_string();
                        (Some(Step::Name), true)
                    })
                };
                // Offer a saved draft once per ID, as soon as it's named.
                if went.is_some() {
                    let key = format!("account-create/{id}");
                    if draft.as_ref().map(|(k, _)| k) != Some(&key) {
                        let saved = Draft::for_key(&key)?;
                        // Only what the draft fills in counts as given: an
                        // answer typed before going back to change the ID is
                        // still asked.
                        let before: Vec<String> = body.keys().cloned().collect();
                        saved.resume(ask, body)?;
                        for k in body.keys() {
                            if !before.contains(k) && !given.contains(k) {
                                given.push(k.clone());
                            }
                        }
                        draft = Some((key, saved));
                    }
                }
                went
            }
            Step::Name if given.iter().any(|k| k == "name") => Some((Some(Step::Bio), false)),
            Step::Name => {
                let was = match current(body, "name") {
                    n if n.is_empty() => crate::product::title_from_id(&id),
                    n => n,
                };
                ask.input_or_back("Name", &was, false)?.map(|n| {
                    body.insert("name".into(), json!(n));
                    (Some(Step::Bio), true)
                })
            }
            Step::Bio if given.iter().any(|k| k == "bio") => Some((Some(Step::Review), false)),
            Step::Bio => ask
                .long_text_or_back("Bio", &current(body, "bio"))?
                .map(|b| {
                    // Left empty, it isn't sent, as the web form doesn't.
                    if b.is_empty() {
                        body.remove("bio");
                    } else {
                        body.insert("bio".into(), json!(b));
                    }
                    (Some(Step::Review), true)
                }),
            // A last look before anything is created, when something was
            // asked: a run given every field goes straight through.
            Step::Review if asked.is_empty() => Some((None, false)),
            Step::Review => {
                let mut rows = vec![format!("{:<12}  {id}", "Organization")];
                rows.extend(review_lines(body));
                match ask.confirm_or_back("Create this organization?", &rows)? {
                    None => None,
                    Some(true) => Some((None, true)),
                    Some(false) => return Err(crate::prompt::CANCELLED.into()),
                }
            }
        };
        step = match next {
            Some((then, true)) => {
                asked.push(now);
                then
            }
            Some((then, false)) => then,
            // Back from the first question asks it again.
            None => asked.pop().or(Some(now)),
        };
    }
    let (_, draft) = draft.expect("the ID step always opens one");
    Ok((id, draft))
}

/// What's about to be sent, as `Label  value` rows to look over.
fn review_lines(body: &Map<String, Value>) -> Vec<String> {
    LABELS
        .iter()
        .filter(|(key, _)| body.contains_key(*key))
        .map(|(key, label)| {
            let value = match body.get(*key) {
                Some(Value::Array(vs)) => vs
                    .iter()
                    .map(|v| v.as_str().unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join(", "),
                Some(Value::Bool(b)) => b.to_string(),
                _ => one_line(&str_field_map(body, key)),
            };
            format!("{label:<12}  {value}")
        })
        .collect()
}

/// The fields a body may hold, with their labels, in the order shown.
const LABELS: [(&str, &str); 9] = [
    ("name", "Name"),
    ("bio", "Bio"),
    ("location", "Location"),
    ("websites", "Websites"),
    ("email", "Email"),
    ("ror_id", "ROR ID"),
    ("orcid", "ORCID"),
    ("disabled", "Disabled"),
    ("owner_account_id", "Owner"),
];

async fn create(
    args: CreateArgs,
    client: &Client,
    site: &str,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    let mut body = args.fields.body()?;
    // The ID argument wins over one in --from-file (a saved draft holds it).
    let named = args.account.or_else(|| {
        body.get("account_id")
            .and_then(Value::as_str)
            .map(String::from)
    });
    let (id, draft) = match prompter.as_deref_mut() {
        Some(ask) => {
            // Before the first question, so nobody fills in a form only to
            // be refused.
            client.check_signed_in().await?;
            let (id, draft) = ask_create(ask, named, &mut body)?;
            (id, Some(draft))
        }
        None => match named {
            Some(id) => (id, None),
            None => return Err("Name the organization to create: its ID.".into()),
        },
    };
    body.insert("account_id".into(), json!(id));

    let url = client.url(&["accounts"]);
    let sent = send_until_accepted(client, Method::POST, url, &mut body, prompter, question).await;
    let created = match &draft {
        Some(draft) => draft.finish(sent, &body)?,
        None => {
            let created = sent?;
            if let Ok(saved) = Draft::for_key(&format!("account-create/{id}")) {
                saved.sent_from(args.fields.from_file.as_deref());
            }
            created
        }
    };
    report(&created, args.json, "Created", site);
    Ok(())
}

async fn edit(
    args: EditArgs,
    client: &Client,
    site: &str,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    let id = named(&args.account)?;
    let mut body = args.fields.body()?;
    insert_some(&mut body, "location", &args.location);
    insert_some(&mut body, "ror_id", &args.ror_id);
    insert_some(&mut body, "orcid", &args.orcid);
    if args.disable || args.enable {
        body.insert("disabled".into(), json!(args.disable));
    }
    let url = account_url(client, &id);
    let key = format!("account-edit/{id}");

    let mut draft = None;
    if body.is_empty() {
        let Some(ask) = prompter.as_deref_mut() else {
            return Err(
                "Nothing to change: pass --name, --bio, --location, --website, --email, \
                 --ror-id, --orcid, --disable, --enable or --from-file."
                    .into(),
            );
        };
        let (signed_in, current) =
            tokio::join!(client.check_signed_in(), client.get::<Value>(url.clone()));
        signed_in?;
        let saved = Draft::for_key(&key)?;
        if !saved.resume(ask, &mut body)? {
            prompt_edits(ask, &current?, &mut body)?;
        }
        if body.is_empty() {
            eprintln!("No changes to {id}.");
            return Ok(());
        }
        draft = Some(saved);
    }

    let sent = send_until_accepted(client, Method::PATCH, url, &mut body, prompter, question).await;
    let account = match &draft {
        Some(draft) => draft.finish(sent, &body)?,
        None => {
            let account = sent?;
            if let Ok(saved) = Draft::for_key(&key) {
                saved.sent_from(args.fields.from_file.as_deref());
            }
            account
        }
    };
    report(&account, args.json, "Edited", site);
    Ok(())
}

/// The profile's text fields the edit form offers: (label, body key, where
/// the record keeps it).
const FORM: [(&str, &str, &str); 3] = [
    ("Name", "name", "/name"),
    ("Bio", "bio", "/metadata_public/bio"),
    ("Location", "location", "/metadata_public/location"),
];

/// The edit form: each field with its current value, ↑/↓ to move, Enter to
/// change the highlighted one starting from what's there, `s` (or the Save
/// row) to review and send. Only the fields that changed are kept.
fn prompt_edits(
    ask: &mut dyn Prompter,
    current: &Value,
    body: &mut Map<String, Value>,
) -> Result<(), String> {
    let was = |pointer: &str| {
        current
            .pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let id = str_field(current, "account_id");
    let mut edited: Map<String, Value> = Map::new();
    let mut place = Place::default();
    let _screen = ask.fullscreen();
    loop {
        let value = |key: &str, pointer: &str| match edited.get(key) {
            Some(v) => v.as_str().unwrap_or_default().to_string(),
            None => was(pointer),
        };
        let mut rows: Vec<String> = FORM
            .iter()
            .map(|(label, key, pointer)| {
                let shown = one_line(&value(key, pointer));
                if edited.contains_key(*key) {
                    format!("{label:<10} ● {shown}   (was: {})", one_line(&was(pointer)))
                } else {
                    format!("{label:<10}   {shown}")
                }
            })
            .collect();
        rows.push(match edited.len() {
            0 => "Save changes (nothing changed yet)".into(),
            1 => "Save changes (1 field)".into(),
            n => format!("Save changes ({n} fields)"),
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
        match action {
            Action::Back if edited.is_empty() => return Err(crate::prompt::CANCELLED.into()),
            // ← is "back" everywhere else, so leaving with changes asks first.
            Action::Back => {
                ask.clear();
                match ask.confirm(&format!("Discard your changes to {id}?"), false) {
                    Ok(true) => return Err(crate::prompt::CANCELLED.into()),
                    Err(e) if e != crate::prompt::CANCELLED => return Err(e),
                    _ => continue,
                }
            }
            Action::Open if at < FORM.len() => {
                let (label, key, pointer) = FORM[at];
                // The form stays in view above the question.
                ask.clear();
                for (i, row) in rows[..FORM.len()].iter().enumerate() {
                    eprintln!("{} {row}", if i == at { "›" } else { " " });
                }
                eprintln!();
                let start = value(key, pointer);
                let now = match key {
                    "bio" => ask.long_text_or_back(label, &start),
                    _ => ask.input_or_back(label, &start, key != "name"),
                };
                let now = match now {
                    Ok(Some(now)) => now,
                    Ok(None) => continue,
                    Err(e) if e == crate::prompt::CANCELLED => continue,
                    Err(e) if e == crate::prompt::INTERRUPTED => return Err(e),
                    // Anything else (an editor that won't open) is told on
                    // the form, keeping the changes made so far.
                    Err(e) => {
                        place.notice = Some(crate::prompt::describe(&e));
                        continue;
                    }
                };
                if now == was(pointer) {
                    edited.remove(key);
                } else {
                    edited.insert(key.into(), json!(now));
                }
            }
            _ if edited.is_empty() => return Ok(()),
            _ => {
                let review: Vec<String> = FORM
                    .iter()
                    .filter(|(_, key, _)| edited.contains_key(*key))
                    .map(|(label, key, pointer)| {
                        format!(
                            "{label:<10}  {}  →  {}",
                            one_line(&was(pointer)),
                            one_line(&value(key, pointer))
                        )
                    })
                    .collect();
                ask.clear();
                match ask.confirm_or_back(&format!("Save these changes to {id}?"), &review)? {
                    None => continue,
                    Some(false) => return Err(crate::prompt::CANCELLED.into()),
                    Some(true) => {
                        body.extend(edited);
                        return Ok(());
                    }
                }
            }
        }
    }
}

const EDIT_HINT: &str = "↑/↓ move · Enter edit · s save · Esc cancel";

/// How `create` and `edit` ask again for a field the API rejected; a taken
/// ID is a 409 on `account_id`.
fn question(field: &str) -> Option<Question> {
    Some(match field {
        "account_id" => Question::Line("Organization ID", false),
        "name" => Question::Line("Name", false),
        "bio" => Question::Long("Bio"),
        "location" => Question::Line("Location", true),
        "email" => Question::Line("Email", true),
        _ => return None,
    })
}

/// The account a command was given; `run` fills it in for `-i`.
fn named(account: &Option<String>) -> Result<String, String> {
    account
        .clone()
        .ok_or_else(|| "Name the account, or pass -i to pick it.".into())
}

fn account_url(client: &Client, id: &str) -> url::Url {
    client.url(&["accounts", id])
}

fn web_url(site: &str, id: &str) -> String {
    format!("{}/{id}", site.trim_end_matches('/'))
}

fn insert_some(body: &mut Map<String, Value>, key: &str, value: &Option<String>) {
    if let Some(v) = value {
        body.insert(key.into(), json!(v));
    }
}

fn str_field_map(body: &Map<String, Value>, key: &str) -> String {
    body.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// The account as JSON, or a line on stderr for the person and its page on
/// stdout for a script: `url=$(source-coop account create ...)`.
fn report(account: &Value, as_json: bool, verb: &str, site: &str) {
    if as_json {
        crate::output::json(account);
    } else {
        let id = str_field(account, "account_id");
        eprintln!("{verb} {id}");
        println!("{}", web_url(site, id));
    }
}

/// The name, then one `Label  value` row per field shown, then the bio.
/// Emails, flags and the rest are in `--json`.
fn account_lines(
    a: &Value,
    site: &str,
    color: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<String> {
    let paint = |code: &str, s: &str| crate::style::paint(color, code, s);
    let id = str_field(a, "account_id");
    let public = |key: &str| {
        a.pointer(&format!("/metadata_public/{key}"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let date = |key: &str| {
        chrono::DateTime::parse_from_rfc3339(str_field(a, key))
            .map(|d| crate::style::when(color, d.with_timezone(&chrono::Utc), now, false))
            .unwrap_or_default()
    };
    let websites: Vec<&str> = a
        .pointer("/metadata_public/domains")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|d| str_field(d, "domain"))
        .filter(|d| !d.is_empty())
        .collect();
    let emails: Vec<String> = a
        .get("emails")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|e| {
            let address = str_field(e, "address").to_string();
            match e.get("verified").and_then(Value::as_bool) {
                Some(false) => format!("{address} {}", paint("33", "(unverified)")),
                _ => address,
            }
        })
        .collect();
    let disabled = a.get("disabled").and_then(Value::as_bool) == Some(true);
    let rows: Vec<(&str, String)> = [
        ("Account", crate::style::id(color, id)),
        ("Type", str_field(a, "type").to_string()),
        (
            "Disabled",
            if disabled {
                paint("31", "yes")
            } else {
                "no".into()
            },
        ),
        ("Location", public("location")),
        ("Websites", websites.join("\n")),
        ("Email", emails.join("\n")),
        ("ROR ID", public("ror_id")),
        ("ORCID", public("orcid")),
        ("Created", date("created_at")),
        ("Updated", date("updated_at")),
        ("URL", paint("4", &web_url(site, id))),
    ]
    .into_iter()
    .filter(|(_, v)| !v.is_empty())
    .collect();
    let width = rows.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    let mut lines = vec![paint("1", str_field(a, "name")), String::new()];
    for (label, value) in &rows {
        // A value of several lines lines up under its first.
        for (i, part) in value.lines().enumerate() {
            let label = if i == 0 { *label } else { "" };
            lines.push(format!(
                "{}  {part}",
                paint("2", &format!("{label:<width$}"))
            ));
        }
    }
    let bio = public("bio");
    if !bio.is_empty() {
        lines.push(String::new());
        lines.extend(bio.lines().map(String::from));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::scripted::{Answer::*, Script};
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SITE: &str = "https://source.coop";

    fn org(id: &str) -> Value {
        json!({"account_id": id, "type": "organization", "name": format!("{id} name"),
               "disabled": false, "flags": [], "metadata_public": {},
               "created_at": "2026-10-01T00:00:00Z", "updated_at": "2026-10-01T00:00:00Z"})
    }

    /// A stand-in API that knows the caller: "acct", a member of "org" and
    /// invited to "later".
    async fn api_server() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/whoami"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "account": {"account_id": "acct", "type": "individual",
                            "flags": ["create_organizations"]},
                "memberships": [
                    {"account_id": "acct", "membership_account_id": "org",
                     "role": "owners", "state": "member"},
                    {"account_id": "acct", "membership_account_id": "later",
                     "role": "read", "state": "invited"}]
            })))
            .mount(&server)
            .await;
        server
    }

    fn client(server: &MockServer) -> Client {
        Client::new(&server.uri(), Some("tkn".into()), false).unwrap()
    }

    fn create_args(account: Option<&str>) -> CreateArgs {
        CreateArgs {
            account: account.map(String::from),
            fields: Fields::default(),
            json: false,
        }
    }

    fn edit_args() -> EditArgs {
        EditArgs {
            account: Some("org".into()),
            interactive: false,
            fields: Fields::default(),
            location: None,
            ror_id: None,
            orcid: None,
            disable: false,
            enable: false,
            json: false,
        }
    }

    #[tokio::test]
    async fn create_asks_id_name_and_bio_then_reviews_and_can_go_back() {
        let server = api_server().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/accounts"))
            .and(body_json(
                json!({"account_id": "new-org", "name": "Renamed"}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(org("new-org")))
            .expect(1)
            .mount(&server)
            .await;
        let mut ask = Script::new([
            Text("new-org"),
            Default,
            Back,
            Text("Renamed"),
            Text(""),
            Yes(true),
        ]);
        create(create_args(None), &client(&server), SITE, Some(&mut ask))
            .await
            .unwrap();
        assert_eq!(
            ask.asked,
            [
                "Organization ID []",
                "Name [New Org]",
                "Bio (back)",
                "Name [New Org]",
                "Bio (long) []",
                "Create this organization? {Organization  new-org | Name          Renamed} [true]",
            ]
        );
    }

    #[tokio::test]
    async fn create_asks_the_name_again_after_going_back_to_change_the_id() {
        let server = api_server().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/accounts"))
            .and(body_json(
                json!({"account_id": "other-org", "name": "Other Org"}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(org("other-org")))
            .expect(1)
            .mount(&server)
            .await;
        let mut ask = Script::new([
            Text("new-org"),
            Default,
            Back,
            Back,
            Text("other-org"),
            Text("Other Org"),
            Text(""),
            Yes(true),
        ]);
        create(create_args(None), &client(&server), SITE, Some(&mut ask))
            .await
            .unwrap();
        assert_eq!(
            ask.asked,
            [
                "Organization ID []",
                "Name [New Org]",
                "Bio (back)",
                "Name (back)",
                "Organization ID [new-org]",
                "Name [New Org]",
                "Bio (long) []",
                "Create this organization? {Organization  other-org | Name          Other Org} [true]",
            ]
        );
    }

    #[tokio::test]
    async fn create_takes_the_id_from_the_file_without_a_terminal() {
        let server = api_server().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/accounts"))
            .and(body_json(json!({"account_id": "filed-org", "name": "F"})))
            .respond_with(ResponseTemplate::new(201).set_body_json(org("filed-org")))
            .expect(1)
            .mount(&server)
            .await;
        let file = std::env::temp_dir().join(format!("account-create-{}.json", std::process::id()));
        std::fs::write(&file, r#"{"account_id": "filed-org", "name": "F"}"#).unwrap();
        let mut args = create_args(None);
        args.fields.from_file = Some(file.to_string_lossy().into());
        let result = create(args, &client(&server), SITE, None).await;
        let _ = std::fs::remove_file(&file);
        result.unwrap();
    }

    #[tokio::test]
    async fn create_checks_sign_in_before_asking_anything() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/whoami"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "type": "https://source.coop/api/problems/unauthenticated", "title": "T",
                "status": 401, "detail": "Authentication required", "code": "unauthenticated"})))
            .mount(&server)
            .await;
        let mut ask = Script::new([]);
        let err = create(create_args(None), &client(&server), SITE, Some(&mut ask))
            .await
            .unwrap_err();
        assert!(err.contains("This needs you signed in"), "{err}");
        assert!(ask.asked.is_empty());
    }

    #[tokio::test]
    async fn create_without_a_terminal_sends_what_it_was_given() {
        let server = api_server().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/accounts"))
            .and(body_json(json!({"account_id": "new-org", "name": "N",
                                  "websites": ["a.org", "b.org"]})))
            .respond_with(ResponseTemplate::new(201).set_body_json(org("new-org")))
            .expect(1)
            .mount(&server)
            .await;
        let mut args = create_args(Some("new-org"));
        args.fields.name = Some("N".into());
        args.fields.websites = vec!["a.org".into(), "b.org".into()];
        create(args, &client(&server), SITE, None).await.unwrap();

        let err = create(create_args(None), &client(&server), SITE, None)
            .await
            .unwrap_err();
        assert!(err.contains("Name the organization"), "{err}");
    }

    #[tokio::test]
    async fn a_taken_id_is_asked_for_again() {
        let server = api_server().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/accounts"))
            .and(body_json(json!({"account_id": "taken", "name": "N"})))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "type": "https://source.coop/api/problems/conflict", "title": "Conflict",
                "status": 409, "detail": "That ID is taken",
                "errors": [{"pointer": "#/account_id", "detail": "is taken"}]})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/accounts"))
            .and(body_json(json!({"account_id": "free", "name": "N"})))
            .respond_with(ResponseTemplate::new(201).set_body_json(org("free")))
            .expect(1)
            .mount(&server)
            .await;
        let mut args = create_args(Some("taken"));
        args.fields.name = Some("N".into());
        // Only the bio is asked, as the name came by flag: left empty, it's
        // not sent. Then the review, then the ID again.
        let mut ask = Script::new([Text(""), Yes(true), Text("free")]);
        create(args, &client(&server), SITE, Some(&mut ask))
            .await
            .unwrap();
        assert_eq!(ask.asked.last().unwrap(), "Organization ID [taken]");
    }

    #[tokio::test]
    async fn yours_is_your_account_then_the_ones_you_belong_to() {
        let server = api_server().await;
        // An invitation not yet accepted isn't one of yours.
        assert_eq!(yours(&client(&server)).await.unwrap(), ["acct", "org"]);
    }

    #[tokio::test]
    async fn an_account_the_api_hides_is_left_out_not_fatal() {
        let server = api_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/accounts/acct"))
            .respond_with(ResponseTemplate::new(200).set_body_json(org("acct")))
            .mount(&server)
            .await;
        // A disabled organization, to a member who isn't an owner or
        // maintainer.
        Mock::given(method("GET"))
            .and(path("/api/v1/accounts/org"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "type": "https://source.coop/api/problems/not_found", "title": "Not found",
                "status": 404, "detail": "No account org"})))
            .mount(&server)
            .await;
        let records = your_records(&client(&server)).await.unwrap();
        let ids: Vec<&str> = records.iter().map(|a| str_field(a, "account_id")).collect();
        assert_eq!(ids, ["acct"]);
    }

    #[tokio::test]
    async fn edit_sends_its_flags_without_asking() {
        let server = api_server().await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/accounts/org"))
            .and(body_json(
                json!({"bio": "", "location": "Here", "disabled": true}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(org("org")))
            .expect(1)
            .mount(&server)
            .await;
        let mut args = edit_args();
        args.fields.bio = Some(String::new());
        args.location = Some("Here".into());
        args.disable = true;
        let mut ask = Script::new([]);
        edit(args, &client(&server), SITE, Some(&mut ask))
            .await
            .unwrap();
        assert!(ask.asked.is_empty());
    }

    #[tokio::test]
    async fn the_edit_form_sends_only_what_changed() {
        let server = api_server().await;
        let mut current = org("org");
        current["metadata_public"] = json!({"bio": "Old", "location": "There"});
        Mock::given(method("GET"))
            .and(path("/api/v1/accounts/org"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&current))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/accounts/org"))
            .and(body_json(json!({"bio": "New"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(org("org")))
            .expect(1)
            .mount(&server)
            .await;
        let mut ask = Script::new([
            Browse(1, Action::Open),
            Text("New"),
            Browse(3, Action::Open),
            Yes(true),
        ]);
        edit(edit_args(), &client(&server), SITE, Some(&mut ask))
            .await
            .unwrap();
        assert_eq!(
            ask.asked,
            [
                "Edit org [Name         org name] of Name         org name | Bio          Old | \
                 Location     There | Save changes (nothing changed yet) (keys s)",
                "Bio (long) [Old]",
                "Edit org [Bio        ● New   (was: Old)] of Name         org name | \
                 Bio        ● New   (was: Old) | Location     There | Save changes (1 field) (keys s)",
                "Save these changes to org? {Bio         Old  →  New} [true]",
            ]
        );
    }

    #[tokio::test]
    async fn list_i_opens_an_account_and_edits_it_from_its_screen() {
        let server = api_server().await;
        for id in ["acct", "org"] {
            Mock::given(method("GET"))
                .and(path(format!("/api/v1/accounts/{id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(org(id)))
                .mount(&server)
                .await;
        }
        Mock::given(method("PATCH"))
            .and(path("/api/v1/accounts/org"))
            .and(body_json(json!({"name": "Better"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(org("org")))
            .expect(1)
            .mount(&server)
            .await;
        let mut ask = Script::new([
            Browse(1, Action::Open),
            Press(Action::Key('e')),
            Browse(0, Action::Open),
            Text("Better"),
            Browse(3, Action::Open),
            Yes(true),
            Press(Action::Back),
            Browse(1, Action::Back),
        ]);
        let cmd = AccountCommand::List(ListArgs {
            json: false,
            interactive: true,
            no_pager: false,
        });
        run(cmd, &client(&server), SITE, Some(&mut ask))
            .await
            .unwrap();
        assert_eq!(ask.asked[0], "Your accounts [acct  acct name  organization] of acct  acct name  organization | org  org name  organization (keys b)");
        assert_eq!(ask.asked[1], "b browser · e edit · ← back (keys be)");
        // The stub hands back the same record, so nothing looks changed.
        assert_eq!(ask.asked[6], "b browser · e edit · ← back (keys be)");
    }

    #[test]
    fn view_shows_chosen_fields_and_leaves_the_rest_to_json() {
        let mut a = org("org");
        a["flags"] = json!(["create_repositories"]);
        a["metadata_private"] = json!({"internal": 1});
        a["emails"] = json!([{"address": "hi@org.example", "verified": false}]);
        a["metadata_public"] = json!({"bio": "Open data", "ror_id": "05abc",
                                      "domains": [{"domain": "org.example"}]});
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-02T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let text = account_lines(&a, SITE, false, now).join("\n");
        assert_eq!(
            text,
            "org name\n\n\
             Account   org\n\
             Type      organization\n\
             Disabled  no\n\
             Websites  org.example\n\
             Email     hi@org.example (unverified)\n\
             ROR ID    05abc\n\
             Created   2026-10-01T00:00:00Z (1 day ago)\n\
             Updated   2026-10-01T00:00:00Z (1 day ago)\n\
             URL       https://source.coop/org\n\
             \n\
             Open data"
        );
    }
}
