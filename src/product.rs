//! `source-coop product`: list, view, create, edit and delete products through
//! `/api/v1/products`.

use crate::api::{ApiError, Client, Page};
use crate::draft::Draft;
use crate::prompt::{Action, Place, Prompter};
use clap::{Args, Subcommand, ValueEnum};
use clap_complete::engine::ArgValueCompleter;
use reqwest::Method;
use serde_json::{json, Map, Value};
use std::io::{IsTerminal, Write};

#[derive(Subcommand)]
pub enum ProductCommand {
    /// List public products, or one account's products
    #[command(
        after_help = crate::style::examples(&[
            "source-coop product list my-org --json",
            "source-coop product list -q climate --format table",
        ])
    )]
    List(ListArgs),
    /// Show one product
    #[command(after_help = crate::style::examples(&["source-coop product view my-org/my-data --json"]))]
    View(ViewArgs),
    /// Create a product
    #[command(
        after_help = crate::style::examples(&[
            "source-coop product create my-org/my-data -t \"My data\" --visibility public --json",
            "echo '{\"title\": \"My data\"}' | source-coop product create my-org/my-data -F - --json",
        ])
    )]
    Create(CreateArgs),
    /// Change a product's title, description, visibility or state
    #[command(
        after_help = crate::style::examples(&["source-coop product edit my-org/my-data -d \"New description\" --json"])
    )]
    Edit(EditArgs),
    /// Delete a product and, unless --preserve-data, its data
    #[command(after_help = crate::style::examples(&["source-coop product delete my-org/my-data --yes --json"]))]
    Delete(DeleteArgs),
}

impl ProductCommand {
    /// Whether `--json` was asked for, so a failure is reported as JSON too.
    pub fn wants_json(&self) -> bool {
        match self {
            ProductCommand::List(a) => a.json,
            ProductCommand::View(a) => a.json,
            ProductCommand::Create(a) => a.json,
            ProductCommand::Edit(a) => a.json,
            ProductCommand::Delete(a) => a.json,
        }
    }
}

/// Which products `list` shows, or `list -i` picks from.
#[derive(Args, Default)]
pub struct Filters {
    /// This account's products (all public products when omitted)
    #[arg(add = ArgValueCompleter::new(crate::complete::account))]
    account: Option<String>,

    /// Only products whose title, description or IDs contain this text
    #[arg(long, short = 'q')]
    search: Option<String>,

    /// Only products with every one of these tags (comma-separated)
    #[arg(long)]
    tags: Option<String>,

    /// Only featured products
    #[arg(long)]
    featured: bool,
}

impl Filters {
    fn url(&self, client: &Client) -> url::Url {
        let mut url = match &self.account {
            Some(account) => client.url(&["products", account]),
            None => client.url(&["products"]),
        };
        {
            let mut q = url.query_pairs_mut();
            if let Some(s) = &self.search {
                q.append_pair("q", s);
            }
            if let Some(t) = &self.tags {
                q.append_pair("tags", t);
            }
            if self.featured {
                q.append_pair("featured", "true");
            }
        }
        url
    }
}

#[derive(Args)]
pub struct ListArgs {
    #[command(flatten)]
    filters: Filters,

    /// Maximum number of products to list [default: 30, or all in a pager]
    #[arg(long, short = 'L')]
    limit: Option<usize>,

    /// Start after the products already listed: the cursor a previous list
    /// printed for its next page
    #[arg(long)]
    cursor: Option<String>,

    /// How to lay out the products: `details` (each product's fields, as
    /// `view` shows them) or `table` (one row each; tab-separated when piped)
    #[arg(long, value_enum, default_value_t = ListFormat::Details)]
    format: ListFormat,

    /// Print the products as JSON
    #[arg(long)]
    json: bool,

    /// Pick a product from the list, then view, open, edit or delete it
    #[arg(long, short = 'i', conflicts_with_all = ["json", "format", "cursor", "limit"])]
    interactive: bool,

    /// Print straight to the terminal instead of through $SOURCE_PAGER,
    /// $PAGER or `less -FRX`
    #[arg(long)]
    no_pager: bool,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ListFormat {
    Details,
    Table,
}

#[derive(Args)]
pub struct ViewArgs {
    /// The product, as ACCOUNT/PRODUCT (with -i, picked from public products
    /// when omitted)
    #[arg(
        required_unless_present = "interactive",
        add = ArgValueCompleter::new(crate::complete::product)
    )]
    product: Option<ProductRef>,

    /// Show the product with shortcuts: b browser, e edit, d delete, ← back
    #[arg(long, short = 'i', conflicts_with_all = ["web", "json"])]
    interactive: bool,

    /// Open the product's page in the browser instead
    #[arg(long, short = 'w')]
    web: bool,

    /// Print the product as JSON
    #[arg(long)]
    json: bool,
}

/// The fields `product create` and `product edit` both take.
#[derive(Args, Default)]
pub struct Fields {
    /// The product's title
    #[arg(long, short = 't')]
    title: Option<String>,

    /// The product's description
    #[arg(long, short = 'd')]
    description: Option<String>,

    /// public, unlisted or restricted
    #[arg(long)]
    visibility: Option<String>,

    /// Read fields from a JSON object in this file (`-` for stdin); flags win
    #[arg(long, short = 'F', value_name = "PATH")]
    from_file: Option<String>,
}

#[derive(Args)]
pub struct CreateArgs {
    /// The new product, as ACCOUNT/PRODUCT (prompted for when omitted)
    #[arg(add = ArgValueCompleter::new(crate::complete::new_product))]
    product: Option<ProductRef>,

    #[command(flatten)]
    fields: Fields,

    /// The data connection that stores the product's data (fixed once created)
    #[arg(long = "data-connection")]
    data_connection_id: Option<String>,

    /// Print the new product as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct EditArgs {
    /// The product, as ACCOUNT/PRODUCT (with -i, picked from your account's
    /// products when omitted)
    #[arg(
        required_unless_present = "interactive",
        add = ArgValueCompleter::new(crate::complete::product)
    )]
    product: Option<ProductRef>,

    /// Pick the product from your account's products when it isn't named
    #[arg(long, short = 'i')]
    interactive: bool,

    #[command(flatten)]
    fields: Fields,

    /// Deactivate the product
    #[arg(long, conflicts_with = "enable")]
    disable: bool,

    /// Reactivate a deactivated product (admins only)
    #[arg(long)]
    enable: bool,

    /// Print the edited product as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct DeleteArgs {
    /// The product, as ACCOUNT/PRODUCT (with -i, picked from your account's
    /// products when omitted)
    #[arg(
        required_unless_present = "interactive",
        add = ArgValueCompleter::new(crate::complete::product)
    )]
    product: Option<ProductRef>,

    /// Pick the product from your account's products when it isn't named
    #[arg(long, short = 'i', conflicts_with = "yes")]
    interactive: bool,

    /// Keep the product's objects in storage
    #[arg(long)]
    preserve_data: bool,

    /// Skip the confirmation prompt
    #[arg(long, short = 'y')]
    yes: bool,

    /// Print the deleted product as JSON
    #[arg(long)]
    json: bool,
}

/// `ACCOUNT/PRODUCT`, the way products are named everywhere else.
#[derive(Clone, Debug, PartialEq)]
pub struct ProductRef {
    pub account_id: String,
    pub product_id: String,
}

impl std::str::FromStr for ProductRef {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim_matches('/').split_once('/') {
            Some((a, p)) if !a.is_empty() && !p.is_empty() && !p.contains('/') => Ok(ProductRef {
                account_id: a.to_string(),
                product_id: p.to_string(),
            }),
            _ => Err(format!("expected ACCOUNT/PRODUCT, got '{s}'")),
        }
    }
}

impl std::fmt::Display for ProductRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.account_id, self.product_id)
    }
}

impl ProductRef {
    fn web_url(&self, site: &str) -> String {
        format!(
            "{}/{}/{}",
            site.trim_end_matches('/'),
            self.account_id,
            self.product_id
        )
    }
}

pub async fn run(
    cmd: ProductCommand,
    client: &Client,
    site: &str,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    match cmd {
        ProductCommand::List(args) if args.interactive => {
            let ask = prompter.ok_or(NEEDS_TERMINAL)?;
            let url = args.filters.url(client);
            browse_products(url, client, site, ask, false)
                .await
                .map(drop)
        }
        ProductCommand::List(args) => list(args, client, site).await,
        ProductCommand::View(args) => view(args, client, site, prompter).await,
        ProductCommand::Create(args) => create(args, client, site, prompter).await,
        // Without a product, clap has required -i: choose one, then carry on
        // as if it had been named.
        ProductCommand::Edit(mut args) if args.product.is_none() => {
            let ask = prompter.ok_or(NEEDS_TERMINAL)?;
            let url = own_products(client).await?;
            let Some(p) = browse_products(url, client, site, &mut *ask, true).await? else {
                return Ok(());
            };
            args.product = Some(p);
            edit(args, client, site, Some(ask)).await
        }
        ProductCommand::Edit(args) => edit(args, client, site, prompter).await,
        ProductCommand::Delete(mut args) if args.product.is_none() => {
            let ask = prompter.ok_or(NEEDS_TERMINAL)?;
            let url = own_products(client).await?;
            let Some(p) = browse_products(url, client, site, &mut *ask, true).await? else {
                return Ok(());
            };
            args.product = Some(p);
            delete(args, client, Some(ask)).await
        }
        ProductCommand::Delete(args) => delete(args, client, prompter).await,
    }
}

pub(crate) const NEEDS_TERMINAL: &str = "-i needs a terminal to pick from.";

/// The product a command was given; `run` fills it in for `-i`.
fn named(product: &Option<ProductRef>) -> Result<ProductRef, String> {
    product
        .clone()
        .ok_or_else(|| "Name the product as ACCOUNT/PRODUCT, or pass -i to pick it.".into())
}

async fn list(args: ListArgs, client: &Client, site: &str) -> Result<(), String> {
    let url = args.filters.url(client);

    // On a terminal, stream pages into a pager as they come: a full pipe holds
    // off fetching until the user scrolls, so without -L it goes to the end.
    let mut pager = (!args.json && !args.no_pager && std::io::stdout().is_terminal())
        .then(Pager::spawn)
        .flatten();
    let limit = args
        .limit
        .unwrap_or(if pager.is_some() { usize::MAX } else { 30 });

    // Follow next_cursor until there are enough, asking for no more per page
    // than the API's maximum.
    let mut items: Vec<Value> = vec![];
    let mut count = 0;
    let mut layout = Layout::new(args.format, std::io::stdout().is_terminal(), site);
    let mut cursor = args.cursor.clone();
    let mut quit = false;
    while count < limit {
        let page = fetch_page(client, &url, limit - count, cursor.as_deref()).await?;
        count += page.items.len();
        cursor = page.next_cursor;
        match &mut pager {
            Some(_) if page.items.is_empty() => {}
            Some(p) => {
                // The user quit the pager: nothing left to show.
                if p.write(&layout.page(&page.items)).is_err() {
                    quit = true;
                    break;
                }
            }
            None => items.extend(page.items),
        }
        if cursor.is_none() {
            break;
        }
    }
    // ponytail: no truncating to the limit. A search page can hold more than
    // asked for, and dropping the extra would skip them: the cursor resumes
    // after the whole page.

    let paged = pager.is_some();
    drop(pager);
    if args.json {
        print_json(&Value::Array(items));
    } else if count == 0 {
        eprintln!("No products found.");
    } else if !paged {
        for line in layout.page(&items) {
            println!("{line}");
        }
    }
    // A pager that stopped at -L still has a next page to offer; one the user
    // quit early doesn't, as its cursor would skip what was never shown.
    if let Some(cursor) = cursor.filter(|_| !quit && std::io::stderr().is_terminal()) {
        eprintln!("\nMore products: run again with --cursor {cursor}");
    }
    Ok(())
}

/// How many products `-i` fetches at a time.
const PICK_PAGE: usize = 50;

/// The shortcuts on a product, wherever one is highlighted or shown.
/// Shortcuts in the list: only harmless ones. Editing or deleting a product
/// takes opening it first, so a stray key on a long list changes nothing.
const LIST_KEYS: &str = "b";
/// Shortcuts on an opened product.
const SCREEN_KEYS: &str = "bed";
const LIST_HINT: &str = "↑↓ move · → open to edit or delete · b browser · / filter · ← quit";
const CHOOSE_HINT: &str = "↑↓ move · → choose · / filter · ← quit";
const SCREEN_HINT: &str = "b browser · e edit · d delete · ← back";

/// A listing being picked from, a page at a time; the picker asks for the
/// next page as the highlight nears the end.
struct Listing {
    url: url::Url,
    items: Vec<Value>,
    cursor: Option<String>,
}

impl Listing {
    async fn open(client: &Client, url: url::Url) -> Result<Self, String> {
        let page = fetch_page(client, &url, PICK_PAGE, None).await?;
        Ok(Listing {
            url,
            items: page.items,
            cursor: page.next_cursor,
        })
    }

    async fn more(&mut self, client: &Client) -> Result<(), String> {
        let page = fetch_page(client, &self.url, PICK_PAGE, self.cursor.as_deref()).await?;
        self.items.extend(page.items);
        self.cursor = page.next_cursor;
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.items.is_empty() && self.cursor.is_none()
    }

    /// `id  Title  visibility`, the ID gray and the visibility colored as
    /// `view` shows them.
    fn labels(&self) -> Vec<String> {
        let color = crate::style::on_stderr();
        self.items
            .iter()
            .map(|p| {
                let id = crate::style::id(color, &name(p));
                let visibility = visibility_label(color, str_field(p, "visibility"));
                format!("{id}  {}  {visibility}", str_field(p, "title"))
                    .trim_end()
                    .to_string()
            })
            .collect()
    }
}

/// A product's visibility, green when public and yellow otherwise, so the
/// ones not everyone can see stand out.
fn visibility_label(color: bool, visibility: &str) -> String {
    match visibility {
        "public" => crate::style::paint(color, "32", visibility),
        "" => String::new(),
        v => crate::style::paint(color, "33", v),
    }
}

/// Move through `url`'s products until they back out (None). For `list -i`,
/// opening one shows it as `view` does and the shortcuts act on it; when
/// `choosing` (`view|edit|delete -i` without a product), opening one returns it.
async fn browse_products(
    url: url::Url,
    client: &Client,
    site: &str,
    ask: &mut dyn Prompter,
    choosing: bool,
) -> Result<Option<ProductRef>, String> {
    let (keys, hint) = if choosing {
        ("", CHOOSE_HINT)
    } else {
        (LIST_KEYS, LIST_HINT)
    };
    let mut listing = Listing::open(client, url.clone()).await?;
    if listing.is_empty() {
        eprintln!("No products found.");
        return Ok(None);
    }
    // Only the listing of all public products takes a search (`q`); an
    // account's is filtered on what's loaded.
    let server_search = url.path() == client.url(&["products"]).path();
    let fresh = || Place {
        server_search,
        ..Place::default()
    };
    let mut place = fresh();
    // The search the listing shows, from `/` and Enter.
    let mut query: Option<String> = None;
    // Every screen clears and redraws until they leave, and leaving puts the
    // terminal back as it was. Errors propagate after it's dropped.
    let _screen = ask.fullscreen();
    loop {
        // While more load, the list stays up to be redrawn in place.
        if place.drawn == 0 {
            ask.clear();
        }
        let label = match &query {
            Some(q) => format!("Products matching \"{q}\" · from the server"),
            None => "Products".into(),
        };
        let more = listing.cursor.is_some();
        // Back from search results is back to the whole listing, not out.
        let hint = match query {
            Some(_) => hint.replace("← quit", "← all products"),
            None => hint.to_string(),
        };
        let action = ask.browse(&label, &listing.labels(), &mut place, more, keys, &hint)?;
        let i = place.at;
        let (after, notice) = match action {
            // Back from search results is back to the whole listing.
            Action::Back if query.take().is_some() => {
                listing = Listing::open(client, url.clone()).await?;
                place = fresh();
                continue;
            }
            Action::Back => return Ok(None),
            Action::Search => {
                let q = std::mem::take(&mut place.filter).trim().to_string();
                listing = Listing::open(client, with_query(&url, &q)).await?;
                query = Some(q);
                place = fresh();
                continue;
            }
            Action::More => {
                listing.more(client).await?;
                continue;
            }
            Action::Open if choosing => return name(&listing.items[i]).parse().map(Some),
            Action::Open => product_screen(&mut listing.items[i], client, site, ask).await?,
            Action::Key(key) => act(key, &mut listing.items[i], client, site, ask).await?,
        };
        if after == After::Deleted {
            listing.items.remove(i);
        }
        place.notice = notice;
    }
}

/// `url` searching for `q`, in place of any search it had (`-q`), keeping its
/// other filters.
fn with_query(url: &url::Url, q: &str) -> url::Url {
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != "q")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let mut searched = url.clone();
    searched
        .query_pairs_mut()
        .clear()
        .extend_pairs(kept)
        .append_pair("q", q);
    searched
}

/// The listing of the signed-in account's products, for `edit -i` and
/// `delete -i`.
async fn own_products(client: &Client) -> Result<url::Url, String> {
    let me: Value = client.get(client.url(&["whoami"])).await?;
    let account = me
        .pointer("/account/account_id")
        .and_then(Value::as_str)
        .ok_or("Couldn't tell which account you're signed in as.")?;
    Ok(client.url(&["products", account]))
}

/// Whether an action left the product in place.
#[derive(PartialEq)]
enum After {
    Kept,
    Deleted,
}

/// One product as `view` shows it, with the shortcuts, until back. Returns
/// what happened to it and anything to tell the list about.
async fn product_screen(
    product: &mut Value,
    client: &Client,
    site: &str,
    ask: &mut dyn Prompter,
) -> Result<(After, Option<String>), String> {
    let color = crate::style::wanted(std::io::stdout().is_terminal());
    let mut notice: Option<String> = None;
    loop {
        ask.clear();
        for line in product_lines(product, site, color) {
            println!("{line}");
        }
        println!();
        // What the last shortcut did, once, as the screen redraws.
        if let Some(n) = notice.take() {
            eprintln!("{}", crate::style::paint(color, "33", &n));
        }
        match ask.keypress(SCREEN_HINT, SCREEN_KEYS)? {
            // keypress never pages or searches; those are only from browse.
            Action::Back | Action::Open | Action::More | Action::Search => {
                return Ok((After::Kept, None))
            }
            Action::Key(key) => match act(key, product, client, site, ask).await? {
                (After::Deleted, said) => return Ok((After::Deleted, said)),
                (After::Kept, said) => notice = said,
            },
        }
    }
}

/// Run a shortcut on `product` with the same code as the commands: `b` opens
/// it in the browser, `e` edits it (then fetches it as it now is), `d`
/// deletes it. Returns what happened to it and what to tell the person, so a
/// screen that redraws can still say it; a failed action is told, not
/// returned, so the list or screen it came from carries on.
async fn act(
    key: char,
    product: &mut Value,
    client: &Client,
    site: &str,
    ask: &mut dyn Prompter,
) -> Result<(After, Option<String>), String> {
    let p: ProductRef = name(product).parse()?;
    let told = |e: String| Some(crate::prompt::describe(&e));
    let notice = match key {
        'b' => {
            let url = p.web_url(site);
            match open::that(&url) {
                Ok(()) => Some(format!("Opened {url} in your browser.")),
                Err(e) => Some(format!("Couldn't open a browser: {e}")),
            }
        }
        'e' => {
            let args = EditArgs {
                product: Some(p.clone()),
                interactive: false,
                fields: Fields::default(),
                disable: false,
                enable: false,
                json: false,
            };
            let refetched = match edit(args, client, site, Some(&mut *ask)).await {
                Ok(()) => client
                    .get(product_url(client, &p))
                    .await
                    .map_err(String::from),
                Err(e) => Err(e),
            };
            match refetched {
                Ok(now) if now == *product => Some(format!("No changes to {p}.")),
                Ok(now) => {
                    *product = now;
                    Some(format!("Edited {p}."))
                }
                Err(e) => told(e),
            }
        }
        'd' => {
            let args = DeleteArgs {
                product: Some(p.clone()),
                interactive: false,
                preserve_data: false,
                yes: false,
                json: false,
            };
            match delete(args, client, Some(&mut *ask)).await {
                Ok(()) => return Ok((After::Deleted, Some(format!("Deleted {p}.")))),
                Err(e) => told(e),
            }
        }
        _ => None,
    };
    Ok((After::Kept, notice))
}

/// One page of a listing: up to `limit` products (the API caps a page at
/// 100), from `cursor` on.
pub(crate) async fn fetch_page(
    client: &Client,
    url: &url::Url,
    limit: usize,
    cursor: Option<&str>,
) -> Result<Page<Value>, String> {
    let mut url = url.clone();
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("limit", &limit.min(100).to_string());
        if let Some(c) = cursor {
            q.append_pair("cursor", c);
        }
    }
    Ok(client.get(url).await?)
}

/// `$SOURCE_PAGER`, `$PAGER` or `less -FRX`, reading what is written to its
/// stdin. Dropping it closes stdin and waits for the user to quit.
pub(crate) struct Pager(std::process::Child);

impl Pager {
    /// None when the pager is empty or `cat`, or won't start (no `less` on
    /// Windows): print straight to stdout.
    pub(crate) fn spawn() -> Option<Pager> {
        let cmd = std::env::var("SOURCE_PAGER")
            .or_else(|_| std::env::var("PAGER"))
            .unwrap_or_else(|_| "less -FRX".into());
        let mut words = cmd.split_whitespace();
        let program = words.next().filter(|p| *p != "cat")?;
        std::process::Command::new(program)
            .args(words)
            .stdin(std::process::Stdio::piped())
            .spawn()
            .ok()
            .map(Pager)
    }

    pub(crate) fn write(&mut self, rows: &[String]) -> std::io::Result<()> {
        let stdin = self.0.stdin.as_mut().expect("piped stdin");
        stdin.write_all((rows.join("\n") + "\n").as_bytes())
    }
}

impl Drop for Pager {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        let _ = self.0.wait();
    }
}

async fn view(
    args: ViewArgs,
    client: &Client,
    site: &str,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    if args.interactive {
        let ask = prompter.ok_or(NEEDS_TERMINAL)?;
        let chosen = match args.product {
            None => {
                browse_products(Filters::default().url(client), client, site, ask, true).await?
            }
            named => named,
        };
        let Some(p) = chosen else { return Ok(()) };
        let mut product: Value = client.get(product_url(client, &p)).await?;
        product_screen(&mut product, client, site, ask).await?;
        return Ok(());
    }
    let p = named(&args.product)?;
    if args.web {
        let url = p.web_url(site);
        eprintln!("Opening {url} in your browser.");
        return open::that(&url).map_err(|e| format!("Couldn't open a browser: {e}"));
    }
    let product: Value = client.get(product_url(client, &p)).await?;
    if args.json {
        print_json(&product);
    } else {
        print_product(&product, site);
    }
    Ok(())
}

const VISIBILITIES: [&str; 3] = ["public", "unlisted", "restricted"];

/// The accounts `me`, a `/whoami` session, may create products under, as
/// source.coop decides (`createRepository` in its authz): their own when it
/// has the `create_repositories` flag, then each organization they're an
/// org-wide owner or maintainer of; none for a disabled or service account.
/// The flag says whether they're an admin, who may create under any account.
/// The API still decides; this only chooses what to offer.
pub(crate) fn creatable_accounts(me: &Value) -> (Vec<String>, bool) {
    let account = me.get("account").unwrap_or(&Value::Null);
    let has_flag = |flag: &str| {
        account
            .get("flags")
            .and_then(Value::as_array)
            .is_some_and(|fs| fs.iter().any(|f| f.as_str() == Some(flag)))
    };
    if account.get("disabled").and_then(Value::as_bool) == Some(true)
        || str_field(account, "type") == "service"
        || str_field(account, "account_id").is_empty()
    {
        return (vec![], false);
    }
    let mut accounts = vec![];
    if has_flag("create_repositories") || has_flag("admin") {
        accounts.push(str_field(account, "account_id").to_string());
    }
    let orgs = me
        .get("memberships")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|m| {
            str_field(m, "state") == "member"
                // A product-scoped membership names its product `product_id`,
                // or `repository_id` on servers that predate the rename.
                && ["product_id", "repository_id"]
                    .iter()
                    .all(|k| m.get(*k).is_none_or(Value::is_null))
                && matches!(str_field(m, "role"), "owners" | "maintainers")
        })
        .map(|m| str_field(m, "membership_account_id").to_string());
    for org in orgs {
        if !org.is_empty() && !accounts.contains(&org) {
            accounts.push(org);
        }
    }
    (accounts, has_flag("admin"))
}

/// What `create` is about to send, as `Label  value` rows to look over: the
/// description's first line only, marked when there's more.
fn review_lines(name: &str, body: &Map<String, Value>) -> Vec<String> {
    let field = |key: &str| body.get(key).and_then(Value::as_str).unwrap_or_default();
    let description = one_line(field("description"));
    [
        ("Product", name.to_string()),
        ("Title", field("title").to_string()),
        ("Description", description),
        ("Data connection", field("data_connection_id").to_string()),
        ("Visibility", field("visibility").to_string()),
    ]
    .iter()
    .map(|(label, value)| format!("{label:<15}  {value}"))
    .collect()
}

/// `create`'s questions, in the order they're asked.
#[derive(Clone, Copy)]
enum Step {
    Account,
    AccountId,
    ProductId,
    Title,
    Description,
    Connection,
    Visibility,
    Review,
}

/// Where a step leads: on to the next (None once all are answered), having
/// asked or not, or back to the question before.
enum Next {
    Asked(Option<Step>),
    Skipped(Option<Step>),
    Back,
}

/// Ask for what a new product still needs: the account (from the ones they
/// may create in) and ID unless `named`, then each field `body` doesn't have.
/// ↑ or ← goes back to the question before, starting from the answer given
/// there; later answers are kept. A field from a flag, a file or a resumed
/// draft isn't asked either way. The defaults are the web form's, and the
/// choices are the data connections the account could use and the
/// visibilities the chosen one allows; the API still decides what's
/// acceptable. Returns the product and its draft.
async fn ask_create(
    ask: &mut dyn Prompter,
    client: &Client,
    me: &Value,
    named: Option<ProductRef>,
    body: &mut Map<String, Value>,
) -> Result<(ProductRef, Draft), String> {
    const ANOTHER: &str = "Another account…";
    let (accounts, anywhere) = creatable_accounts(me);
    let mut options = accounts.clone();
    if anywhere {
        options.push(ANOTHER.into());
    }
    let mut account = named.as_ref().map(|p| p.account_id.clone());
    if account.is_none() && !anywhere {
        match accounts.as_slice() {
            [] => {
                return Err("You can't create products yet: your own account needs \
                     permission from source.coop, or an organization's owner can make \
                     you one of its maintainers."
                    .into())
            }
            [only] => {
                eprintln!("Creating under {only}, the only account you can create products in.");
                account = Some(only.clone());
            }
            _ => {}
        }
    }
    let choose_account = account.is_none();
    let mut product_id = named
        .as_ref()
        .map(|p| p.product_id.clone())
        .unwrap_or_default();
    let mut given: Vec<String> = body.keys().cloned().collect();
    let mut picked = 0;
    let mut draft: Option<(String, Draft)> = None;
    let mut connections: Option<(String, Vec<Value>)> = None;
    let mut allowed: Vec<String> = VISIBILITIES.iter().map(|v| v.to_string()).collect();
    // An answer given earlier, to start from when the question comes again.
    let current = |body: &Map<String, Value>, key: &str| {
        body.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };

    let mut asked: Vec<Step> = vec![];
    let mut step = Some(Step::Account);
    while let Some(now) = step {
        let next = match now {
            Step::Account if !choose_account => Next::Skipped(Some(Step::ProductId)),
            Step::Account => match ask.select_or_back("Account", &options, picked)? {
                None => Next::Back,
                Some(i) if options[i] == ANOTHER => {
                    picked = i;
                    Next::Asked(Some(Step::AccountId))
                }
                Some(i) => {
                    picked = i;
                    account = Some(options[i].clone());
                    Next::Asked(Some(Step::ProductId))
                }
            },
            Step::AccountId => {
                let was = account.clone().unwrap_or_default();
                match ask.input_or_back("Account ID", &was, false)? {
                    None => Next::Back,
                    Some(a) => {
                        account = Some(a.trim().to_string());
                        Next::Asked(Some(Step::ProductId))
                    }
                }
            }
            Step::ProductId => {
                let next = if named.is_some() {
                    Next::Skipped(Some(Step::Title))
                } else {
                    match ask.input_or_back("Product ID", &product_id, false)? {
                        None => Next::Back,
                        Some(id) => {
                            product_id = id.trim().to_string();
                            Next::Asked(Some(Step::Title))
                        }
                    }
                };
                // Offer a saved draft once per product named, as soon as it is.
                if !matches!(next, Next::Back) {
                    let key = format!(
                        "product-create/{}/{product_id}",
                        account.as_deref().unwrap_or("")
                    );
                    if draft.as_ref().map(|(k, _)| k) != Some(&key) {
                        let saved = Draft::for_key(&key)?;
                        saved.resume(ask, body)?;
                        // What the draft filled in isn't asked, as before.
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
            Step::Title if given.iter().any(|k| k == "title") => {
                Next::Skipped(Some(Step::Description))
            }
            Step::Title => {
                let was = match current(body, "title") {
                    t if t.is_empty() => title_from_id(&product_id),
                    t => t,
                };
                match ask.input_or_back("Title", &was, false)? {
                    None => Next::Back,
                    Some(title) => {
                        body.insert("title".into(), json!(title));
                        Next::Asked(Some(Step::Description))
                    }
                }
            }
            Step::Description if given.iter().any(|k| k == "description") => {
                Next::Skipped(Some(Step::Connection))
            }
            Step::Description => {
                match ask.long_text_or_back("Description", &current(body, "description"))? {
                    None => Next::Back,
                    Some(description) => {
                        body.insert("description".into(), json!(description));
                        Next::Asked(Some(Step::Connection))
                    }
                }
            }
            Step::Connection if given.iter().any(|k| k == "data_connection_id") => {
                Next::Skipped(Some(Step::Visibility))
            }
            Step::Connection => {
                let account_id = account.clone().unwrap_or_default();
                if connections.as_ref().map(|(a, _)| a) != Some(&account_id) {
                    connections = Some((
                        account_id.clone(),
                        usable_connections(client, &account_id).await,
                    ));
                }
                let usable = &connections.as_ref().expect("just fetched").1;
                let was = current(body, "data_connection_id");
                if usable.is_empty() {
                    match ask.input_or_back("Data connection ID", &was, false)? {
                        None => Next::Back,
                        Some(id) => {
                            body.insert("data_connection_id".into(), json!(id));
                            Next::Asked(Some(Step::Visibility))
                        }
                    }
                } else {
                    let labels: Vec<String> = usable.iter().map(connection_label).collect();
                    let at = usable
                        .iter()
                        .position(|c| str_field(c, "data_connection_id") == was)
                        .unwrap_or(0);
                    match ask.select_or_back("Data connection", &labels, at)? {
                        None => Next::Back,
                        Some(i) => {
                            let chosen = &usable[i];
                            body.insert(
                                "data_connection_id".into(),
                                json!(str_field(chosen, "data_connection_id")),
                            );
                            allowed = allowed_visibilities(Some(chosen));
                            Next::Asked(Some(Step::Visibility))
                        }
                    }
                }
            }
            Step::Visibility if given.iter().any(|k| k == "visibility") => {
                Next::Skipped(Some(Step::Review))
            }
            Step::Visibility => {
                let was = current(body, "visibility");
                let at = allowed
                    .iter()
                    .position(|v| *v == was)
                    .or_else(|| allowed.iter().position(|v| v == "public"))
                    .unwrap_or(0);
                match ask.select_or_back("Visibility", &allowed, at)? {
                    None => Next::Back,
                    Some(i) => {
                        body.insert("visibility".into(), json!(allowed[i]));
                        Next::Asked(Some(Step::Review))
                    }
                }
            }
            // A last look at everything before anything is created, when
            // something was asked: a run given every field by flag or file
            // goes straight through, as it did.
            Step::Review if asked.is_empty() => Next::Skipped(None),
            Step::Review => {
                let name = format!("{}/{product_id}", account.as_deref().unwrap_or(""));
                match ask.confirm_or_back("Create this product?", &review_lines(&name, body))? {
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
            // Back from the first question asks it again.
            Next::Back => asked.pop().or(Some(now)),
        };
    }

    let product = format!("{}/{product_id}", account.unwrap_or_default()).parse()?;
    let (_, draft) = draft.expect("the product step always opens one");
    Ok((product, draft))
}

async fn create(
    args: CreateArgs,
    client: &Client,
    site: &str,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    let mut body = read_fields(args.fields.from_file.as_deref())?;
    insert_some(&mut body, "title", args.fields.title);
    insert_some(&mut body, "description", args.fields.description);
    insert_some(&mut body, "visibility", args.fields.visibility);
    insert_some(&mut body, "data_connection_id", args.data_connection_id);

    // Before the first question, so nobody types a product only to be refused.
    let me = match prompter {
        Some(_) => Some(client.check_signed_in().await?),
        None => None,
    };
    let (product, draft) = match (prompter.as_deref_mut(), &me) {
        (Some(ask), Some(me)) => {
            let (product, draft) = ask_create(ask, client, me, args.product, &mut body).await?;
            (product, Some(draft))
        }
        _ => match args.product {
            Some(p) => (p, None),
            None => return Err("Name the product to create, as ACCOUNT/PRODUCT.".into()),
        },
    };
    body.insert("product_id".into(), json!(product.product_id));
    let key = format!("product-create/{product}");

    let url = client.url(&["products", &product.account_id]);
    let sent = send_until_accepted(client, Method::POST, url, &mut body, prompter).await;
    let created = match &draft {
        Some(draft) => draft.finish(sent, &body)?,
        None => {
            let created = sent?;
            if let Ok(saved) = Draft::for_key(&key) {
                saved.sent_from(args.fields.from_file.as_deref());
            }
            created
        }
    };
    report(&created, args.json, "Created", site);
    Ok(())
}

/// The fields a person can be asked for again when the API rejects them.
const REASKABLE: [&str; 5] = [
    "product_id",
    "title",
    "description",
    "visibility",
    "data_connection_id",
];

/// Send `body`, and when the API rejects some of its fields and someone is
/// there to answer, show why and ask for just those fields again, keeping
/// every other answer. The API stays the only judge of what's acceptable.
async fn send_until_accepted(
    client: &Client,
    method: Method,
    url: url::Url,
    body: &mut Map<String, Value>,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<Value, String> {
    loop {
        match client
            .request::<Value>(method.clone(), url.clone(), Some(&*body))
            .await
        {
            Ok(product) => return Ok(product),
            Err(e) => match prompter.as_deref_mut() {
                Some(ask) if reaskable(&e) => {
                    eprintln!("{e}");
                    reask(ask, &e, body)?;
                }
                _ => return Err(e.into()),
            },
        }
    }
}

/// A 400 naming only fields a person can answer again.
fn reaskable(e: &ApiError) -> bool {
    e.status == Some(reqwest::StatusCode::BAD_REQUEST)
        && !e.field_errors.is_empty()
        && e.field_errors
            .keys()
            .all(|f| REASKABLE.contains(&f.as_str()))
}

fn reask(
    ask: &mut dyn Prompter,
    e: &ApiError,
    body: &mut Map<String, Value>,
) -> Result<(), String> {
    for field in e.field_errors.keys() {
        let current = body
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let answer = match field.as_str() {
            "product_id" => ask.input("Product ID", &current, false)?,
            "title" => ask.input("Title", &current, false)?,
            "description" => ask.long_text("Description", &current)?,
            "visibility" => {
                let options: Vec<String> = VISIBILITIES.iter().map(|v| v.to_string()).collect();
                let default = options.iter().position(|v| *v == current).unwrap_or(0);
                options[ask.select("Visibility", &options, default)?].clone()
            }
            "data_connection_id" => ask.input("Data connection ID", &current, false)?,
            _ => unreachable!("reaskable() checked every field"),
        };
        body.insert(field.clone(), json!(answer));
    }
    Ok(())
}

/// The data connections a product of `account_id` could be stored on, as the
/// API judges them (`usable_for`): the platform's own the caller may use, and
/// the account's own. Empty if they can't be listed, in which case the caller
/// asks for an ID instead.
async fn usable_connections(client: &Client, account_id: &str) -> Vec<Value> {
    let mut url = client.url(&["data-connections"]);
    url.query_pairs_mut().append_pair("usable_for", account_id);
    match client.get::<Page<Value>>(url).await {
        Ok(page) => page.items,
        Err(_) => vec![],
    }
}

/// The visibilities a product on connection `c` may have: its
/// `allowed_visibilities`, or all of them when it doesn't say.
fn allowed_visibilities(c: Option<&Value>) -> Vec<String> {
    let vs: Vec<String> = c
        .and_then(|c| c.get("allowed_visibilities"))
        .and_then(Value::as_array)
        .map(|vs| {
            vs.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    if vs.is_empty() {
        VISIBILITIES.iter().map(|v| v.to_string()).collect()
    } else {
        vs
    }
}

/// The data connection a product's data lives on: its primary mirror's
/// (flagged on the mirror, or named by `primary_mirror`), or its only one's.
fn primary_connection(p: &Value) -> Option<String> {
    let mirrors = p.pointer("/metadata/mirrors")?.as_object()?;
    let primary = p
        .pointer("/metadata/primary_mirror")
        .and_then(Value::as_str);
    let (key, m) = mirrors
        .iter()
        .find(|(key, m)| {
            m.get("is_primary").and_then(Value::as_bool) == Some(true)
                || primary == Some(key.as_str())
        })
        .or_else(|| (mirrors.len() == 1).then(|| mirrors.iter().next())?)?;
    Some(match str_field(m, "connection_id") {
        "" => key.clone(),
        c => c.to_string(),
    })
}

fn connection_label(c: &Value) -> String {
    let name = str_field(c, "name");
    let id = str_field(c, "data_connection_id");
    let ro = if c.get("read_only").and_then(Value::as_bool) == Some(true) {
        ", read-only"
    } else {
        ""
    };
    format!("{name} ({id}{ro})")
}

/// `my-new-product` → `My New Product`.
fn title_from_id(id: &str) -> String {
    id.split(['-', '_'])
        .filter(|w| !w.is_empty())
        .map(|w| {
            let mut cs = w.chars();
            cs.next()
                .map(|c| c.to_uppercase().chain(cs).collect::<String>())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

async fn edit(
    args: EditArgs,
    client: &Client,
    site: &str,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    let target = named(&args.product)?;
    let mut body = read_fields(args.fields.from_file.as_deref())?;
    insert_some(&mut body, "title", args.fields.title);
    insert_some(&mut body, "description", args.fields.description);
    insert_some(&mut body, "visibility", args.fields.visibility);
    if args.disable || args.enable {
        body.insert("disabled".into(), json!(args.disable));
    }
    let url = product_url(client, &target);
    let key = format!("product-edit/{target}");

    let mut draft = None;
    if body.is_empty() {
        let Some(ask) = prompter.as_deref_mut() else {
            return Err(
                "Nothing to change: pass --title, --description, --visibility, --disable, --enable or --from-file."
                    .into(),
            );
        };
        // Together, as none waits on another: one round trip, not three.
        let (signed_in, current, connections) = tokio::join!(
            client.check_signed_in(),
            client.get::<Value>(url.clone()),
            usable_connections(client, &target.account_id),
        );
        signed_in?;
        let saved = Draft::for_key(&key)?;
        if !saved.resume(ask, &mut body)? {
            prompt_edits(ask, &current?, connections, &mut body)?;
        }
        if body.is_empty() {
            eprintln!("No changes to {}.", target);
            return Ok(());
        }
        draft = Some(saved);
    }

    let sent = send_until_accepted(client, Method::PATCH, url, &mut body, prompter).await;
    let product = match &draft {
        Some(draft) => draft.finish(sent, &body)?,
        None => {
            let product = sent?;
            if let Ok(saved) = Draft::for_key(&key) {
                saved.sent_from(args.fields.from_file.as_deref());
            }
            product
        }
    };
    report(&product, args.json, "Edited", site);
    Ok(())
}

/// The edit form: every field with its current value, ↑/↓ to move, Enter to
/// change the highlighted one starting from what's there, `s` (or the Save
/// row) to review and send. Only the fields that changed are kept. The
/// visibilities offered are the ones the product's data connection allows.
fn prompt_edits(
    ask: &mut dyn Prompter,
    current: &Value,
    connections: Vec<Value>,
    body: &mut Map<String, Value>,
) -> Result<(), String> {
    let connection = primary_connection(current).and_then(|id| {
        connections
            .into_iter()
            .find(|c| str_field(c, "data_connection_id") == id)
    });
    let visibilities = allowed_visibilities(connection.as_ref());
    let fields = [
        ("Title", "title"),
        ("Description", "description"),
        ("Visibility", "visibility"),
    ];
    let mut edited: Map<String, Value> = Map::new();
    let label = format!("Edit {}", name(current));
    let mut place = Place::default();
    let _screen = ask.fullscreen();
    loop {
        let value = |key: &str| {
            edited
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or(str_field(current, key))
                .to_string()
        };
        let mut rows: Vec<String> = fields
            .iter()
            .map(|(label, key)| {
                let shown = one_line(&value(key));
                if edited.contains_key(*key) {
                    format!(
                        "{label:<12} ● {shown}   (was: {})",
                        one_line(str_field(current, key))
                    )
                } else {
                    format!("{label:<12}   {shown}")
                }
            })
            .collect();
        rows.push(match edited.len() {
            0 => "Save changes (nothing changed yet)".into(),
            1 => "Save changes (1 field)".into(),
            n => format!("Save changes ({n} fields)"),
        });
        ask.clear();
        let action = ask.browse(&label, &rows, &mut place, false, "s", EDIT_HINT)?;
        let at = place.at;
        match action {
            Action::Back if edited.is_empty() => return Err(crate::prompt::CANCELLED.into()),
            // ← is "back" everywhere else, so leaving with changes asks first.
            Action::Back => {
                ask.clear();
                let question = format!("Discard your changes to {}?", name(current));
                match ask.confirm(&question, false) {
                    Ok(true) => return Err(crate::prompt::CANCELLED.into()),
                    Err(e) if e != crate::prompt::CANCELLED => return Err(e),
                    // No, or Esc: back to the form, changes kept.
                    _ => continue,
                }
            }
            Action::Open if at < fields.len() => {
                let (label, key) = fields[at];
                // The form stays in view above the question.
                ask.clear();
                for (i, row) in rows[..fields.len()].iter().enumerate() {
                    eprintln!("{} {row}", if i == at { "›" } else { " " });
                }
                eprintln!();
                let was = value(key);
                // Esc or ↑ leaves the field as it was.
                let now = match key {
                    "title" => ask.input_or_back(label, &was, false),
                    "description" => ask.long_text_or_back(label, &was),
                    _ => {
                        let default = visibilities.iter().position(|v| *v == was).unwrap_or(0);
                        ask.select_or_back(label, &visibilities, default)
                            .map(|i| i.map(|i| visibilities[i].clone()))
                    }
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
                if now == str_field(current, key) {
                    edited.remove(key);
                } else {
                    edited.insert(key.into(), json!(now));
                }
            }
            _ if edited.is_empty() => return Ok(()),
            _ => {
                let review: Vec<String> = fields
                    .iter()
                    .filter(|(_, key)| edited.contains_key(*key))
                    .map(|(label, key)| {
                        format!(
                            "{label:<12}  {}  →  {}",
                            one_line(str_field(current, key)),
                            one_line(&value(key))
                        )
                    })
                    .collect();
                ask.clear();
                match ask.confirm_or_back(
                    &format!("Save these changes to {}?", name(current)),
                    &review,
                )? {
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

/// `text`'s first line, marked "…" when there's more, or "(none)".
fn one_line(text: &str) -> String {
    match text.lines().next() {
        None => "(none)".into(),
        Some(first) if text.trim_end() != first => format!("{first} …"),
        Some(first) => first.into(),
    }
}

async fn delete(
    args: DeleteArgs,
    client: &Client,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    let target = named(&args.product)?;
    let mut preserve_data = args.preserve_data;
    if !args.yes {
        let Some(ask) = prompter else {
            return Err(format!(
                "Refusing to delete {} without confirmation: pass --yes.",
                target
            ));
        };
        client.check_signed_in().await?;
        if !preserve_data {
            preserve_data = ask.confirm("Keep the product's data in storage?", false)?;
        }
        let data = if preserve_data {
            "its data will be kept"
        } else {
            "its data will be deleted too"
        };
        eprintln!("This deletes {} and {data}.", target);
        crate::prompt::confirm_by_name(ask, &target.to_string(), "deleted")?;
    }
    let mut url = product_url(client, &target);
    url.query_pairs_mut()
        .append_pair("preserve_data", &preserve_data.to_string());
    let product: Value = client.request(Method::DELETE, url, None::<&()>).await?;
    if args.json {
        print_json(&product);
    } else {
        eprintln!("Deleted {}", name(&product));
    }
    Ok(())
}

/// The JSON object in `path` (`-` for stdin), or an empty one. Its fields are
/// sent as they are; the API says if any is wrong.
pub(crate) fn read_fields(path: Option<&str>) -> Result<Map<String, Value>, String> {
    let Some(path) = path else {
        return Ok(Map::new());
    };
    match crate::api_cmd::read_json(path)? {
        Value::Object(fields) => Ok(fields),
        _ => Err(format!("{path} must hold a JSON object")),
    }
}

fn product_url(client: &Client, p: &ProductRef) -> url::Url {
    client.url(&["products", &p.account_id, &p.product_id])
}

fn insert_some(body: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        body.insert(key.into(), Value::String(v));
    }
}

/// The product as JSON, or a line on stderr for the person and its URL on
/// stdout for a script: `url=$(source-coop product create ...)`.
fn report(product: &Value, as_json: bool, verb: &str, site: &str) {
    if as_json {
        print_json(product);
    } else {
        let name = name(product);
        eprintln!("{verb} {name}");
        println!("{}/{name}", site.trim_end_matches('/'));
    }
}

pub(crate) fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn name(product: &Value) -> String {
    format!(
        "{}/{}",
        str_field(product, "account_id"),
        str_field(product, "product_id")
    )
}

fn print_json(v: &Value) {
    crate::output::json(v);
}

fn print_product(p: &Value, site: &str) {
    let color = crate::style::wanted(std::io::stdout().is_terminal());
    for line in product_lines(p, site, color) {
        println!("{line}");
    }
}

/// The title, then one `Label  value` row per field, then the description.
/// `color` adds ANSI styling: bold title, dim labels, and the visibility and
/// flags in green, yellow or red.
fn product_lines(p: &Value, site: &str, color: bool) -> Vec<String> {
    product_lines_at(p, site, color, chrono::Utc::now())
}

/// `product_lines` with relative dates counted from `now`.
fn product_lines_at(
    p: &Value,
    site: &str,
    color: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<String> {
    let paint = |code: &str, s: &str| crate::style::paint(color, code, s);
    let yes_no = |flag: bool, yes_code: &str| {
        if flag {
            paint(yes_code, "yes")
        } else {
            "no".to_string()
        }
    };
    let name = name(p);
    let visibility = str_field(p, "visibility");
    let disabled = p.get("disabled").and_then(Value::as_bool) == Some(true);
    let account = p.get("account").map(|a| {
        let label = match str_field(a, "name") {
            "" => str_field(a, "account_id"),
            n => n,
        };
        match str_field(a, "type") {
            "" => label.to_string(),
            t => format!("{label} ({t})"),
        }
    });
    let date = |key: &str| {
        chrono::DateTime::parse_from_rfc3339(str_field(p, key))
            .map(|d| crate::style::when(color, d.with_timezone(&chrono::Utc), now, false))
            .ok()
    };
    let none = || paint("2", "(none)");
    // Some stored lists hold an empty string, e.g. `[""]`.
    let tags: Vec<&str> = p
        .pointer("/metadata/tags")
        .and_then(Value::as_array)
        .map(|tags| {
            tags.iter()
                .filter_map(Value::as_str)
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();
    // Where the data lives: each mirror's connection and prefix, the primary
    // (flagged on the mirror, or named by `primary_mirror`) first.
    let primary = p
        .pointer("/metadata/primary_mirror")
        .and_then(Value::as_str);
    let mut mirrors: Vec<(bool, String)> = p
        .pointer("/metadata/mirrors")
        .and_then(Value::as_object)
        .map(|ms| {
            ms.iter()
                .map(|(key, m)| {
                    let is_primary = m.get("is_primary").and_then(Value::as_bool) == Some(true)
                        || primary == Some(key.as_str());
                    let connection = match str_field(m, "connection_id") {
                        "" => key.as_str(),
                        c => c,
                    };
                    let mut line = format!("{connection}  {}", str_field(m, "prefix"));
                    if is_primary {
                        line.push_str(&format!("  {}", paint("32", "(primary)")));
                    }
                    (is_primary, line)
                })
                .collect()
        })
        .unwrap_or_default();
    mirrors.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let mirrors: Vec<String> = mirrors.into_iter().map(|(_, line)| line).collect();
    let featured = p.get("featured").and_then(Value::as_i64).unwrap_or(0) > 0;

    let rows: Vec<(&str, String)> = [
        ("Product", Some(crate::style::id(color, &name))),
        ("Visibility", Some(visibility_label(color, visibility))),
        ("Disabled", Some(yes_no(disabled, "31"))),
        ("Featured", Some(yes_no(featured, "32"))),
        (
            "Tags",
            Some(if tags.is_empty() {
                none()
            } else {
                tags.join(", ")
            }),
        ),
        ("Account", account),
        (
            "Mirrors",
            Some(if mirrors.is_empty() {
                none()
            } else {
                mirrors.join("\n")
            }),
        ),
        ("Created", date("created_at")),
        ("Updated", date("updated_at")),
        (
            "URL",
            Some(paint(
                "4",
                &format!("{}/{name}", site.trim_end_matches('/')),
            )),
        ),
    ]
    .into_iter()
    .filter_map(|(label, value)| value.filter(|v| !v.is_empty()).map(|v| (label, v)))
    .collect();

    let width = rows.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    let mut lines = vec![paint("1", str_field(p, "title")), String::new()];
    for (label, value) in &rows {
        // A value of several lines (mirrors) lines up under its first.
        for (i, part) in value.lines().enumerate() {
            let label = if i == 0 { *label } else { "" };
            lines.push(format!(
                "{}  {part}",
                paint("2", &format!("{label:<width$}"))
            ));
        }
    }
    let description = str_field(p, "description");
    if !description.is_empty() {
        lines.push(String::new());
        lines.extend(description.lines().map(String::from));
    }
    lines
}

/// Lays out a list one page at a time, keeping what later pages need from
/// earlier ones: the table's column widths, or whether a product has been
/// shown yet, so details get a rule between products.
struct Layout<'a> {
    format: ListFormat,
    /// Writing to a terminal (or a pager on one) rather than a pipe
    terminal: bool,
    color: bool,
    site: &'a str,
    widths: Option<[usize; 2]>,
    started: bool,
}

impl<'a> Layout<'a> {
    fn new(format: ListFormat, terminal: bool, site: &'a str) -> Self {
        Layout {
            format,
            terminal,
            color: crate::style::wanted(terminal),
            site,
            widths: None,
            started: false,
        }
    }

    /// Details: each product as `view` shows it. Table on a terminal:
    /// `NAME  VISIBILITY  TITLE` under a header, padded to line up; piped, the
    /// same columns tab-separated with no header, for `cut` and `awk`.
    fn page(&mut self, items: &[Value]) -> Vec<String> {
        match self.format {
            ListFormat::Table if self.terminal => padded_rows(items, &mut self.widths, self.color),
            ListFormat::Table => columns(items).iter().map(|r| r.join("\t")).collect(),
            ListFormat::Details => {
                let rule = if self.color {
                    format!("\x1b[2m{}\x1b[0m", "─".repeat(40))
                } else {
                    "─".repeat(40)
                };
                let mut lines = vec![];
                for p in items {
                    if self.started {
                        lines.extend([String::new(), rule.clone(), String::new()]);
                    }
                    self.started = true;
                    lines.extend(product_lines(p, self.site, self.color));
                }
                lines
            }
        }
    }
}

/// The padded rows for one page of a streamed table. The first page (with
/// `widths` None) gets the header and sets the column widths; later pages
/// reuse them.
fn padded_rows(items: &[Value], widths: &mut Option<[usize; 2]>, color: bool) -> Vec<String> {
    let mut rows = columns(items);
    let header = widths.is_none();
    if header {
        rows.insert(0, ["NAME", "VISIBILITY", "TITLE"].map(String::from));
    }
    let [w0, w1] = *widths.get_or_insert_with(|| {
        let width = |i: usize| rows.iter().map(|r| r[i].chars().count()).max().unwrap_or(0);
        [width(0), width(1)]
    });
    rows.iter()
        .enumerate()
        .map(|(i, [n, v, t])| {
            // Padded before it's painted, so the codes don't count as width.
            let n = format!("{n:<w0$}");
            let n = if header && i == 0 {
                n
            } else {
                crate::style::id(color, &n)
            };
            format!("{n}  {v:<w1$}  {t}").trim_end().to_string()
        })
        .collect()
}

fn columns(items: &[Value]) -> Vec<[String; 3]> {
    items
        .iter()
        .map(|p| {
            [
                name(p),
                str_field(p, "visibility").to_string(),
                str_field(p, "title").to_string(),
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::scripted::{Answer::*, Script};
    use wiremock::matchers::{
        body_json, header, method, path, query_param, query_param_is_missing,
    };
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SITE: &str = "https://source.coop";

    fn product(account: &str, id: &str) -> Value {
        json!({"account_id": account, "product_id": id, "title": format!("{id} title"),
               "description": "", "visibility": "public", "disabled": false})
    }

    fn create_args(product: Option<&str>) -> CreateArgs {
        CreateArgs {
            product: product.map(|p| p.parse().unwrap()),
            fields: Fields::default(),
            data_connection_id: None,
            json: false,
        }
    }

    fn edit_args() -> EditArgs {
        EditArgs {
            product: Some("acct/prod".parse().unwrap()),
            interactive: false,
            fields: Fields::default(),
            disable: false,
            enable: false,
            json: false,
        }
    }

    fn delete_args(yes: bool, preserve_data: bool) -> DeleteArgs {
        DeleteArgs {
            product: Some("acct/prod".parse().unwrap()),
            interactive: false,
            preserve_data,
            yes,
            json: false,
        }
    }

    /// Answer a POST to the account's products with the product, but only if
    /// the body is exactly `expected`.
    /// A stand-in API that knows the caller, as `check_signed_in` asks before
    /// any prompt.
    async fn api_server() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/whoami"))
            // A UserSession, as source.coop's /whoami returns it: an account
            // that may create products, and a maintainer of the org "org".
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "account": {"account_id": "acct", "type": "individual",
                            "flags": ["create_repositories"]},
                "memberships": [{"account_id": "acct", "membership_account_id": "org",
                                 "role": "maintainers", "state": "member"}]
            })))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn create_checks_sign_in_before_asking_anything() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/whoami"))
            .respond_with(ResponseTemplate::new(401).set_body_json(
                json!({"type": "https://source.coop/api/problems/unauthenticated", "title": "T", "status": 401,
                "detail": "Authentication required", "code": "unauthenticated"}),
            ))
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("stale".into()), false).unwrap();
        // No scripted answers: a single question would panic.
        let mut ask = Script::new([]);
        let err = create(create_args(None), &client, SITE, Some(&mut ask))
            .await
            .unwrap_err();
        assert!(err.contains("This needs you signed in"), "{err}");
        assert!(ask.asked.is_empty());
    }

    #[tokio::test]
    async fn create_keeps_answers_from_a_failed_send_for_the_next_run() {
        let server = api_server().await;
        let expected = json!({"product_id": "drafted", "title": "T", "visibility": "public",
                              "data_connection_id": "dc", "description": "Typed once"});
        Mock::given(method("POST"))
            .and(path("/api/v1/products/acct"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/products/acct"))
            .and(body_json(&expected))
            .respond_with(ResponseTemplate::new(201).set_body_json(product("acct", "drafted")))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let args = || {
            let mut args = create_args(Some("acct/drafted"));
            args.fields.title = Some("T".into());
            args.fields.visibility = Some("public".into());
            args.data_connection_id = Some("dc".into());
            args
        };

        let mut first = Script::new([Text("Typed once"), Default]);
        let err = create(args(), &client, SITE, Some(&mut first))
            .await
            .unwrap_err();
        assert!(err.contains("Your answers are saved"), "{err}");

        // The next run offers them back and asks for nothing else.
        let mut second = Script::new([Yes(true)]);
        create(args(), &client, SITE, Some(&mut second))
            .await
            .unwrap();
        assert_eq!(
            second.asked,
            ["Use the answers saved from your last try? [true]"]
        );
    }

    /// How the scripted prompter records create's review of `sent`.
    fn review_asked(name: &str, sent: &Value) -> String {
        let body = sent.as_object().unwrap();
        format!(
            "Create this product? {{{}}} [true]",
            review_lines(name, body).join(" | ")
        )
    }

    #[tokio::test]
    async fn create_sends_nothing_when_the_review_is_declined() {
        let server = api_server().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201))
            .expect(0)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut args = create_args(Some("acct/prod"));
        args.data_connection_id = Some("dc".into());
        args.fields.visibility = Some("public".into());
        let mut ask = Script::new([Text("T"), Text("D"), Yes(false)]);
        let err = create(args, &client, SITE, Some(&mut ask))
            .await
            .unwrap_err();
        assert_eq!(err, crate::prompt::CANCELLED);
    }

    #[test]
    fn review_lists_what_will_be_sent() {
        let body = json!({"title": "T", "description": "First line\nmore", "data_connection_id": "dc",
                          "visibility": "public"});
        assert_eq!(
            review_lines("acct/p", body.as_object().unwrap()),
            [
                "Product          acct/p",
                "Title            T",
                // Only the first line, marked when there's more.
                "Description      First line …",
                "Data connection  dc",
                "Visibility       public",
            ]
        );
        let empty = json!({"description": ""});
        assert_eq!(
            review_lines("acct/p", empty.as_object().unwrap())[2],
            "Description      (none)"
        );
    }

    async fn expect_create(server: &MockServer, expected: Value) {
        Mock::given(method("POST"))
            .and(path("/api/v1/products/acct"))
            .and(body_json(expected))
            .respond_with(ResponseTemplate::new(201).set_body_json(product("acct", "prod")))
            .expect(1)
            .mount(server)
            .await;
    }

    #[test]
    fn list_i_takes_filters_but_not_printing_flags() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(subcommand)]
            cmd: ProductCommand,
        }
        let parse = |args: &[&str]| Cli::try_parse_from([&["sc"], args].concat());
        let Ok(Cli {
            cmd: ProductCommand::List(list),
        }) = parse(&["list", "acct", "-i", "-q", "crop"])
        else {
            panic!("list -i should parse");
        };
        assert!(list.interactive);
        assert_eq!(list.filters.search.as_deref(), Some("crop"));
        for flag in [&["--json"][..], &["--format", "table"], &["-L", "5"]] {
            assert!(
                parse(&[&["list", "-i"][..], flag].concat()).is_err(),
                "{flag:?}"
            );
        }
    }

    #[test]
    fn parses_account_slash_product() {
        let r: ProductRef = "acct/prod".parse().unwrap();
        assert_eq!(r.to_string(), "acct/prod");
        assert_eq!("/acct/prod/".parse::<ProductRef>().unwrap(), r);
        for bad in ["acct", "acct/", "/prod", "a/b/c", ""] {
            assert!(bad.parse::<ProductRef>().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn titles_come_from_ids() {
        assert_eq!(title_from_id("my-new_product"), "My New Product");
        assert_eq!(title_from_id("x--y"), "X Y");
    }

    #[test]
    fn view_lists_fields_with_labels_and_colors_only_when_asked() {
        let p = json!({
            "account_id": "acct", "product_id": "p", "title": "A product",
            "visibility": "public", "disabled": true, "data_mode": "open",
            "metadata": {
                "tags": ["geospatial", "", "open"],
                // The primary named only by `primary_mirror`, listed second.
                "primary_mirror": "west",
                "mirrors": {
                    "east": {"connection_id": "aws-us-east-1", "prefix": "acct/p/"},
                    "west": {"connection_id": "aws-us-west-2", "prefix": "acct/p/"}
                }
            },
            "featured": 1, "created_at": "2024-12-13T20:32:55.681Z",
            "updated_at": "2026-10-13T20:00:00Z",
            "account": {"account_id": "acct", "name": "Acct Inc", "type": "organization"},
            "description": "Line one\nLine two"
        });
        let now = "2026-10-14T12:00:00Z".parse().unwrap();
        assert_eq!(
            product_lines_at(&p, "https://source.coop/", false, now),
            [
                "A product",
                "",
                "Product     acct/p",
                "Visibility  public",
                "Disabled    yes",
                "Featured    yes",
                "Tags        geospatial, open",
                "Account     Acct Inc (organization)",
                "Mirrors     aws-us-west-2  acct/p/  (primary)",
                "            aws-us-east-1  acct/p/",
                "Created     2024-12-13T20:32:55Z (1 year ago)",
                "Updated     2026-10-13T20:00:00Z (16 hours ago)",
                "URL         https://source.coop/acct/p",
                "",
                "Line one",
                "Line two",
            ]
        );
        let colored = product_lines_at(&p, "https://source.coop", true, now);
        assert_eq!(colored[0], "\x1b[1mA product\x1b[0m");
        assert!(colored[3].contains("\x1b[32mpublic\x1b[0m"));
        assert!(
            colored[4].ends_with("\x1b[31myes\x1b[0m"),
            "disabled in red"
        );

        // A bare product says what it lacks rather than leaving rows out.
        let bare = json!({"account_id": "a", "product_id": "b", "title": "B"});
        // (Labels pad to the widest present, so compare words.)
        let words: Vec<String> = product_lines_at(&bare, "https://source.coop", false, now)
            .iter()
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        for row in [
            "Disabled no",
            "Featured no",
            "Tags (none)",
            "Mirrors (none)",
        ] {
            assert!(words.contains(&row.to_string()), "{row} in {words:?}");
        }
    }

    #[test]
    fn table_lines_up_on_a_terminal_and_tabs_when_piped() {
        let items = [product("a", "one"), product("longer", "two")];
        let terminal = |color| {
            let mut layout = Layout::new(ListFormat::Table, true, "");
            layout.color = color;
            layout.page(&items)
        };
        assert_eq!(
            terminal(false),
            [
                "NAME        VISIBILITY  TITLE",
                "a/one       public      one title",
                "longer/two  public      two title"
            ]
        );
        // In color, IDs are gray after padding, so columns still line up; the
        // header isn't.
        let colored = terminal(true);
        assert_eq!(colored[0], "NAME        VISIBILITY  TITLE");
        assert_eq!(
            colored[1],
            "\x1b[90ma/one     \x1b[0m  public      one title"
        );
        assert_eq!(
            Layout::new(ListFormat::Table, false, "").page(&items),
            ["a/one\tpublic\tone title", "longer/two\tpublic\ttwo title"]
        );
    }

    #[test]
    fn details_rule_off_products_across_pages() {
        let mut layout = Layout::new(ListFormat::Details, false, "https://source.coop");
        let first = layout.page(&[product("a", "one")]);
        assert_eq!(first[0], "one title");
        assert!(first.contains(&"URL         https://source.coop/a/one".to_string()));
        assert!(!first.iter().any(|l| l.starts_with('─')));
        // The second page's first product follows a rule, as the first page's would.
        let second = layout.page(&[product("b", "two")]);
        assert_eq!(second[..4], ["", &"─".repeat(40), "", "two title"]);
    }

    #[test]
    fn streamed_pages_keep_the_first_pages_widths() {
        let mut widths = None;
        assert_eq!(
            padded_rows(&[product("a", "one")], &mut widths, false),
            ["NAME   VISIBILITY  TITLE", "a/one  public      one title"]
        );
        assert_eq!(
            padded_rows(
                &[product("b", "two"), product("longer", "x")],
                &mut widths,
                false
            ),
            [
                "b/two  public      two title",
                "longer/x  public      x title"
            ]
        );
    }

    #[test]
    fn reads_fields_from_a_file() {
        let dir = std::env::temp_dir().join(format!("scc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("p.json");
        std::fs::write(&f, r#"{"title": "From file", "visibility": "unlisted"}"#).unwrap();
        let fields = read_fields(Some(f.to_str().unwrap())).unwrap();
        assert_eq!(fields["title"], "From file");
        std::fs::write(&f, "[1]").unwrap();
        assert!(read_fields(Some(f.to_str().unwrap()))
            .unwrap_err()
            .contains("JSON object"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn list_follows_cursors_up_to_the_limit() {
        let server = api_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/acct"))
            .and(query_param("cursor", "c1"))
            .and(query_param("limit", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"items": [product("acct", "b"), product("acct", "c")], "next_cursor": "c2"}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/acct"))
            .and(query_param("limit", "3"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"items": [product("acct", "a")], "next_cursor": "c1"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(&server.uri(), None, false).unwrap();
        let args = ListArgs {
            filters: Filters {
                account: Some("acct".into()),
                search: None,
                tags: None,
                featured: false,
            },
            limit: Some(3),
            cursor: None,
            json: true,
            interactive: false,
            format: ListFormat::Table,
            no_pager: false,
        };
        list(args, &client, "https://source.coop").await.unwrap();
    }

    #[tokio::test]
    async fn create_without_a_terminal_sends_only_what_it_was_given() {
        let server = api_server().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/products/acct"))
            .and(header("authorization", "Bearer tkn"))
            .and(body_json(json!({"product_id": "prod", "title": "T"})))
            .respond_with(ResponseTemplate::new(201).set_body_json(product("acct", "prod")))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut args = create_args(Some("acct/prod"));
        args.fields.title = Some("T".into());
        create(args, &client, SITE, None).await.unwrap();
    }

    #[tokio::test]
    async fn create_without_a_terminal_needs_the_product_named() {
        let client = Client::new("http://127.0.0.1:9", None, false).unwrap();
        let err = create(create_args(None), &client, SITE, None)
            .await
            .unwrap_err();
        assert!(err.contains("ACCOUNT/PRODUCT"));
    }

    #[tokio::test]
    async fn create_prompts_for_what_is_missing_with_defaults() {
        let server = api_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/data-connections"))
            .and(query_param("usable_for", "acct"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": [
                {"data_connection_id": "shared", "name": "Shared", "read_only": false,
                 "allowed_visibilities": ["public", "unlisted"]},
                {"data_connection_id": "mine", "name": "Mine", "owner": "acct", "read_only": true,
                 "allowed_visibilities": ["restricted", "public"]},
            ], "next_cursor": null})))
            .mount(&server)
            .await;
        expect_create(
            &server,
            json!({"product_id": "my-data", "title": "My Data", "description": "",
                   "data_connection_id": "mine", "visibility": "public"}),
        )
        .await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([
            Default,
            Text("my-data"),
            Default,
            Default,
            Pick(1),
            Default,
            Default,
        ]);
        create(create_args(None), &client, SITE, Some(&mut ask))
            .await
            .unwrap();
        let (review, questions) = ask.asked.split_last().unwrap();
        assert_eq!(
            questions,
            [
                // Only the accounts they may create in: their own, then the org.
                "Account [acct] of acct | org",
                "Product ID []",
                "Title [My Data]",
                "Description (long) []",
                // The connections the API says the account may use.
                "Data connection [Shared (shared)] of Shared (shared) | Mine (mine, read-only)",
                // Only what the chosen connection allows, starting on public.
                "Visibility [public] of restricted | public",
            ]
        );
        // Then a last look at all of it before it's sent.
        let sent = json!({"title": "My Data", "description": "", "data_connection_id": "mine",
                          "visibility": "public"});
        assert_eq!(review, &review_asked("acct/my-data", &sent));
    }

    #[tokio::test]
    async fn create_goes_back_to_earlier_questions_keeping_answers() {
        let server = api_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/data-connections"))
            .and(query_param("usable_for", "acct"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": [
                {"data_connection_id": "shared", "name": "Shared",
                 "allowed_visibilities": ["public", "unlisted"]},
                {"data_connection_id": "mine", "name": "Mine", "owner": "acct", "read_only": true,
                 "allowed_visibilities": ["restricted", "public"]},
            ], "next_cursor": null})))
            .mount(&server)
            .await;
        expect_create(
            &server,
            json!({"product_id": "my-data", "title": "Better Title", "description": "first",
                   "data_connection_id": "shared", "visibility": "public"}),
        )
        .await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([
            Back,            // on the first question: asked again
            Default,         // Account: acct
            Text("my-data"), // Product ID
            Default,         // Title: My Data
            Text("first"),   // Description
            Back,            // at Data connection: to Description
            Back,            // to Title
            Text("Better Title"),
            Default, // Description: keeps "first"
            Pick(1), // Data connection: mine
            Back,    // at Visibility: to Data connection
            Pick(0), // shared instead
            Default, // Visibility: public, of what shared allows
            Back,    // at the review: to Visibility
            Default, // public again
            Default, // create it
        ]);
        create(create_args(None), &client, SITE, Some(&mut ask))
            .await
            .unwrap();
        let sent = json!({"title": "Better Title", "description": "first",
                          "data_connection_id": "shared", "visibility": "public"});
        let review = review_asked("acct/my-data", &sent);
        let (last, before) = ask.asked.split_last().unwrap();
        assert_eq!(last, &review);
        assert_eq!(
            before[before.len() - 2..],
            [
                format!("{} (back)", review.trim_end_matches(" [true]")),
                "Visibility [public] of public | unlisted".to_string(),
            ]
        );
        assert_eq!(
            before[..before.len() - 2],
            [
                "Account (back)",
                "Account [acct] of acct | org",
                "Product ID []",
                "Title [My Data]",
                "Description (long) []",
                "Data connection (back)",
                "Description (back)",
                // Each question comes back starting from the answer given.
                "Title [My Data]",
                "Description (long) [first]",
                "Data connection [Shared (shared)] of Shared (shared) | Mine (mine, read-only)",
                "Visibility (back)",
                "Data connection [Mine (mine, read-only)] of Shared (shared) | Mine (mine, read-only)",
                // The visibilities follow the connection chosen last.
                "Visibility [public] of public | unlisted",
            ]
        );
    }

    #[test]
    fn creatable_accounts_follow_source_coops_rule() {
        let session = |account: Value, memberships: Value| json!({"account": account, "memberships": memberships});
        let org = |id: &str, role: &str, state: &str| json!({"membership_account_id": id, "role": role, "state": state});
        let me = json!({"account_id": "me", "type": "individual", "flags": []});

        // Org-wide owners and maintainers; not other roles, pending invites,
        // or product-scoped memberships. Own account only with the flag.
        let memberships = json!([
            org("owned", "owners", "member"),
            org("kept", "maintainers", "member"),
            org("read", "read_data", "member"),
            org("invited", "owners", "invited"),
            {"membership_account_id": "scoped", "role": "owners", "state": "member",
             "product_id": "one-product"},
            {"membership_account_id": "legacy", "role": "owners", "state": "member",
             "repository_id": "one-product"}
        ]);
        assert_eq!(
            creatable_accounts(&session(me.clone(), memberships)),
            (vec!["owned".to_string(), "kept".to_string()], false)
        );

        let mut flagged = me.clone();
        flagged["flags"] = json!(["create_repositories"]);
        assert_eq!(
            creatable_accounts(&session(flagged, json!([]))),
            (vec!["me".to_string()], false)
        );

        let mut admin = me.clone();
        admin["flags"] = json!(["admin"]);
        assert_eq!(
            creatable_accounts(&session(admin, json!([]))),
            (vec!["me".to_string()], true)
        );

        let mut disabled = me.clone();
        disabled["flags"] = json!(["create_repositories"]);
        disabled["disabled"] = json!(true);
        let owner = json!([org("owned", "owners", "member")]);
        assert_eq!(
            creatable_accounts(&session(disabled, owner.clone())),
            (vec![], false)
        );
        let service = json!({"account_id": "bot", "type": "service", "flags": ["admin"]});
        assert_eq!(
            creatable_accounts(&session(service, owner)),
            (vec![], false)
        );
    }

    #[tokio::test]
    async fn create_offers_no_account_choice_with_only_one() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/whoami"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "account": {"account_id": "solo", "flags": ["create_repositories"]}
            })))
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        // Esc at the product ID: only that was asked, with no account picker.
        let mut ask = Script::new([Cancel]);
        let err = create(create_args(None), &client, SITE, Some(&mut ask))
            .await
            .unwrap_err();
        assert_eq!(err, crate::prompt::CANCELLED);
        assert_eq!(ask.asked, ["Product ID []"]);
    }

    #[tokio::test]
    async fn create_refuses_someone_who_can_create_nowhere_before_asking() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/whoami"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"account": {"account_id": "me", "flags": []}})),
            )
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([]);
        let err = create(create_args(None), &client, SITE, Some(&mut ask))
            .await
            .unwrap_err();
        assert!(err.starts_with("You can't create products yet"), "{err}");
        assert!(ask.asked.is_empty());
    }

    #[tokio::test]
    async fn create_prompts_only_for_what_flags_and_file_leave_out() {
        let server = api_server().await;
        expect_create(
            &server,
            json!({"product_id": "prod", "title": "Flag wins", "description": "From file",
                   "data_connection_id": "dc", "visibility": "unlisted"}),
        )
        .await;

        let dir = std::env::temp_dir().join(format!("scc-create-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("p.json");
        std::fs::write(
            &f,
            r#"{"title": "From file", "description": "From file", "data_connection_id": "dc"}"#,
        )
        .unwrap();

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut args = create_args(Some("acct/prod"));
        args.fields.title = Some("Flag wins".into());
        args.fields.from_file = Some(f.to_str().unwrap().into());
        let mut ask = Script::new([Pick(1), Default]);
        create(args, &client, SITE, Some(&mut ask)).await.unwrap();
        let sent = json!({"title": "Flag wins", "description": "From file",
                          "data_connection_id": "dc", "visibility": "unlisted"});
        assert_eq!(
            ask.asked,
            [
                "Visibility [public] of public | unlisted | restricted".to_string(),
                // The review shows flag and file answers too.
                review_asked("acct/prod", &sent),
            ]
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn create_asks_for_a_connection_id_when_none_can_be_listed() {
        let server = api_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/data-connections"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        expect_create(
            &server,
            json!({"product_id": "prod", "title": "T", "description": "D",
                   "data_connection_id": "typed", "visibility": "public"}),
        )
        .await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([Text("T"), Text("D"), Text("typed"), Default, Default]);
        create(
            create_args(Some("acct/prod")),
            &client,
            SITE,
            Some(&mut ask),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn create_surfaces_the_apis_field_errors() {
        let server = api_server().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/products/acct"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({"type": "https://source.coop/api/problems/invalid", "title": "T", "status": 400,
                "detail": "A data connection is required", "code": "invalid",
                "errors": [{"detail": "A data connection is required", "pointer": "#/data_connection_id"}]})))
            .mount(&server)
            .await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let err = create(create_args(Some("acct/prod")), &client, SITE, None)
            .await
            .unwrap_err();
        assert!(err.contains("data_connection_id: A data connection is required"));
    }

    #[test]
    fn search_results_can_relabel_the_hints_quit() {
        // `browse_products` swaps this text for "← all products".
        assert!(LIST_HINT.contains("← quit") && CHOOSE_HINT.contains("← quit"));
    }

    #[tokio::test]
    async fn edit_sends_disabled_and_without_a_terminal_refuses_an_empty_patch() {
        let server = api_server().await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/products/acct/prod"))
            .and(body_json(json!({"disabled": true})))
            .respond_with(ResponseTemplate::new(200).set_body_json(product("acct", "prod")))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();

        let mut args = edit_args();
        args.disable = true;
        edit(args, &client, SITE, None).await.unwrap();
        assert!(edit(edit_args(), &client, SITE, None)
            .await
            .unwrap_err()
            .contains("Nothing to change"));
    }

    #[tokio::test]
    async fn edit_prompts_from_current_values_and_sends_only_changes() {
        let server = api_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/acct/prod"))
            .respond_with(ResponseTemplate::new(200).set_body_json(product("acct", "prod")))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/products/acct/prod"))
            .and(body_json(
                json!({"description": "New", "visibility": "unlisted"}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(product("acct", "prod")))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([
            Browse(1, Action::Open),
            Text("New"),
            Browse(2, Action::Open),
            Pick(1),
            // ← at the review is back to the form, as it was.
            Browse(2, Action::Key('s')),
            Back,
            Browse(2, Action::Key('s')),
            Default,
        ]);
        edit(edit_args(), &client, SITE, Some(&mut ask))
            .await
            .unwrap();
        assert_eq!(
            ask.asked,
            [
                "Edit acct/prod [Title          prod title] of Title          prod title | Description    (none) | Visibility     public | Save changes (nothing changed yet) (keys s)",
                "Description (long) []",
                "Edit acct/prod [Description  ● New   (was: (none))] of Title          prod title | Description  ● New   (was: (none)) | Visibility     public | Save changes (1 field) (keys s)",
                "Visibility [public] of public | unlisted | restricted",
                "Edit acct/prod [Visibility   ● unlisted   (was: public)] of Title          prod title | Description  ● New   (was: (none)) | Visibility   ● unlisted   (was: public) | Save changes (2 fields) (keys s)",
                "Save these changes to acct/prod? {Description   (none)  →  New | Visibility    public  →  unlisted} (back)",
                "Edit acct/prod [Visibility   ● unlisted   (was: public)] of Title          prod title | Description  ● New   (was: (none)) | Visibility   ● unlisted   (was: public) | Save changes (2 fields) (keys s)",
                "Save these changes to acct/prod? {Description   (none)  →  New | Visibility    public  →  unlisted} [true]",
            ]
        );
    }

    #[tokio::test]
    async fn edit_offers_the_visibilities_the_product_s_connection_allows() {
        let server = api_server().await;
        let mut current = product("acct", "prod");
        current["metadata"] = json!({"primary_mirror": "west", "mirrors": {
            "east": {"connection_id": "other", "prefix": "acct/prod/"},
            "west": {"connection_id": "shared", "prefix": "acct/prod/"}}});
        Mock::given(method("GET"))
            .and(path("/api/v1/products/acct/prod"))
            .respond_with(ResponseTemplate::new(200).set_body_json(current))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/data-connections"))
            .and(query_param("usable_for", "acct"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": [
                {"data_connection_id": "other", "allowed_visibilities": ["restricted"]},
                {"data_connection_id": "shared", "allowed_visibilities": ["public", "unlisted"]},
            ], "next_cursor": null})))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/products/acct/prod"))
            .and(body_json(json!({"visibility": "unlisted"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(product("acct", "prod")))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([
            Browse(2, Action::Open),
            Pick(1),
            Browse(3, Action::Open),
            Default,
        ]);
        edit(edit_args(), &client, SITE, Some(&mut ask))
            .await
            .unwrap();
        assert_eq!(
            ask.asked,
            [
                "Edit acct/prod [Title          prod title] of Title          prod title | Description    (none) | Visibility     public | Save changes (nothing changed yet) (keys s)",
                "Visibility [public] of public | unlisted",
                "Edit acct/prod [Visibility   ● unlisted   (was: public)] of Title          prod title | Description    (none) | Visibility   ● unlisted   (was: public) | Save changes (1 field) (keys s)",
                "Save these changes to acct/prod? {Visibility    public  →  unlisted} [true]",
            ]
        );
    }

    #[tokio::test]
    async fn leaving_the_edit_form_or_no_at_its_review_sends_nothing() {
        let server = api_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/acct/prod"))
            .respond_with(ResponseTemplate::new(200).set_body_json(product("acct", "prod")))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();

        // Esc on an unchanged form; Esc on a changed one, which asks before
        // discarding (No and Esc there return to the form); "No" at the review.
        let form = "Edit acct/prod [Title          prod title] of Title          prod title | Description    (none) | Visibility     public | Save changes (nothing changed yet) (keys s)";
        let changed = "Edit acct/prod [Title        ● New title   (was: prod title)] of Title        ● New title   (was: prod title) | Description    (none) | Visibility     public | Save changes (1 field) (keys s)";
        let discard = "Discard your changes to acct/prod? [false]";
        for (script, asked) in [
            (Script::new([Browse(0, Action::Back)]), vec![form]),
            (
                Script::new([
                    Browse(0, Action::Open),
                    Text("New title"),
                    Browse(0, Action::Back),
                    Yes(false),
                    Browse(0, Action::Back),
                    Cancel,
                    Browse(0, Action::Back),
                    Yes(true),
                ]),
                vec![
                    form,
                    "Title [prod title]",
                    changed,
                    discard,
                    changed,
                    discard,
                    changed,
                    discard,
                ],
            ),
            (
                Script::new([
                    Browse(0, Action::Open),
                    Text("New title"),
                    Browse(3, Action::Open),
                    Yes(false),
                ]),
                vec![
                    form,
                    "Title [prod title]",
                    changed,
                    "Save these changes to acct/prod? {Title         prod title  →  New title} [true]",
                ],
            ),
        ] {
            let mut ask = script;
            let err = edit(edit_args(), &client, SITE, Some(&mut ask))
                .await
                .unwrap_err();
            assert_eq!(err, crate::prompt::CANCELLED);
            assert!(ask.answers.is_empty(), "unused: {:?}", ask.answers);
            assert_eq!(ask.asked, asked);
        }
    }

    #[tokio::test]
    async fn an_editor_that_fails_is_told_on_the_form_keeping_the_changes() {
        let server = api_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/acct/prod"))
            .respond_with(ResponseTemplate::new(200).set_body_json(product("acct", "prod")))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/products/acct/prod"))
            .and(body_json(json!({"title": "New title"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(product("acct", "prod")))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([
            Browse(0, Action::Open),
            Text("New title"),
            Browse(1, Action::Open),
            Fail("Couldn't open your editor"),
            Browse(1, Action::Key('s')),
            Default,
        ]);
        edit(edit_args(), &client, SITE, Some(&mut ask))
            .await
            .unwrap();
        let changed = |at: &str, notice: &str| {
            format!("Edit acct/prod [{at}] of Title        ● New title   (was: prod title) | Description    (none) | Visibility     public | Save changes (1 field){notice} (keys s)")
        };
        assert_eq!(
            ask.asked,
            [
                "Edit acct/prod [Title          prod title] of Title          prod title | Description    (none) | Visibility     public | Save changes (nothing changed yet) (keys s)".into(),
                "Title [prod title]".into(),
                changed("Title        ● New title   (was: prod title)", ""),
                "Description (long) []".into(),
                changed("Description    (none)", " !Error: Couldn't open your editor"),
                "Save these changes to acct/prod? {Title         prod title  →  New title} [true]".into(),
            ]
        );
    }

    #[tokio::test]
    async fn edit_with_nothing_changed_sends_nothing() {
        let server = api_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/acct/prod"))
            .respond_with(ResponseTemplate::new(200).set_body_json(product("acct", "prod")))
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        // Keeping a field's value, or Esc on one, changes nothing either; and
        // saving nothing sends nothing, without a review.
        let mut ask = Script::new([
            Browse(0, Action::Open),
            Default,
            Browse(1, Action::Open),
            Cancel,
            Browse(2, Action::Key('s')),
        ]);
        edit(edit_args(), &client, SITE, Some(&mut ask))
            .await
            .unwrap();
        let form = |at: &str| {
            format!("Edit acct/prod [{at}] of Title          prod title | Description    (none) | Visibility     public | Save changes (nothing changed yet) (keys s)")
        };
        assert_eq!(
            ask.asked,
            [
                form("Title          prod title"),
                "Title [prod title]".into(),
                form("Title          prod title"),
                "Description (long) []".into(),
                form("Description    (none)"),
            ]
        );
    }

    /// Answer a DELETE of acct/prod, but only with this `preserve_data`.
    async fn expect_delete(server: &MockServer, preserve_data: &str, times: u64) {
        Mock::given(method("DELETE"))
            .and(path("/api/v1/products/acct/prod"))
            .and(query_param("preserve_data", preserve_data))
            .respond_with(ResponseTemplate::new(200).set_body_json(product("acct", "prod")))
            .expect(times)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn list_i_pages_itself_deletes_through_the_menu_and_quits() {
        let server = api_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/acct"))
            .and(query_param("cursor", "c1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"items": [product("acct", "c")], "next_cursor": null})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/acct"))
            .and(query_param_is_missing("cursor"))
            .and(query_param("limit", "50"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"items": [product("acct", "a"), product("acct", "prod")], "next_cursor": "c1"}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        expect_delete(&server, "false", 1).await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let filters = Filters {
            account: Some("acct".into()),
            search: None,
            tags: None,
            featured: false,
        };
        let mut ask = Script::new([
            Browse(1, Action::More), // the highlight nears the end
            Browse(1, Action::Open), // into acct/prod
            Press(Action::Key('d')), // delete it
            Yes(false),              // don't keep the data
            Text("acct/prod"),       // confirm
            Browse(1, Action::Open), // into acct/c: d isn't a list key
            Press(Action::Key('d')), // delete it
            Default,                 // keep the data? no
            Text("not it"),          // a wrong confirmation: nothing deleted
            Press(Action::Back),     // back to the list
            Browse(1, Action::Back), // quit
        ]);
        let url = filters.url(&client);
        browse_products(url, &client, "https://source.coop", &mut ask, false)
            .await
            .unwrap();

        // No "Load more…" item: the picker is told there's more instead.
        assert_eq!(
            ask.asked[0],
            "Products [acct/a  a title  public] of acct/a  a title  public | acct/prod  prod title  public (more) (keys b)"
        );
        // The next page is appended with the highlight where it was, and the
        // picker stops asking once the listing runs out.
        assert_eq!(
            ask.asked[1],
            "Products [acct/prod  prod title  public] of acct/a  a title  public | acct/prod  prod title  public | acct/c  c title  public (keys b)"
        );
        // The list offers only the browser; edit and delete are on a product.
        assert!(ask.asked[0].ends_with("(keys b)"), "{}", ask.asked[0]);
        assert_eq!(ask.asked[2], format!("{SCREEN_HINT} (keys bed)"));
        // The deleted product is gone, the cursor sits on the one after it, and
        // the list says what happened, as a cleared screen wouldn't otherwise.
        assert_eq!(
            ask.asked[5],
            "Products [acct/c  c title  public] of acct/a  a title  public | acct/c  c title  public !Deleted acct/prod. (keys b)"
        );
        // A refused delete stays on the product's screen, and the list it goes
        // back to is as it was.
        assert_eq!(ask.asked[9], format!("{SCREEN_HINT} (keys bed)"));
        assert_eq!(
            ask.asked[10],
            "Products [acct/c  c title  public] of acct/a  a title  public | acct/c  c title  public (keys b)"
        );
    }

    #[tokio::test]
    async fn list_i_searches_public_products_on_the_server_and_backs_out_to_all() {
        let server = api_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products"))
            .and(query_param("q", "crop"))
            .and(query_param("featured", "true"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"items": [product("ag", "crop")], "next_cursor": null})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products"))
            .and(query_param_is_missing("q"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"items": [product("a", "one"), product("b", "two")], "next_cursor": null}),
            ))
            // Opened, then again on backing out of the search.
            .expect(2)
            .mount(&server)
            .await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let filters = Filters {
            account: None,
            search: None,
            tags: None,
            featured: true,
        };
        let mut ask = Script::new([
            Search("crop"),          // `/crop`, Enter
            Browse(0, Action::Back), // back from the results
            Browse(0, Action::Back), // quit
        ]);
        browse_products(filters.url(&client), &client, SITE, &mut ask, true)
            .await
            .unwrap();
        assert_eq!(
            ask.asked,
            [
                "Products [a/one  one title  public] of a/one  one title  public | b/two  two title  public (keys )",
                "Products matching \"crop\" · from the server [ag/crop  crop title  public] of ag/crop  crop title  public (keys )",
                "Products [a/one  one title  public] of a/one  one title  public | b/two  two title  public (keys )",
            ]
        );
    }

    #[tokio::test]
    async fn edit_i_chooses_from_your_own_products_then_edits() {
        let server = api_server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/acct"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"items": [product("acct", "a"), product("acct", "prod")], "next_cursor": null}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/v1/products/acct/prod"))
            .and(body_json(json!({"title": "New"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(product("acct", "prod")))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([Browse(1, Action::Open)]);
        let mut args = edit_args();
        args.product = None;
        args.interactive = true;
        args.fields.title = Some("New".into());
        run(
            ProductCommand::Edit(args),
            &client,
            "https://source.coop",
            Some(&mut ask),
        )
        .await
        .unwrap();
        assert_eq!(
            ask.asked,
            ["Products [acct/a  a title  public] of acct/a  a title  public | acct/prod  prod title  public (keys )"]
        );
    }

    #[test]
    fn i_makes_the_product_optional_where_it_picks_one() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(subcommand)]
            cmd: ProductCommand,
        }
        let parse = |args: &[&str]| Cli::try_parse_from([&["sc"], args].concat()).is_ok();
        for cmd in ["view", "edit", "delete"] {
            assert!(parse(&[cmd, "-i"]), "{cmd} -i");
            assert!(parse(&[cmd, "acct/p", "-i"]), "{cmd} PRODUCT -i");
            assert!(!parse(&[cmd]), "{cmd} needs a product or -i");
        }
        assert!(!parse(&["view", "-i", "--json"]));
        assert!(!parse(&["delete", "-i", "--yes"]));
    }

    #[tokio::test]
    async fn delete_with_yes_passes_preserve_data() {
        let server = api_server().await;
        expect_delete(&server, "true", 1).await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        delete(delete_args(true, true), &client, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn backing_out_of_delete_at_either_step_deletes_nothing() {
        let server = api_server().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();

        // Esc on "Keep the product's data?", then Enter on the name.
        for script in [Script::new([Cancel]), Script::new([Yes(false), Text("")])] {
            let mut ask = script;
            let err = delete(delete_args(false, false), &client, Some(&mut ask))
                .await
                .unwrap_err();
            assert_eq!(err, crate::prompt::CANCELLED);
        }
    }

    #[tokio::test]
    async fn delete_without_a_terminal_needs_yes() {
        let client = Client::new("http://127.0.0.1:9", None, false).unwrap();
        let err = delete(delete_args(false, false), &client, None)
            .await
            .unwrap_err();
        assert!(err.contains("--yes"));
    }

    #[tokio::test]
    async fn delete_asks_about_data_then_for_the_name() {
        let server = api_server().await;
        expect_delete(&server, "true", 1).await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([Yes(true), Text("acct/prod")]);
        delete(delete_args(false, false), &client, Some(&mut ask))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_stops_on_the_wrong_name() {
        let server = api_server().await;
        expect_delete(&server, "false", 0).await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([Default, Text("acct/other")]);
        let err = delete(delete_args(false, false), &client, Some(&mut ask))
            .await
            .unwrap_err();
        assert!(err.contains("nothing was deleted"));
    }
    #[tokio::test]
    async fn create_asks_again_for_just_the_rejected_fields() {
        let server = api_server().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/products/acct"))
            .and(body_json(json!({"product_id": "Bad--ID", "title": "T", "description": "D",
                                  "data_connection_id": "dc", "visibility": "public"})))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({"type": "https://source.coop/api/problems/invalid", "title": "T", "status": 400,
                "detail": "Product ID may not contain consecutive hyphens", "code": "invalid",
                "errors": [{"detail": "Product ID may not contain consecutive hyphens", "pointer": "#/product_id"}]})))
            .expect(1)
            .mount(&server)
            .await;
        expect_create(
            &server,
            json!({"product_id": "good-id", "title": "T", "description": "D",
                   "data_connection_id": "dc", "visibility": "public"}),
        )
        .await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut args = create_args(Some("acct/Bad--ID"));
        args.fields.title = Some("T".into());
        args.fields.description = Some("D".into());
        args.data_connection_id = Some("dc".into());
        args.fields.visibility = Some("public".into());
        let mut ask = Script::new([Text("good-id")]);
        create(args, &client, SITE, Some(&mut ask)).await.unwrap();
        // Only the rejected field is asked for, starting from what was sent.
        assert_eq!(ask.asked, ["Product ID [Bad--ID]"]);
    }

    #[tokio::test]
    async fn a_rejection_naming_other_fields_is_just_an_error() {
        let server = api_server().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({"type": "https://source.coop/api/problems/invalid", "title": "T", "status": 400,
                "detail": "Not allowed", "code": "invalid",
                "errors": [{"detail": "Not allowed", "pointer": "#/metadata"}]})))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut args = create_args(Some("acct/prod"));
        args.fields.title = Some("T".into());
        args.fields.description = Some("D".into());
        args.data_connection_id = Some("dc".into());
        args.fields.visibility = Some("public".into());
        let mut ask = Script::new([]);
        let err = create(args, &client, SITE, Some(&mut ask))
            .await
            .unwrap_err();
        assert!(err.contains("metadata: Not allowed"));
    }
}
