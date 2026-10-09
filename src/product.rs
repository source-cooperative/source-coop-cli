//! `source-coop product`: list, view, create, edit and delete products through
//! `/api/v1/products`.

use crate::api::{ApiError, Client, Page};
use crate::prompt::Prompter;
use clap::{Args, Subcommand};
use reqwest::Method;
use serde_json::{json, Map, Value};
use std::io::{IsTerminal, Read};

#[derive(Subcommand)]
pub enum ProductCommand {
    /// List public products, or one account's products
    List(ListArgs),
    /// Show one product
    View(ViewArgs),
    /// Create a product
    Create(CreateArgs),
    /// Change a product's title, description, visibility or state
    Edit(EditArgs),
    /// Delete a product and, unless --preserve-data, its data
    Delete(DeleteArgs),
}

#[derive(Args)]
pub struct ListArgs {
    /// List this account's products (all public products when omitted)
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

    /// Maximum number of products to list
    #[arg(long, short = 'L', default_value_t = 30)]
    limit: usize,

    /// Print the products as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct ViewArgs {
    /// The product, as ACCOUNT/PRODUCT
    product: ProductRef,

    /// Open the product's page in the browser instead
    #[arg(long, short = 'w')]
    web: bool,

    /// Print the product as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct CreateArgs {
    /// The new product, as ACCOUNT/PRODUCT (prompted for when omitted)
    product: Option<ProductRef>,

    #[arg(long, short = 't')]
    title: Option<String>,

    #[arg(long, short = 'd')]
    description: Option<String>,

    /// public, unlisted or restricted
    #[arg(long)]
    visibility: Option<String>,

    /// The data connection that stores the product's data (fixed once created)
    #[arg(long = "data-connection")]
    data_connection_id: Option<String>,

    /// Read fields from a JSON object in this file (`-` for stdin); flags win
    #[arg(long, short = 'F', value_name = "PATH")]
    from_file: Option<String>,

    /// Print the new product as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct EditArgs {
    /// The product, as ACCOUNT/PRODUCT
    product: ProductRef,

    #[arg(long, short = 't')]
    title: Option<String>,

    #[arg(long, short = 'd')]
    description: Option<String>,

    /// public, unlisted or restricted
    #[arg(long)]
    visibility: Option<String>,

    /// Deactivate the product
    #[arg(long, conflicts_with = "enable")]
    disable: bool,

    /// Reactivate a deactivated product (admins only)
    #[arg(long)]
    enable: bool,

    /// Read fields from a JSON object in this file (`-` for stdin); flags win
    #[arg(long, short = 'F', value_name = "PATH")]
    from_file: Option<String>,

    /// Print the edited product as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub struct DeleteArgs {
    /// The product, as ACCOUNT/PRODUCT
    product: ProductRef,

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
        ProductCommand::List(args) => list(args, client).await,
        ProductCommand::View(args) => view(args, client, site).await,
        ProductCommand::Create(args) => create(args, client, site, prompter).await,
        ProductCommand::Edit(args) => edit(args, client, site, prompter).await,
        ProductCommand::Delete(args) => delete(args, client, prompter).await,
    }
}

async fn list(args: ListArgs, client: &Client) -> Result<(), String> {
    let mut url = match &args.account {
        Some(account) => client.url(&["products", account]),
        None => client.url(&["products"]),
    };
    {
        let mut q = url.query_pairs_mut();
        if let Some(s) = &args.search {
            q.append_pair("q", s);
        }
        if let Some(t) = &args.tags {
            q.append_pair("tags", t);
        }
        if args.featured {
            q.append_pair("featured", "true");
        }
    }

    // Follow next_cursor until there are enough, asking for no more per page
    // than the API's maximum.
    let mut items: Vec<Value> = vec![];
    let mut cursor: Option<String> = None;
    while items.len() < args.limit {
        let mut page_url = url.clone();
        {
            let mut q = page_url.query_pairs_mut();
            q.append_pair("limit", &(args.limit - items.len()).min(100).to_string());
            if let Some(c) = &cursor {
                q.append_pair("cursor", c);
            }
        }
        let page: Page<Value> = client.get(page_url).await?;
        items.extend(page.items);
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    items.truncate(args.limit);

    if args.json {
        print_json(&Value::Array(items));
    } else if items.is_empty() {
        eprintln!("No products found.");
    } else {
        print_table(&items);
    }
    Ok(())
}

async fn view(args: ViewArgs, client: &Client, site: &str) -> Result<(), String> {
    if args.web {
        let url = args.product.web_url(site);
        eprintln!("Opening {url} in your browser.");
        return open::that(&url).map_err(|e| format!("Couldn't open a browser: {e}"));
    }
    let product: Value = client.get(product_url(client, &args.product)).await?;
    if args.json {
        print_json(&product);
    } else {
        print_product(&product, site);
    }
    Ok(())
}

const VISIBILITIES: [&str; 3] = ["public", "unlisted", "restricted"];

async fn create(
    args: CreateArgs,
    client: &Client,
    site: &str,
    mut prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    let mut body = read_fields(args.from_file.as_deref())?;
    insert_some(&mut body, "title", args.title);
    insert_some(&mut body, "description", args.description);
    insert_some(&mut body, "visibility", args.visibility);
    insert_some(&mut body, "data_connection_id", args.data_connection_id);

    let product = match (args.product, prompter.as_deref_mut()) {
        (Some(p), _) => p,
        (None, Some(ask)) => ask.input("Product (ACCOUNT/PRODUCT)", "", false)?.parse()?,
        (None, None) => return Err("Name the product to create, as ACCOUNT/PRODUCT.".into()),
    };
    body.insert("product_id".into(), json!(product.product_id));

    if let Some(ask) = prompter.as_deref_mut() {
        prompt_new_product(ask, client, &product, &mut body).await?;
    }

    let url = client.url(&["products", &product.account_id]);
    let created = send_until_accepted(client, Method::POST, url, &mut body, prompter).await?;
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

/// Ask for each field `body` doesn't have yet. The defaults are the ones the
/// web UI's form starts with, and the choices are the data connections the
/// account could use and the visibilities the chosen one allows; the API still
/// decides what's acceptable.
async fn prompt_new_product(
    ask: &mut dyn Prompter,
    client: &Client,
    product: &ProductRef,
    body: &mut Map<String, Value>,
) -> Result<(), String> {
    if !body.contains_key("title") {
        let title = ask.input("Title", &title_from_id(&product.product_id), false)?;
        body.insert("title".into(), json!(title));
    }
    if !body.contains_key("description") {
        let description = ask.long_text("Description", "")?;
        body.insert("description".into(), json!(description));
    }

    let mut allowed: Vec<String> = VISIBILITIES.iter().map(|v| v.to_string()).collect();
    match body.get("data_connection_id").and_then(Value::as_str) {
        Some(_) => {}
        None => {
            let connections = usable_connections(client, &product.account_id).await;
            if connections.is_empty() {
                let id = ask.input("Data connection ID", "", false)?;
                body.insert("data_connection_id".into(), json!(id));
            } else {
                let labels: Vec<String> = connections.iter().map(connection_label).collect();
                let picked = &connections[ask.select("Data connection", &labels, 0)?];
                body.insert(
                    "data_connection_id".into(),
                    json!(str_field(picked, "data_connection_id")),
                );
                if let Some(vs) = picked.get("allowed_visibilities").and_then(Value::as_array) {
                    let vs: Vec<String> = vs
                        .iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect();
                    if !vs.is_empty() {
                        allowed = vs;
                    }
                }
            }
        }
    }
    if !body.contains_key("visibility") {
        let default = allowed.iter().position(|v| v == "public").unwrap_or(0);
        let picked = ask.select("Visibility", &allowed, default)?;
        body.insert("visibility".into(), json!(allowed[picked]));
    }
    Ok(())
}

/// The data connections a product of `account_id` could be stored on: the
/// unowned ones and the account's own. Empty if they can't be listed, in which
/// case the caller asks for an ID instead.
async fn usable_connections(client: &Client, account_id: &str) -> Vec<Value> {
    let all: Vec<Value> = match client.get(client.url(&["data-connections"])).await {
        Ok(all) => all,
        Err(_) => return vec![],
    };
    all.into_iter()
        .filter(|c| match c.get("owner").and_then(Value::as_str) {
            None => true,
            Some(owner) => owner == account_id,
        })
        .collect()
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
    let mut body = read_fields(args.from_file.as_deref())?;
    insert_some(&mut body, "title", args.title);
    insert_some(&mut body, "description", args.description);
    insert_some(&mut body, "visibility", args.visibility);
    if args.disable || args.enable {
        body.insert("disabled".into(), json!(args.disable));
    }
    let url = product_url(client, &args.product);

    if body.is_empty() {
        let Some(ask) = prompter.as_deref_mut() else {
            return Err(
                "Nothing to change: pass --title, --description, --visibility, --disable, --enable or --from-file."
                    .into(),
            );
        };
        let current: Value = client.get(url.clone()).await?;
        prompt_edits(ask, &current, &mut body)?;
        if body.is_empty() {
            eprintln!("No changes to {}.", args.product);
            return Ok(());
        }
    }

    let product = send_until_accepted(client, Method::PATCH, url, &mut body, prompter).await?;
    report(&product, args.json, "Edited", site);
    Ok(())
}

/// Ask which fields to change, then for each, starting from its current value;
/// only the ones that changed are kept.
fn prompt_edits(
    ask: &mut dyn Prompter,
    current: &Value,
    body: &mut Map<String, Value>,
) -> Result<(), String> {
    let fields = ["Title", "Description", "Visibility"].map(String::from);
    for picked in ask.multi_select("What do you want to change?", &fields)? {
        let (key, now) = match picked {
            0 => (
                "title",
                ask.input("Title", str_field(current, "title"), false)?,
            ),
            1 => (
                "description",
                ask.long_text("Description", str_field(current, "description"))?,
            ),
            _ => {
                let was = str_field(current, "visibility");
                let options: Vec<String> = VISIBILITIES.iter().map(|v| v.to_string()).collect();
                let default = options.iter().position(|v| v == was).unwrap_or(0);
                let now = options[ask.select("Visibility", &options, default)?].clone();
                ("visibility", now)
            }
        };
        if now != str_field(current, key) {
            body.insert(key.into(), json!(now));
        }
    }
    Ok(())
}

async fn delete(
    args: DeleteArgs,
    client: &Client,
    prompter: Option<&mut dyn Prompter>,
) -> Result<(), String> {
    let mut preserve_data = args.preserve_data;
    if !args.yes {
        let Some(ask) = prompter else {
            return Err(format!(
                "Refusing to delete {} without confirmation: pass --yes.",
                args.product
            ));
        };
        if !preserve_data {
            preserve_data = ask.confirm("Keep the product's data in storage?", false)?;
        }
        let data = if preserve_data {
            "its data will be kept"
        } else {
            "its data will be deleted too"
        };
        eprintln!("This deletes {} and {data}.", args.product);
        let typed = ask.input(&format!("Type {} to confirm", args.product), "", true)?;
        if typed.trim() != args.product.to_string() {
            return Err("Not confirmed; nothing was deleted.".into());
        }
    }
    let mut url = product_url(client, &args.product);
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
fn read_fields(path: Option<&str>) -> Result<Map<String, Value>, String> {
    let Some(path) = path else {
        return Ok(Map::new());
    };
    let text = if path == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("Couldn't read stdin: {e}"))?;
        s
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("Couldn't read {path}: {e}"))?
    };
    match serde_json::from_str(&text) {
        Ok(Value::Object(fields)) => Ok(fields),
        Ok(_) => Err(format!("{path} must hold a JSON object")),
        Err(e) => Err(format!("{path} isn't JSON: {e}")),
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

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
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
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}

fn print_product(p: &Value, site: &str) {
    let name = name(p);
    let mut state = str_field(p, "visibility").to_string();
    if p.get("disabled").and_then(Value::as_bool) == Some(true) {
        state.push_str(", deactivated");
    }
    println!("{}", str_field(p, "title"));
    println!("{name} ({state})");
    let description = str_field(p, "description");
    if !description.is_empty() {
        println!("\n{description}");
    }
    println!("\n{}/{name}", site.trim_end_matches('/'));
}

/// On a terminal, `NAME  VISIBILITY  TITLE` under a header, padded to line
/// up; piped, the same columns tab-separated with no header, for `cut` and
/// `awk`.
fn table_rows(items: &[Value], terminal: bool) -> Vec<String> {
    let rows: Vec<[String; 3]> = items
        .iter()
        .map(|p| {
            [
                name(p),
                str_field(p, "visibility").to_string(),
                str_field(p, "title").to_string(),
            ]
        })
        .collect();
    if !terminal {
        return rows.iter().map(|r| r.join("\t")).collect();
    }
    let header = ["NAME", "VISIBILITY", "TITLE"].map(String::from);
    let all: Vec<&[String; 3]> = std::iter::once(&header).chain(&rows).collect();
    let w0 = all.iter().map(|r| r[0].chars().count()).max().unwrap_or(0);
    let w1 = all.iter().map(|r| r[1].chars().count()).max().unwrap_or(0);
    all.iter()
        .map(|[n, v, t]| format!("{n:<w0$}  {v:<w1$}  {t}").trim_end().to_string())
        .collect()
}

fn print_table(items: &[Value]) {
    for row in table_rows(items, std::io::stdout().is_terminal()) {
        println!("{row}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::scripted::{Answer::*, Script};
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SITE: &str = "https://source.coop";

    fn product(account: &str, id: &str) -> Value {
        json!({"account_id": account, "product_id": id, "title": format!("{id} title"),
               "description": "", "visibility": "public", "disabled": false})
    }

    fn create_args(product: Option<&str>) -> CreateArgs {
        CreateArgs {
            product: product.map(|p| p.parse().unwrap()),
            title: None,
            description: None,
            visibility: None,
            data_connection_id: None,
            from_file: None,
            json: false,
        }
    }

    fn edit_args() -> EditArgs {
        EditArgs {
            product: "acct/prod".parse().unwrap(),
            title: None,
            description: None,
            visibility: None,
            disable: false,
            enable: false,
            from_file: None,
            json: false,
        }
    }

    fn delete_args(yes: bool, preserve_data: bool) -> DeleteArgs {
        DeleteArgs {
            product: "acct/prod".parse().unwrap(),
            preserve_data,
            yes,
            json: false,
        }
    }

    /// Answer a POST to the account's products with the product, but only if
    /// the body is exactly `expected`.
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
    fn table_lines_up_on_a_terminal_and_tabs_when_piped() {
        let items = [product("a", "one"), product("longer", "two")];
        assert_eq!(
            table_rows(&items, true),
            [
                "NAME        VISIBILITY  TITLE",
                "a/one       public      one title",
                "longer/two  public      two title"
            ]
        );
        assert_eq!(
            table_rows(&items, false),
            ["a/one\tpublic\tone title", "longer/two\tpublic\ttwo title"]
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
        let server = MockServer::start().await;
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
            account: Some("acct".into()),
            search: None,
            tags: None,
            featured: false,
            limit: 3,
            json: true,
        };
        list(args, &client).await.unwrap();
    }

    #[tokio::test]
    async fn create_without_a_terminal_sends_only_what_it_was_given() {
        let server = MockServer::start().await;
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
        args.title = Some("T".into());
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
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/data-connections"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"data_connection_id": "theirs", "name": "Theirs", "owner": "someone-else",
                 "allowed_visibilities": ["public"]},
                {"data_connection_id": "shared", "name": "Shared", "read_only": false,
                 "allowed_visibilities": ["public", "unlisted"]},
                {"data_connection_id": "mine", "name": "Mine", "owner": "acct", "read_only": true,
                 "allowed_visibilities": ["restricted", "public"]},
            ])))
            .mount(&server)
            .await;
        expect_create(
            &server,
            json!({"product_id": "my-data", "title": "My Data", "description": "",
                   "data_connection_id": "mine", "visibility": "public"}),
        )
        .await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([Text("acct/my-data"), Default, Default, Pick(1), Default]);
        create(create_args(None), &client, SITE, Some(&mut ask))
            .await
            .unwrap();
        assert_eq!(
            ask.asked,
            [
                "Product (ACCOUNT/PRODUCT) []",
                "Title [My Data]",
                "Description (long) []",
                // Someone else's connection isn't offered.
                "Data connection [Shared (shared)] of Shared (shared) | Mine (mine, read-only)",
                // Only what the chosen connection allows, starting on public.
                "Visibility [public] of restricted | public",
            ]
        );
    }

    #[tokio::test]
    async fn create_prompts_only_for_what_flags_and_file_leave_out() {
        let server = MockServer::start().await;
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
        args.title = Some("Flag wins".into());
        args.from_file = Some(f.to_str().unwrap().into());
        let mut ask = Script::new([Pick(1)]);
        create(args, &client, SITE, Some(&mut ask)).await.unwrap();
        assert_eq!(
            ask.asked,
            ["Visibility [public] of public | unlisted | restricted"]
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn create_asks_for_a_connection_id_when_none_can_be_listed() {
        let server = MockServer::start().await;
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
        let mut ask = Script::new([Text("T"), Text("D"), Text("typed"), Default]);
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
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/products/acct"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": {
                "code": "invalid", "message": "The request is invalid.",
                "field_errors": {"data_connection_id": ["A data connection is required"]}}})))
            .mount(&server)
            .await;

        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let err = create(create_args(Some("acct/prod")), &client, SITE, None)
            .await
            .unwrap_err();
        assert!(err.contains("data_connection_id: A data connection is required"));
    }

    #[tokio::test]
    async fn edit_sends_disabled_and_without_a_terminal_refuses_an_empty_patch() {
        let server = MockServer::start().await;
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
        let server = MockServer::start().await;
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
        let mut ask = Script::new([Picks(&[1, 2]), Text("New"), Pick(1)]);
        edit(edit_args(), &client, SITE, Some(&mut ask))
            .await
            .unwrap();
        assert_eq!(
            ask.asked,
            [
                "What do you want to change? of Title | Description | Visibility",
                "Description (long) []",
                "Visibility [public] of public | unlisted | restricted",
            ]
        );
    }

    #[tokio::test]
    async fn edit_with_nothing_changed_sends_nothing() {
        let server = MockServer::start().await;
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
        // Picking a field and keeping its value changes nothing either.
        let mut ask = Script::new([Picks(&[0]), Default]);
        edit(edit_args(), &client, SITE, Some(&mut ask))
            .await
            .unwrap();
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
    async fn delete_with_yes_passes_preserve_data() {
        let server = MockServer::start().await;
        expect_delete(&server, "true", 1).await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        delete(delete_args(true, true), &client, None)
            .await
            .unwrap();
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
        let server = MockServer::start().await;
        expect_delete(&server, "true", 1).await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut ask = Script::new([Yes(true), Text("acct/prod")]);
        delete(delete_args(false, false), &client, Some(&mut ask))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_stops_on_the_wrong_name() {
        let server = MockServer::start().await;
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
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/products/acct"))
            .and(body_json(json!({"product_id": "Bad--ID", "title": "T", "description": "D",
                                  "data_connection_id": "dc", "visibility": "public"})))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": {
                "code": "invalid", "message": "The request is invalid.",
                "field_errors": {"product_id": ["Product ID may not contain consecutive hyphens"]}}})))
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
        args.title = Some("T".into());
        args.description = Some("D".into());
        args.data_connection_id = Some("dc".into());
        args.visibility = Some("public".into());
        let mut ask = Script::new([Text("good-id")]);
        create(args, &client, SITE, Some(&mut ask)).await.unwrap();
        // Only the rejected field is asked for, starting from what was sent.
        assert_eq!(ask.asked, ["Product ID [Bad--ID]"]);
    }

    #[tokio::test]
    async fn a_rejection_naming_other_fields_is_just_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": {
                "code": "invalid", "message": "The request is invalid.",
                "field_errors": {"metadata": ["Not allowed"]}}})))
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), Some("tkn".into()), false).unwrap();
        let mut args = create_args(Some("acct/prod"));
        args.title = Some("T".into());
        args.description = Some("D".into());
        args.data_connection_id = Some("dc".into());
        args.visibility = Some("public".into());
        let mut ask = Script::new([]);
        let err = create(args, &client, SITE, Some(&mut ask))
            .await
            .unwrap_err();
        assert!(err.contains("metadata: Not allowed"));
    }
}
