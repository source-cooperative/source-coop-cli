//! Shell completion of record names, such as `product view my-org/<TAB>`.
//! Commands, flags and their values complete from the clap definitions
//! (`CompleteEnv` in `main`); these add the names only the API knows.
//!
//! A completer runs on every TAB, so it never prints or refreshes the login:
//! it uses an unexpired cached token (or `SOURCE_TOKEN`), and offers nothing
//! when the API fails or is slow. Its one longer wait is on the OS, when
//! reading the login from the keyring raises a password dialog (`complete`).

use crate::api::Client;
use crate::member::{self, Scope};
use crate::{cache, defaults, product, session};
use clap::ValueEnum;
use clap_complete::engine::CompletionCandidate;
use clap_complete::env::Shells;
use serde_json::Value;
use std::ffi::OsStr;
use std::future::Future;
use std::time::Duration;

/// How long a TAB waits on the API before offering nothing.
const TIMEOUT: Duration = Duration::from_secs(2);

/// How long a TAB waits for the keyring, which may be showing a password
/// dialog, before offering nothing.
const ANSWER: Duration = Duration::from_secs(60);

/// Set, to the shell's name, only by the script `source-coop completions`
/// prints, when it runs the binary to ask for completions. A name of our own,
/// so a `COMPLETE` meant for another program can't turn every run into one.
pub const VAR: &str = "SOURCE_COOP_COMPLETE";

/// A shell `source-coop completions` writes a script for.
#[derive(Clone, Copy, ValueEnum)]
pub enum Shell {
    Bash,
    Elvish,
    Fish,
    Powershell,
    Zsh,
}

/// Write `shell`'s script registering completion for `source-coop`. On each
/// TAB it runs this binary again with `VAR` set: by name from `PATH` if it
/// was run that way, so an upgrade doesn't break it, otherwise by its path.
pub fn registration(shell: Shell, out: &mut dyn std::io::Write) -> Result<(), String> {
    let name = shell.to_possible_value().unwrap();
    let shells = Shells::builtins();
    let shell = shells
        .completer(name.get_name())
        .ok_or_else(|| format!("No completion script for {}", name.get_name()))?;
    let bin = std::env::args_os()
        .next()
        .unwrap_or_else(|| "source-coop".into());
    let bin = std::path::Path::new(&bin);
    let bin = if bin.components().count() > 1 {
        std::path::absolute(bin).map_err(|e| e.to_string())?
    } else {
        bin.to_path_buf()
    };
    shell
        .write_registration(
            VAR,
            "source-coop",
            "source-coop",
            &bin.to_string_lossy(),
            out,
        )
        .map_err(|e| format!("Couldn't write the completion script: {e}"))
}

/// An existing product, as `ACCOUNT/PRODUCT`.
pub fn product(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(client, ANSWER, TIMEOUT, current, |c, s| async move {
        products(&c, &s).await
    })
}

/// A product to create: the accounts you may create under, then nothing,
/// since the product ID is new.
pub fn new_product(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(client, ANSWER, TIMEOUT, current, |c, s| async move {
        new_products(&c, &s).await
    })
}

/// An account you belong to.
pub fn account(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(client, ANSWER, TIMEOUT, current, |c, s| async move {
        accounts(&c, &s).await
    })
}

/// An organization you belong to (`ACCOUNT`), or one of its products
/// (`ACCOUNT/PRODUCT`).
pub fn scope(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(client, ANSWER, TIMEOUT, current, |c, s| async move {
        scopes(&c, &s).await
    })
}

/// A member of the organization or product named before it.
pub fn member(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(client, ANSWER, TIMEOUT, current, |c, s| async move {
        members_of_named(&c, &s, false).await
    })
}

/// Someone to invite to the product named before it: its organization's
/// members who aren't on it yet. Nothing for an organization, since there's
/// no listing of accounts to offer.
pub fn invitee(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(client, ANSWER, TIMEOUT, current, |c, s| async move {
        members_of_named(&c, &s, true).await
    })
}

/// Where you're invited.
pub fn invitation(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(client, ANSWER, TIMEOUT, current, |c, s| async move {
        mine(&c, &s, "invited").await
    })
}

/// Where you're a member.
pub fn membership(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(client, ANSWER, TIMEOUT, current, |c, s| async move {
        mine(&c, &s, "member").await
    })
}

/// An existing service account, as `OWNER--NAME`.
pub fn service_account(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(client, ANSWER, TIMEOUT, current, |c, s| async move {
        service_accounts(&c, &s).await
    })
}

/// A service account to create, whose ID is new: nothing to offer.
/// ponytail: `OWNER--` would be the useful start, but bash and zsh add a
/// space after any candidate not ending in `=`, `/` or `:`, so it would have
/// to be deleted before typing the name. Offer it if clap ever lets a
/// candidate say "no space".
pub fn new_service_account(_: &OsStr) -> Vec<CompletionCandidate> {
    vec![]
}

/// Make the client with `client`, run `find` with `current`, and offer what
/// it returns, or nothing once `timeout` passes. `client` is passed in so
/// tests never reach `client()`, which reads the login session from the OS
/// keyring. That read can wait on macOS's password dialog, so it gets
/// `answer` rather than `timeout`: someone pressed TAB to answer it, and
/// exiting mid-dialog would throw away their "Always Allow" and ask again on
/// the next TAB. It is still bounded, since a keyring's unlock prompt may be
/// somewhere nobody can see, such as a desktop behind an SSH session.
fn complete<F>(
    client: impl FnOnce() -> Option<Client> + Send + 'static,
    answer: Duration,
    timeout: Duration,
    current: &OsStr,
    find: impl FnOnce(Client, String) -> F,
) -> Vec<CompletionCandidate>
where
    F: Future<Output = Result<Vec<String>, String>>,
{
    let (tx, rx) = std::sync::mpsc::channel();
    // Fails only once we've stopped waiting, when there's no one to tell.
    std::thread::spawn(move || {
        let _ = tx.send(client());
    });
    let Ok(Some(client)) = rx.recv_timeout(answer) else {
        return vec![];
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return vec![];
    };
    let current = current.to_string_lossy().into_owned();
    // The timer needs the runtime, so it is made inside it.
    let found = rt.block_on(async { tokio::time::timeout(timeout, find(client, current)).await });
    rt.shutdown_background();
    found
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default()
        .into_iter()
        .map(CompletionCandidate::new)
        .collect()
}

/// The client the command being completed would use, from the environment
/// alone: a completer sees only the word being completed, not the flags.
fn client() -> Option<Client> {
    let var = |k| {
        std::env::var(k)
            .ok()
            .filter(|v: &String| !v.trim().is_empty())
    };
    let proxy_url = var("SOURCE_PROXY_URL").unwrap_or_else(|| defaults::PROXY_URL.into());
    let token = var("SOURCE_TOKEN").or_else(|| {
        let env = cache::env(&proxy_url).ok()?;
        session::cached(env.as_deref(), session::Want::Access)
    });
    let api_url = var("SOURCE_API_URL").unwrap_or_else(|| defaults::API_URL.into());
    Client::new(&api_url, token, false).ok()
}

/// `ACCOUNT/PRODUCT` names starting with `current`: before the `/`, the
/// accounts you belong to; after it, that account's products. An account's
/// listing may ignore `q`, so every page is read (within the timeout) and
/// filtered here.
async fn products(client: &Client, current: &str) -> Result<Vec<String>, String> {
    let Some((account, prefix)) = current.split_once('/').filter(|(a, _)| !a.is_empty()) else {
        return Ok(slashed(accounts(client, current).await?));
    };
    let mut url = client.url(&["products", account]);
    if !prefix.is_empty() {
        url.query_pairs_mut().append_pair("q", prefix);
    }
    let mut found = vec![];
    let mut cursor = None;
    loop {
        let page = product::fetch_page(client, &url, 100, cursor.as_deref()).await?;
        found.extend(
            page.items
                .iter()
                .filter_map(|p| p.get("product_id")?.as_str())
                .filter(|id| id.starts_with(prefix))
                .map(|id| format!("{account}/{id}")),
        );
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => return Ok(found),
        }
    }
}

/// Whole `OWNER--NAME` IDs starting with `current`, from the service
/// accounts of each of your accounts that could own one, since a partial
/// `OWNER--` would get a space after it (see `new_service_account`). Only an
/// owner's managers may list them, so the other owners are skipped.
async fn service_accounts(client: &Client, current: &str) -> Result<Vec<String>, String> {
    let owners: Vec<String> = accounts(client, "")
        .await?
        .into_iter()
        .filter(|o| o.starts_with(current) || current.starts_with(&format!("{o}--")))
        .collect();
    let mut found = vec![];
    for owner in owners {
        let url = client.url(&["accounts", &owner, "service-accounts"]);
        let mut cursor = None;
        loop {
            let Ok(page) = product::fetch_page(client, &url, 100, cursor.as_deref()).await else {
                break;
            };
            found.extend(
                page.items
                    .iter()
                    .filter_map(|a| a.get("account_id")?.as_str())
                    .filter(|id| id.starts_with(current))
                    .map(String::from),
            );
            match page.next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
    }
    Ok(found)
}

async fn new_products(client: &Client, current: &str) -> Result<Vec<String>, String> {
    if current.contains('/') {
        return Ok(vec![]);
    }
    let me: Value = client.get(client.url(&["whoami"])).await?;
    let (accounts, _) = product::creatable_accounts(&me);
    Ok(slashed(starting_with(accounts, current)))
}

/// Your own account, then the organizations you're a member of.
async fn accounts(client: &Client, current: &str) -> Result<Vec<String>, String> {
    let me: Value = client.get(client.url(&["whoami"])).await?;
    let own = me.pointer("/account/account_id").and_then(Value::as_str);
    let orgs = me
        .get("memberships")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|m| m.get("state").and_then(Value::as_str) == Some("member"))
        .filter_map(|m| m.get("membership_account_id")?.as_str());
    let mut all: Vec<String> = vec![];
    for a in own.into_iter().chain(orgs) {
        if !all.iter().any(|x| x == a) {
            all.push(a.to_string());
        }
    }
    Ok(starting_with(all, current))
}

/// Before a `/`, your accounts both as they are (an organization) and as
/// the start of a product; after it, that account's products.
async fn scopes(client: &Client, current: &str) -> Result<Vec<String>, String> {
    if current.contains('/') {
        return products(client, current).await;
    }
    let accounts = accounts(client, current).await?;
    Ok(accounts
        .into_iter()
        .flat_map(|a| [format!("{a}/"), a])
        .collect())
}

/// The members of the scope named earlier on the command line or, for
/// `invitees`, the members of a product's organization not on the product.
async fn members_of_named(
    client: &Client,
    current: &str,
    invitees: bool,
) -> Result<Vec<String>, String> {
    let args: Vec<String> = std::env::args().collect();
    let Some(scope) = scope_on_line(&args) else {
        return Ok(vec![]);
    };
    let ids = |ms: Vec<Value>| -> Vec<String> {
        ms.iter()
            .filter_map(|m| m.get("account_id")?.as_str().map(String::from))
            .collect()
    };
    let on_scope = ids(member::members(client, &scope).await?);
    let names = match (invitees, &scope.product_id) {
        (false, _) => on_scope,
        (true, None) => vec![],
        (true, Some(_)) => {
            let org = Scope {
                account_id: scope.account_id.clone(),
                product_id: None,
            };
            let mut org_members = ids(member::members(client, &org).await?);
            org_members.retain(|a| !on_scope.contains(a));
            org_members
        }
    };
    Ok(starting_with(names, current))
}

/// Where your memberships in `state` are, as `ACCOUNT` or `ACCOUNT/PRODUCT`.
async fn mine(client: &Client, current: &str, state: &str) -> Result<Vec<String>, String> {
    let ms = member::my_memberships(client, state).await?;
    let names = ms.iter().map(|m| Scope::of(m).to_string()).collect();
    Ok(starting_with(names, current))
}

/// The SCOPE in `member SUBCOMMAND … SCOPE …`: the first word after the
/// subcommand that is neither a flag nor a flag's value. Completers see only
/// the word being completed, but the shell passes the whole line as our
/// arguments.
fn scope_on_line(args: &[String]) -> Option<Scope> {
    const TAKE_VALUES: [&str; 10] = [
        "--api-url",
        "--proxy-url",
        "-r",
        "--role",
        "-F",
        "--from-file",
        "-A",
        "--accounts-file",
        "--state",
        "-L",
    ];
    let at = args.iter().position(|a| a == "member")?;
    let mut words = args.get(at + 2..)?.iter();
    while let Some(w) = words.next() {
        if TAKE_VALUES.contains(&w.as_str()) {
            words.next();
        } else if !w.starts_with('-') {
            return w.parse().ok();
        }
    }
    None
}

fn starting_with(names: Vec<String>, prefix: &str) -> Vec<String> {
    names
        .into_iter()
        .filter(|n| n.starts_with(prefix))
        .collect()
}

/// Accounts as the start of `ACCOUNT/PRODUCT`. Shells add no space after a
/// trailing `/`, so the next TAB goes on to the products.
fn slashed(accounts: Vec<String>) -> Vec<String> {
    accounts.into_iter().map(|a| a + "/").collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn server() -> (MockServer, Client) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/whoami"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "account": {"account_id": "acct", "type": "individual",
                            "flags": ["create_repositories"]},
                "memberships": [
                    {"account_id": "acct", "membership_account_id": "org",
                     "role": "maintainers", "state": "member"},
                    {"account_id": "acct", "membership_account_id": "other",
                     "role": "readers", "state": "member"},
                    {"account_id": "acct", "membership_account_id": "invited",
                     "role": "owners", "state": "invited"}
                ]
            })))
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), None, false).unwrap();
        (server, client)
    }

    #[test]
    fn every_shell_s_script_calls_back_with_our_variable() {
        for shell in Shell::value_variants() {
            let mut out = vec![];
            registration(*shell, &mut out).unwrap();
            let script = String::from_utf8(out).unwrap();
            assert!(script.contains(VAR), "{script}");
        }
    }

    #[tokio::test]
    async fn before_the_slash_offers_your_accounts() {
        let (_server, client) = server().await;
        assert_eq!(
            products(&client, "").await.unwrap(),
            ["acct/", "org/", "other/"]
        );
        assert_eq!(products(&client, "o").await.unwrap(), ["org/", "other/"]);
        assert_eq!(accounts(&client, "a").await.unwrap(), ["acct"]);
    }

    #[tokio::test]
    async fn after_the_slash_offers_the_account_s_products() {
        let (server, client) = server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/org"))
            .and(query_param("q", "cl"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                // The API's search also matches titles and descriptions.
                "items": [{"product_id": "climate"}, {"product_id": "aerial", "title": "Clouds"}],
                "next_cursor": null
            })))
            .mount(&server)
            .await;
        assert_eq!(products(&client, "org/cl").await.unwrap(), ["org/climate"]);
        // No account before the `/` is not an account's listing.
        assert!(products(&client, "/cl").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn every_page_of_an_account_s_products_is_read() {
        let (server, client) = server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/org"))
            .and(query_param("cursor", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"product_id": "zebra"}], "next_cursor": null
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/products/org"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"product_id": "aerial"}], "next_cursor": "2"
            })))
            .mount(&server)
            .await;
        assert_eq!(products(&client, "org/z").await.unwrap(), ["org/zebra"]);
    }

    #[tokio::test]
    async fn a_scope_is_an_account_or_one_of_its_products() {
        let (server, client) = server().await;
        assert_eq!(
            scopes(&client, "o").await.unwrap(),
            ["org/", "org", "other/", "other"]
        );
        Mock::given(method("GET"))
            .and(path("/api/v1/products/org"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"account_id": "org", "product_id": "data"}], "next_cursor": null
            })))
            .mount(&server)
            .await;
        assert_eq!(scopes(&client, "org/").await.unwrap(), ["org/data"]);
    }

    #[test]
    fn a_member_completes_from_the_scope_named_before_it() {
        let line = |s: &str| -> Vec<String> { s.split(' ').map(String::from).collect() };
        let scope = |s: &str| scope_on_line(&line(s)).map(|s| s.to_string());
        // As the shell calls us: the binary, `--`, then the line.
        assert_eq!(
            scope("source-coop -- source-coop member edit org/data al"),
            Some("org/data".into())
        );
        // Flags and their values before it are passed over.
        assert_eq!(
            scope("source-coop -- source-coop member edit --role owners -F x.json org al"),
            Some("org".into())
        );
        assert_eq!(scope("source-coop -- source-coop member edit"), None);
        assert_eq!(scope("source-coop -- source-coop product view"), None);
    }

    #[tokio::test]
    async fn your_invitations_and_memberships_complete_by_where_they_are() {
        let (server, client) = server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/memberships"))
            .and(query_param("account_id", "acct"))
            .and(query_param("state", "invited"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": [
                {"membership_account_id": "geo", "product_id": "elevation"},
                {"membership_account_id": "river"}
            ], "next_cursor": null})))
            .mount(&server)
            .await;
        assert_eq!(
            mine(&client, "", "invited").await.unwrap(),
            ["geo/elevation", "river"]
        );
        assert_eq!(mine(&client, "r", "invited").await.unwrap(), ["river"]);
    }

    #[tokio::test]
    async fn service_accounts_complete_whole_from_the_owners_you_can_list() {
        let (server, client) = server().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/accounts/org/service-accounts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"account_id": "org--nightly"}, {"account_id": "org--indexer"}],
                "next_cursor": null
            })))
            .mount(&server)
            .await;
        // Not one of other's managers.
        Mock::given(method("GET"))
            .and(path("/api/v1/accounts/other/service-accounts"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        assert_eq!(
            service_accounts(&client, "o").await.unwrap(),
            ["org--nightly", "org--indexer"]
        );
        assert_eq!(
            service_accounts(&client, "org--n").await.unwrap(),
            ["org--nightly"]
        );
        // acct lists none: its listing isn't mocked, so it fails and is skipped.
        assert!(service_accounts(&client, "acct").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn create_offers_only_accounts_you_may_create_under() {
        let (_server, client) = server().await;
        assert_eq!(new_products(&client, "").await.unwrap(), ["acct/", "org/"]);
        assert!(new_products(&client, "org/").await.unwrap().is_empty());
    }

    /// Clap calls completers outside any runtime, as `main` runs them.
    #[test]
    fn a_completer_runs_and_times_out_without_a_runtime_of_its_own() {
        let offline = || Client::new("http://127.0.0.1:1", None, false).ok();
        let names = |found: Vec<CompletionCandidate>| -> Vec<String> {
            found
                .iter()
                .map(|c| c.get_value().to_string_lossy().into())
                .collect()
        };
        let found = complete(
            offline,
            ANSWER,
            TIMEOUT,
            OsStr::new("org/"),
            |_, s| async move {
                tokio::time::sleep(Duration::from_millis(1)).await;
                Ok(vec![s])
            },
        );
        assert_eq!(names(found), ["org/"]);
        let short = Duration::from_millis(50);
        let found = complete(offline, ANSWER, short, OsStr::new(""), |_, _| async {
            tokio::time::sleep(TIMEOUT).await;
            Ok(vec!["too late".into()])
        });
        assert!(found.is_empty());
        // A keyring read waiting on its password dialog outlasts the API's
        // timeout: giving up would discard the answer.
        let slow = move || {
            std::thread::sleep(short * 2);
            offline()
        };
        let found = complete(slow, ANSWER, short, OsStr::new(""), |_, _| async {
            Ok(vec!["answered".into()])
        });
        assert_eq!(names(found), ["answered"]);
        // But one nobody answers is given up on.
        let stuck = move || {
            std::thread::sleep(ANSWER);
            offline()
        };
        let found = complete(stuck, short, short, OsStr::new(""), |_, _| async {
            Ok(vec!["unreachable".into()])
        });
        assert!(found.is_empty());
    }

    #[tokio::test]
    async fn signed_out_offers_nothing() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/whoami"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), None, false).unwrap();
        assert!(products(&client, "").await.is_err());
    }
}
