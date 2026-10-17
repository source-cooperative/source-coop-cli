//! Shell completion of record names, such as `product view my-org/<TAB>`.
//! Commands, flags and their values complete from the clap definitions
//! (`CompleteEnv` in `main`); these add the names only the API knows.
//!
//! A completer runs on every TAB, so it never prompts, prints or refreshes the
//! login: it uses an unexpired cached token (or `SOURCE_TOKEN`), and offers
//! nothing when the API fails or is slow.

use crate::api::{Client, Page};
use crate::{cache, defaults, product, session};
use clap_complete::engine::CompletionCandidate;
use serde_json::Value;
use std::ffi::OsStr;
use std::future::Future;
use std::time::Duration;

/// How long a TAB waits on the API before offering nothing.
const TIMEOUT: Duration = Duration::from_secs(2);

/// An existing product, as `ACCOUNT/PRODUCT`.
pub fn product(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(
        client(),
        current,
        |c, s| async move { products(&c, &s).await },
    )
}

/// A product to create: the accounts you may create under, then nothing,
/// since the product ID is new.
pub fn new_product(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(client(), current, |c, s| async move {
        new_products(&c, &s).await
    })
}

/// An account you belong to.
pub fn account(current: &OsStr) -> Vec<CompletionCandidate> {
    complete(
        client(),
        current,
        |c, s| async move { accounts(&c, &s).await },
    )
}

/// Run `find` with `current` and offer what it returns. The client is passed
/// in, not made here, so tests never reach `client()`, which reads the login
/// session from the OS keyring.
fn complete<F>(
    client: Option<Client>,
    current: &OsStr,
    find: impl FnOnce(Client, String) -> F,
) -> Vec<CompletionCandidate>
where
    F: Future<Output = Result<Vec<String>, String>>,
{
    let (Some(client), Ok(rt)) = (
        client,
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build(),
    ) else {
        return vec![];
    };
    let current = current.to_string_lossy().into_owned();
    // The timer needs the runtime, so it is made inside it.
    rt.block_on(async { tokio::time::timeout(TIMEOUT, find(client, current)).await })
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
/// accounts you belong to; after it, that account's products.
async fn products(client: &Client, current: &str) -> Result<Vec<String>, String> {
    let Some((account, prefix)) = current.split_once('/') else {
        return Ok(slashed(accounts(client, current).await?));
    };
    let mut url = client.url(&["products", account]);
    {
        let mut q = url.query_pairs_mut();
        // ponytail: one page; an account with more than 100 matches is narrowed by typing more
        q.append_pair("limit", "100");
        if !prefix.is_empty() {
            q.append_pair("q", prefix);
        }
    }
    let page: Page<Value> = client.get(url).await?;
    Ok(page
        .items
        .iter()
        .filter_map(|p| p.get("product_id")?.as_str())
        .filter(|id| id.starts_with(prefix))
        .map(|id| format!("{account}/{id}"))
        .collect())
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
        let client = || Client::new("http://127.0.0.1:1", None, false).ok();
        let names = |found: Vec<CompletionCandidate>| -> Vec<String> {
            found
                .iter()
                .map(|c| c.get_value().to_string_lossy().into())
                .collect()
        };
        let found = complete(client(), OsStr::new("org/"), |_, s| async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            Ok(vec![s])
        });
        assert_eq!(names(found), ["org/"]);
        let found = complete(client(), OsStr::new(""), |_, _| async {
            tokio::time::sleep(TIMEOUT * 2).await;
            Ok(vec!["too late".into()])
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
