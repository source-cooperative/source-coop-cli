//! The Ory login session, shared by everything that needs to act as the person
//! who ran `login`.
//!
//! One session holds one refresh token, and it is the only copy: refresh
//! tokens rotate on use and a replayed one can revoke the whole family, so
//! every role's STS credentials and every API call refresh through here, under
//! one lock. A refresh returns a new ID token (exchanged at the proxy's `/.sts`
//! for S3 credentials) and a new access token (sent to the source.coop API).

use crate::{cache, oidc};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// A token this close to expiry is treated as expired, so it can't lapse
/// between being read here and being checked by the server.
const SKEW_SECONDS: i64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub client_id: String,
    pub token_endpoint: String,
    /// What the access token was requested for, if anything.
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub id_token: String,
    #[serde(default)]
    pub access_token: Option<String>,
    /// When the access token expires, in Unix seconds.
    #[serde(default)]
    pub access_token_expires_at: Option<i64>,
}

/// Which token a caller needs from the session.
#[derive(Clone, Copy, Debug)]
pub enum Want {
    /// The access token, for the source.coop API.
    Access,
    /// The ID token, for the proxy's STS exchange.
    Id,
}

impl Session {
    pub fn new(
        tokens: oidc::Tokens,
        client_id: String,
        token_endpoint: String,
        audience: Option<String>,
        now: i64,
    ) -> Self {
        let mut session = Session {
            client_id,
            token_endpoint,
            audience,
            refresh_token: None,
            id_token: String::new(),
            access_token: None,
            access_token_expires_at: None,
        };
        session.apply(tokens, now);
        session
    }

    /// Take a token response, keeping the refresh token if it wasn't rotated.
    fn apply(&mut self, tokens: oidc::Tokens, now: i64) {
        self.id_token = tokens.id_token;
        if let Some(rotated) = tokens.refresh_token {
            self.refresh_token = Some(rotated);
        }
        self.access_token_expires_at = tokens
            .expires_in
            .map(|s| now + s)
            .or_else(|| tokens.access_token.as_deref().and_then(jwt_exp));
        self.access_token = tokens.access_token;
    }

    /// The wanted token if it's still good at `now`. `Ok(None)` means the
    /// session has no such token at all (an access token, when login asked
    /// for no audience); `Err(())` means it has one that has expired.
    fn current(&self, want: Want, now: i64) -> Result<Option<&str>, ()> {
        let (token, expires_at) = match want {
            Want::Id => (Some(self.id_token.as_str()), jwt_exp(&self.id_token)),
            Want::Access => (self.access_token.as_deref(), self.access_token_expires_at),
        };
        match (token, expires_at) {
            (None, _) => Ok(None),
            // A token whose expiry can't be read is left to the server to judge.
            (Some(t), None) => Ok(Some(t)),
            (Some(t), Some(exp)) if exp > now + SKEW_SECONDS => Ok(Some(t)),
            (Some(_), Some(_)) => Err(()),
        }
    }
}

/// The `exp` claim of a JWT, read without verifying it: only to know when to
/// refresh, never to trust the token.
fn jwt_exp(token: &str) -> Option<i64> {
    let payload = URL_SAFE_NO_PAD.decode(token.split('.').nth(1)?).ok()?;
    serde_json::from_slice::<serde_json::Value>(&payload)
        .ok()?
        .get("exp")?
        .as_i64()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

const EXPIRED: &str = "Your login has expired. Run 'source-coop login'.";

/// The wanted token from `session`, refreshing the session first if that
/// token has expired. `save` persists the session after a refresh, before the
/// new token is used. Returns `None` if the session can't have the token.
pub async fn ensure(
    session: &mut Session,
    want: Want,
    now: i64,
    verbose: bool,
    mut save: impl FnMut(&Session) -> Result<(), String>,
) -> Result<Option<String>, String> {
    if let Ok(token) = session.current(want, now) {
        return Ok(token.map(String::from));
    }
    let refresh_token = session.refresh_token.as_deref().ok_or(EXPIRED)?;
    if verbose {
        eprintln!("[verbose] Refreshing the login session");
    }
    let tokens = oidc::refresh(
        &session.token_endpoint,
        &session.client_id,
        refresh_token,
        verbose,
    )
    .await?;
    session.apply(tokens, now);
    // The old refresh token is spent; persist the new one before anything can fail.
    save(session)?;
    session
        .current(want, now)
        .map(|t| t.map(String::from))
        .map_err(|()| "The refreshed token has already expired; check the system clock.".into())
}

/// The wanted token from the cached session, or `None` if there is no session
/// (or it can't have that token). Refreshes under the session lock when needed.
pub async fn token(want: Want, verbose: bool) -> Result<Option<String>, String> {
    let Some(session) = cache::read_session()? else {
        return Ok(None);
    };
    if let Ok(token) = session.current(want, now()) {
        return Ok(token.map(String::from));
    }
    // Re-read under the lock: another process may have refreshed already.
    let _lock = cache::lock_session()?;
    let Some(mut session) = cache::read_session()? else {
        return Ok(None);
    };
    ensure(&mut session, want, now(), verbose, |s| {
        cache::write_session(s).map(drop)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const NOW: i64 = 1_800_000_000;

    /// An unsigned JWT that expires at `exp`; only its claims are ever read.
    fn jwt(exp: i64) -> String {
        let claims = URL_SAFE_NO_PAD.encode(json!({ "exp": exp }).to_string());
        format!("e30.{claims}.sig")
    }

    fn tokens(id_exp: i64, access: Option<&str>, expires_in: Option<i64>) -> oidc::Tokens {
        oidc::Tokens {
            id_token: jwt(id_exp),
            refresh_token: Some("rt-1".into()),
            access_token: access.map(String::from),
            expires_in,
        }
    }

    fn session(server: &MockServer, t: oidc::Tokens) -> Session {
        Session::new(
            t,
            "cid".into(),
            format!("{}/oauth2/token", server.uri()),
            Some("https://source.coop".into()),
            NOW,
        )
    }

    async fn mock_refresh(server: &MockServer, body: serde_json::Value, times: u64) {
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .and(body_string_contains("grant_type=refresh_token"))
            .and(body_string_contains("refresh_token=rt-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(times)
            .mount(server)
            .await;
    }

    #[test]
    fn reads_jwt_expiry() {
        assert_eq!(jwt_exp(&jwt(42)), Some(42));
        assert_eq!(jwt_exp("opaque-token"), None);
    }

    #[tokio::test]
    async fn fresh_tokens_are_used_without_refreshing() {
        let server = MockServer::start().await;
        mock_refresh(&server, json!({}), 0).await;
        let mut s = session(&server, tokens(NOW + 3600, Some("at"), Some(3600)));

        let saves = std::cell::Cell::new(0);
        let save = |_: &Session| {
            saves.set(saves.get() + 1);
            Ok(())
        };
        let access = ensure(&mut s, Want::Access, NOW, false, save)
            .await
            .unwrap();
        assert_eq!(access.as_deref(), Some("at"));
        let id = ensure(&mut s, Want::Id, NOW, false, save).await.unwrap();
        assert_eq!(id, Some(jwt(NOW + 3600)));
        assert_eq!(saves.get(), 0);
    }

    #[tokio::test]
    async fn an_expired_access_token_refreshes_and_rotates() {
        let server = MockServer::start().await;
        mock_refresh(
            &server,
            json!({"id_token": jwt(NOW + 3600), "access_token": "at-2",
                   "expires_in": 3600, "refresh_token": "rt-2"}),
            1,
        )
        .await;
        // Expires inside the skew window, so it counts as expired.
        let mut s = session(&server, tokens(NOW + 3600, Some("at-1"), Some(30)));

        let mut saved = vec![];
        let access = ensure(&mut s, Want::Access, NOW, false, |s| {
            saved.push(s.refresh_token.clone().unwrap());
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(access.as_deref(), Some("at-2"));
        assert_eq!(saved, ["rt-2"]);
        assert_eq!(s.access_token_expires_at, Some(NOW + 3600));
    }

    #[tokio::test]
    async fn an_expired_id_token_refreshes_for_sts() {
        let server = MockServer::start().await;
        mock_refresh(&server, json!({"id_token": jwt(NOW + 3600)}), 1).await;
        let mut s = session(&server, tokens(NOW - 10, None, None));

        let id = ensure(&mut s, Want::Id, NOW, false, |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(id, Some(jwt(NOW + 3600)));
        // Not rotated, so the old refresh token stays.
        assert_eq!(s.refresh_token.as_deref(), Some("rt-1"));
    }

    #[tokio::test]
    async fn no_access_token_without_an_audience() {
        let server = MockServer::start().await;
        mock_refresh(&server, json!({}), 0).await;
        let mut s = session(&server, tokens(NOW + 3600, None, None));
        let access = ensure(&mut s, Want::Access, NOW, false, |_| Ok(()))
            .await
            .unwrap();
        assert_eq!(access, None);
    }

    #[tokio::test]
    async fn an_expired_session_without_a_refresh_token_says_to_log_in() {
        let server = MockServer::start().await;
        let mut t = tokens(NOW - 10, Some("at"), Some(-10));
        t.refresh_token = None;
        let mut s = session(&server, t);
        let err = ensure(&mut s, Want::Access, NOW, false, |_| Ok(()))
            .await
            .unwrap_err();
        assert!(err.contains("source-coop login"));
    }

    #[test]
    fn reads_a_session_without_optional_fields() {
        let s: Session = serde_json::from_value(json!({
            "client_id": "cid", "token_endpoint": "https://auth.test/oauth2/token",
            "id_token": "x"
        }))
        .unwrap();
        assert!(s.access_token.is_none() && s.refresh_token.is_none());
    }
}
