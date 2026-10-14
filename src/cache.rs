use crate::session::Session;
use crate::sts::Credentials;
use chrono::Utc;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const KEYRING_SERVICE: &str = "source-coop-cli";

/// What gets cached per proxy + role: the STS credentials, and how to mint new ones
/// from the login session when they expire. `flatten` keeps caches written by
/// older versions (bare credentials) readable.
#[derive(Serialize, Deserialize)]
pub struct CacheEntry {
    #[serde(flatten)]
    pub creds: Credentials,
    /// The STS settings `login` was given, reused when minting new credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sts: Option<StsSettings>,
    /// A refresh token of the role's own, from versions before the login
    /// session was shared. Still honoured so those caches keep working; a new
    /// `login` replaces it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<RefreshState>,
}

impl CacheEntry {
    /// Whether this entry records that it was minted at a proxy in `env`.
    fn minted_in(&self, env: Option<&str>) -> bool {
        let proxy_url = match (&self.sts, &self.refresh) {
            (Some(sts), _) => &sts.proxy_url,
            (None, Some(refresh)) => &refresh.proxy_url,
            (None, None) => return false,
        };
        in_env(proxy_url, env)
    }

    /// Whether this entry can be used in its own slot in `env`. Bare
    /// credentials record no proxy and can't be renewed, so they're taken as
    /// they are.
    fn belongs_to(&self, env: Option<&str>) -> bool {
        (self.sts.is_none() && self.refresh.is_none()) || self.minted_in(env)
    }
}

/// Whether `proxy_url` is in `env`. An unparseable URL is in none.
fn in_env(proxy_url: &str, env: Option<&str>) -> bool {
    self::env(proxy_url).is_ok_and(|e| e.as_deref() == env)
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StsSettings {
    pub proxy_url: String,
    pub duration: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshState {
    pub refresh_token: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub proxy_url: String,
    pub duration: Option<u64>,
}

/// Where one cached item lives: its keyring account, and its file when the
/// keyring is unavailable.
struct Slot {
    account: String,
    path: PathBuf,
}

/// The OS-idiomatic cache directory (`~/Library/Caches` on macOS, `~/.cache`
/// on Linux, `%LocalAppData%` on Windows).
fn cache_dir() -> Result<PathBuf, String> {
    Ok(dirs::cache_dir()
        .ok_or("Could not determine cache directory")?
        .join("source-coop"))
}

/// The production proxy's host. Its slots keep the names they had before
/// environments existed, in every build: tying them to the build's default
/// proxy would let a staging build and a production build, which share the
/// keyring, read each other's caches as their own.
const PROD_HOST: &str = "data.source.coop";

/// The environment a proxy URL belongs to: `None` for production, otherwise
/// the proxy's host (and port, if not the scheme's default).
pub fn env(proxy_url: &str) -> Result<Option<String>, String> {
    let url = url::Url::parse(proxy_url).map_err(|e| {
        format!("Invalid proxy URL {proxy_url:?} (from --proxy-url or SOURCE_PROXY_URL): {e}")
    })?;
    let host = url
        .host_str()
        .ok_or_else(|| format!("Proxy URL {proxy_url:?} has no host"))?;
    Ok(match url.port() {
        Some(port) => Some(format!("{host}:{port}")),
        None if host == PROD_HOST => None,
        None => Some(host.to_string()),
    })
}

/// The keyring account for `name` in `env`. Hosts can't contain `/`, so a
/// prefixed account never equals a default-environment one.
fn account(env: Option<&str>, name: &str) -> String {
    match env {
        None => name.to_string(),
        Some(env) => format!("{env}/{name}"),
    }
}

/// The directory `env`'s cache files live in: `env/<host>[/<port>]`. Each
/// non-production environment gets its own, so their files can't collide with
/// each other's or prod's. The port is its own segment because `_`, which
/// sanitizing produces, is allowed in hosts.
fn env_dir(env: Option<&str>) -> Result<PathBuf, String> {
    let dir = cache_dir()?;
    let Some(env) = env else { return Ok(dir) };
    let (host, port) = env
        .rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or((env, ""));
    let dir = dir.join("env").join(sanitize(host, &['-', '.', '_']));
    Ok(if port.is_empty() { dir } else { dir.join(port) })
}

fn role_slot(env: Option<&str>, role_arn: &str) -> Result<Slot, String> {
    Ok(Slot {
        account: account(env, role_arn),
        path: env_dir(env)?
            .join("credentials")
            .join(format!("{}.json", sanitize(role_arn, &['-', '_']))),
    })
}

/// The login session's slot. `@` can't begin a role ARN or role name, so its
/// keyring account never collides with a role's.
fn session_slot(env: Option<&str>) -> Result<Slot, String> {
    Ok(Slot {
        account: account(env, "@session"),
        path: env_dir(env)?.join("session.json"),
    })
}

/// Returns `true` for keyring errors that indicate the keyring backend is
/// unavailable (headless Linux, containers, CI). These trigger a fallback to
/// file-based caching. Other error variants are treated as hard errors.
fn is_keyring_unavailable(err: &keyring::Error) -> bool {
    matches!(
        err,
        keyring::Error::NoStorageAccess(_)
            | keyring::Error::PlatformFailure(_)
            | keyring::Error::TooLong(_, _)
    )
}

/// Replace any character that isn't alphanumeric or in `keep` with `_`.
pub(crate) fn sanitize(s: &str, keep: &[char]) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || keep.contains(&c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Take an exclusive per-role lock, held until the returned file is dropped,
/// so concurrent `creds` calls for one role mint once.
pub fn lock(env: Option<&str>, role_arn: &str) -> Result<fs::File, String> {
    lock_slot(&role_slot(env, role_arn)?)
}

/// Take the login session's lock. Refresh tokens rotate on use, and the IdP
/// may revoke the whole token family if an old one is replayed, so nothing may
/// refresh the session in parallel. Taken after a role's lock, never before.
pub fn lock_session(env: Option<&str>) -> Result<fs::File, String> {
    lock_slot(&session_slot(env)?)
}

fn lock_slot(slot: &Slot) -> Result<fs::File, String> {
    let path = slot.path.with_extension("lock");
    let dir = path.parent().unwrap();
    fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create cache directory {}: {e}", dir.display()))?;
    let file = fs::File::create(&path)
        .map_err(|e| format!("Failed to open lock file {}: {e}", path.display()))?;
    file.lock()
        .map_err(|e| format!("Failed to lock {}: {e}", path.display()))?;
    Ok(file)
}

/// Write credentials, trying the OS keyring first with file fallback.
/// Returns a human-readable description of where credentials were stored.
pub fn write_credentials(
    env: Option<&str>,
    role_arn: &str,
    creds: &CacheEntry,
) -> Result<String, String> {
    write_slot(&role_slot(env, role_arn)?, creds)
}

/// Read credentials, trying the OS keyring first with file fallback.
/// Returns `None` if no cached credentials are found in either location, or
/// if they were minted at another environment's proxy.
///
/// Versions before environments existed cached every proxy's credentials in
/// the production slot, so an environment with nothing of its own takes its
/// entry from there, copying it into its own slot.
pub fn read_credentials(env: Option<&str>, role_arn: &str) -> Result<Option<CacheEntry>, String> {
    find_credentials(env, role_arn, true)
}

/// `read_credentials` without the copy, for reporting: writes nothing.
pub fn peek_credentials(env: Option<&str>, role_arn: &str) -> Result<Option<CacheEntry>, String> {
    find_credentials(env, role_arn, false)
}

fn find_credentials(
    env: Option<&str>,
    role_arn: &str,
    migrate: bool,
) -> Result<Option<CacheEntry>, String> {
    let slot = role_slot(env, role_arn)?;
    let entry: Option<CacheEntry> = read_slot(&slot)?;
    if entry.is_some() || env.is_none() {
        return Ok(entry.filter(|e| e.belongs_to(env)));
    }
    let legacy: Option<CacheEntry> = read_slot(&role_slot(None, role_arn)?)?;
    // Only an entry that records its proxy: bare ones there are production's.
    let Some(legacy) = legacy.filter(|e| e.minted_in(env)) else {
        return Ok(None);
    };
    if migrate {
        write_slot(&slot, &legacy)?;
    }
    Ok(Some(legacy))
}

pub fn write_session(env: Option<&str>, session: &Session) -> Result<String, String> {
    write_slot(&session_slot(env)?, session)
}

/// Read `env`'s login session, or `None` if there is none or it belongs to
/// another environment's proxy.
pub fn read_session(env: Option<&str>) -> Result<Option<Session>, String> {
    let session: Option<Session> = read_slot(&session_slot(env)?)?;
    Ok(session.filter(|s| s.proxy_url.as_deref().is_none_or(|p| in_env(p, env))))
}

/// Remove the role's cached credentials. Returns whether there were any.
pub fn delete_credentials(env: Option<&str>, role_arn: &str) -> Result<bool, String> {
    let mut removed = delete_slot(&role_slot(env, role_arn)?)?;
    // Otherwise `read_credentials` would copy a legacy entry for `env` back
    // out of production's slot.
    if env.is_some() {
        let legacy = role_slot(None, role_arn)?;
        if read_slot::<CacheEntry>(&legacy)?.is_some_and(|e| e.minted_in(env)) {
            removed |= delete_slot(&legacy)?;
        }
    }
    Ok(removed)
}

/// Remove `env`'s login session. Returns whether there was one.
pub fn delete_session(env: Option<&str>) -> Result<bool, String> {
    delete_slot(&session_slot(env)?)
}

/// Remove a slot from both the keyring and its file, under the slot's lock.
fn delete_slot(slot: &Slot) -> Result<bool, String> {
    let _lock = lock_slot(slot)?;
    let mut removed = false;
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &slot.account) {
        match entry.delete_credential() {
            Ok(()) => removed = true,
            Err(keyring::Error::NoEntry) => {}
            Err(ref e) if is_keyring_unavailable(e) => {}
            Err(e) => return Err(format!("Failed to delete from keyring: {e}")),
        }
    }
    Ok(remove_file(&slot.path)? || removed)
}

/// Remove a cache file. Returns whether it existed.
fn remove_file(path: &Path) -> Result<bool, String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("Failed to remove cache {}: {e}", path.display())),
    }
}

fn write_slot<T: Serialize>(slot: &Slot, value: &T) -> Result<String, String> {
    let json =
        serde_json::to_string(value).map_err(|e| format!("Failed to serialize cache: {e}"))?;

    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &slot.account) {
        match entry.set_password(&json) {
            Ok(()) => return Ok(format!("OS keyring (service: {KEYRING_SERVICE})")),
            // Fall through to file-based caching
            Err(ref e) if is_keyring_unavailable(e) => {}
            Err(e) => return Err(format!("Failed to write to keyring: {e}")),
        }
    }
    write_file(&slot.path, &json)
}

fn read_slot<T: DeserializeOwned>(slot: &Slot) -> Result<Option<T>, String> {
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &slot.account) {
        match entry.get_password() {
            Ok(json) => {
                return serde_json::from_str(&json)
                    .map(Some)
                    .map_err(|e| format!("Failed to parse cache from keyring: {e}"));
            }
            // Keyring works but nothing stored, or is unavailable: try the file
            Err(keyring::Error::NoEntry) => {}
            Err(ref e) if is_keyring_unavailable(e) => {}
            Err(e) => return Err(format!("Failed to read from keyring: {e}")),
        }
    }
    match fs::read_to_string(&slot.path) {
        Ok(contents) => serde_json::from_str(&contents)
            .map(Some)
            .map_err(|e| format!("Failed to parse cache {}: {e}", slot.path.display())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("Failed to read cache {}: {e}", slot.path.display())),
    }
}

/// Write a cache file readable only by its owner. Returns the file path.
pub(crate) fn write_file(path: &Path, json: &str) -> Result<String, String> {
    let dir = path.parent().unwrap();
    fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create cache directory {}: {e}", dir.display()))?;
    // Owner-only before anything is written, so a refresh token is never
    // readable by others, even briefly.
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(path)
        .map_err(|e| format!("Failed to write cache {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        // An existing file keeps its mode through `open`.
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set permissions on {}: {e}", path.display()))?;
    }
    io::Write::write_all(&mut file, json.as_bytes())
        .map_err(|e| format!("Failed to write cache {}: {e}", path.display()))?;
    Ok(path.display().to_string())
}

/// Check if credentials are expired or will expire within a 60-second buffer.
pub fn is_expired(creds: &Credentials) -> Result<bool, String> {
    let expiration = chrono::DateTime::parse_from_rfc3339(&creds.expiration).map_err(|e| {
        format!(
            "Failed to parse expiration timestamp '{}': {e}",
            creds.expiration
        )
    })?;

    let now = Utc::now();
    let buffer = chrono::Duration::seconds(60);

    Ok(expiration <= now + buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_creds(expiration: &str) -> Credentials {
        Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: "FwoGZXIvYXdzEtest".to_string(),
            expiration: expiration.to_string(),
        }
    }

    #[test]
    fn env_normalizes_proxy_urls() {
        // Production is the bare environment in every build, staging never is.
        assert_eq!(env("https://data.source.coop").unwrap(), None);
        assert_eq!(env("https://data.source.coop/").unwrap(), None);
        assert_eq!(env("HTTPS://DATA.SOURCE.COOP").unwrap(), None);
        assert_eq!(env("https://data.source.coop:443").unwrap(), None);
        assert_eq!(
            env("https://Data.Staging.Source.Coop/").unwrap().as_deref(),
            Some("data.staging.source.coop")
        );
        assert_eq!(
            env("https://data.source.coop:8443").unwrap().as_deref(),
            Some("data.source.coop:8443")
        );
        assert_eq!(
            env("http://localhost:8080").unwrap().as_deref(),
            Some("localhost:8080")
        );
        assert!(env("not a url").is_err());
    }

    #[test]
    fn slots_never_collide_across_environments() {
        let default = cache_dir().unwrap();
        let prod = role_slot(None, "_default").unwrap();
        assert_eq!(prod.account, "_default");
        assert_eq!(prod.path, default.join("credentials").join("_default.json"));
        assert_eq!(session_slot(None).unwrap().account, "@session");

        // A role whose sanitized name looks like an environment's still lands elsewhere.
        let local = role_slot(Some("localhost:8080"), "_default").unwrap();
        let lookalike = role_slot(None, "localhost_8080__default").unwrap();
        assert_eq!(local.account, "localhost:8080/_default");
        assert_eq!(
            local.path,
            default
                .join("env")
                .join("localhost")
                .join("8080")
                .join("credentials")
                .join("_default.json")
        );
        assert_ne!(local.path, lookalike.path);
        // `_` is legal in hosts, so the port can't be joined to the host with one.
        let underscored = role_slot(Some("localhost_8080"), "_default").unwrap();
        assert_ne!(local.path, underscored.path);

        let staging = session_slot(Some("data.staging.source.coop")).unwrap();
        assert_eq!(staging.account, "data.staging.source.coop/@session");
        assert_eq!(
            staging.path,
            default
                .join("env")
                .join("data.staging.source.coop")
                .join("session.json")
        );
    }

    #[test]
    fn entries_belong_to_their_proxys_environment() {
        let entry = |proxy_url: &str| CacheEntry {
            creds: sample_creds("2026-03-01T00:00:00Z"),
            sts: Some(StsSettings {
                proxy_url: proxy_url.to_string(),
                duration: None,
            }),
            refresh: None,
        };
        let other = entry("https://data.staging.source.coop");
        assert!(other.belongs_to(Some("data.staging.source.coop")));
        assert!(!other.belongs_to(None));
        assert!(entry("https://data.source.coop").belongs_to(None));
        assert!(other.minted_in(Some("data.staging.source.coop")));
        let bare = CacheEntry { sts: None, ..other };
        assert!(bare.belongs_to(None));
        // A bare entry stays where it is: migration never hands it to another environment.
        assert!(!bare.minted_in(Some("data.staging.source.coop")));
    }

    #[test]
    fn remove_file_reports_whether_it_existed() {
        let path =
            std::env::temp_dir().join(format!("source-coop-test-{}.json", std::process::id()));
        write_file(&path, "{}").unwrap();
        assert!(remove_file(&path).unwrap());
        assert!(!path.exists());
        assert!(!remove_file(&path).unwrap());
    }

    #[test]
    fn sanitize_arn_with_special_chars() {
        assert_eq!(
            sanitize("arn:aws:iam::123:role/Foo", &['-', '_']),
            "arn_aws_iam__123_role_Foo"
        );
        assert_eq!(sanitize("my_role-name", &['-', '_']), "my_role-name");
    }

    #[test]
    fn expired_future_date() {
        let future = (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let creds = sample_creds(&future);
        assert!(!is_expired(&creds).unwrap());
    }

    #[test]
    fn expired_past_date() {
        let past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let creds = sample_creds(&past);
        assert!(is_expired(&creds).unwrap());
    }

    #[test]
    fn expired_within_buffer() {
        // 30 seconds from now is within the 60s buffer
        let near_future = (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339();
        let creds = sample_creds(&near_future);
        assert!(is_expired(&creds).unwrap());
    }

    #[test]
    fn expired_invalid_timestamp() {
        let creds = sample_creds("not-a-timestamp");
        assert!(is_expired(&creds).is_err());
    }

    #[test]
    fn round_trip_serialization() {
        let creds = sample_creds("2026-03-01T00:00:00Z");
        let json = serde_json::to_string_pretty(&creds).unwrap();
        let loaded: Credentials = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.access_key_id, creds.access_key_id);
        assert_eq!(loaded.secret_access_key, creds.secret_access_key);
        assert_eq!(loaded.session_token, creds.session_token);
        assert_eq!(loaded.expiration, creds.expiration);
    }

    #[test]
    fn cache_entry_reads_legacy_format_and_round_trips_refresh() {
        let legacy = serde_json::to_string(&sample_creds("2026-03-01T00:00:00Z")).unwrap();
        let entry: CacheEntry = serde_json::from_str(&legacy).unwrap();
        assert!(entry.refresh.is_none());
        assert_eq!(entry.creds.access_key_id, "AKIAIOSFODNN7EXAMPLE");

        assert!(entry.sts.is_none());
        let entry = CacheEntry {
            refresh: Some(RefreshState {
                refresh_token: "rt".to_string(),
                token_endpoint: "https://auth.test/oauth2/token".to_string(),
                client_id: "cid".to_string(),
                proxy_url: "https://data.test".to_string(),
                duration: Some(3600),
            }),
            ..entry
        };
        let loaded: CacheEntry =
            serde_json::from_str(&serde_json::to_string(&entry).unwrap()).unwrap();
        assert_eq!(loaded.refresh.unwrap().refresh_token, "rt");
        assert_eq!(loaded.creds.session_token, entry.creds.session_token);
    }

    #[test]
    fn is_keyring_unavailable_classifies_no_storage() {
        let inner: Box<dyn std::error::Error + Send + Sync> = "no storage".into();
        let err = keyring::Error::NoStorageAccess(inner);
        assert!(is_keyring_unavailable(&err));
    }

    #[test]
    fn is_keyring_unavailable_classifies_platform_failure() {
        let inner: Box<dyn std::error::Error + Send + Sync> = "platform error".into();
        let err = keyring::Error::PlatformFailure(inner);
        assert!(is_keyring_unavailable(&err));
    }

    #[test]
    fn is_keyring_unavailable_rejects_no_entry() {
        let err = keyring::Error::NoEntry;
        assert!(!is_keyring_unavailable(&err));
    }

    #[test]
    fn is_keyring_unavailable_rejects_invalid() {
        let err = keyring::Error::Invalid("param".into(), "detail".into());
        assert!(!is_keyring_unavailable(&err));
    }

    #[test]
    #[ignore] // Requires real OS keyring — run with `cargo test -- --ignored`
    fn keyring_round_trip() {
        let role = "test-keyring-round-trip";
        let creds = sample_creds("2026-03-01T00:00:00Z");

        // Write to keyring
        let json = serde_json::to_string(&creds).unwrap();
        let entry = keyring::Entry::new(KEYRING_SERVICE, role).unwrap();
        entry.set_password(&json).unwrap();

        // Read back
        let stored = entry.get_password().unwrap();
        let loaded: Credentials = serde_json::from_str(&stored).unwrap();
        assert_eq!(loaded.access_key_id, creds.access_key_id);
        assert_eq!(loaded.secret_access_key, creds.secret_access_key);
        assert_eq!(loaded.session_token, creds.session_token);
        assert_eq!(loaded.expiration, creds.expiration);

        // Cleanup
        let _ = entry.delete_credential();
    }
}
