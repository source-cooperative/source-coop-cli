use crate::session::Session;
use crate::sts::Credentials;
use chrono::Utc;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const KEYRING_SERVICE: &str = "source-coop-cli";

/// What gets cached per role: the STS credentials, and how to mint new ones
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

fn cache_dir() -> Result<PathBuf, String> {
    Ok(dirs::cache_dir()
        .ok_or("Could not determine cache directory")?
        .join("source-coop"))
}

fn role_slot(role_arn: &str) -> Result<Slot, String> {
    Ok(Slot {
        account: role_arn.to_string(),
        path: cache_path(role_arn)?,
    })
}

/// The login session's slot. `@` can't begin a role ARN or role name, so its
/// keyring account never collides with a role's.
fn session_slot() -> Result<Slot, String> {
    Ok(Slot {
        account: "@session".to_string(),
        path: cache_dir()?.join("session.json"),
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

/// Replace any character that isn't alphanumeric, `-`, or `_` with `_`.
fn sanitize_role_arn(role_arn: &str) -> String {
    role_arn
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Full path to the credentials cache file for a given role.
/// Uses the OS-idiomatic cache directory (`~/Library/Caches` on macOS,
/// `~/.cache` on Linux, `%LocalAppData%` on Windows).
fn cache_path(role_arn: &str) -> Result<PathBuf, String> {
    let sanitized = sanitize_role_arn(role_arn);
    Ok(cache_dir()?
        .join("credentials")
        .join(format!("{sanitized}.json")))
}

/// Take an exclusive per-role lock, held until the returned file is dropped,
/// so concurrent `creds` calls for one role mint once.
pub fn lock(role_arn: &str) -> Result<fs::File, String> {
    lock_slot(&role_slot(role_arn)?)
}

/// Take the login session's lock. Refresh tokens rotate on use, and the IdP
/// may revoke the whole token family if an old one is replayed, so nothing may
/// refresh the session in parallel. Taken after a role's lock, never before.
pub fn lock_session() -> Result<fs::File, String> {
    lock_slot(&session_slot()?)
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
pub fn write_credentials(role_arn: &str, creds: &CacheEntry) -> Result<String, String> {
    write_slot(&role_slot(role_arn)?, creds)
}

/// Read credentials, trying the OS keyring first with file fallback.
/// Returns `None` if no cached credentials are found in either location.
pub fn read_credentials(role_arn: &str) -> Result<Option<CacheEntry>, String> {
    read_slot(&role_slot(role_arn)?)
}

pub fn write_session(session: &Session) -> Result<String, String> {
    write_slot(&session_slot()?, session)
}

pub fn read_session() -> Result<Option<Session>, String> {
    read_slot(&session_slot()?)
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
fn write_file(path: &Path, json: &str) -> Result<String, String> {
    let dir = path.parent().unwrap();
    fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create cache directory {}: {e}", dir.display()))?;
    fs::write(path, json).map_err(|e| format!("Failed to write cache {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set permissions on {}: {e}", path.display()))?;
    }
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
    fn sanitize_simple_name() {
        assert_eq!(sanitize_role_arn("source-coop-user"), "source-coop-user");
    }

    #[test]
    fn sanitize_arn_with_special_chars() {
        assert_eq!(
            sanitize_role_arn("arn:aws:iam::123:role/Foo"),
            "arn_aws_iam__123_role_Foo"
        );
    }

    #[test]
    fn sanitize_preserves_underscores() {
        assert_eq!(sanitize_role_arn("my_role-name"), "my_role-name");
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
