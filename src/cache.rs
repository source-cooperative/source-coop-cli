use crate::sts::Credentials;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;

const KEYRING_SERVICE: &str = "source-coop-cli";

/// What gets cached per role: the STS credentials plus, when the IdP issued
/// one, what's needed to mint fresh credentials without a browser login.
/// `flatten` keeps caches written by older versions (bare credentials) readable.
#[derive(Serialize, Deserialize)]
pub struct CacheEntry {
    #[serde(flatten)]
    pub creds: Credentials,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<RefreshState>,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshState {
    pub refresh_token: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub proxy_url: String,
    pub duration: Option<u64>,
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
    let cache_dir = dirs::cache_dir().ok_or("Could not determine cache directory")?;
    let sanitized = sanitize_role_arn(role_arn);
    Ok(cache_dir
        .join("source-coop")
        .join("credentials")
        .join(format!("{sanitized}.json")))
}

/// Take an exclusive per-role lock, held until the returned file is dropped.
/// Refresh tokens rotate on use, and the IdP may revoke the whole token family
/// if an old one is replayed, so concurrent `creds` calls must not refresh in
/// parallel.
pub fn lock(role_arn: &str) -> Result<fs::File, String> {
    let path = cache_path(role_arn)?.with_extension("lock");
    let dir = path.parent().unwrap();
    fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create cache directory {}: {e}", dir.display()))?;
    let file = fs::File::create(&path)
        .map_err(|e| format!("Failed to open lock file {}: {e}", path.display()))?;
    file.lock()
        .map_err(|e| format!("Failed to lock {}: {e}", path.display()))?;
    Ok(file)
}

/// Write credentials to a cache file. Returns the file path as a string.
fn write_credentials_file(role_arn: &str, creds: &CacheEntry) -> Result<String, String> {
    let path = cache_path(role_arn)?;
    let dir = path.parent().unwrap();

    fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create cache directory {}: {e}", dir.display()))?;

    let json = serde_json::to_string_pretty(creds)
        .map_err(|e| format!("Failed to serialize credentials: {e}"))?;

    fs::write(&path, &json)
        .map_err(|e| format!("Failed to write credentials cache {}: {e}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set permissions on {}: {e}", path.display()))?;
    }

    Ok(path.display().to_string())
}

/// Read credentials from a cache file. Returns `None` if the file does not exist.
fn read_credentials_file(role_arn: &str) -> Result<Option<CacheEntry>, String> {
    let path = cache_path(role_arn)?;
    match fs::read_to_string(&path) {
        Ok(contents) => {
            let creds: CacheEntry = serde_json::from_str(&contents)
                .map_err(|e| format!("Failed to parse credentials cache: {e}"))?;
            Ok(Some(creds))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "Failed to read credentials cache {}: {e}",
            path.display()
        )),
    }
}

/// Write credentials, trying the OS keyring first with file fallback.
/// Returns a human-readable description of where credentials were stored.
pub fn write_credentials(role_arn: &str, creds: &CacheEntry) -> Result<String, String> {
    let json = serde_json::to_string(creds)
        .map_err(|e| format!("Failed to serialize credentials: {e}"))?;

    let entry = keyring::Entry::new(KEYRING_SERVICE, role_arn)
        .map_err(|e| format!("Failed to create keyring entry: {e}"));

    if let Ok(entry) = entry {
        match entry.set_password(&json) {
            Ok(()) => {
                return Ok(format!("OS keyring (service: {KEYRING_SERVICE})"));
            }
            Err(ref e) if is_keyring_unavailable(e) => {
                // Fall through to file-based caching
            }
            Err(e) => {
                return Err(format!("Failed to write credentials to keyring: {e}"));
            }
        }
    }

    write_credentials_file(role_arn, creds)
}

/// Read credentials, trying the OS keyring first with file fallback.
/// Returns `None` if no cached credentials are found in either location.
pub fn read_credentials(role_arn: &str) -> Result<Option<CacheEntry>, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, role_arn)
        .map_err(|e| format!("Failed to create keyring entry: {e}"));

    if let Ok(entry) = entry {
        match entry.get_password() {
            Ok(json) => {
                let creds: CacheEntry = serde_json::from_str(&json)
                    .map_err(|e| format!("Failed to parse credentials from keyring: {e}"))?;
                return Ok(Some(creds));
            }
            Err(keyring::Error::NoEntry) => {
                // Keyring works but nothing stored — fall through to file
            }
            Err(ref e) if is_keyring_unavailable(e) => {
                // Keyring unavailable — fall through to file
            }
            Err(e) => {
                return Err(format!("Failed to read credentials from keyring: {e}"));
            }
        }
    }

    read_credentials_file(role_arn)
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
