//! `source-coop auth setup-aws`: a profile in the AWS config file that gets
//! credentials from `source-coop creds` and points S3 at the proxy, so the
//! AWS CLI and SDKs renew credentials themselves as they expire.

use std::path::PathBuf;

/// The production proxy's host, whose profile gets the bare name.
const PROD_HOST: &str = "data.source.coop";

/// The AWS config file: `AWS_CONFIG_FILE` if set, else `~/.aws/config`, as
/// the AWS CLI and SDKs read it.
pub fn path() -> Result<PathBuf, String> {
    if let Some(file) = std::env::var_os("AWS_CONFIG_FILE").filter(|f| !f.is_empty()) {
        return Ok(file.into());
    }
    Ok(dirs::home_dir()
        .ok_or("Could not determine your home directory")?
        .join(".aws")
        .join("config"))
}

/// The profile name for the environment at `proxy_url`: `source-coop` for
/// production, `source-coop-staging` for `data.staging.source.coop`, and the
/// host (and port) for anything else.
pub fn default_profile(proxy_url: &str) -> Result<String, String> {
    let url =
        url::Url::parse(proxy_url).map_err(|e| format!("Invalid proxy URL {proxy_url:?}: {e}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| format!("Proxy URL {proxy_url:?} has no host"))?;
    if host == PROD_HOST && url.port().is_none() {
        return Ok("source-coop".into());
    }
    let short = host.strip_prefix("data.").unwrap_or(host);
    let short = short.strip_suffix(".source.coop").unwrap_or(short);
    let label = match url.port() {
        Some(port) => format!("{short}-{port}"),
        None => short.to_string(),
    };
    let label: String = label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    Ok(format!("source-coop-{label}"))
}

/// The settings the profile gets, in order. The proxy is always named, so a
/// `SOURCE_PROXY_URL` left in the shell can't hand the profile another
/// environment's credentials; the role only when it isn't the default.
pub fn settings(proxy_url: &str, role_arn: Option<&str>) -> Vec<(&'static str, String)> {
    let endpoint = proxy_url.trim_end_matches('/');
    let mut command = format!("source-coop creds --proxy-url {endpoint}");
    if let Some(role) = role_arn {
        command.push_str(&format!(" --role-arn {role}"));
    }
    vec![
        ("credential_process", command),
        ("endpoint_url", endpoint.to_string()),
    ]
}

/// Settings added only when the profile has none of its own: the proxy
/// ignores the region, but signing needs one.
pub const DEFAULTS: &[(&str, &str)] = &[("region", "us-east-1")];

/// `text` with `[profile name]` holding `settings` (and `DEFAULTS` where it
/// has no value of its own). Everything else is kept as it was: other
/// profiles, comments, and the section's other keys.
pub fn upsert(text: &str, name: &str, settings: &[(&'static str, String)]) -> String {
    let nl = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let Some((start, end)) = find(&lines, name) else {
        while lines.last().is_some_and(|l| l.trim().is_empty()) {
            lines.pop();
        }
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push(format!("[profile {name}]"));
        lines.extend(settings.iter().map(|(k, v)| format!("{k} = {v}")));
        lines.extend(DEFAULTS.iter().map(|(k, v)| format!("{k} = {v}")));
        return lines.join(nl) + nl;
    };

    // Replace the managed keys where they are; drop repeats of them.
    let mut seen: Vec<&str> = vec![];
    let mut body = vec![];
    for line in &lines[start + 1..end] {
        let key = (!line.starts_with(char::is_whitespace))
            .then(|| line.split_once('=').map(|(k, _)| k.trim()))
            .flatten();
        match key.and_then(|k| settings.iter().find(|(s, _)| *s == k)) {
            Some((k, v)) if !seen.contains(k) => {
                seen.push(k);
                body.push(format!("{k} = {v}"));
            }
            Some(_) => {}
            None => {
                if let Some(k) = key.and_then(|k| DEFAULTS.iter().find(|(d, _)| *d == k)) {
                    seen.push(k.0);
                }
                body.push(line.clone());
            }
        }
    }
    // Add what's missing after the section's last line, before blank ones.
    let at = body
        .iter()
        .rposition(|l| !l.trim().is_empty())
        .map_or(0, |i| i + 1);
    let missing = settings
        .iter()
        .map(|(k, v)| (*k, v.clone()))
        .chain(DEFAULTS.iter().map(|(k, v)| (*k, v.to_string())))
        .filter(|(k, _)| !seen.contains(k))
        .map(|(k, v)| format!("{k} = {v}"));
    body.splice(at..at, missing);

    lines.splice(start + 1..end, body);
    lines.join(nl) + nl
}

/// The `[profile name]` section's lines in `text`, header included, without
/// trailing blank lines; None without one.
pub fn section(text: &str, name: &str) -> Option<Vec<String>> {
    let lines: Vec<&str> = text.lines().collect();
    let (start, end) = find(&lines, name)?;
    let mut section: Vec<String> = lines[start..end].iter().map(|l| l.to_string()).collect();
    while section.last().is_some_and(|l| l.trim().is_empty()) {
        section.pop();
    }
    Some(section)
}

/// Where `[profile name]` starts (its header) and ends (the next header, or
/// the end of the file).
fn find(lines: &[impl AsRef<str>], name: &str) -> Option<(usize, usize)> {
    let header = |l: &str| {
        let t = l.trim();
        t.starts_with('[')
            .then(|| t.trim_start_matches('[').trim_end_matches(']').to_string())
    };
    let start = lines.iter().position(|l| {
        header(l.as_ref()).is_some_and(|h| h.split_whitespace().eq(["profile", name]))
    })?;
    let end = (start + 1..lines.len())
        .find(|&i| header(lines[i].as_ref()).is_some())
        .unwrap_or(lines.len());
    Some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prod() -> Vec<(&'static str, String)> {
        settings("https://data.source.coop", None)
    }

    const PROD: &str = "[profile source-coop]\n\
        credential_process = source-coop creds --proxy-url https://data.source.coop\n\
        endpoint_url = https://data.source.coop\n\
        region = us-east-1\n";

    #[test]
    fn profile_names_follow_the_environment() {
        assert_eq!(
            default_profile("https://data.source.coop").unwrap(),
            "source-coop"
        );
        assert_eq!(
            default_profile("https://data.source.coop/").unwrap(),
            "source-coop"
        );
        assert_eq!(
            default_profile("https://data.staging.source.coop").unwrap(),
            "source-coop-staging"
        );
        assert_eq!(
            default_profile("http://localhost:9000").unwrap(),
            "source-coop-localhost-9000"
        );
    }

    #[test]
    fn the_role_is_named_only_when_given() {
        let s = settings("https://data.staging.source.coop/", Some("admin-role"));
        assert_eq!(
            s[0].1,
            "source-coop creds --proxy-url https://data.staging.source.coop --role-arn admin-role"
        );
        assert_eq!(s[1].1, "https://data.staging.source.coop");
    }

    #[test]
    fn a_new_file_gets_the_profile() {
        assert_eq!(upsert("", "source-coop", &prod()), PROD);
    }

    #[test]
    fn other_profiles_and_comments_are_kept() {
        let before = "# mine\n[default]\nregion = eu-west-1\n\n[profile work]\nsso_session = x";
        let after = upsert(before, "source-coop", &prod());
        assert_eq!(after, format!("{before}\n\n{PROD}"));
        assert_eq!(upsert(&after, "source-coop", &prod()), after, "idempotent");
    }

    #[test]
    fn an_existing_profile_is_updated_in_place() {
        let before = "[profile  source-coop ]\n\
            credential_process = old\n\
            s3 =\n  addressing_style = path\n\
            region = eu-central-1\n\
            credential_process = older\n\
            \n\
            [profile other]\n\
            endpoint_url = https://elsewhere\n";
        let after = upsert(before, "source-coop", &prod());
        assert_eq!(
            after,
            "[profile  source-coop ]\n\
            credential_process = source-coop creds --proxy-url https://data.source.coop\n\
            s3 =\n  addressing_style = path\n\
            region = eu-central-1\n\
            endpoint_url = https://data.source.coop\n\
            \n\
            [profile other]\n\
            endpoint_url = https://elsewhere\n"
        );
    }

    #[test]
    fn windows_line_endings_are_kept() {
        let after = upsert("[default]\r\nregion = x\r\n", "source-coop", &prod());
        assert!(after.starts_with("[default]\r\nregion = x\r\n\r\n[profile source-coop]\r\n"));
        assert!(!after.replace("\r\n", "").contains('\n'));
    }

    #[test]
    fn section_reads_back_the_profile() {
        let text = format!("[default]\n{PROD}\n[profile x]\n");
        assert_eq!(section(&text, "source-coop").unwrap().len(), 4);
        assert!(section(&text, "missing").is_none());
    }
}
