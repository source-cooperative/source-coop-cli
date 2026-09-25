use crate::sts::Credentials;

/// Credentials in AWS credential_process JSON format.
fn credential_process_json(creds: &Credentials) -> String {
    let json = serde_json::json!({
        "Version": 1,
        "AccessKeyId": creds.access_key_id,
        "SecretAccessKey": creds.secret_access_key,
        "SessionToken": creds.session_token,
        "Expiration": creds.expiration,
    });
    serde_json::to_string_pretty(&json).unwrap()
}

/// Print credentials in AWS credential_process JSON format.
pub fn print_credential_process(creds: &Credentials) {
    println!("{}", credential_process_json(creds));
}

/// Print credentials as shell export statements.
pub fn print_env(creds: &Credentials) {
    println!("export AWS_ACCESS_KEY_ID={}", creds.access_key_id);
    println!("export AWS_SECRET_ACCESS_KEY={}", creds.secret_access_key);
    println!("export AWS_SESSION_TOKEN={}", creds.session_token);
}

/// Print credentials as an AWS credentials-file (INI) profile,
/// suitable for appending to ~/.aws/credentials.
pub fn print_aws_credentials(creds: &Credentials, profile: &str) {
    println!("[{profile}]");
    println!("# expires {}", creds.expiration);
    println!("aws_access_key_id = {}", creds.access_key_id);
    println!("aws_secret_access_key = {}", creds.secret_access_key);
    println!("aws_session_token = {}", creds.session_token);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_process_json_has_the_fields_sdks_and_gdal_read() {
        let creds = Credentials {
            access_key_id: "AKID".into(),
            secret_access_key: "SECRET".into(),
            session_token: "TOKEN".into(),
            expiration: "2099-01-01T00:00:00Z".into(),
        };
        let json: serde_json::Value =
            serde_json::from_str(&credential_process_json(&creds)).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "Version": 1,
                "AccessKeyId": "AKID",
                "SecretAccessKey": "SECRET",
                "SessionToken": "TOKEN",
                "Expiration": "2099-01-01T00:00:00Z",
            })
        );
    }
}
