use serde::Deserialize;
use std::collections::HashMap;

const API_BASE: &str = "https://source.coop/api/v1";

#[derive(Debug, Deserialize)]
struct ProductResponse {
    metadata: ProductMetadata,
}

#[derive(Debug, Deserialize)]
struct ProductMetadata {
    mirrors: HashMap<String, Mirror>,
    primary_mirror: String,
}

#[derive(Debug, Deserialize)]
struct Mirror {
    connection_id: String,
    prefix: String,
}

#[derive(Debug, Deserialize)]
struct DataConnection {
    data_connection_id: String,
    #[serde(default)]
    name: String,
    details: ConnectionDetails,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "provider", rename_all = "lowercase")]
enum ConnectionDetails {
    S3 {
        bucket: String,
        #[serde(default)]
        base_prefix: String,
        region: String,
    },
    Azure {
        account_name: String,
        container_name: String,
        #[serde(default)]
        base_prefix: String,
        region: String,
    },
    Gcs {
        bucket: String,
        #[serde(default)]
        base_prefix: String,
    },
}

pub struct StorageInfo {
    pub uri: String,
    pub provider: String,
    pub bucket_or_container: String,
    pub region: Option<String>,
    pub connection_id: String,
    pub connection_name: String,
    pub prefix: String,
}

pub async fn get_storage_info(
    account_id: &str,
    repository_id: &str,
    verbose: bool,
) -> Result<StorageInfo, String> {
    let product_url = format!("{API_BASE}/products/{account_id}/{repository_id}");

    if verbose {
        eprintln!("[verbose] GET {product_url}");
    }

    let product_resp = reqwest::get(&product_url)
        .await
        .map_err(|e| format!("Failed to fetch repository: {e}"))?;

    let status = product_resp.status();
    if verbose {
        eprintln!("[verbose] Response: {status}");
    }
    if status.as_u16() == 404 {
        return Err(format!(
            "Repository '{account_id}/{repository_id}' not found"
        ));
    }
    if !status.is_success() {
        return Err(format!(
            "Failed to fetch repository (HTTP {status}): {}",
            product_resp.text().await.unwrap_or_default()
        ));
    }

    let product: ProductResponse = product_resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse repository response: {e}"))?;

    let primary_key = &product.metadata.primary_mirror;
    let mirror =
        product.metadata.mirrors.get(primary_key).ok_or_else(|| {
            format!("Primary mirror '{primary_key}' not found in repository mirrors")
        })?;

    let dc_url = format!("{API_BASE}/data-connections/{}", mirror.connection_id);

    if verbose {
        eprintln!("[verbose] GET {dc_url}");
    }

    let dc_resp = reqwest::get(&dc_url)
        .await
        .map_err(|e| format!("Failed to fetch data connection: {e}"))?;

    let dc_status = dc_resp.status();
    if verbose {
        eprintln!("[verbose] Response: {dc_status}");
    }
    if !dc_status.is_success() {
        return Err(format!(
            "Failed to fetch data connection '{}' (HTTP {dc_status})",
            mirror.connection_id
        ));
    }

    let dc: DataConnection = dc_resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse data connection response: {e}"))?;

    let prefix = mirror.prefix.clone();

    let (uri, provider, bucket_or_container, region) = match &dc.details {
        ConnectionDetails::S3 {
            bucket,
            base_prefix,
            region,
            ..
        } => {
            let full_prefix = format!("{base_prefix}{prefix}");
            let uri = format!("s3://{bucket}/{full_prefix}");
            (uri, "s3".to_string(), bucket.clone(), Some(region.clone()))
        }
        ConnectionDetails::Azure {
            account_name,
            container_name,
            base_prefix,
            region,
        } => {
            let full_prefix = format!("{base_prefix}{prefix}");
            let uri =
                format!("az://{account_name}.blob.core.windows.net/{container_name}/{full_prefix}");
            (
                uri,
                "azure".to_string(),
                format!("{account_name}/{container_name}"),
                Some(region.clone()),
            )
        }
        ConnectionDetails::Gcs {
            bucket,
            base_prefix,
        } => {
            let full_prefix = format!("{base_prefix}{prefix}");
            let uri = format!("gs://{bucket}/{full_prefix}");
            (uri, "gcs".to_string(), bucket.clone(), None)
        }
    };

    Ok(StorageInfo {
        uri,
        provider,
        bucket_or_container,
        region,
        connection_id: dc.data_connection_id,
        connection_name: dc.name,
        prefix,
    })
}
