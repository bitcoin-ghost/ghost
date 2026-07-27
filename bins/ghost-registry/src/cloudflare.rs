//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: cloudflare.rs                                                                                                  |
//|======================================================================================================================|

//! Cloudflare DNS API client for managing pool DNS records

use crate::config::{CloudflareConfig, DnsConfig};
use ghost_common::config::Region;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, info, warn};

const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Cloudflare API errors
#[derive(Debug, Error)]
pub(crate) enum CloudflareError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("API error: {0}")]
    Api(String),
    #[error("Configuration error: {0}")]
    Config(String),
}

/// DNS A record from Cloudflare
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DnsRecord {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    pub ttl: u32,
    pub proxied: bool,
}

/// Cloudflare API response wrapper
#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    code: i32,
    message: String,
}

/// Create DNS record request
#[derive(Debug, Serialize)]
struct CreateRecordRequest {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
    proxied: bool,
}

/// Cloudflare DNS client
pub(crate) struct CloudflareClient {
    client: Client,
    config: CloudflareConfig,
    dns_config: DnsConfig,
}

impl CloudflareClient {
    /// Create a new Cloudflare client
    pub(crate) fn new(
        config: CloudflareConfig,
        dns_config: DnsConfig,
    ) -> Result<Self, CloudflareError> {
        if config.enabled && (config.zone_id.is_empty() || config.api_token.is_empty()) {
            return Err(CloudflareError::Config(
                "zone_id and api_token required when Cloudflare is enabled".to_string(),
            ));
        }

        let client = Client::builder().timeout(Duration::from_secs(30)).build()?;

        Ok(Self {
            client,
            config,
            dns_config,
        })
    }

    /// Check if Cloudflare integration is enabled
    pub(crate) fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the subdomain for a region (e.g., "eu.pool" for EU)
    pub(crate) fn region_subdomain(&self, region: Region) -> String {
        let prefix = region_prefix(region);
        format!("{}.{}", prefix, self.dns_config.subdomain_prefix)
    }

    /// Get the full domain name for a region
    pub(crate) fn region_fqdn(&self, region: Region) -> String {
        format!(
            "{}.{}",
            self.region_subdomain(region),
            self.config.base_domain
        )
    }

    /// List all A records for a region
    pub(crate) async fn list_region_records(
        &self,
        region: Region,
    ) -> Result<Vec<DnsRecord>, CloudflareError> {
        if !self.config.enabled {
            return Ok(Vec::new());
        }

        let name = self.region_fqdn(region);
        let url = format!(
            "{}/zones/{}/dns_records?type=A&name={}",
            CLOUDFLARE_API_BASE, self.config.zone_id, name
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let api_response: ApiResponse<Vec<DnsRecord>> = response.json().await?;

        if !api_response.success {
            let errors: Vec<String> = api_response
                .errors
                .iter()
                .map(|e| format!("[{}] {}", e.code, e.message))
                .collect();
            return Err(CloudflareError::Api(errors.join(", ")));
        }

        Ok(api_response.result.unwrap_or_default())
    }

    /// Create an A record
    pub(crate) async fn create_record(
        &self,
        region: Region,
        ip: &str,
    ) -> Result<DnsRecord, CloudflareError> {
        if !self.config.enabled {
            return Err(CloudflareError::Config(
                "Cloudflare not enabled".to_string(),
            ));
        }

        let name = self.region_subdomain(region);
        let url = format!(
            "{}/zones/{}/dns_records",
            CLOUDFLARE_API_BASE, self.config.zone_id
        );

        let request = CreateRecordRequest {
            record_type: "A".to_string(),
            name,
            content: ip.to_string(),
            ttl: self.dns_config.ttl_seconds,
            proxied: false, // We don't proxy stratum connections
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        let api_response: ApiResponse<DnsRecord> = response.json().await?;

        if !api_response.success {
            let errors: Vec<String> = api_response
                .errors
                .iter()
                .map(|e| format!("[{}] {}", e.code, e.message))
                .collect();
            return Err(CloudflareError::Api(errors.join(", ")));
        }

        api_response
            .result
            .ok_or_else(|| CloudflareError::Api("No record returned".to_string()))
    }

    /// Delete an A record by ID
    pub(crate) async fn delete_record(&self, record_id: &str) -> Result<(), CloudflareError> {
        if !self.config.enabled {
            return Err(CloudflareError::Config(
                "Cloudflare not enabled".to_string(),
            ));
        }

        let url = format!(
            "{}/zones/{}/dns_records/{}",
            CLOUDFLARE_API_BASE, self.config.zone_id, record_id
        );

        let response = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .header("Content-Type", "application/json")
            .send()
            .await?;

        let api_response: ApiResponse<serde_json::Value> = response.json().await?;

        if !api_response.success {
            let errors: Vec<String> = api_response
                .errors
                .iter()
                .map(|e| format!("[{}] {}", e.code, e.message))
                .collect();
            return Err(CloudflareError::Api(errors.join(", ")));
        }

        Ok(())
    }

    /// Sync DNS records for a region with desired IPs
    ///
    /// Returns (added, removed) counts
    pub(crate) async fn sync_region_records(
        &self,
        region: Region,
        desired_ips: &[String],
    ) -> Result<(usize, usize), CloudflareError> {
        if !self.config.enabled {
            debug!(
                region = %region,
                ips = ?desired_ips,
                "Cloudflare disabled, skipping DNS sync"
            );
            return Ok((0, 0));
        }

        // Get current records
        let current_records = self.list_region_records(region).await?;
        let current_ips: HashSet<&str> =
            current_records.iter().map(|r| r.content.as_str()).collect();
        let desired_set: HashSet<&str> = desired_ips.iter().map(|s| s.as_str()).collect();

        let mut added = 0;
        let mut removed = 0;

        // Remove records that shouldn't exist
        for record in &current_records {
            if !desired_set.contains(record.content.as_str()) {
                match self.delete_record(&record.id).await {
                    Ok(_) => {
                        info!(
                            region = %region,
                            ip = %record.content,
                            "Removed DNS record"
                        );
                        removed += 1;
                    }
                    Err(e) => {
                        error!(
                            region = %region,
                            ip = %record.content,
                            error = %e,
                            "Failed to remove DNS record"
                        );
                    }
                }
            }
        }

        // Add records that should exist
        for ip in desired_ips {
            if !current_ips.contains(ip.as_str()) {
                match self.create_record(region, ip).await {
                    Ok(_) => {
                        info!(
                            region = %region,
                            ip = %ip,
                            "Added DNS record"
                        );
                        added += 1;
                    }
                    Err(e) => {
                        error!(
                            region = %region,
                            ip = %ip,
                            error = %e,
                            "Failed to add DNS record"
                        );
                    }
                }
            }
        }

        if added > 0 || removed > 0 {
            info!(
                region = %region,
                added = added,
                removed = removed,
                total = desired_ips.len(),
                "DNS records synced"
            );
        }

        Ok((added, removed))
    }

    /// Sync all regions
    pub(crate) async fn sync_all_regions(
        &self,
        region_ips: &[(Region, Vec<String>)],
    ) -> Result<(usize, usize), CloudflareError> {
        let mut total_added = 0;
        let mut total_removed = 0;

        for (region, ips) in region_ips {
            match self.sync_region_records(*region, ips).await {
                Ok((added, removed)) => {
                    total_added += added;
                    total_removed += removed;
                }
                Err(e) => {
                    warn!(
                        region = %region,
                        error = %e,
                        "Failed to sync region DNS"
                    );
                }
            }
        }

        Ok((total_added, total_removed))
    }
}

/// Get the DNS prefix for a region
fn region_prefix(region: Region) -> &'static str {
    match region {
        Region::UsEast | Region::UsWest => "us",
        Region::EuWest | Region::EuCentral => "eu",
        Region::AsiaSoutheast | Region::AsiaNortheast => "asia",
        Region::Oceania => "au",
        Region::SouthAmerica => "sa",
        Region::Africa => "af",
        Region::Unknown => "default",
    }
}

/// Get all active regions
#[allow(dead_code)]
pub(crate) fn all_regions() -> Vec<Region> {
    vec![
        Region::UsEast,
        Region::UsWest,
        Region::EuWest,
        Region::EuCentral,
        Region::AsiaSoutheast,
        Region::AsiaNortheast,
        Region::Oceania,
        Region::SouthAmerica,
        Region::Africa,
    ]
}

/// Group regions by DNS prefix (multiple regions can share a prefix)
pub(crate) fn group_regions_by_prefix() -> Vec<(String, Vec<Region>)> {
    vec![
        ("us".to_string(), vec![Region::UsEast, Region::UsWest]),
        ("eu".to_string(), vec![Region::EuWest, Region::EuCentral]),
        (
            "asia".to_string(),
            vec![Region::AsiaSoutheast, Region::AsiaNortheast],
        ),
        ("au".to_string(), vec![Region::Oceania]),
        ("sa".to_string(), vec![Region::SouthAmerica]),
        ("af".to_string(), vec![Region::Africa]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_region_prefix() {
        assert_eq!(region_prefix(Region::UsEast), "us");
        assert_eq!(region_prefix(Region::UsWest), "us");
        assert_eq!(region_prefix(Region::EuWest), "eu");
        assert_eq!(region_prefix(Region::AsiaSoutheast), "asia");
        assert_eq!(region_prefix(Region::Oceania), "au");
    }

    #[test]
    fn test_region_subdomain() {
        let config = CloudflareConfig {
            enabled: false,
            ..Default::default()
        };
        let dns_config = DnsConfig::default();

        let client = CloudflareClient::new(config, dns_config).unwrap();

        assert_eq!(client.region_subdomain(Region::EuWest), "eu.pool");
        assert_eq!(client.region_subdomain(Region::UsEast), "us.pool");
    }

    #[test]
    fn test_region_fqdn() {
        let config = CloudflareConfig {
            enabled: false,
            base_domain: "example.com".to_string(),
            ..Default::default()
        };
        let dns_config = DnsConfig::default();

        let client = CloudflareClient::new(config, dns_config).unwrap();

        assert_eq!(client.region_fqdn(Region::EuWest), "eu.pool.example.com");
    }
}
