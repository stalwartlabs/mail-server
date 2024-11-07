/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use hyper::HeaderMap;

use crate::USER_AGENT;

use self::config::ConfigManager;

pub mod backup;
pub mod boot;
pub mod config;
pub mod console;
pub mod reload;
pub mod restore;
pub mod webadmin;

const DEFAULT_SPAMFILTER_URL: &str = "https://get.stalw.art/resources/config/spamfilter.toml";
const DEFAULT_WEBADMIN_URL: &str =
    "https://github.com/stalwartlabs/webadmin/releases/latest/download/webadmin.zip";
pub const WEBADMIN_KEY: &[u8] = "STALWART_WEBADMIN".as_bytes();

impl ConfigManager {
    pub async fn fetch_resource(&self, resource_id: &str) -> Result<Vec<u8>, String> {
        if let Some(url) = self
            .get(&format!("config.resource.{resource_id}"))
            .await
            .map_err(|err| {
                format!("Failed to fetch configuration key 'resource.{resource_id}': {err}",)
            })?
        {
            fetch_resource(&url, None).await
        } else {
            match resource_id {
                "spam-filter" => fetch_resource(DEFAULT_SPAMFILTER_URL, None).await,
                "webadmin" => fetch_resource(DEFAULT_WEBADMIN_URL, None).await,
                _ => Err(format!("Unknown resource: {resource_id}")),
            }
        }
    }
}

pub async fn fetch_resource(url: &str, headers: Option<HeaderMap>) -> Result<Vec<u8>, String> {
    if let Some(path) = url.strip_prefix("file://") {
        tokio::fs::read(path)
            .await
            .map_err(|err| format!("Failed to read {path}: {err}"))
    } else {
        let response = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .danger_accept_invalid_certs(is_localhost_url(url))
            .user_agent(USER_AGENT)
            .build()
            .unwrap_or_default()
            .get(url)
            .headers(headers.unwrap_or_default())
            .send()
            .await
            .map_err(|err| format!("Failed to fetch {url}: {err}"))?;

        if response.status().is_success() {
            response
                .bytes()
                .await
                .map_err(|err| format!("Failed to fetch {url}: {err}"))
                .map(|bytes| bytes.to_vec())
        } else {
            let code = response.status().canonical_reason().unwrap_or_default();
            let reason = response.text().await.unwrap_or_default();

            Err(format!(
                "Failed to fetch {url}: Code: {code}, Details: {reason}",
            ))
        }
    }
}

pub fn is_localhost_url(url: &str) -> bool {
    url.split_once("://")
        .map(|(_, url)| url.split_once('/').map_or(url, |(host, _)| host))
        .map_or(false, |host| {
            let host = host.rsplit_once(':').map_or(host, |(host, _)| host);
            host == "localhost" || host == "127.0.0.1" || host == "[::1]"
        })
}
