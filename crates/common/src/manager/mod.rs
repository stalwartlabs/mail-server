/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use crate::USER_AGENT;

use self::config::ConfigManager;

pub mod backup;
pub mod boot;
pub mod config;
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
            fetch_resource(&url).await
        } else {
            match resource_id {
                "spam-filter" => fetch_resource(DEFAULT_SPAMFILTER_URL).await,
                "webadmin" => fetch_resource(DEFAULT_WEBADMIN_URL).await,
                _ => Err(format!("Unknown resource: {resource_id}")),
            }
        }
    }
}

async fn fetch_resource(url: &str) -> Result<Vec<u8>, String> {
    if let Some(path) = url.strip_prefix("file://") {
        tokio::fs::read(path)
            .await
            .map_err(|err| format!("Failed to read {path}: {err}"))
    } else {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent(USER_AGENT)
            .build()
            .unwrap_or_default()
            .get(url)
            .send()
            .await
            .map_err(|err| format!("Failed to fetch {url}: {err}"))?
            .bytes()
            .await
            .map_err(|err| format!("Failed to fetch {url}: {err}"))
            .map(|bytes| bytes.to_vec())
    }
}
