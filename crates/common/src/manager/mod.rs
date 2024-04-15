/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::time::Duration;

use crate::USER_AGENT;

use self::config::ConfigManager;

pub mod boot;
pub mod config;
pub mod reload;
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
