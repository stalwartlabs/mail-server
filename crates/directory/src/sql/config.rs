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

use std::sync::Arc;

use sqlx::any::{install_default_drivers, AnyPoolOptions};
use utils::config::{utils::AsKey, Config};

use crate::{cache::CachedDirectory, Directory, DirectoryOptions};

use super::{SqlDirectory, SqlMappings};

impl SqlDirectory {
    pub fn from_config(
        config: &Config,
        prefix: impl AsKey,
    ) -> utils::config::Result<Arc<dyn Directory>> {
        let prefix = prefix.as_key();
        let address = config.value_require((&prefix, "address"))?;
        install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(
                config
                    .property((&prefix, "pool.max-connections"))?
                    .unwrap_or(10),
            )
            .min_connections(
                config
                    .property((&prefix, "pool.min-connections"))?
                    .unwrap_or(0),
            )
            .idle_timeout(config.property((&prefix, "pool.idle-timeout"))?)
            .connect_lazy(address)
            .map_err(|err| format!("Failed to create connection pool for {address:?}: {err}"))?;

        let mappings = SqlMappings {
            query_name: config
                .value((&prefix, "query.name"))
                .unwrap_or_default()
                .to_string(),
            query_members: config
                .value((&prefix, "query.members"))
                .unwrap_or_default()
                .to_string(),
            query_recipients: config
                .value((&prefix, "query.recipients"))
                .unwrap_or_default()
                .to_string(),
            query_emails: config
                .value((&prefix, "query.emails"))
                .unwrap_or_default()
                .to_string(),
            query_verify: config
                .value((&prefix, "query.verify"))
                .unwrap_or_default()
                .to_string(),
            query_expand: config
                .value((&prefix, "query.expand"))
                .unwrap_or_default()
                .to_string(),
            query_domains: config
                .value((&prefix, "query.domains"))
                .unwrap_or_default()
                .to_string(),
            column_name: config
                .value((&prefix, "columns.name"))
                .unwrap_or_default()
                .to_string(),
            column_description: config
                .value((&prefix, "columns.description"))
                .unwrap_or_default()
                .to_string(),
            column_secret: config
                .value((&prefix, "columns.secret"))
                .unwrap_or_default()
                .to_string(),
            column_quota: config
                .value((&prefix, "columns.quota"))
                .unwrap_or_default()
                .to_string(),
            column_type: config
                .value((&prefix, "columns.type"))
                .unwrap_or_default()
                .to_string(),
        };

        CachedDirectory::try_from_config(
            config,
            &prefix,
            SqlDirectory {
                pool,
                mappings,
                opt: DirectoryOptions::from_config(config, prefix.as_str())?,
            },
        )
    }
}
