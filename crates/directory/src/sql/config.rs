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

use store::Stores;
use utils::config::{utils::AsKey, Config};

use crate::{cache::CachedDirectory, Directory, DirectoryOptions};

use super::{SqlDirectory, SqlMappings};

impl SqlDirectory {
    pub fn from_config(
        config: &Config,
        prefix: impl AsKey,
        stores: &Stores,
    ) -> utils::config::Result<Arc<dyn Directory>> {
        let prefix = prefix.as_key();
        let store_id = config.value_require((&prefix, "store"))?;
        let store = stores
            .lookup_stores
            .get(store_id)
            .ok_or_else(|| {
                format!("Directory {prefix:?} references a non-existent store {store_id:?}")
            })?
            .clone();

        let mut mappings = SqlMappings {
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
            ..Default::default()
        };

        for (query_id, query) in [
            ("name", &mut mappings.query_name),
            ("members", &mut mappings.query_members),
            ("recipients", &mut mappings.query_recipients),
            ("emails", &mut mappings.query_emails),
            ("verify", &mut mappings.query_verify),
            ("expand", &mut mappings.query_expand),
            ("domains", &mut mappings.query_domains),
        ] {
            if let Some(query_) = stores.lookups.get(&format!("{}/{}", store_id, query_id)) {
                *query = query_.query.to_string();
            }
        }

        CachedDirectory::try_from_config(
            config,
            &prefix,
            SqlDirectory {
                store,
                mappings,
                opt: DirectoryOptions::from_config(config, prefix.as_str())?,
            },
        )
    }
}
