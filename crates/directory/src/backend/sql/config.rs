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

use store::{Store, Stores};
use utils::config::{utils::AsKey, Config};

use super::{SqlDirectory, SqlMappings};

impl SqlDirectory {
    pub fn from_config(
        config: &mut Config,
        prefix: impl AsKey,
        stores: &Stores,
        data_store: Store,
    ) -> Option<Self> {
        let prefix = prefix.as_key();
        let store_id = config.value_require((&prefix, "store"))?.to_string();
        let store = if let Some(store) = stores.lookup_stores.get(&store_id) {
            store.clone()
        } else {
            let err = format!("Directory references a non-existent store {store_id:?}");
            config.new_build_error((&prefix, "store"), err);
            return None;
        };

        let mut mappings = SqlMappings {
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
                .value((&prefix, "columns.class"))
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
            *query = config
                .value(("store", store_id.as_str(), "query", query_id))
                .unwrap_or_default()
                .to_string();
        }

        Some(SqlDirectory {
            store,
            mappings,
            data_store,
        })
    }
}
