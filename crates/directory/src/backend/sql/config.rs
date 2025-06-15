/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::{Store, Stores};
use utils::config::{Config, utils::AsKey};

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
        let sql_store =
            if let Some(sql_store) = stores.stores.get(&store_id).filter(|store| store.is_sql()) {
                sql_store.clone()
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
            column_email: config
                .value((&prefix, "columns.email"))
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
            ("emails", &mut mappings.query_emails),
            ("recipients", &mut mappings.query_recipients),
            ("secrets", &mut mappings.query_secrets),
        ] {
            *query = config
                .value(("store", store_id.as_str(), "query", query_id))
                .unwrap_or_default()
                .to_string();
        }

        Some(SqlDirectory {
            sql_store,
            mappings,
            data_store,
        })
    }
}
