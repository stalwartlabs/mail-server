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
