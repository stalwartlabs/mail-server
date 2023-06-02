use std::sync::Arc;

use ahash::AHashSet;
use mail_send::smtp::tls::build_tls_connector;
use utils::config::{utils::AsKey, Config};

use crate::{cache::CachedDirectory, config::build_pool, imap::ImapConnectionManager, Directory};

use super::ImapDirectory;

impl ImapDirectory {
    pub fn from_config(
        config: &Config,
        prefix: impl AsKey,
        domains: AHashSet<String>,
    ) -> utils::config::Result<Arc<dyn Directory>> {
        let prefix = prefix.as_key();
        let address = config.value_require((&prefix, "address"))?;
        let tls_implicit: bool = config.property_or_static((&prefix, "tls.implicit"), "false")?;
        let port: u16 = config
            .property_or_static((&prefix, "port"), if tls_implicit { "443" } else { "143" })?;

        let manager = ImapConnectionManager {
            addr: format!("{address}:{port}"),
            timeout: config.property_or_static((&prefix, "timeout"), "30s")?,
            tls_connector: build_tls_connector(
                config.property_or_static((&prefix, "tls.allow-invalid-certs"), "false")?,
            ),
            tls_hostname: address.to_string(),
            tls_implicit,
            mechanisms: 0.into(),
        };

        CachedDirectory::try_from_config(
            config,
            &prefix,
            ImapDirectory {
                pool: build_pool(config, &prefix, manager)?,
                domains,
            },
        )
    }
}
