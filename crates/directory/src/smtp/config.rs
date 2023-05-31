use std::sync::Arc;

use mail_send::{smtp::tls::build_tls_connector, SmtpClientBuilder};
use utils::config::{utils::AsKey, Config};

use crate::{config::build_pool, smtp::SmtpConnectionManager, Directory};

use super::SmtpDirectory;

impl SmtpDirectory {
    pub fn from_config(
        config: &Config,
        prefix: impl AsKey,
        is_lmtp: bool,
    ) -> utils::config::Result<Arc<dyn Directory>> {
        let prefix = prefix.as_key();
        let address = config.value_require((&prefix, "address"))?;
        let tls_implicit: bool = config.property_or_static((&prefix, "tls.implicit"), "false")?;
        let port: u16 = config
            .property_or_static((&prefix, "port"), if tls_implicit { "465" } else { "25" })?;

        let manager = SmtpConnectionManager {
            builder: SmtpClientBuilder {
                addr: format!("{address}:{port}"),
                timeout: config.property_or_static((&prefix, "timeout"), "30s")?,
                tls_connector: build_tls_connector(
                    config.property_or_static((&prefix, "tls.allow-invalid-certs"), "false")?,
                ),
                tls_hostname: address.to_string(),
                tls_implicit,
                is_lmtp,
                credentials: None,
                local_host: config
                    .value("server.hostname")
                    .unwrap_or("[127.0.0.1]")
                    .to_string(),
            },
            max_rcpt: config.property_or_static((&prefix, "limits.rcpt"), "10")?,
            max_auth_errors: config.property_or_static((&prefix, "limits.auth-errors"), "3")?,
        };

        Ok(Arc::new(SmtpDirectory {
            pool: build_pool(config, &prefix, manager)?,
        }))
    }
}
