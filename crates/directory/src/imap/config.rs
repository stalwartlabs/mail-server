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

use mail_send::smtp::tls::build_tls_connector;
use utils::config::{utils::AsKey, Config};

use crate::{
    cache::CachedDirectory,
    config::{build_pool, ConfigDirectory, LookupFormat},
    imap::ImapConnectionManager,
    Directory,
};

use super::ImapDirectory;

impl ImapDirectory {
    pub fn from_config(
        config: &Config,
        prefix: impl AsKey,
    ) -> utils::config::Result<Arc<dyn Directory>> {
        let prefix = prefix.as_key();
        let address = config.value_require((&prefix, "address"))?;
        let tls_implicit: bool = config.property_or_static((&prefix, "tls.implicit"), "false")?;
        let port: u16 = config
            .property_or_static((&prefix, "port"), if tls_implicit { "993" } else { "143" })?;

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
                domains: config
                    .parse_lookup_list((&prefix, "lookup.domains"), LookupFormat::default())?,
            },
        )
    }
}
