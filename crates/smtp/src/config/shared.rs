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

use ahash::AHashMap;
use mail_send::Credentials;
use utils::config::Config;

use crate::core::Shared;

use super::{ConfigContext, RelayHost};

pub trait ConfigShared {
    fn parse_shared(&self, ctx: &ConfigContext) -> super::Result<Shared>;
    fn parse_host(&self, id: &str) -> super::Result<RelayHost>;
}

impl ConfigShared for Config {
    fn parse_shared(&self, ctx: &ConfigContext) -> super::Result<Shared> {
        let mut relay_hosts = AHashMap::new();

        for id in self.sub_keys("remote", ".address") {
            relay_hosts.insert(id.to_string(), self.parse_host(id)?);
        }

        Ok(Shared {
            scripts: ctx.scripts.clone(),
            signers: ctx.signers.clone(),
            sealers: ctx.sealers.clone(),
            directories: ctx.directory.directories.clone(),
            lookup_stores: ctx.stores.lookup_stores.clone(),
            relay_hosts,
            default_directory: ctx
                .directory
                .directories
                .get(self.value_require("storage.directory")?)
                .ok_or_else(|| {
                    format!(
                        "Directory {:?} not found for key \"storage.directory\".",
                        self.value_require("storage.directory").unwrap()
                    )
                })?
                .clone(),
            default_data_store: ctx.stores.get_store(self, "storage.data")?,
            default_lookup_store: self
                .value_or_else("storage.lookup", "storage.data")
                .and_then(|id| ctx.stores.lookup_stores.get(id))
                .ok_or_else(|| {
                    format!(
                        "Lookup store {:?} not found for key \"storage.lookup\".",
                        self.value_or_else("storage.lookup", "storage.data")
                            .unwrap()
                    )
                })?
                .clone(),
            default_blob_store: self
                .value_or_else("storage.blob", "storage.data")
                .and_then(|id| ctx.stores.blob_stores.get(id))
                .ok_or_else(|| {
                    format!(
                        "Lookup store {:?} not found for key \"storage.blob\".",
                        self.value_or_else("storage.blob", "storage.data").unwrap()
                    )
                })?
                .clone(),
        })
    }

    fn parse_host(&self, id: &str) -> super::Result<RelayHost> {
        let username = self.value(("remote", id, "auth.username"));
        let secret = self.value(("remote", id, "auth.secret"));

        Ok(RelayHost {
            address: self.property_require(("remote", id, "address"))?,
            port: self.property_require(("remote", id, "port"))?,
            protocol: self.property_require(("remote", id, "protocol"))?,
            auth: if let (Some(username), Some(secret)) = (username, secret) {
                Credentials::new(username.to_string(), secret.to_string()).into()
            } else {
                None
            },
            tls_implicit: self
                .property(("remote", id, "tls.implicit"))?
                .unwrap_or(true),
            tls_allow_invalid_certs: self
                .property(("remote", id, "tls.allow-invalid-certs"))?
                .unwrap_or(false),
        })
    }
}
