/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use std::{sync::Arc, time::Duration};

use tokio::sync::mpsc;
use utils::config::Config;

use crate::lookup::Lookup;

use super::{ConfigContext, Host};

pub trait ConfigHost {
    fn parse_remote_hosts(&self, ctx: &mut ConfigContext) -> super::Result<()>;
    fn parse_host(&self, id: &str) -> super::Result<Host>;
}

impl ConfigHost for Config {
    fn parse_remote_hosts(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for id in self.sub_keys("remote") {
            let host = self.parse_host(id)?;
            if host.lookup {
                ctx.lookup.insert(
                    format!("remote/{id}"),
                    Arc::new(Lookup::Remote(host.channel_tx.clone().into())),
                );
            }
            ctx.hosts.insert(id.to_string(), host);
        }

        Ok(())
    }

    fn parse_host(&self, id: &str) -> super::Result<Host> {
        let (channel_tx, channel_rx) = mpsc::channel(1024);

        Ok(Host {
            address: self.property_require(("remote", id, "address"))?,
            port: self.property_require(("remote", id, "port"))?,
            protocol: self.property_require(("remote", id, "protocol"))?,
            concurrency: self.property(("remote", id, "concurrency"))?.unwrap_or(10),
            tls_implicit: self
                .property(("remote", id, "tls.implicit"))?
                .unwrap_or(true),
            tls_allow_invalid_certs: self
                .property(("remote", id, "tls.allow-invalid-certs"))?
                .unwrap_or(false),
            username: self.property(("remote", id, "auth.username"))?,
            secret: self.property(("remote", id, "auth.secret"))?,
            cache_entries: self
                .property(("remote", id, "cache.entries"))?
                .unwrap_or(1024),
            cache_ttl_positive: self
                .property(("remote", id, "cache.ttl.positive"))?
                .unwrap_or(Duration::from_secs(86400)),
            cache_ttl_negative: self
                .property(("remote", id, "cache.ttl.positive"))?
                .unwrap_or(Duration::from_secs(3600)),
            timeout: self
                .property(("remote", id, "timeout"))?
                .unwrap_or(Duration::from_secs(60)),
            max_errors: self.property(("remote", id, "limits.errors"))?.unwrap_or(3),
            max_requests: self
                .property(("remote", id, "limits.requests"))?
                .unwrap_or(50),
            channel_tx,
            channel_rx,
            lookup: self.property(("remote", id, "lookup"))?.unwrap_or(false),
        })
    }
}
