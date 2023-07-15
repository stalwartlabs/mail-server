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

use std::time::Duration;

use utils::config::Config;

use super::{ConfigContext, Host};

pub trait ConfigHost {
    fn parse_remote_hosts(&self, ctx: &mut ConfigContext) -> super::Result<()>;
    fn parse_host(&self, id: &str) -> super::Result<Host>;
}

impl ConfigHost for Config {
    fn parse_remote_hosts(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for id in self.sub_keys("remote") {
            ctx.hosts.insert(id.to_string(), self.parse_host(id)?);
        }

        Ok(())
    }

    fn parse_host(&self, id: &str) -> super::Result<Host> {
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
            timeout: self
                .property(("remote", id, "timeout"))?
                .unwrap_or(Duration::from_secs(60)),
        })
    }
}
