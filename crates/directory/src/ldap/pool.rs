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

use bb8::ManageConnection;
use ldap3::{exop::WhoAmI, Ldap, LdapConnAsync, LdapError};

use super::LdapConnectionManager;

#[async_trait::async_trait]
impl ManageConnection for LdapConnectionManager {
    type Connection = Ldap;
    type Error = LdapError;

    /// Attempts to create a new connection.
    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let (conn, mut ldap) =
            LdapConnAsync::with_settings(self.settings.clone(), &self.address).await?;
        ldap3::drive!(conn);

        if let Some(bind) = &self.bind_dn {
            ldap.simple_bind(&bind.dn, &bind.password).await?;
        }

        Ok(ldap)
    }

    /// Determines if the connection is still connected to the database.
    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        conn.extended(WhoAmI).await.map(|_| ())
    }

    /// Synchronously determine if the connection is no longer usable, if possible.
    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.is_closed()
    }
}
