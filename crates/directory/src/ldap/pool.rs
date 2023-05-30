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
