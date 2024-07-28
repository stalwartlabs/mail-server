/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use async_trait::async_trait;
use deadpool::managed;
use ldap3::{exop::WhoAmI, Ldap, LdapConnAsync, LdapError};

use super::LdapConnectionManager;

#[async_trait]
impl managed::Manager for LdapConnectionManager {
    type Type = Ldap;
    type Error = LdapError;

    async fn create(&self) -> Result<Ldap, LdapError> {
        let (conn, mut ldap) =
            LdapConnAsync::with_settings(self.settings.clone(), &self.address).await?;

        ldap3::drive!(conn);

        trc::event!(
            Store(trc::StoreEvent::LdapBind),
            Details = self
                .bind_dn
                .as_ref()
                .map(|b| trc::Value::String(b.dn.clone())),
        );

        if let Some(bind) = &self.bind_dn {
            ldap.simple_bind(&bind.dn, &bind.password)
                .await?
                .success()?;
        }

        Ok(ldap)
    }

    async fn recycle(
        &self,
        conn: &mut Ldap,
        _: &managed::Metrics,
    ) -> managed::RecycleResult<LdapError> {
        conn.extended(WhoAmI)
            .await
            .map(|_| ())
            .map_err(managed::RecycleError::Backend)
    }
}
