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

use crate::{
    backend::internal::lookup::DirectoryStore, Directory, DirectoryInner, Principal, QueryBy,
};

impl Directory {
    pub async fn query(
        &self,
        by: QueryBy<'_>,
        return_member_of: bool,
    ) -> crate::Result<Option<Principal<u32>>> {
        match &self.store {
            DirectoryInner::Internal(store) => store.query(by, return_member_of).await,
            DirectoryInner::Ldap(store) => store.query(by, return_member_of).await,
            DirectoryInner::Sql(store) => store.query(by, return_member_of).await,
            DirectoryInner::Imap(store) => store.query(by).await,
            DirectoryInner::Smtp(store) => store.query(by).await,
            DirectoryInner::Memory(store) => store.query(by).await,
        }
    }

    pub async fn email_to_ids(&self, email: &str) -> crate::Result<Vec<u32>> {
        match &self.store {
            DirectoryInner::Internal(store) => store.email_to_ids(email).await,
            DirectoryInner::Ldap(store) => store.email_to_ids(email).await,
            DirectoryInner::Sql(store) => store.email_to_ids(email).await,
            DirectoryInner::Imap(store) => store.email_to_ids(email).await,
            DirectoryInner::Smtp(store) => store.email_to_ids(email).await,
            DirectoryInner::Memory(store) => store.email_to_ids(email).await,
        }
    }

    pub async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        // Check cache
        if let Some(cache) = &self.cache {
            if let Some(result) = cache.get_domain(domain) {
                return Ok(result);
            }
        }

        let result = match &self.store {
            DirectoryInner::Internal(store) => store.is_local_domain(domain).await,
            DirectoryInner::Ldap(store) => store.is_local_domain(domain).await,
            DirectoryInner::Sql(store) => store.is_local_domain(domain).await,
            DirectoryInner::Imap(store) => store.is_local_domain(domain).await,
            DirectoryInner::Smtp(store) => store.is_local_domain(domain).await,
            DirectoryInner::Memory(store) => store.is_local_domain(domain).await,
        }?;

        // Update cache
        if let Some(cache) = &self.cache {
            cache.set_domain(domain, result);
        }

        Ok(result)
    }

    pub async fn rcpt(&self, email: &str) -> crate::Result<bool> {
        // Check cache
        if let Some(cache) = &self.cache {
            if let Some(result) = cache.get_rcpt(email) {
                return Ok(result);
            }
        }

        let result = match &self.store {
            DirectoryInner::Internal(store) => store.rcpt(email).await,
            DirectoryInner::Ldap(store) => store.rcpt(email).await,
            DirectoryInner::Sql(store) => store.rcpt(email).await,
            DirectoryInner::Imap(store) => store.rcpt(email).await,
            DirectoryInner::Smtp(store) => store.rcpt(email).await,
            DirectoryInner::Memory(store) => store.rcpt(email).await,
        }?;

        if result {
            // Update cache
            if let Some(cache) = &self.cache {
                cache.set_rcpt(email, true);
            }
        }

        Ok(result)
    }

    pub async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
        match &self.store {
            DirectoryInner::Internal(store) => store.vrfy(address).await,
            DirectoryInner::Ldap(store) => store.vrfy(address).await,
            DirectoryInner::Sql(store) => store.vrfy(address).await,
            DirectoryInner::Imap(store) => store.vrfy(address).await,
            DirectoryInner::Smtp(store) => store.vrfy(address).await,
            DirectoryInner::Memory(store) => store.vrfy(address).await,
        }
    }

    pub async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
        match &self.store {
            DirectoryInner::Internal(store) => store.expn(address).await,
            DirectoryInner::Ldap(store) => store.expn(address).await,
            DirectoryInner::Sql(store) => store.expn(address).await,
            DirectoryInner::Imap(store) => store.expn(address).await,
            DirectoryInner::Smtp(store) => store.expn(address).await,
            DirectoryInner::Memory(store) => store.expn(address).await,
        }
    }
}
