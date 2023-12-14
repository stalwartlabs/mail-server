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

use store::Store;

use crate::{Directory, Principal, QueryBy};

use super::CachedDirectory;

#[async_trait::async_trait]
impl<T: Directory> Directory for CachedDirectory<T> {
    async fn query(&self, by: QueryBy<'_>) -> crate::Result<Option<Principal>> {
        self.inner.query(by).await
    }

    async fn email_to_ids(&self, address: &str, store: &Store) -> crate::Result<Vec<u32>> {
        self.inner.email_to_ids(address, store).await
    }

    async fn rcpt(&self, address: &str) -> crate::Result<bool> {
        if let Some(result) = {
            let result = self.cached_rcpts.lock().get(address);
            result
        } {
            Ok(result)
        } else if self.inner.rcpt(address).await? {
            self.cached_rcpts.lock().insert_pos(address.to_string());
            Ok(true)
        } else {
            self.cached_rcpts.lock().insert_neg(address.to_string());
            Ok(false)
        }
    }

    async fn vrfy(&self, address: &str) -> crate::Result<Vec<String>> {
        self.inner.vrfy(address).await
    }

    async fn expn(&self, address: &str) -> crate::Result<Vec<String>> {
        self.inner.expn(address).await
    }

    async fn is_local_domain(&self, domain: &str) -> crate::Result<bool> {
        if let Some(result) = {
            let result = self.cached_domains.lock().get(domain);
            result
        } {
            Ok(result)
        } else if self.inner.is_local_domain(domain).await? {
            self.cached_domains.lock().insert_pos(domain.to_string());
            Ok(true)
        } else {
            self.cached_domains.lock().insert_neg(domain.to_string());
            Ok(false)
        }
    }
}
