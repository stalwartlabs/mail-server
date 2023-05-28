/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use roaring::RoaringBitmap;

use crate::{BitmapKey, Deserialize, Key, Store};

impl Store {
    pub async fn get_value<U>(&self, key: impl Key) -> crate::Result<Option<U>>
    where
        U: Deserialize + 'static,
    {
        #[cfg(not(feature = "is_sync"))]
        {
            self.read_transaction().await?.get_value(key).await
        }

        #[cfg(feature = "is_sync")]
        {
            let trx = self.read_transaction()?;
            self.spawn_worker(move || trx.get_value(key)).await
        }
    }

    pub async fn get_values<U>(&self, key: Vec<impl Key>) -> crate::Result<Vec<Option<U>>>
    where
        U: Deserialize + 'static,
    {
        #[cfg(not(feature = "is_sync"))]
        {
            let mut trx = self.read_transaction().await?;
            let mut results = Vec::with_capacity(key.len());

            for key in key {
                trx.refresh_if_old().await?;
                results.push(trx.get_value(key).await?);
            }

            Ok(results)
        }

        #[cfg(feature = "is_sync")]
        {
            let trx = self.read_transaction()?;
            self.spawn_worker(move || {
                let mut results = Vec::with_capacity(key.len());
                for key in key {
                    results.push(trx.get_value(key)?);
                }

                Ok(results)
            })
            .await
        }
    }

    pub async fn get_last_change_id(
        &self,
        account_id: u32,
        collection: impl Into<u8>,
    ) -> crate::Result<Option<u64>> {
        let collection = collection.into();

        #[cfg(not(feature = "is_sync"))]
        {
            self.read_transaction()
                .await?
                .get_last_change_id(account_id, collection)
                .await
        }

        #[cfg(feature = "is_sync")]
        {
            let trx = self.read_transaction()?;
            self.spawn_worker(move || trx.get_last_change_id(account_id, collection))
                .await
        }
    }

    pub async fn get_bitmap<T: AsRef<[u8]> + Send + Sync + 'static>(
        &self,
        key: BitmapKey<T>,
    ) -> crate::Result<Option<RoaringBitmap>> {
        #[cfg(not(feature = "is_sync"))]
        {
            self.read_transaction().await?.get_bitmap(key).await
        }

        #[cfg(feature = "is_sync")]
        {
            let trx = self.read_transaction()?;
            self.spawn_worker(move || trx.get_bitmap(key)).await
        }
    }

    pub async fn iterate<T: Sync + Send + 'static>(
        &self,
        acc: T,
        begin: impl Key,
        end: impl Key,
        first: bool,
        ascending: bool,
        cb: impl Fn(&mut T, &[u8], &[u8]) -> crate::Result<bool> + Sync + Send + 'static,
    ) -> crate::Result<T> {
        #[cfg(not(feature = "is_sync"))]
        {
            self.read_transaction()
                .await?
                .iterate(acc, begin, end, first, ascending, cb)
                .await
        }

        #[cfg(feature = "is_sync")]
        {
            let trx = self.read_transaction()?;
            self.spawn_worker(move || trx.iterate(acc, begin, end, first, ascending, cb))
                .await
        }
    }
}
