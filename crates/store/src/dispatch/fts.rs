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

use std::fmt::Display;

use roaring::RoaringBitmap;

use crate::{
    fts::{index::FtsDocument, FtsFilter},
    FtsStore,
};

impl FtsStore {
    pub async fn index<T: Into<u8> + Display + Clone + std::fmt::Debug>(
        &self,
        document: FtsDocument<'_, T>,
    ) -> crate::Result<()> {
        match self {
            FtsStore::Store(store) => store.fts_index(document).await,
            #[cfg(feature = "elastic")]
            FtsStore::ElasticSearch(store) => store.fts_index(document).await,
        }
    }

    pub async fn query<T: Into<u8> + Display + Clone + std::fmt::Debug>(
        &self,
        account_id: u32,
        collection: impl Into<u8>,
        filters: Vec<FtsFilter<T>>,
    ) -> crate::Result<RoaringBitmap> {
        match self {
            FtsStore::Store(store) => store.fts_query(account_id, collection, filters).await,
            #[cfg(feature = "elastic")]
            FtsStore::ElasticSearch(store) => {
                store.fts_query(account_id, collection, filters).await
            }
        }
    }

    pub async fn remove(
        &self,
        account_id: u32,
        collection: u8,
        document_id: u32,
    ) -> crate::Result<bool> {
        match self {
            FtsStore::Store(store) => store.fts_remove(account_id, collection, document_id).await,
            #[cfg(feature = "elastic")]
            FtsStore::ElasticSearch(store) => {
                store.fts_remove(account_id, collection, document_id).await
            }
        }
    }

    pub async fn remove_all(&self, account_id: u32) -> crate::Result<()> {
        match self {
            FtsStore::Store(store) => store.fts_remove_all(account_id).await,
            #[cfg(feature = "elastic")]
            FtsStore::ElasticSearch(store) => store.fts_remove_all(account_id).await,
        }
    }
}
