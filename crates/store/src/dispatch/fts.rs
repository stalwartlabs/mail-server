/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use roaring::RoaringBitmap;

use crate::{
    fts::{index::FtsDocument, FtsFilter},
    FtsStore,
};

use super::DocumentSet;

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
        document_ids: &impl DocumentSet,
    ) -> crate::Result<()> {
        match self {
            FtsStore::Store(store) => store.fts_remove(account_id, collection, document_ids).await,
            #[cfg(feature = "elastic")]
            FtsStore::ElasticSearch(store) => {
                store.fts_remove(account_id, collection, document_ids).await
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
