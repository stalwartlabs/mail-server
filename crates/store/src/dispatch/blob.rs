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

use std::ops::Range;

use crate::{BlobStore, Store};

impl BlobStore {
    pub async fn get_blob(&self, key: &[u8], range: Range<u32>) -> crate::Result<Option<Vec<u8>>> {
        match self {
            Self::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.get_blob(key, range).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.get_blob(key, range).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.get_blob(key, range).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.get_blob(key, range).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.get_blob(key, range).await,
                _ => unreachable!()
            },
            Self::Fs(store) => store.get_blob(key, range).await,
            #[cfg(feature = "s3")]
            Self::S3(store) => store.get_blob(key, range).await,
        }
    }

    pub async fn put_blob(&self, key: &[u8], data: &[u8]) -> crate::Result<()> {
        match self {
            Self::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.put_blob(key, data).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.put_blob(key, data).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.put_blob(key, data).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.put_blob(key, data).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.put_blob(key, data).await,
                _ => unreachable!()
            },
            Self::Fs(store) => store.put_blob(key, data).await,
            #[cfg(feature = "s3")]
            Self::S3(store) => store.put_blob(key, data).await,
        }
    }

    pub async fn delete_blob(&self, key: &[u8]) -> crate::Result<bool> {
        match self {
            Self::Store(store) => match store {
                #[cfg(feature = "sqlite")]
                Store::SQLite(store) => store.delete_blob(key).await,
                #[cfg(feature = "foundation")]
                Store::FoundationDb(store) => store.delete_blob(key).await,
                #[cfg(feature = "postgres")]
                Store::PostgreSQL(store) => store.delete_blob(key).await,
                #[cfg(feature = "mysql")]
                Store::MySQL(store) => store.delete_blob(key).await,
                #[cfg(feature = "rocks")]
                Store::RocksDb(store) => store.delete_blob(key).await,
                _ => unreachable!()
            },
            Self::Fs(store) => store.delete_blob(key).await,
            #[cfg(feature = "s3")]
            Self::S3(store) => store.delete_blob(key).await,
        }
    }
}
