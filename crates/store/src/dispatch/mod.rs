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

use crate::Store;

pub mod blob;
pub mod fts;
pub mod lookup;
pub mod store;

impl Store {
    pub fn id(&self) -> &'static str {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SQLite(_) => "sqlite",
            #[cfg(feature = "foundation")]
            Self::FoundationDb(_) => "foundationdb",
            #[cfg(feature = "postgres")]
            Self::PostgreSQL(_) => "postgresql",
            #[cfg(feature = "mysql")]
            Self::MySQL(_) => "mysql",
            #[cfg(feature = "rocks")]
            Self::RocksDb(_) => "rocksdb",
            Self::None => "none",
        }
    }
}

#[allow(clippy::len_without_is_empty)]
pub trait DocumentSet: Sync + Send {
    fn min(&self) -> u32;
    fn max(&self) -> u32;
    fn contains(&self, id: u32) -> bool;
    fn len(&self) -> usize;
    fn iterate(&self) -> impl Iterator<Item = u32>;
}

impl DocumentSet for RoaringBitmap {
    fn min(&self) -> u32 {
        self.min().unwrap_or(0)
    }

    fn max(&self) -> u32 {
        self.max().map(|m| m + 1).unwrap_or(0)
    }

    fn contains(&self, id: u32) -> bool {
        self.contains(id)
    }

    fn len(&self) -> usize {
        self.len() as usize
    }

    fn iterate(&self) -> impl Iterator<Item = u32> {
        self.iter()
    }
}

impl DocumentSet for Vec<u32> {
    fn contains(&self, id: u32) -> bool {
        self.binary_search(&id).is_ok()
    }

    fn min(&self) -> u32 {
        self.first().copied().unwrap_or(0)
    }

    fn max(&self) -> u32 {
        self.last().copied().map(|m| m + 1).unwrap_or(0)
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn iterate(&self) -> impl Iterator<Item = u32> {
        self.iter().copied()
    }
}

impl DocumentSet for () {
    fn min(&self) -> u32 {
        0
    }

    fn max(&self) -> u32 {
        u32::MAX
    }

    fn contains(&self, _: u32) -> bool {
        true
    }

    fn len(&self) -> usize {
        0
    }

    fn iterate(&self) -> impl Iterator<Item = u32> {
        std::iter::empty()
    }
}
