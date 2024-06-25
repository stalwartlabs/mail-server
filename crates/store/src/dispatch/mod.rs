/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
