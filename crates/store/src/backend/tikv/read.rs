/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use tikv_client::{Transaction, Value};
use futures::TryStreamExt;
use roaring::RoaringBitmap;
use crate::{
    backend::deserialize_i64_le,
    write::{
        key::{DeserializeBigEndian, KeySerializer},
        BitmapClass, ValueClass,
    },
    BitmapKey, Deserialize, IterateParams, Key, ValueKey, U32_LEN, WITH_SUBSPACE,
};

use super::{into_error, TikvStore};

#[allow(dead_code)]
pub(crate) enum ChunkedValue {
    Single(Value),
    Chunked { n_chunks: u8, bytes: Vec<u8> },
    None,
}

impl TikvStore {
    pub(crate) async fn get_value<U>(&self, key: impl Key) -> trc::Result<Option<U>>
    where
        U: Deserialize,
    {
        todo!()
    }

    pub(crate) async fn get_bitmap(
        &self,
        mut key: BitmapKey<BitmapClass<u32>>,
    ) -> trc::Result<Option<RoaringBitmap>> {
        todo!()
    }

    pub(crate) async fn iterate<T: Key>(
        &self,
        params: IterateParams<T>,
        mut cb: impl for<'x> FnMut(&'x [u8], &'x [u8]) -> trc::Result<bool> + Sync + Send,
    ) -> trc::Result<()> {
        todo!()
    }

    pub(crate) async fn get_counter(
        &self,
        key: impl Into<ValueKey<ValueClass<u32>>> + Sync + Send,
    ) -> trc::Result<i64> {
        todo!()
    }

    pub(crate) async fn read_trx(&self) -> trc::Result<Transaction> {
        todo!()
    }

    pub(crate) async fn timed_read_trx(&self) -> trc::Result<Transaction> {
        todo!()
    }
}

pub(crate) async fn read_chunked_value(
    key: &[u8],
    trx: &Transaction,
    snapshot: bool,
) -> trc::Result<ChunkedValue> {
    todo!()
}
