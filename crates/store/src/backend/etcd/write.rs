/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use roaring::RoaringBitmap;

use super::{into_error, EtcdStore};

use crate::{
    backend::deserialize_i64_le,
    write::{key::DeserializeBigEndian, BitmapClass, ValueClass, AssignedIds, Batch},
    BitmapKey, Deserialize, IterateParams, Key, ValueKey, U32_LEN, WITH_SUBSPACE
};


impl EtcdStore {

    pub(crate) async fn write(&self, batch: Batch) -> trc::Result<AssignedIds> {
        todo!()
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        todo!()
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        todo!()
    }
}
