/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use etcd_client::DeleteOptions;
use roaring::RoaringBitmap;

use super::{into_error, EtcdStore};

use crate::{
    backend::deserialize_i64_le,
    write::{key::DeserializeBigEndian, BitmapClass, ValueClass, AssignedIds, Batch},
    BitmapKey, Deserialize, IterateParams, Key, ValueKey, U32_LEN, WITH_SUBSPACE, SUBSPACE_QUOTA, SUBSPACE_COUNTER
};


impl EtcdStore {

    pub(crate) async fn write(&self, batch: Batch) -> trc::Result<AssignedIds> {
        todo!()
    }

    pub(crate) async fn purge_store(&self) -> trc::Result<()> {
        for subspace in [SUBSPACE_QUOTA, SUBSPACE_COUNTER] {
            let mut client = self.client.clone();
            client.delete(vec![subspace],  Some(DeleteOptions::new().with_prefix()))
            .await
            .map_err(into_error)?;
        }

        Ok(())
    }

    pub(crate) async fn delete_range(&self, from: impl Key, to: impl Key) -> trc::Result<()> {
        let key_subspace: u8 = from.subspace();
        let from = from.serialize(0);
        let to = to.serialize(0);

        let mut client = self.get_prefix_client(key_subspace);

        client.delete(from,  Some(DeleteOptions::new().with_range(to)))
        .await
        .map_err(into_error)
        .map(|_| ())
    }
}
