/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::Range;
use utils::BLOB_HASH_LEN;
use crate::SUBSPACE_BLOBS;
use crate::write::key::KeySerializer;
use super::{into_error, MAX_SCAN_KEYS_SIZE, MAX_SCAN_VALUES_SIZE, MAX_VALUE_SIZE, TikvStore};

impl TikvStore {
    pub(crate) async fn get_blob(
        &self,
        key: &[u8],
        range: Range<usize>,
    ) -> trc::Result<Option<Vec<u8>>> {
        todo!()
    }

    pub(crate) async fn put_blob(&self, key: &[u8], data: &[u8]) -> trc::Result<()> {
        todo!()
    }

    pub(crate) async fn delete_blob(&self, key: &[u8]) -> trc::Result<bool> {
        todo!()
    }
}