/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ops::Range;

use super::TikvStore;

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