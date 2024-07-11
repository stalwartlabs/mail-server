/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    object::index::{IndexAs, IndexProperty},
    types::property::Property,
};

use crate::JMAP;

impl JMAP {
    pub async fn quota_set(
        &self,
        account_id: u32,
        quota: &AccessToken,
    ) -> trc::Result<SetResponse> {
    }
}
