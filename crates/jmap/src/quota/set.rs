/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    object::index::{IndexAs, IndexProperty},
    types::property::Property,
};
use std::future::Future;

pub trait QuotaSet: Sync + Send {
    fn quota_set(
        &self,
        account_id: u32,
        quota: &AccessToken,
    ) -> impl Future<Output = trc::Result<SetResponse>> + Send;
}

impl QuotaSet for Server {
    async fn quota_set(&self, account_id: u32, quota: &AccessToken) -> trc::Result<SetResponse> {}
}
