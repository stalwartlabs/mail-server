/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use common::Server;
use jmap_proto::types::collection::Collection;
use std::future::Future;
use store::{
    write::{log::ChangeLogBuilder, BatchBuilder},
    LogKey,
};
use trc::AddContext;

pub trait ChangeLog: Sync + Send {
    fn begin_changes(
        &self,
        account_id: u32,
    ) -> impl Future<Output = trc::Result<ChangeLogBuilder>> + Send;
    fn assign_change_id(&self, account_id: u32) -> impl Future<Output = trc::Result<u64>> + Send;
    fn generate_snowflake_id(&self) -> trc::Result<u64>;
    fn commit_changes(
        &self,
        account_id: u32,
        changes: ChangeLogBuilder,
    ) -> impl Future<Output = trc::Result<u64>> + Send;
    fn delete_changes(
        &self,
        account_id: u32,
        before: Duration,
    ) -> impl Future<Output = trc::Result<()>> + Send;
}

impl ChangeLog for Server {
    async fn begin_changes(&self, account_id: u32) -> trc::Result<ChangeLogBuilder> {
        self.assign_change_id(account_id)
            .await
            .map(ChangeLogBuilder::with_change_id)
    }

    async fn assign_change_id(&self, _: u32) -> trc::Result<u64> {
        self.generate_snowflake_id()
    }

    fn generate_snowflake_id(&self) -> trc::Result<u64> {
        self.inner.data.jmap_id_gen.generate().ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .into_err()
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "Failed to generate snowflake id.")
        })
    }

    async fn commit_changes(
        &self,
        account_id: u32,
        mut changes: ChangeLogBuilder,
    ) -> trc::Result<u64> {
        if changes.change_id == u64::MAX || changes.change_id == 0 {
            changes.change_id = self.assign_change_id(account_id).await?;
        }
        let state = changes.change_id;

        let mut builder = BatchBuilder::new();
        builder.with_account_id(account_id).custom(changes);
        self.core
            .storage
            .data
            .write(builder.build())
            .await
            .caused_by(trc::location!())
            .map(|_| state)
    }

    async fn delete_changes(&self, account_id: u32, before: Duration) -> trc::Result<()> {
        let reference_cid = self.inner.data.jmap_id_gen.past_id(before).ok_or_else(|| {
            trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "Failed to generate reference change id.")
        })?;

        for collection in [
            Collection::Email,
            Collection::Mailbox,
            Collection::Thread,
            Collection::Identity,
            Collection::EmailSubmission,
        ] {
            self.core
                .storage
                .data
                .delete_range(
                    LogKey {
                        account_id,
                        collection: collection.into(),
                        change_id: 0,
                    },
                    LogKey {
                        account_id,
                        collection: collection.into(),
                        change_id: reference_cid,
                    },
                )
                .await?;
        }

        Ok(())
    }
}
