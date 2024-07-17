/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use jmap_proto::types::collection::Collection;
use store::{
    write::{log::ChangeLogBuilder, BatchBuilder},
    LogKey,
};
use trc::AddContext;

use crate::JMAP;

impl JMAP {
    pub async fn begin_changes(&self, account_id: u32) -> trc::Result<ChangeLogBuilder> {
        self.assign_change_id(account_id)
            .await
            .map(ChangeLogBuilder::with_change_id)
    }

    pub async fn assign_change_id(&self, _: u32) -> trc::Result<u64> {
        self.generate_snowflake_id()
    }

    pub fn generate_snowflake_id(&self) -> trc::Result<u64> {
        self.inner.snowflake_id.generate().ok_or_else(|| {
            trc::StoreCause::Unexpected
                .into_err()
                .caused_by(trc::location!())
                .ctx(trc::Key::Reason, "Failed to generate snowflake id.")
        })
    }

    pub async fn commit_changes(
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

    pub async fn delete_changes(&self, account_id: u32, before: Duration) -> trc::Result<()> {
        let reference_cid = self.inner.snowflake_id.past_id(before).ok_or_else(|| {
            trc::StoreCause::Unexpected
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
