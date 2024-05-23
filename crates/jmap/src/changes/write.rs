/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::time::Duration;

use jmap_proto::{error::method::MethodError, types::collection::Collection};
use store::{
    write::{log::ChangeLogBuilder, BatchBuilder},
    LogKey,
};

use crate::JMAP;

impl JMAP {
    pub async fn begin_changes(&self, account_id: u32) -> Result<ChangeLogBuilder, MethodError> {
        self.assign_change_id(account_id)
            .await
            .map(ChangeLogBuilder::with_change_id)
    }

    pub async fn assign_change_id(&self, _: u32) -> Result<u64, MethodError> {
        self.generate_snowflake_id()
    }

    pub fn generate_snowflake_id(&self) -> Result<u64, MethodError> {
        self.inner.snowflake_id.generate().ok_or_else(|| {
            tracing::error!(
                event = "error",
                context = "change_log",
                "Failed to generate snowflake id."
            );
            MethodError::ServerPartialFail
        })
    }

    pub async fn commit_changes(
        &self,
        account_id: u32,
        mut changes: ChangeLogBuilder,
    ) -> Result<u64, MethodError> {
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
            .map_err(|err| {
                tracing::error!(
                    event = "error",
                    context = "change_log",
                    error = ?err,
                    "Failed to write changes.");
                MethodError::ServerPartialFail
            })?;

        Ok(state)
    }

    pub async fn delete_changes(&self, account_id: u32, before: Duration) -> store::Result<()> {
        let reference_cid = self.inner.snowflake_id.past_id(before).ok_or_else(|| {
            store::Error::InternalError("Failed to generate reference change id.".to_string())
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
