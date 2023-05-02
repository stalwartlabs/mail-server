use jmap_proto::{error::method::MethodError, types::state::State};
use store::write::{log::ChangeLogBuilder, BatchBuilder};

use crate::JMAP;

impl JMAP {
    pub async fn begin_changes(&self, account_id: u32) -> Result<ChangeLogBuilder, MethodError> {
        Ok(ChangeLogBuilder::with_change_id(
            self.store
                .assign_change_id(account_id)
                .await
                .map_err(|err| {
                    tracing::error!(
                        event = "error",
                        context = "change_log",
                        error = ?err,
                        "Failed to assign changeId.");
                    MethodError::ServerPartialFail
                })?,
        ))
    }
    pub async fn commit_changes(
        &self,
        account_id: u32,
        mut changes: ChangeLogBuilder,
    ) -> Result<State, MethodError> {
        if changes.change_id == u64::MAX {
            changes.change_id = self
                .store
                .assign_change_id(account_id)
                .await
                .map_err(|err| {
                    tracing::error!(
                        event = "error",
                        context = "change_log",
                        error = ?err,
                        "Failed to assign changeId.");
                    MethodError::ServerPartialFail
                })?;
        }
        let state = State::from(changes.change_id);

        let mut builder = BatchBuilder::new();
        builder.with_account_id(account_id).custom(changes);
        self.store.write(builder.build()).await.map_err(|err| {
            tracing::error!(
                    event = "error",
                    context = "change_log",
                    error = ?err,
                    "Failed to write changes.");
            MethodError::ServerPartialFail
        })?;

        Ok(state)
    }
}
