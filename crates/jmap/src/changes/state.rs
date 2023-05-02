use jmap_proto::{
    error::method::MethodError,
    types::{collection::Collection, state::State},
};

use crate::JMAP;

impl JMAP {
    pub async fn get_state(
        &self,
        account_id: u32,
        collection: Collection,
    ) -> Result<State, MethodError> {
        match self.store.get_last_change_id(account_id, collection).await {
            Ok(id) => Ok(id.into()),
            Err(err) => {
                tracing::error!(event = "error",
                    context = "store",
                    account_id = account_id,
                    collection = ?collection,
                    error = ?err,
                    "Failed to obtain state");
                Err(MethodError::ServerPartialFail)
            }
        }
    }

    pub async fn assert_state(
        &self,
        account_id: u32,
        collection: Collection,
        if_in_state: &Option<State>,
    ) -> Result<State, MethodError> {
        let old_state: State = self.get_state(account_id, collection).await?;
        if let Some(if_in_state) = if_in_state {
            if &old_state != if_in_state {
                return Err(MethodError::StateMismatch);
            }
        }

        Ok(old_state)
    }
}
