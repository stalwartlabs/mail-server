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

use jmap_proto::{
    error::method::MethodError,
    types::{collection::Collection, state::State},
};

use crate::JMAP;

impl JMAP {
    pub async fn get_state(
        &self,
        account_id: u32,
        collection: impl Into<u8>,
    ) -> Result<State, MethodError> {
        let collection = collection.into();
        match self.store.get_last_change_id(account_id, collection).await {
            Ok(id) => Ok(id.into()),
            Err(err) => {
                tracing::error!(event = "error",
                    context = "store",
                    account_id = account_id,
                    collection = ?Collection::from(collection),
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
