/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::types::{collection::Collection, state::State};
use trc::AddContext;

use crate::JMAP;

impl JMAP {
    pub async fn get_state(
        &self,
        account_id: u32,
        collection: impl Into<u8>,
    ) -> trc::Result<State> {
        let collection = collection.into();
        self.core
            .storage
            .data
            .get_last_change_id(account_id, collection)
            .await
            .caused_by(trc::location!())
            .map(State::from)
    }

    pub async fn assert_state(
        &self,
        account_id: u32,
        collection: Collection,
        if_in_state: &Option<State>,
    ) -> trc::Result<State> {
        let old_state: State = self.get_state(account_id, collection).await?;
        if let Some(if_in_state) = if_in_state {
            if &old_state != if_in_state {
                return Err(trc::JmapEvent::StateMismatch.into_err());
            }
        }

        Ok(old_state)
    }
}
