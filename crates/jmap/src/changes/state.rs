/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use jmap_proto::types::{collection::Collection, state::State};
use std::future::Future;
use trc::AddContext;

pub trait StateManager: Sync + Send {
    fn get_state(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Send,
    ) -> impl Future<Output = trc::Result<State>> + Send;

    fn assert_state(
        &self,
        account_id: u32,
        collection: Collection,
        if_in_state: &Option<State>,
    ) -> impl Future<Output = trc::Result<State>> + Send;
}

impl StateManager for Server {
    async fn get_state(
        &self,
        account_id: u32,
        collection: impl Into<u8> + Send,
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

    async fn assert_state(
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
