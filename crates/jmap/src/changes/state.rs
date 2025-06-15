/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{MessageStoreCache, Server};
use jmap_proto::types::{collection::SyncCollection, state::State};
use std::future::Future;
use trc::AddContext;

pub trait StateManager: Sync + Send {
    fn get_state(
        &self,
        account_id: u32,
        collection: SyncCollection,
    ) -> impl Future<Output = trc::Result<State>> + Send;

    fn assert_state(
        &self,
        account_id: u32,
        collection: SyncCollection,
        if_in_state: &Option<State>,
    ) -> impl Future<Output = trc::Result<State>> + Send;
}

pub trait MessageCacheState: Sync + Send {
    fn get_state(&self, is_mailbox: bool) -> State;

    fn assert_state(&self, is_mailbox: bool, if_in_state: &Option<State>) -> trc::Result<State>;
}

impl StateManager for Server {
    async fn get_state(&self, account_id: u32, collection: SyncCollection) -> trc::Result<State> {
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
        collection: SyncCollection,
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

impl MessageCacheState for MessageStoreCache {
    fn get_state(&self, is_mailbox: bool) -> State {
        if is_mailbox {
            State::from(self.mailboxes.change_id)
        } else {
            State::from(self.emails.change_id)
        }
    }

    fn assert_state(&self, is_mailbox: bool, if_in_state: &Option<State>) -> trc::Result<State> {
        let old_state: State = self.get_state(is_mailbox);
        if let Some(if_in_state) = if_in_state {
            if &old_state != if_in_state {
                return Err(trc::JmapEvent::StateMismatch.into_err());
            }
        }
        Ok(old_state)
    }
}
