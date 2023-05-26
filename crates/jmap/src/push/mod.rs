/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

pub mod ece;
pub mod get;
pub mod manager;
pub mod set;

use std::time::Instant;

use jmap_proto::types::{id::Id, state::StateChange, type_state::TypeState};
use utils::map::bitmap::Bitmap;

#[derive(Debug)]
pub enum UpdateSubscription {
    Unverified {
        id: u32,
        url: String,
        code: String,
        keys: Option<EncryptionKeys>,
    },
    Verified(PushSubscription),
}

#[derive(Debug)]
pub struct PushSubscription {
    pub id: u32,
    pub url: String,
    pub expires: u64,
    pub types: Bitmap<TypeState>,
    pub keys: Option<EncryptionKeys>,
}

#[derive(Debug, Clone)]
pub struct EncryptionKeys {
    pub p256dh: Vec<u8>,
    pub auth: Vec<u8>,
}

#[derive(Debug)]
pub enum Event {
    Update {
        updates: Vec<PushUpdate>,
    },
    Push {
        ids: Vec<Id>,
        state_change: StateChange,
    },
    DeliverySuccess {
        id: Id,
    },
    DeliveryFailure {
        id: Id,
        state_changes: Vec<StateChange>,
    },
    Reset,
}

#[derive(Debug)]
pub enum PushUpdate {
    Verify {
        id: u32,
        account_id: u32,
        url: String,
        code: String,
        keys: Option<EncryptionKeys>,
    },
    Register {
        id: Id,
        url: String,
        keys: Option<EncryptionKeys>,
    },
    Unregister {
        id: Id,
    },
}

#[derive(Debug)]
pub struct PushServer {
    url: String,
    keys: Option<EncryptionKeys>,
    num_attempts: u32,
    last_request: Instant,
    state_changes: Vec<StateChange>,
    in_flight: bool,
}
