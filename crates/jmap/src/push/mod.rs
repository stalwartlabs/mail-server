/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod ece;
pub mod get;
pub mod manager;
pub mod set;

use std::time::Instant;

use jmap_proto::types::{id::Id, state::StateChange, type_state::DataType};
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
    pub types: Bitmap<DataType>,
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
