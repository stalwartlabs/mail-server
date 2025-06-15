/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod ece;
pub mod http;
pub mod manager;
pub mod push;

use std::time::{Duration, Instant};

use common::ipc::EncryptionKeys;

use jmap_proto::types::{id::Id, state::StateChange, type_state::DataType};
use tokio::sync::mpsc;
use utils::map::bitmap::Bitmap;

#[derive(Debug)]
struct Subscriber {
    types: Bitmap<DataType>,
    subscription: SubscriberType,
}

#[derive(Debug)]
pub enum SubscriberType {
    Ipc { tx: mpsc::Sender<StateChange> },
    Push { expires: u64 },
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

impl Subscriber {
    fn is_valid(&self, current_time: u64) -> bool {
        match &self.subscription {
            SubscriberType::Ipc { tx } => !tx.is_closed(),
            SubscriberType::Push { expires } => expires > &current_time,
        }
    }
}

const PURGE_EVERY: Duration = Duration::from_secs(3600);
const SEND_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SubscriberId {
    Ipc(u32),
    Push(u32),
}

impl From<SubscriberId> for u32 {
    fn from(subscriber_id: SubscriberId) -> u32 {
        match subscriber_id {
            SubscriberId::Ipc(id) => id,
            SubscriberId::Push(id) => id,
        }
    }
}
