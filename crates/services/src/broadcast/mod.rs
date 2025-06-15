/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::ipc::BroadcastEvent;
use jmap_proto::types::state::StateChange;
use utils::map::bitmap::Bitmap;

pub mod publisher;
pub mod subscriber;

#[derive(Debug)]
pub(crate) struct BroadcastBatch<T> {
    messages: T,
}

const MAX_BATCH_SIZE: usize = 100;
const MESSAGE_SIZE: usize = std::mem::size_of::<u32>() + (std::mem::size_of::<u64>() * 2);
pub(crate) const BROADCAST_TOPIC: &str = "stwt.agora";

impl BroadcastBatch<Vec<BroadcastEvent>> {
    pub fn init() -> Self {
        Self {
            messages: Vec::with_capacity(MAX_BATCH_SIZE),
        }
    }

    pub fn insert(&mut self, message: BroadcastEvent) -> bool {
        self.messages.push(message);
        self.messages.len() < MAX_BATCH_SIZE
    }

    pub fn serialize(&self, node_id: u16) -> Vec<u8> {
        let mut serialized =
            Vec::with_capacity((self.messages.len() * MESSAGE_SIZE) + std::mem::size_of::<u16>());
        serialized.extend_from_slice(&node_id.to_le_bytes());
        for message in &self.messages {
            let msg_id: u32 = match message {
                BroadcastEvent::StateChange(state_change) => {
                    serialized.extend_from_slice(&state_change.change_id.to_le_bytes());
                    serialized.extend_from_slice(&state_change.types.as_ref().to_le_bytes());
                    serialized.extend_from_slice(&state_change.account_id.to_le_bytes());
                    continue;
                }
                BroadcastEvent::ReloadSettings => 0,
                BroadcastEvent::ReloadBlockedIps => 1,
            };

            serialized.extend_from_slice(&u64::MAX.to_le_bytes());
            serialized.extend_from_slice(&u64::MAX.to_le_bytes());
            serialized.extend_from_slice(&msg_id.to_le_bytes());
        }
        serialized
    }

    pub fn clear(&mut self) {
        self.messages.clear();
    }
}

impl<T: AsRef<[u8]>> BroadcastBatch<T> {
    pub fn node_id(&self) -> Option<u16> {
        self.messages
            .as_ref()
            .get(0..std::mem::size_of::<u16>())
            .and_then(|bytes| bytes.try_into().ok())
            .map(u16::from_le_bytes)
    }

    pub fn events(&self) -> impl Iterator<Item = Option<BroadcastEvent>> {
        self.messages
            .as_ref()
            .get(std::mem::size_of::<u16>()..)
            .unwrap_or_default()
            .chunks_exact(MESSAGE_SIZE)
            .map(|chunk| {
                let change_id =
                    u64::from_le_bytes(chunk[0..std::mem::size_of::<u64>()].try_into().unwrap());
                let types = u64::from_le_bytes(
                    chunk[std::mem::size_of::<u64>()..std::mem::size_of::<u64>() * 2]
                        .try_into()
                        .unwrap(),
                );
                let account_id = u32::from_le_bytes(
                    chunk[std::mem::size_of::<u64>() * 2..20]
                        .try_into()
                        .unwrap(),
                );

                Some(if change_id != u64::MAX {
                    BroadcastEvent::StateChange(StateChange {
                        change_id,
                        types: Bitmap::from(types),
                        account_id,
                    })
                } else {
                    match account_id {
                        0 => BroadcastEvent::ReloadSettings,
                        1 => BroadcastEvent::ReloadBlockedIps,
                        _ => return None,
                    }
                })
            })
    }
}

impl<T> BroadcastBatch<T> {
    pub fn new(messages: T) -> Self {
        Self { messages }
    }
}
