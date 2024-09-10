/*
 * SPDX-FileCopyrightText: 2024 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use etcd_client::{KvClient, KvClientPrefix, Error as EtcdError};

pub mod main;
pub mod read;
pub mod write;

#[allow(dead_code)]
pub struct EtcdStore {
    client: KvClient,
}

impl EtcdStore {
    fn get_prefix_client(&self, pfx: u8) -> KvClientPrefix {
        // Clone clients they said: https://github.com/etcdv3/etcd-client/issues/17
        KvClientPrefix::new(self.client.clone(), vec![pfx])
    }
}

#[inline(always)]
fn into_error(error: EtcdError) -> trc::Error {
    trc::StoreEvent::EtcdError
        .reason(error.to_string())
}
