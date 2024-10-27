/*
 * SPDX-FileCopyrightText: 2024 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use etcd_client::{KvClient, KvClientPrefix, Error as EtcdError};

pub mod main;
pub mod read;
pub mod write;
pub mod blob;

// See: https://etcd.io/docs/v3.4/dev-guide/limit/
// maximum size of any request is 1.5 MiB

// The default storage size limit is 2 GiB, configurable with --quota-backend-bytes flag. 8 GiB is a suggested maximum size for normal environments and etcd warns at startup if the configured value exceeds it.
const MAX_VALUE_SIZE: usize = 2147483648;// 2 GiB

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
