/*
 * SPDX-FileCopyrightText: 2024 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */
use etcd_client::{Client, Error as EtcdError};

pub mod main;

#[allow(dead_code)]
pub struct EtcdStore {
    client: Client,
}

#[inline(always)]
fn into_error(error: EtcdError) -> trc::Error {
    trc::StoreEvent::EtcdError
        .reason(error.to_string())
}
