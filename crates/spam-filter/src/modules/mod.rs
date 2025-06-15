/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use store::{
    Deserialize, Value,
    dispatch::lookup::{KeyValue, LookupKey},
};

pub mod bayes;
pub mod dnsbl;
pub mod expression;
pub mod html;
pub mod pyzor;
pub mod sanitize;

pub(crate) async fn key_get<T: Deserialize + From<Value<'static>> + std::fmt::Debug + 'static>(
    server: &Server,
    span_id: u64,
    key: impl Into<LookupKey<'_>>,
) -> Result<Option<T>, ()> {
    server.in_memory_store().key_get(key).await.map_err(|err| {
        trc::error!(err.span_id(span_id).caused_by(trc::location!()));
    })
}

pub(crate) async fn key_set(server: &Server, span_id: u64, kv: KeyValue<Vec<u8>>) {
    if let Err(err) = server.in_memory_store().key_set(kv).await {
        trc::error!(err.span_id(span_id).caused_by(trc::location!()));
    }
}
