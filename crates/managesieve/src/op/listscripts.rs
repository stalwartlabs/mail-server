/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{
    object::Object,
    types::{collection::Collection, property::Property, value::Value},
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Session, StatusResponse};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn handle_listscripts(&mut self) -> super::OpResult {
        let account_id = self.state.access_token().primary_id();
        let document_ids = self
            .jmap
            .get_document_ids(account_id, Collection::SieveScript)
            .await?
            .unwrap_or_default();

        if document_ids.is_empty() {
            return Ok(StatusResponse::ok("").into_bytes());
        }

        let mut response = Vec::with_capacity(128);

        for document_id in document_ids {
            if let Some(script) = self
                .jmap
                .get_property::<Object<Value>>(
                    account_id,
                    Collection::SieveScript,
                    document_id,
                    Property::Value,
                )
                .await?
            {
                response.push(b'\"');
                if let Some(name) = script.get(&Property::Name).as_string() {
                    for ch in name.as_bytes() {
                        if [b'\\', b'\"'].contains(ch) {
                            response.push(b'\\');
                        }
                        response.push(*ch);
                    }
                }

                if script.get(&Property::IsActive).as_bool() == Some(true) {
                    response.extend_from_slice(b"\" ACTIVE\r\n");
                } else {
                    response.extend_from_slice(b"\"\r\n");
                }
            }
        }

        Ok(StatusResponse::ok("").serialize(response))
    }
}
