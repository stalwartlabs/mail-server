/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::listener::SessionStream;
use directory::Permission;
use email::sieve::SieveScript;
use jmap_proto::types::collection::Collection;
use trc::AddContext;

use crate::core::{Session, StatusResponse};

impl<T: SessionStream> Session<T> {
    pub async fn handle_listscripts(&mut self) -> trc::Result<Vec<u8>> {
        // Validate access
        self.assert_has_permission(Permission::SieveListScripts)?;

        let op_start = Instant::now();
        let account_id = self.state.access_token().primary_id();
        let document_ids = self
            .server
            .get_document_ids(account_id, Collection::SieveScript)
            .await
            .caused_by(trc::location!())?
            .unwrap_or_default();

        if document_ids.is_empty() {
            return Ok(StatusResponse::ok("").into_bytes());
        }

        let mut response = Vec::with_capacity(128);
        let count = document_ids.len();

        for document_id in document_ids {
            if let Some(script_) = self
                .server
                .get_archive(account_id, Collection::SieveScript, document_id)
                .await
                .caused_by(trc::location!())?
            {
                let script = script_
                    .unarchive::<SieveScript>()
                    .caused_by(trc::location!())?;
                response.push(b'\"');
                for ch in script.name.as_bytes() {
                    if [b'\\', b'\"'].contains(ch) {
                        response.push(b'\\');
                    }
                    response.push(*ch);
                }
                if script.is_active {
                    response.extend_from_slice(b"\" ACTIVE\r\n");
                } else {
                    response.extend_from_slice(b"\"\r\n");
                }
            }
        }

        trc::event!(
            ManageSieve(trc::ManageSieveEvent::ListScripts),
            SpanId = self.session_id,
            Total = count,
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::ok("").serialize(response))
    }
}
