/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::listener::SessionStream;
use directory::Permission;
use email::message::metadata::MessageMetadata;
use jmap_proto::types::{collection::Collection, property::Property};
use trc::AddContext;

use crate::{Session, protocol::response::Response};

impl<T: SessionStream> Session<T> {
    pub async fn handle_fetch(&mut self, msg: u32, lines: Option<u32>) -> trc::Result<()> {
        // Validate access
        self.state
            .access_token()
            .assert_has_permission(Permission::Pop3Retr)?;

        let op_start = Instant::now();
        let mailbox = self.state.mailbox();
        if let Some(message) = mailbox.messages.get(msg.saturating_sub(1) as usize) {
            if let Some(metadata_) = self
                .server
                .get_archive_by_property(
                    mailbox.account_id,
                    Collection::Email,
                    message.id,
                    Property::BodyStructure,
                )
                .await
                .caused_by(trc::location!())?
            {
                let metadata = metadata_
                    .unarchive::<MessageMetadata>()
                    .caused_by(trc::location!())?;
                if let Some(bytes) = self
                    .server
                    .blob_store()
                    .get_blob(metadata.blob_hash.0.as_slice(), 0..usize::MAX)
                    .await
                    .caused_by(trc::location!())?
                {
                    trc::event!(
                        Pop3(trc::Pop3Event::Fetch),
                        SpanId = self.session_id,
                        DocumentId = message.id,
                        Elapsed = op_start.elapsed()
                    );

                    self.write_bytes(
                        Response::Message::<u32> {
                            bytes,
                            lines: lines.unwrap_or(0),
                        }
                        .serialize(),
                    )
                    .await
                } else {
                    Err(trc::Pop3Event::Error
                        .into_err()
                        .details("Failed to fetch message. Perhaps another session deleted it?")
                        .caused_by(trc::location!()))
                }
            } else {
                Err(trc::Pop3Event::Error
                    .into_err()
                    .details("Failed to fetch message. Perhaps another session deleted it?")
                    .caused_by(trc::location!()))
            }
        } else {
            Err(trc::Pop3Event::Error.into_err().details("No such message."))
        }
    }
}
