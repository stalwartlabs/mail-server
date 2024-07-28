/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::listener::SessionStream;
use jmap::email::metadata::MessageMetadata;
use jmap_proto::types::{collection::Collection, property::Property};
use store::write::Bincode;
use trc::AddContext;

use crate::{protocol::response::Response, Session};

impl<T: SessionStream> Session<T> {
    pub async fn handle_fetch(&mut self, msg: u32, lines: Option<u32>) -> trc::Result<()> {
        let op_start = Instant::now();
        let mailbox = self.state.mailbox();
        if let Some(message) = mailbox.messages.get(msg.saturating_sub(1) as usize) {
            if let Some(metadata) = self
                .jmap
                .get_property::<Bincode<MessageMetadata>>(
                    mailbox.account_id,
                    Collection::Email,
                    message.id,
                    &Property::BodyStructure,
                )
                .await
                .caused_by(trc::location!())?
            {
                if let Some(bytes) = self
                    .jmap
                    .get_blob(&metadata.inner.blob_hash, 0..usize::MAX)
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
