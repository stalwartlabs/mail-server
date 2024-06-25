/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::SessionStream;
use jmap::email::metadata::MessageMetadata;
use jmap_proto::types::{collection::Collection, property::Property};
use store::write::Bincode;

use crate::{protocol::response::Response, Session};

impl<T: SessionStream> Session<T> {
    pub async fn handle_fetch(&mut self, msg: u32, lines: Option<u32>) -> Result<(), ()> {
        let mailbox = self.state.mailbox();
        if let Some(message) = mailbox.messages.get(msg.saturating_sub(1) as usize) {
            match self
                .jmap
                .get_property::<Bincode<MessageMetadata>>(
                    mailbox.account_id,
                    Collection::Email,
                    message.id,
                    &Property::BodyStructure,
                )
                .await
            {
                Ok(Some(metadata)) => {
                    match self
                        .jmap
                        .get_blob(&metadata.inner.blob_hash, 0..usize::MAX)
                        .await
                    {
                        Ok(Some(bytes)) => {
                            self.write_bytes(
                                Response::Message::<u32> {
                                    bytes,
                                    lines: lines.unwrap_or(0),
                                }
                                .serialize(),
                            )
                            .await
                        }
                        _ => {
                            self.write_err(
                                "Failed to fetch message. Perhaps another session deleted it?",
                            )
                            .await
                        }
                    }
                }
                _ => {
                    self.write_err("Failed to fetch message. Perhaps another session deleted it?")
                        .await
                }
            }
        } else {
            self.write_err("No such message").await
        }
    }
}
