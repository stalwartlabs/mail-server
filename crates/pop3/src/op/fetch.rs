/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
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
