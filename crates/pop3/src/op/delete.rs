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
use jmap_proto::types::{state::StateChange, type_state::DataType};
use store::roaring::RoaringBitmap;

use crate::{Session, State};

impl<T: SessionStream> Session<T> {
    pub async fn handle_dele(&mut self, msgs: Vec<u32>) -> Result<(), ()> {
        let mailbox = self.state.mailbox_mut();
        let mut response = Vec::new();

        for msg in msgs {
            if let Some(message) = mailbox.messages.get_mut(msg.saturating_sub(1) as usize) {
                if !message.deleted {
                    response.extend_from_slice(format!("+OK message {msg} deleted\r\n").as_bytes());
                    message.deleted = true;
                } else {
                    response.extend_from_slice(
                        format!("-ERR message {msg} already deleted\r\n").as_bytes(),
                    );
                }
            } else {
                response.extend_from_slice("-ERR no such message\r\n".as_bytes());
            }
        }

        self.write_bytes(response).await
    }

    pub async fn handle_rset(&mut self) -> Result<(), ()> {
        let mut count = 0;
        let mailbox = self.state.mailbox_mut();
        for message in &mut mailbox.messages {
            if message.deleted {
                count += 1;
                message.deleted = false;
            }
        }
        self.write_ok(format!("{count} messages undeleted")).await
    }

    pub async fn handle_quit(&mut self) -> Result<(), ()> {
        if let State::Authenticated { mailbox, .. } = &self.state {
            let mut deleted = RoaringBitmap::new();
            for message in &mailbox.messages {
                if message.deleted {
                    deleted.insert(message.id);
                }
            }

            if !deleted.is_empty() {
                let num_deleted = deleted.len();
                match self
                    .jmap
                    .emails_tombstone(mailbox.account_id, deleted)
                    .await
                {
                    Ok((changes, not_deleted)) => {
                        if !changes.is_empty() {
                            if let Ok(change_id) =
                                self.jmap.commit_changes(mailbox.account_id, changes).await
                            {
                                self.jmap
                                    .broadcast_state_change(
                                        StateChange::new(mailbox.account_id)
                                            .with_change(DataType::Email, change_id)
                                            .with_change(DataType::Mailbox, change_id)
                                            .with_change(DataType::Thread, change_id),
                                    )
                                    .await;
                            }
                        }
                        if not_deleted.is_empty() {
                            self.write_ok(format!(
                                "Stalwart POP3 bids you farewell ({num_deleted} messages deleted)."
                            ))
                            .await?;
                        } else {
                            self.write_err("Some messages could not be deleted").await?;
                        }
                    }
                    Err(_) => {
                        self.write_err("Failed to delete messages").await?;
                    }
                }
            }
        } else {
            self.write_ok("Stalwart POP3 bids you farewell.").await?;
        }

        Err(())
    }
}
