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

use std::sync::Arc;

use ahash::AHashMap;
use imap_proto::{
    parser::parse_sequence_set,
    receiver::{Request, Token},
    Command, ResponseCode, StatusResponse,
};

use jmap::email::set::TagManager;
use jmap_proto::{
    error::method::MethodError,
    types::{
        acl::Acl, collection::Collection, id::Id, keyword::Keyword, property::Property,
        state::StateChange, type_state::DataType,
    },
};
use store::write::{assert::HashedValue, log::ChangeLogBuilder, BatchBuilder, F_VALUE};
use tokio::io::AsyncRead;

use crate::core::{ImapId, SavedSearch, SelectedMailbox, Session, SessionData};

impl<T: AsyncRead> Session<T> {
    pub async fn handle_expunge(
        &mut self,
        request: Request<Command>,
        is_uid: bool,
    ) -> crate::OpResult {
        let (data, mailbox) = self.state.select_data();

        // Validate ACL
        match data
            .check_mailbox_acl(
                mailbox.id.account_id,
                mailbox.id.mailbox_id.unwrap_or_default(),
                Acl::RemoveItems,
            )
            .await
        {
            Ok(true) => (),
            Ok(false) => {
                return self
                .write_bytes(StatusResponse::no(
                    "You do not have the required permissions to remove messages from this mailbox.",
                )
                .with_tag(request.tag)
                .with_code(ResponseCode::NoPerm).into_bytes())
                .await;
            }
            Err(response) => {
                return self
                    .write_bytes(response.with_tag(request.tag).into_bytes())
                    .await;
            }
        }

        // Parse sequence to operate on
        let sequence = match request.tokens.into_iter().next() {
            Some(Token::Argument(value)) if is_uid => match parse_sequence_set(&value) {
                Ok(sequence) => match mailbox.sequence_to_ids(&sequence, true).await {
                    Ok(sequence) => Some(sequence),
                    Err(response) => {
                        return self
                            .write_bytes(response.with_tag(request.tag).into_bytes())
                            .await;
                    }
                },
                Err(err) => {
                    return self
                        .write_bytes(StatusResponse::bad(err).with_tag(request.tag).into_bytes())
                        .await;
                }
            },
            _ => None,
        };

        if let Err(response) = data.expunge(mailbox.clone(), sequence).await {
            return self
                .write_bytes(response.with_tag(request.tag).into_bytes())
                .await;
        }

        // Clear saved searches
        *mailbox.saved_search.lock() = SavedSearch::None;

        // Synchronize messages
        match data.write_mailbox_changes(&mailbox, self.is_qresync).await {
            Ok(_) => {
                self.write_bytes(
                    StatusResponse::completed(Command::Expunge(is_uid))
                        .with_tag(request.tag)
                        .into_bytes(),
                )
                .await
            }
            Err(response) => {
                self.write_bytes(response.with_tag(request.tag).into_bytes())
                    .await
            }
        }
    }
}

impl SessionData {
    pub async fn expunge(
        &self,
        mailbox: Arc<SelectedMailbox>,
        sequence: Option<AHashMap<u32, ImapId>>,
    ) -> crate::op::Result<()> {
        // Obtain message ids
        let account_id = mailbox.id.account_id;
        let deleted_ids = if let Some(mailbox_id) = mailbox.id.mailbox_id {
            self.jmap
                .get_tag(
                    account_id,
                    Collection::Email,
                    Property::MailboxIds,
                    mailbox_id,
                )
                .await?
                .unwrap_or_default()
                & self
                    .jmap
                    .get_tag(
                        account_id,
                        Collection::Email,
                        Property::Keywords,
                        Keyword::Deleted,
                    )
                    .await?
                    .unwrap_or_default()
        } else {
            self.jmap
                .get_tag(
                    account_id,
                    Collection::Email,
                    Property::Keywords,
                    Keyword::Deleted,
                )
                .await?
                .unwrap_or_default()
        };

        // Delete ids
        let mut changelog = ChangeLogBuilder::new();
        for id in deleted_ids {
            if sequence
                .as_ref()
                .map_or(false, |ids| !ids.contains_key(&id))
            {
                continue;
            }

            if let Some(mailbox_id) = mailbox.id.mailbox_id {
                // If the message is present in multiple mailboxes, untag it from this mailbox.
                let (mut mailboxes, thread_id) =
                    if let Some(result) = self.get_mailbox_tags(account_id, id).await? {
                        result
                    } else {
                        continue;
                    };
                if !mailboxes.current().contains(&mailbox_id) {
                    continue;
                } else if mailboxes.current().len() > 1 {
                    // Remove deleted flag
                    let mut keywords = if let Some(keywords) = self
                        .jmap
                        .get_property::<HashedValue<Vec<Keyword>>>(
                            account_id,
                            Collection::Email,
                            id,
                            Property::Keywords,
                        )
                        .await?
                    {
                        TagManager::new(keywords)
                    } else {
                        continue;
                    };

                    // Untag message from this mailbox and remove Deleted flag
                    mailboxes.update(mailbox_id, false);
                    keywords.update(Keyword::Deleted, false);

                    // Write changes
                    let mut batch = BatchBuilder::new();
                    batch
                        .with_account_id(account_id)
                        .with_collection(Collection::Email)
                        .update_document(id);
                    mailboxes.update_batch(&mut batch, Property::MailboxIds);
                    keywords.update_batch(&mut batch, Property::Keywords);
                    if changelog.change_id == u64::MAX {
                        changelog.change_id = self.jmap.assign_change_id(account_id).await?
                    }
                    batch.value(Property::Cid, changelog.change_id, F_VALUE);
                    match self.jmap.write_batch(batch).await {
                        Ok(_) => {
                            changelog.log_update(Collection::Email, Id::from_parts(thread_id, id));
                            changelog.log_child_update(Collection::Mailbox, mailbox_id);
                        }
                        Err(MethodError::ServerUnavailable) => {}
                        Err(_) => {
                            return Err(StatusResponse::database_failure());
                        }
                    }
                } else {
                    // Delete message from all mailboxes
                    if let Ok(changes) = self.jmap.email_delete(account_id, id).await? {
                        changelog.merge(changes);
                    }
                }
            } else {
                // Delete message from all mailboxes
                if let Ok(changes) = self.jmap.email_delete(account_id, id).await? {
                    changelog.merge(changes);
                }
            }
        }

        // Write changes on source account
        if !changelog.is_empty() {
            let change_id = self.jmap.commit_changes(account_id, changelog).await?;
            self.jmap
                .broadcast_state_change(
                    StateChange::new(account_id)
                        .with_change(DataType::Email, change_id)
                        .with_change(DataType::Mailbox, change_id)
                        .with_change(DataType::Thread, change_id),
                )
                .await;
        }

        Ok(())
    }
}
