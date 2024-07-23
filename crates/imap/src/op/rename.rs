/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::BTreeMap;

use crate::{
    core::{Session, SessionData},
    spawn_op,
};
use common::listener::SessionStream;
use imap_proto::{
    protocol::rename::Arguments, receiver::Request, Command, ResponseCode, StatusResponse,
};
use jmap::{auth::acl::EffectiveAcl, mailbox::set::SCHEMA};
use jmap_proto::{
    object::{index::ObjectIndexBuilder, Object},
    types::{
        acl::Acl, collection::Collection, id::Id, property::Property, state::StateChange,
        type_state::DataType, value::Value,
    },
};
use store::write::{assert::HashedValue, BatchBuilder};
use trc::AddContext;

use super::ImapContext;

impl<T: SessionStream> Session<T> {
    pub async fn handle_rename(&mut self, request: Request<Command>) -> trc::Result<()> {
        let arguments = request.parse_rename(self.version)?;
        let data = self.state.session_data();

        spawn_op!(data, {
            let response = data.rename_folder(arguments).await?;
            data.write_bytes(response.into_bytes()).await
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn rename_folder(&self, arguments: Arguments) -> trc::Result<StatusResponse> {
        // Refresh mailboxes
        self.synchronize_mailboxes(false)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Validate mailbox name
        let mut params = self
            .validate_mailbox_create(&arguments.new_mailbox_name, None)
            .await
            .add_context(|err| err.id(arguments.tag.clone()))?;
        params.is_rename = true;

        // Validate source mailbox
        let mailbox_id = {
            let mut mailbox_id = None;
            for account in self.mailboxes.lock().iter() {
                if let Some(mailbox_id_) = account.mailbox_names.get(&arguments.mailbox_name) {
                    if account.account_id == params.account_id {
                        mailbox_id = (*mailbox_id_).into();
                        break;
                    } else {
                        return Err(trc::ImapEvent::Error
                            .into_err()
                            .details("Cannot move mailboxes between accounts.")
                            .code(ResponseCode::Cannot)
                            .id(arguments.tag));
                    }
                }
            }
            if let Some(mailbox_id) = mailbox_id {
                mailbox_id
            } else {
                return Err(trc::ImapEvent::Error
                    .into_err()
                    .details(format!("Mailbox '{}' not found.", arguments.mailbox_name))
                    .code(ResponseCode::NonExistent)
                    .id(arguments.tag));
            }
        };

        // Obtain mailbox
        let mailbox = self
            .jmap
            .get_property::<HashedValue<Object<Value>>>(
                params.account_id,
                Collection::Mailbox,
                mailbox_id,
                Property::Value,
            )
            .await
            .imap_ctx(&arguments.tag, trc::location!())?
            .ok_or_else(|| {
                trc::ImapEvent::Error
                    .into_err()
                    .details(format!("Mailbox '{}' not found.", arguments.mailbox_name))
                    .caused_by(trc::location!())
                    .code(ResponseCode::NonExistent)
                    .id(arguments.tag.clone())
            })?;

        // Validate ACL
        let access_token = self
            .get_access_token()
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;
        if access_token.is_shared(params.account_id)
            && !mailbox
                .inner
                .effective_acl(&access_token)
                .contains(Acl::Modify)
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details("You are not allowed to rename this mailbox.")
                .code(ResponseCode::NoPerm)
                .id(arguments.tag));
        }

        // Get new mailbox name from path
        let new_mailbox_name = params.path.pop().unwrap();

        // Build batch
        let mut changes = self
            .jmap
            .begin_changes(params.account_id)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        let mut parent_id = params.parent_mailbox_id.map(|id| id + 1).unwrap_or(0);
        let mut create_ids = Vec::with_capacity(params.path.len());
        for &path_item in params.path.iter() {
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(params.account_id)
                .with_collection(Collection::Mailbox)
                .create_document()
                .custom(
                    ObjectIndexBuilder::new(SCHEMA).with_changes(
                        Object::with_capacity(3)
                            .with_property(Property::Name, path_item)
                            .with_property(Property::ParentId, Value::Id(Id::from(parent_id)))
                            .with_property(
                                Property::Cid,
                                Value::UnsignedInt(rand::random::<u32>() as u64),
                            ),
                    ),
                );

            let mailbox_id = self
                .jmap
                .write_batch_expect_id(batch)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;

            changes.log_insert(Collection::Mailbox, mailbox_id);
            parent_id = mailbox_id + 1;
            create_ids.push(mailbox_id);
        }

        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(params.account_id)
            .with_collection(Collection::Mailbox)
            .update_document(mailbox_id)
            .custom(
                ObjectIndexBuilder::new(SCHEMA)
                    .with_current(mailbox)
                    .with_changes(
                        Object::with_capacity(3)
                            .with_property(Property::Name, new_mailbox_name)
                            .with_property(Property::ParentId, Value::Id(Id::from(parent_id)))
                            .with_property(
                                Property::Cid,
                                Value::UnsignedInt(rand::random::<u32>() as u64),
                            ),
                    ),
            );
        changes.log_update(Collection::Mailbox, mailbox_id);

        let change_id = changes.change_id;
        batch.custom(changes);
        self.jmap
            .write_batch(batch)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Broadcast changes
        self.jmap
            .broadcast_state_change(
                StateChange::new(params.account_id).with_change(DataType::Mailbox, change_id),
            )
            .await;

        let mut mailboxes = if !create_ids.is_empty() {
            self.add_created_mailboxes(&mut params, change_id, create_ids)
                .add_context(|err| err.id(arguments.tag.clone()))?
        } else {
            self.mailboxes.lock()
        };

        // Rename mailbox cache
        for account in mailboxes.iter_mut() {
            if account.account_id == params.account_id {
                // Update state
                account.state_mailbox = change_id.into();

                // Update parents
                if arguments.mailbox_name.contains('/') {
                    let mut parent_path = arguments.mailbox_name.split('/').collect::<Vec<_>>();
                    parent_path.pop();
                    let parent_path = parent_path.join("/");
                    if let Some(old_parent_id) = account.mailbox_names.get(&parent_path) {
                        if let Some(old_parent) = account.mailbox_state.get_mut(old_parent_id) {
                            let prefix = format!("{}/", parent_path);
                            old_parent.has_children = account.mailbox_names.keys().any(|name| {
                                name != &arguments.mailbox_name && name.starts_with(&prefix)
                            });
                        }
                    }
                }
                if let Some(parent_mailbox) = params
                    .parent_mailbox_id
                    .and_then(|id| account.mailbox_state.get_mut(&id))
                {
                    parent_mailbox.has_children = true;
                }

                let prefix = format!("{}/", arguments.mailbox_name);
                let mut new_mailbox_names = BTreeMap::new();
                for (mailbox_name, mailbox_id) in std::mem::take(&mut account.mailbox_names) {
                    if mailbox_name != arguments.mailbox_name {
                        if let Some(child_name) = mailbox_name.strip_prefix(&prefix) {
                            new_mailbox_names
                                .insert(format!("{}/{}", params.full_path, child_name), mailbox_id);
                        } else {
                            new_mailbox_names.insert(mailbox_name, mailbox_id);
                        }
                    }
                }
                new_mailbox_names.insert(params.full_path, mailbox_id);
                account.mailbox_names = new_mailbox_names;
                break;
            }
        }

        Ok(StatusResponse::completed(Command::Rename).with_tag(arguments.tag))
    }
}
