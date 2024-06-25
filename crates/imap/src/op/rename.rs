/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::BTreeMap;

use crate::core::{Session, SessionData};
use common::listener::SessionStream;
use imap_proto::{
    protocol::rename::Arguments, receiver::Request, Command, ResponseCode, StatusResponse,
};
use jmap::{auth::acl::EffectiveAcl, mailbox::set::SCHEMA};
use jmap_proto::{
    error::method::MethodError,
    object::{index::ObjectIndexBuilder, Object},
    types::{
        acl::Acl, collection::Collection, id::Id, property::Property, state::StateChange,
        type_state::DataType, value::Value,
    },
};
use store::write::{assert::HashedValue, BatchBuilder};

impl<T: SessionStream> Session<T> {
    pub async fn handle_rename(&mut self, request: Request<Command>) -> crate::OpResult {
        match request.parse_rename(self.version) {
            Ok(arguments) => {
                let data = self.state.session_data();
                tokio::spawn(async move {
                    data.write_bytes(data.rename_folder(arguments).await.into_bytes())
                        .await;
                });
                Ok(())
            }
            Err(response) => self.write_bytes(response.into_bytes()).await,
        }
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn rename_folder(&self, arguments: Arguments) -> StatusResponse {
        // Refresh mailboxes
        if let Err(err) = self.synchronize_mailboxes(false).await {
            return err.with_tag(arguments.tag);
        }

        // Validate mailbox name
        let mut params = match self
            .validate_mailbox_create(&arguments.new_mailbox_name, None)
            .await
        {
            Ok(mut params) => {
                params.is_rename = true;
                params
            }
            Err(response) => {
                return response.with_tag(arguments.tag);
            }
        };

        // Validate source mailbox
        let mailbox_id = {
            let mut mailbox_id = None;
            for account in self.mailboxes.lock().iter() {
                if let Some(mailbox_id_) = account.mailbox_names.get(&arguments.mailbox_name) {
                    if account.account_id == params.account_id {
                        mailbox_id = (*mailbox_id_).into();
                        break;
                    } else {
                        return StatusResponse::no("Cannot move mailboxes between accounts.")
                            .with_tag(arguments.tag)
                            .with_code(ResponseCode::Cannot);
                    }
                }
            }
            if let Some(mailbox_id) = mailbox_id {
                mailbox_id
            } else {
                return StatusResponse::no(format!(
                    "Mailbox '{}' not found.",
                    arguments.mailbox_name
                ))
                .with_tag(arguments.tag)
                .with_code(ResponseCode::NonExistent);
            }
        };

        // Obtain mailbox
        let mailbox = if let Ok(Some(mailbox)) = self
            .jmap
            .get_property::<HashedValue<Object<Value>>>(
                params.account_id,
                Collection::Mailbox,
                mailbox_id,
                Property::Value,
            )
            .await
        {
            mailbox
        } else {
            return StatusResponse::database_failure().with_tag(arguments.tag);
        };

        // Validate ACL
        let access_token = match self.get_access_token().await {
            Ok(access_token) => access_token,
            Err(response) => return response.with_tag(arguments.tag),
        };
        if access_token.is_shared(params.account_id)
            && !mailbox
                .inner
                .effective_acl(&access_token)
                .contains(Acl::Modify)
        {
            return StatusResponse::no("You are not allowed to rename this mailbox.")
                .with_tag(arguments.tag)
                .with_code(ResponseCode::NoPerm);
        }

        // Get new mailbox name from path
        let new_mailbox_name = params.path.pop().unwrap();

        // Build batch
        let mut changes = match self.jmap.begin_changes(params.account_id).await {
            Ok(changes) => changes,
            Err(_) => {
                return StatusResponse::database_failure().with_tag(arguments.tag);
            }
        };

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

            let mailbox_id = match self.jmap.write_batch_expect_id(batch).await {
                Ok(mailbox_id) => mailbox_id,
                Err(_) => {
                    return StatusResponse::database_failure().with_tag(arguments.tag);
                }
            };

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
        match self.jmap.write_batch(batch).await {
            Ok(_) => (),
            Err(MethodError::ServerUnavailable) => {
                return StatusResponse::no(
                    "Another process modified this mailbox, please try again.",
                )
                .with_tag(arguments.tag);
            }
            Err(_) => {
                return StatusResponse::database_failure().with_tag(arguments.tag);
            }
        }

        // Broadcast changes
        self.jmap
            .broadcast_state_change(
                StateChange::new(params.account_id).with_change(DataType::Mailbox, change_id),
            )
            .await;

        let mut mailboxes = if !create_ids.is_empty() {
            match self.add_created_mailboxes(&mut params, change_id, create_ids) {
                Ok(mailboxes) => mailboxes,
                Err(response) => {
                    return response.with_tag(arguments.tag);
                }
            }
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

        StatusResponse::completed(Command::Rename).with_tag(arguments.tag)
    }
}
