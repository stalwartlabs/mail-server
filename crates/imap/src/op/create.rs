/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    core::{Account, Mailbox, Session, SessionData},
    op::ImapContext,
    spawn_op,
};
use common::listener::SessionStream;
use imap_proto::{
    protocol::{create::Arguments, list::Attribute},
    receiver::Request,
    Command, ResponseCode, StatusResponse,
};
use jmap::mailbox::set::SCHEMA;
use jmap_proto::{
    object::{index::ObjectIndexBuilder, Object},
    types::{
        acl::Acl, collection::Collection, id::Id, property::Property, state::StateChange,
        type_state::DataType, value::Value,
    },
};
use store::{query::Filter, write::BatchBuilder};
use trc::AddContext;

impl<T: SessionStream> Session<T> {
    pub async fn handle_create(&mut self, requests: Vec<Request<Command>>) -> trc::Result<()> {
        let data = self.state.session_data();
        let version = self.version;

        spawn_op!(data, {
            for request in requests {
                match request.parse_create(version) {
                    Ok(argument) => match data.create_folder(argument).await {
                        Ok(response) => {
                            data.write_bytes(response.into_bytes()).await?;
                        }
                        Err(error) => {
                            data.write_error(error).await?;
                        }
                    },
                    Err(err) => data.write_error(err).await?,
                }
            }

            Ok(())
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn create_folder(&self, arguments: Arguments) -> trc::Result<StatusResponse> {
        // Refresh mailboxes
        self.synchronize_mailboxes(false)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Validate mailbox name
        let mut params = self
            .validate_mailbox_create(&arguments.mailbox_name, arguments.mailbox_role)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;
        debug_assert!(!params.path.is_empty());

        // Build batch
        let mut changes = self
            .jmap
            .begin_changes(params.account_id)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        let mut parent_id = params.parent_mailbox_id.map(|id| id + 1).unwrap_or(0);
        let mut create_ids = Vec::with_capacity(params.path.len());
        for (pos, &path_item) in params.path.iter().enumerate() {
            let mut mailbox = Object::with_capacity(4)
                .with_property(Property::Name, path_item)
                .with_property(Property::ParentId, Value::Id(Id::from(parent_id)))
                .with_property(
                    Property::Cid,
                    Value::UnsignedInt(rand::random::<u32>() as u64),
                );
            if pos == params.path.len() - 1 {
                if let Some(mailbox_role) = arguments.mailbox_role {
                    mailbox.set(Property::Role, mailbox_role);
                }
            }
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(params.account_id)
                .with_collection(Collection::Mailbox)
                .create_document()
                .custom(ObjectIndexBuilder::new(SCHEMA).with_changes(mailbox));
            let mailbox_id = self
                .jmap
                .write_batch_expect_id(batch)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;
            changes.log_insert(Collection::Mailbox, mailbox_id);
            parent_id = mailbox_id + 1;
            create_ids.push(mailbox_id);
        }

        // Write changes
        let change_id = changes.change_id;
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(params.account_id)
            .with_collection(Collection::Mailbox)
            .custom(changes);
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

        // Add created mailboxes to session
        std::mem::drop(
            self.add_created_mailboxes(&mut params, change_id, create_ids)
                .imap_ctx(&arguments.tag, trc::location!())?,
        );

        // Build response
        Ok(StatusResponse::ok("Mailbox created.")
            .with_code(ResponseCode::MailboxId {
                mailbox_id: Id::from_parts(params.account_id, parent_id - 1).to_string(),
            })
            .with_tag(arguments.tag))
    }

    pub fn add_created_mailboxes(
        &self,
        params: &mut CreateParams<'_>,
        new_state: u64,
        mailbox_ids: Vec<u32>,
    ) -> trc::Result<parking_lot::MutexGuard<'_, Vec<Account>>> {
        // Lock mailboxes
        let mut mailboxes = self.mailboxes.lock();
        let account = if let Some(account) = mailboxes
            .iter_mut()
            .find(|account| account.account_id == params.account_id)
        {
            account
        } else {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details("Account no longer available.")
                .caused_by(trc::location!()));
        };

        // Update state
        account.state_mailbox = new_state.into();

        // Add mailboxes
        let mut mailbox_name = if let Some(parent_mailbox_name) = params.parent_mailbox_name.take()
        {
            if let Some(parent_mailbox) = account
                .mailbox_state
                .get_mut(params.parent_mailbox_id.as_ref().unwrap())
            {
                parent_mailbox.has_children = true;
            }
            parent_mailbox_name
        } else if let Some(account_prefix) = account.prefix.as_ref() {
            account_prefix.to_string()
        } else {
            "".to_string()
        };

        for (pos, (mailbox_id, path_item)) in
            mailbox_ids.into_iter().zip(params.path.iter()).enumerate()
        {
            mailbox_name = if !mailbox_name.is_empty() {
                format!("{}/{}", mailbox_name, path_item)
            } else {
                path_item.to_string()
            };

            let effective_id = self
                .jmap
                .core
                .jmap
                .default_folders
                .iter()
                .find(|f| f.aliases.iter().any(|a| a == &mailbox_name))
                .and_then(|f| account.mailbox_names.get(&f.name))
                .copied()
                .unwrap_or(mailbox_id);

            account
                .mailbox_names
                .insert(mailbox_name.clone(), effective_id);

            account.mailbox_state.insert(
                mailbox_id,
                Mailbox {
                    has_children: pos < params.path.len() - 1 || params.is_rename,
                    is_subscribed: false,
                    total_messages: 0.into(),
                    total_unseen: 0.into(),
                    total_deleted: 0.into(),
                    uid_validity: None,
                    uid_next: None,
                    size: 0.into(),
                    special_use: if pos == params.path.len() - 1 {
                        params.special_use
                    } else {
                        None
                    },
                },
            );
        }

        Ok(mailboxes)
    }

    pub async fn validate_mailbox_create<'x>(
        &self,
        mailbox_name: &'x str,
        mailbox_role: Option<&'x str>,
    ) -> trc::Result<CreateParams<'x>> {
        // Remove leading and trailing separators
        let mut name = mailbox_name.trim();
        if let Some(suffix) = name.strip_prefix('/') {
            name = suffix.trim();
        };
        if let Some(prefix) = name.strip_suffix('/') {
            name = prefix.trim();
        }
        if name.is_empty() {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details(format!("Invalid folder name '{mailbox_name}'.",)));
        }

        // Build path
        let mut path = Vec::new();
        if name.contains('/') {
            // Locate parent mailbox
            for path_item in name.split('/') {
                let path_item = path_item.trim();
                if path_item.is_empty() {
                    return Err(trc::ImapEvent::Error
                        .into_err()
                        .details("Invalid empty path item."));
                } else if path_item.len() > self.jmap.core.jmap.mailbox_name_max_len {
                    return Err(trc::ImapEvent::Error
                        .into_err()
                        .details("Mailbox name is too long."));
                }
                path.push(path_item);
            }

            if path.len() > self.jmap.core.jmap.mailbox_max_depth {
                return Err(trc::ImapEvent::Error
                    .into_err()
                    .details("Mailbox path is too deep."));
            }
        } else {
            path.push(name);
        }

        // Validate special folders
        let full_path = path.join("/");
        let mut parent_mailbox_id = None;
        let mut parent_mailbox_name = None;
        let (account_id, path) = {
            let mailboxes = self.mailboxes.lock();
            let first_path_item = path.first().unwrap();
            let account = if first_path_item == &self.jmap.core.jmap.shared_folder {
                // Shared Folders/<username>/<folder>
                if path.len() < 3 {
                    return Err(trc::ImapEvent::Error
                        .into_err()
                        .details("Mailboxes under root shared folders are not allowed.")
                        .code(ResponseCode::Cannot));
                }
                let prefix = Some(format!("{}/{}", first_path_item, path[1]));

                // Locate account
                if let Some(account) = mailboxes
                    .iter()
                    .skip(1)
                    .find(|account| account.prefix == prefix)
                {
                    account
                } else {
                    #[allow(clippy::unnecessary_literal_unwrap)]
                    return Err(trc::ImapEvent::Error.into_err().details(format!(
                        "Shared account '{}' not found.",
                        prefix.unwrap_or_default()
                    )));
                }
            } else if let Some(account) = mailboxes.first() {
                account
            } else {
                return Err(trc::ImapEvent::Error
                    .into_err()
                    .details("Internal server error.")
                    .caused_by(trc::location!())
                    .code(ResponseCode::ContactAdmin));
            };

            // Locate parent mailbox
            if account.mailbox_names.contains_key(&full_path) {
                return Err(trc::ImapEvent::Error
                    .into_err()
                    .details(format!("Mailbox '{}' already exists.", full_path)));
            }

            (
                account.account_id,
                if path.len() > 1 {
                    let mut create_path = Vec::with_capacity(path.len());
                    while !path.is_empty() {
                        let mailbox_name = path.join("/");
                        if let Some(&mailbox_id) = account.mailbox_names.get(&mailbox_name) {
                            parent_mailbox_id = mailbox_id.into();
                            parent_mailbox_name = mailbox_name.into();
                            break;
                        } else {
                            create_path.push(path.pop().unwrap());
                        }
                    }
                    create_path.reverse();
                    create_path
                } else {
                    path
                },
            )
        };

        // Validate ACLs
        if let Some(parent_mailbox_id) = parent_mailbox_id {
            if !self
                .check_mailbox_acl(account_id, parent_mailbox_id, Acl::CreateChild)
                .await?
            {
                return Err(trc::ImapEvent::Error
                    .into_err()
                    .details("You are not allowed to create sub mailboxes under this mailbox.")
                    .code(ResponseCode::NoPerm));
            }
        } else if self.account_id != account_id
            && !self
                .get_access_token()
                .await
                .caused_by(trc::location!())?
                .is_member(account_id)
        {
            return Err(trc::ImapEvent::Error
                .into_err()
                .details("You are not allowed to create root folders under shared folders.")
                .code(ResponseCode::Cannot));
        }

        Ok(CreateParams {
            account_id,
            path,
            full_path,
            parent_mailbox_id,
            parent_mailbox_name,
            special_use: if let Some(mailbox_role) = mailbox_role {
                // Make sure role is unique
                if !self
                    .jmap
                    .filter(
                        account_id,
                        Collection::Mailbox,
                        vec![Filter::eq(Property::Role, mailbox_role)],
                    )
                    .await
                    .caused_by(trc::location!())?
                    .results
                    .is_empty()
                {
                    return Err(trc::ImapEvent::Error
                        .into_err()
                        .details(format!(
                            "A mailbox with role '{mailbox_role}' already exists.",
                        ))
                        .code(ResponseCode::UseAttr));
                }
                Attribute::try_from(mailbox_role).ok()
            } else {
                None
            },
            is_rename: false,
        })
    }
}

#[derive(Debug)]
pub struct CreateParams<'x> {
    pub account_id: u32,
    pub path: Vec<&'x str>,
    pub full_path: String,
    pub parent_mailbox_id: Option<u32>,
    pub parent_mailbox_name: Option<String>,
    pub special_use: Option<Attribute>,
    pub is_rename: bool,
}
