/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart IMAP Server.
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

use imap_proto::{
    protocol::acl::{
        Arguments, GetAclResponse, ListRightsResponse, ModRightsOp, MyRightsResponse, Rights,
    },
    receiver::Request,
    Command, ResponseCode, StatusResponse,
};

use jmap::{
    auth::{acl::EffectiveAcl, AccessToken},
    mailbox::set::SCHEMA,
};
use jmap_proto::{
    error::method::MethodError,
    object::{index::ObjectIndexBuilder, Object},
    types::{
        acl::Acl, collection::Collection, id::Id, property::Property, state::StateChange,
        type_state::TypeState, value::Value,
    },
};
use store::write::{assert::HashedValue, log::ChangeLogBuilder, BatchBuilder};
use tokio::io::AsyncRead;
use utils::map::bitmap::Bitmap;

use crate::core::{MailboxId, Session, SessionData};

impl<T: AsyncRead> Session<T> {
    pub async fn handle_get_acl(&mut self, request: Request<Command>) -> crate::OpResult {
        match request.parse_acl() {
            Ok(arguments) => {
                let data = self.state.session_data();
                let is_rev2 = self.version.is_rev2();

                tokio::spawn(async move {
                    match data.get_acl_mailbox(&arguments, true).await {
                        Ok((_, values, _)) => {
                            let mut permissions = Vec::new();
                            if let Some(acls) = values
                                .inner
                                .properties
                                .get(&Property::Acl)
                                .and_then(|v| v.as_list())
                            {
                                for item in acls.chunks_exact(2) {
                                    if let (
                                        Some(Value::Id(id)),
                                        Some(Value::UnsignedInt(acl_bits)),
                                    ) = (item.first(), item.last())
                                    {
                                        if let Some(account_name) = data
                                            .jmap
                                            .get_account_name(id.document_id())
                                            .await
                                            .unwrap_or_default()
                                        {
                                            let mut rights = Vec::new();

                                            for acl in Bitmap::<Acl>::from(*acl_bits) {
                                                match acl {
                                                    Acl::Read => {
                                                        rights.push(Rights::Lookup);
                                                    }
                                                    Acl::Modify => {
                                                        rights.push(Rights::CreateMailbox);
                                                    }
                                                    Acl::Delete => {
                                                        rights.push(Rights::DeleteMailbox);
                                                    }
                                                    Acl::ReadItems => {
                                                        rights.push(Rights::Read);
                                                    }
                                                    Acl::AddItems => {
                                                        rights.push(Rights::Insert);
                                                    }
                                                    Acl::ModifyItems => {
                                                        rights.push(Rights::Write);
                                                        rights.push(Rights::Seen);
                                                    }
                                                    Acl::RemoveItems => {
                                                        rights.push(Rights::DeleteMessages);
                                                        rights.push(Rights::Expunge);
                                                    }
                                                    Acl::CreateChild => {
                                                        rights.push(Rights::CreateMailbox);
                                                    }
                                                    Acl::Administer => {
                                                        rights.push(Rights::Administer);
                                                    }
                                                    Acl::Submit => {
                                                        rights.push(Rights::Post);
                                                    }
                                                    Acl::None => (),
                                                }
                                            }

                                            permissions.push((account_name, rights));
                                        }
                                    }
                                }
                            }

                            data.write_bytes(
                                StatusResponse::completed(Command::GetAcl)
                                    .with_tag(arguments.tag)
                                    .serialize(
                                        GetAclResponse {
                                            mailbox_name: arguments.mailbox_name,
                                            permissions,
                                        }
                                        .into_bytes(is_rev2),
                                    ),
                            )
                            .await;
                        }
                        Err(response) => {
                            data.write_bytes(response.with_tag(arguments.tag).into_bytes())
                                .await;
                            return;
                        }
                    }
                });
                Ok(())
            }
            Err(response) => self.write_bytes(response.into_bytes()).await,
        }
    }

    pub async fn handle_my_rights(&mut self, request: Request<Command>) -> crate::OpResult {
        match request.parse_acl() {
            Ok(arguments) => {
                let data = self.state.session_data();
                let is_rev2 = self.version.is_rev2();

                tokio::spawn(async move {
                    match data.get_acl_mailbox(&arguments, false).await {
                        Ok((mailbox, values, access_token)) => {
                            data.write_bytes(
                                StatusResponse::completed(Command::MyRights)
                                    .with_tag(arguments.tag)
                                    .serialize(
                                        MyRightsResponse {
                                            mailbox_name: arguments.mailbox_name,
                                            rights: if access_token.is_shared(mailbox.account_id) {
                                                let acl = values.inner.effective_acl(&access_token);
                                                let mut rights = Vec::with_capacity(5);
                                                if acl.contains(Acl::ReadItems) {
                                                    rights.push(Rights::Read);
                                                    rights.push(Rights::Lookup);
                                                }
                                                if acl.contains(Acl::AddItems) {
                                                    rights.push(Rights::Insert);
                                                }
                                                if acl.contains(Acl::RemoveItems) {
                                                    rights.push(Rights::DeleteMessages);
                                                    rights.push(Rights::Expunge);
                                                }
                                                if acl.contains(Acl::ModifyItems) {
                                                    rights.push(Rights::Seen);
                                                    rights.push(Rights::Write);
                                                }
                                                if acl.contains(Acl::CreateChild) {
                                                    rights.push(Rights::CreateMailbox);
                                                }
                                                if acl.contains(Acl::Delete) {
                                                    rights.push(Rights::DeleteMailbox);
                                                }
                                                if acl.contains(Acl::Submit) {
                                                    rights.push(Rights::Post);
                                                }
                                                rights
                                            } else {
                                                vec![
                                                    Rights::Read,
                                                    Rights::Lookup,
                                                    Rights::Insert,
                                                    Rights::DeleteMessages,
                                                    Rights::Expunge,
                                                    Rights::Seen,
                                                    Rights::Write,
                                                    Rights::CreateMailbox,
                                                    Rights::DeleteMailbox,
                                                    Rights::Post,
                                                ]
                                            },
                                        }
                                        .into_bytes(is_rev2),
                                    ),
                            )
                            .await;
                        }
                        Err(response) => {
                            data.write_bytes(response.with_tag(arguments.tag).into_bytes())
                                .await;
                        }
                    }
                });
                Ok(())
            }
            Err(response) => self.write_bytes(response.into_bytes()).await,
        }
    }

    pub async fn handle_set_acl(&mut self, request: Request<Command>) -> crate::OpResult {
        let command = request.command;
        match request.parse_acl() {
            Ok(arguments) => {
                let data = self.state.session_data();

                tokio::spawn(async move {
                    // Validate mailbox
                    let (mailbox, values, _) = match data.get_acl_mailbox(&arguments, true).await {
                        Ok(result) => result,
                        Err(response) => {
                            data.write_bytes(response.with_tag(arguments.tag).into_bytes())
                                .await;
                            return;
                        }
                    };

                    // Obtain principal id
                    let (acl_account_id, id) = match data
                        .jmap
                        .directory
                        .principal(arguments.identifier.as_ref().unwrap())
                        .await
                    {
                        Ok(Some(principal)) => {
                            match data.jmap.get_account_id(&principal.name()).await {
                                Ok(account_id) => (account_id, Value::Id(Id::from(account_id))),
                                Err(_) => {
                                    data.write_bytes(
                                        StatusResponse::database_failure()
                                            .with_tag(arguments.tag)
                                            .into_bytes(),
                                    )
                                    .await;
                                    return;
                                }
                            }
                        }
                        Ok(None) => {
                            data.write_bytes(
                                StatusResponse::no("Account does not exist")
                                    .with_tag(arguments.tag)
                                    .into_bytes(),
                            )
                            .await;
                            return;
                        }
                        _ => {
                            data.write_bytes(
                                StatusResponse::database_failure()
                                    .with_tag(arguments.tag)
                                    .into_bytes(),
                            )
                            .await;
                            return;
                        }
                    };

                    // Prepare changes
                    let mut changes = Object::with_capacity(1);
                    let (op, rights) = arguments
                        .mod_rights
                        .map(|mr| {
                            (
                                mr.op,
                                Bitmap::from_iter(mr.rights.into_iter().map(Acl::from)),
                            )
                        })
                        .unwrap_or_else(|| (ModRightsOp::Replace, Bitmap::new()));
                    let acl = if let Value::List(acl) =
                        changes
                            .properties
                            .get_mut_or_insert_with(Property::Acl, || {
                                values
                                    .inner
                                    .properties
                                    .get(&Property::Acl)
                                    .cloned()
                                    .unwrap_or_else(|| Value::List(Vec::new()))
                            }) {
                        acl
                    } else {
                        data.write_bytes(
                            StatusResponse::database_failure()
                                .with_tag(arguments.tag)
                                .into_bytes(),
                        )
                        .await;
                        return;
                    };

                    if let Some(idx) = acl.iter().position(|item| item == &id) {
                        match op {
                            ModRightsOp::Replace => {
                                if !rights.is_empty() {
                                    acl[idx + 1] = Value::UnsignedInt(rights.into());
                                } else {
                                    acl.remove(idx);
                                    acl.remove(idx);
                                }
                            }
                            ModRightsOp::Add | ModRightsOp::Remove => {
                                if let Some(Value::UnsignedInt(current)) = acl.get_mut(idx + 1) {
                                    let mut bitmap = Bitmap::from(*current);
                                    if op == ModRightsOp::Add {
                                        bitmap.union(&rights);
                                    } else {
                                        for right in rights {
                                            bitmap.remove(right);
                                        }
                                    }
                                    if !bitmap.is_empty() {
                                        *current = bitmap.into();
                                    } else {
                                        acl.remove(idx);
                                        acl.remove(idx);
                                    }
                                } else {
                                    data.write_bytes(
                                        StatusResponse::database_failure()
                                            .with_tag(arguments.tag)
                                            .into_bytes(),
                                    )
                                    .await;
                                    return;
                                }
                            }
                        }
                    } else if !rights.is_empty() {
                        match op {
                            ModRightsOp::Add | ModRightsOp::Replace => {
                                acl.push(id);
                                acl.push(Value::UnsignedInt(rights.into()));
                            }
                            ModRightsOp::Remove => (),
                        }
                    }

                    // Write changes
                    let mailbox_id = mailbox.mailbox_id.unwrap();
                    let mut batch = BatchBuilder::new();
                    batch
                        .with_account_id(mailbox.account_id)
                        .with_collection(Collection::Mailbox)
                        .update_document(mailbox_id)
                        .custom(
                            ObjectIndexBuilder::new(SCHEMA)
                                .with_changes(changes)
                                .with_current(values),
                        );
                    if !batch.is_empty() {
                        match data.jmap.write_batch(batch).await {
                            Ok(_) => {
                                let mut changes = ChangeLogBuilder::new();
                                changes.log_update(Collection::Mailbox, mailbox_id);
                                match data.jmap.commit_changes(mailbox.account_id, changes).await {
                                    Ok(change_id) => {
                                        data.jmap
                                            .broadcast_state_change(
                                                StateChange::new(mailbox.account_id)
                                                    .with_change(TypeState::Mailbox, change_id),
                                            )
                                            .await;
                                    }
                                    Err(_) => {
                                        data.write_bytes(
                                            StatusResponse::database_failure()
                                                .with_tag(arguments.tag)
                                                .into_bytes(),
                                        )
                                        .await;
                                        return;
                                    }
                                }
                            }
                            Err(MethodError::ServerUnavailable) => {
                                data.write_bytes(
                                    StatusResponse::no(
                                        "Another process is currently updating this mailbox",
                                    )
                                    .with_tag(arguments.tag)
                                    .into_bytes(),
                                )
                                .await;
                                return;
                            }
                            Err(_) => {
                                data.write_bytes(
                                    StatusResponse::database_failure()
                                        .with_tag(arguments.tag)
                                        .into_bytes(),
                                )
                                .await;
                                return;
                            }
                        }
                    }

                    // Invalidate ACLs
                    data.jmap.access_tokens.remove(&acl_account_id);

                    data.write_bytes(
                        StatusResponse::completed(command)
                            .with_tag(arguments.tag)
                            .into_bytes(),
                    )
                    .await;
                });
                Ok(())
            }
            Err(response) => self.write_bytes(response.into_bytes()).await,
        }
    }

    pub async fn handle_list_rights(&mut self, request: Request<Command>) -> crate::OpResult {
        match request.parse_acl() {
            Ok(arguments) => {
                self.write_bytes(
                    StatusResponse::completed(Command::ListRights)
                        .with_tag(arguments.tag)
                        .serialize(
                            ListRightsResponse {
                                mailbox_name: arguments.mailbox_name,
                                identifier: arguments.identifier.unwrap(),
                                permissions: vec![
                                    vec![Rights::Read],
                                    vec![Rights::Lookup],
                                    vec![Rights::Write, Rights::Seen],
                                    vec![Rights::Insert],
                                    vec![Rights::Expunge, Rights::DeleteMessages],
                                    vec![Rights::CreateMailbox],
                                    vec![Rights::DeleteMailbox],
                                    vec![Rights::Post],
                                    vec![Rights::Administer],
                                ],
                            }
                            .into_bytes(self.version.is_rev2()),
                        ),
                )
                .await
            }
            Err(response) => self.write_bytes(response.into_bytes()).await,
        }
    }
}

impl SessionData {
    async fn get_acl_mailbox(
        &self,
        arguments: &Arguments,
        validate: bool,
    ) -> crate::op::Result<(MailboxId, HashedValue<Object<Value>>, Arc<AccessToken>)> {
        if let Some(mailbox) = self.get_mailbox_by_name(&arguments.mailbox_name) {
            if let Some(mailbox_id) = mailbox.mailbox_id {
                match (
                    self.jmap
                        .get_property::<HashedValue<Object<Value>>>(
                            mailbox.account_id,
                            Collection::Mailbox,
                            mailbox_id,
                            Property::Value,
                        )
                        .await,
                    self.get_access_token().await,
                ) {
                    (Ok(Some(values)), Ok(access_token)) => {
                        if !validate
                            || access_token.is_member(mailbox.account_id)
                            || values
                                .inner
                                .effective_acl(&access_token)
                                .contains(Acl::Administer)
                        {
                            Ok((mailbox, values, access_token))
                        } else {
                            Err(StatusResponse::no(
                                "You do not have enough permissions to perform this operation.",
                            )
                            .with_code(ResponseCode::NoPerm))
                        }
                    }
                    (Ok(None), _) => Err(StatusResponse::no("Mailbox no longer exists.")),
                    _ => Err(StatusResponse::database_failure()),
                }
            } else {
                Err(StatusResponse::no(
                    "ACL operations are not permitted on this mailbox.",
                ))
            }
        } else {
            Err(StatusResponse::no("Mailbox does not exist."))
        }
    }
}
