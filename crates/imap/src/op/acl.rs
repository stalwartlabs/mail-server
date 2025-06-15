/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::Instant};

use common::{
    auth::AccessToken, listener::SessionStream, sharing::EffectiveAcl,
    storage::index::ObjectIndexBuilder,
};

use compact_str::ToCompactString;
use directory::{
    Permission, QueryBy, Type,
    backend::internal::{
        PrincipalField,
        manage::{ChangedPrincipals, ManageDirectory},
    },
};
use imap_proto::{
    Command, ResponseCode, StatusResponse,
    protocol::acl::{
        Arguments, GetAclResponse, ListRightsResponse, ModRightsOp, MyRightsResponse, Rights,
    },
    receiver::Request,
};

use jmap_proto::types::{acl::Acl, collection::Collection, value::AclGrant};
use store::write::{AlignedBytes, Archive, BatchBuilder};
use trc::AddContext;
use utils::map::bitmap::Bitmap;

use crate::{
    core::{MailboxId, Session, SessionData, State},
    op::ImapContext,
    spawn_op,
};

impl<T: SessionStream> Session<T> {
    pub async fn handle_get_acl(&mut self, request: Request<Command>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapAuthenticate)?;

        let op_start = Instant::now();
        let arguments = request.parse_acl(self.version)?;
        let is_rev2 = self.version.is_rev2();
        let data = self.state.session_data();

        spawn_op!(data, {
            let (mailbox_id, mailbox_, _) = data
                .get_acl_mailbox(&arguments, true)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;
            let mut permissions = Vec::new();
            let mailbox = mailbox_
                .to_unarchived::<email::mailbox::Mailbox>()
                .imap_ctx(&arguments.tag, trc::location!())?;

            for item in mailbox.inner.acls.iter() {
                if let Some(account_name) = data
                    .server
                    .store()
                    .get_principal_name(item.account_id.into())
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?
                {
                    let mut rights = Vec::new();

                    for acl in Bitmap::from(&item.grants) {
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
                            _ => (),
                        }
                    }

                    permissions.push((account_name, rights));
                }
            }

            trc::event!(
                Imap(trc::ImapEvent::GetAcl),
                SpanId = data.session_id,
                MailboxName = arguments.mailbox_name.clone(),
                AccountId = mailbox_id.account_id,
                MailboxId = mailbox_id.mailbox_id,
                Total = permissions.len(),
                Elapsed = op_start.elapsed()
            );

            data.write_bytes(
                StatusResponse::completed(Command::GetAcl)
                    .with_tag(arguments.tag)
                    .serialize(
                        GetAclResponse {
                            mailbox_name: arguments.mailbox_name.to_string(),
                            permissions,
                        }
                        .into_bytes(is_rev2),
                    ),
            )
            .await
        })
    }

    pub async fn handle_my_rights(&mut self, request: Request<Command>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapMyRights)?;

        let op_start = Instant::now();
        let arguments = request.parse_acl(self.version)?;
        let data = self.state.session_data();
        let is_rev2 = self.version.is_rev2();

        spawn_op!(data, {
            let (mailbox_id, mailbox_, access_token) = data
                .get_acl_mailbox(&arguments, false)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;
            let mailbox = mailbox_
                .to_unarchived::<email::mailbox::Mailbox>()
                .imap_ctx(&arguments.tag, trc::location!())?;
            let rights = if access_token.is_shared(mailbox_id.account_id) {
                let acl = mailbox.inner.acls.effective_acl(&access_token);
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
            };

            trc::event!(
                Imap(trc::ImapEvent::MyRights),
                SpanId = data.session_id,
                MailboxName = arguments.mailbox_name.clone(),
                AccountId = mailbox_id.account_id,
                MailboxId = mailbox_id.mailbox_id,
                Details = rights
                    .iter()
                    .map(|r| trc::Value::String(r.to_compact_string()))
                    .collect::<Vec<_>>(),
                Elapsed = op_start.elapsed()
            );

            data.write_bytes(
                StatusResponse::completed(Command::MyRights)
                    .with_tag(arguments.tag)
                    .serialize(
                        MyRightsResponse {
                            mailbox_name: arguments.mailbox_name.to_string(),
                            rights,
                        }
                        .into_bytes(is_rev2),
                    ),
            )
            .await
        })
    }

    pub async fn handle_set_acl(&mut self, request: Request<Command>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapAclSet)?;

        let op_start = Instant::now();
        let command = request.command;
        let arguments = request.parse_acl(self.version)?;
        let data = self.state.session_data();

        spawn_op!(data, {
            // Validate mailbox
            let (mailbox_id, current_mailbox, _) = data
                .get_acl_mailbox(&arguments, false)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;
            let current_mailbox = current_mailbox
                .into_deserialized::<email::mailbox::Mailbox>()
                .imap_ctx(&arguments.tag, trc::location!())?;

            // Obtain principal id
            let acl_account_id = data
                .server
                .core
                .storage
                .directory
                .query(QueryBy::Name(arguments.identifier.as_ref().unwrap()), false)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?
                .ok_or_else(|| {
                    trc::ImapEvent::Error
                        .into_err()
                        .details("Account does not exist")
                        .id(arguments.tag.to_string())
                        .caused_by(trc::location!())
                })?
                .id();

            // Prepare changes
            let mut mailbox = current_mailbox.inner.clone();
            let (op, rights) = arguments
                .mod_rights
                .map(|mr| {
                    (
                        mr.op,
                        Bitmap::from_iter(mr.rights.into_iter().map(Acl::from)),
                    )
                })
                .unwrap_or_else(|| (ModRightsOp::Replace, Bitmap::new()));

            if let Some(item) = mailbox
                .acls
                .iter_mut()
                .find(|item| item.account_id == acl_account_id)
            {
                match op {
                    ModRightsOp::Replace => {
                        if !rights.is_empty() {
                            item.grants = rights;
                        } else {
                            mailbox
                                .acls
                                .retain(|item| item.account_id != acl_account_id);
                        }
                    }
                    ModRightsOp::Add => {
                        item.grants.union(&rights);
                    }
                    ModRightsOp::Remove => {
                        for right in rights {
                            item.grants.remove(right);
                        }
                        if item.grants.is_empty() {
                            mailbox
                                .acls
                                .retain(|item| item.account_id != acl_account_id);
                        }
                    }
                }
            } else if !rights.is_empty() {
                match op {
                    ModRightsOp::Add | ModRightsOp::Replace => {
                        mailbox.acls.push(AclGrant {
                            account_id: acl_account_id,
                            grants: rights,
                        });
                    }
                    ModRightsOp::Remove => (),
                }
            }

            let grants = mailbox
                .acls
                .iter()
                .map(|r| trc::Value::from(r.account_id))
                .collect::<Vec<_>>();

            // Write changes
            let mut batch = BatchBuilder::new();
            batch
                .with_account_id(mailbox_id.account_id)
                .with_collection(Collection::Mailbox)
                .update_document(mailbox_id.mailbox_id)
                .custom(
                    ObjectIndexBuilder::new()
                        .with_changes(mailbox)
                        .with_current(current_mailbox),
                )
                .imap_ctx(&arguments.tag, trc::location!())?;

            if !batch.is_empty() {
                data.server
                    .commit_batch(batch)
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?;
            }

            // Invalidate ACLs
            data.server
                .increment_token_revision(ChangedPrincipals::from_change(
                    acl_account_id,
                    Type::Individual,
                    PrincipalField::EnabledPermissions,
                ))
                .await;

            trc::event!(
                Imap(trc::ImapEvent::SetAcl),
                SpanId = data.session_id,
                MailboxName = arguments.mailbox_name.clone(),
                AccountId = mailbox_id.account_id,
                MailboxId = mailbox_id.mailbox_id,
                Details = grants,
                Elapsed = op_start.elapsed()
            );

            data.write_bytes(
                StatusResponse::completed(command)
                    .with_tag(arguments.tag)
                    .into_bytes(),
            )
            .await
        })
    }

    pub async fn handle_list_rights(&mut self, request: Request<Command>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapListRights)?;

        let op_start = Instant::now();
        let arguments = request.parse_acl(self.version)?;

        trc::event!(
            Imap(trc::ImapEvent::ListRights),
            SpanId = self.session_id,
            MailboxName = arguments.mailbox_name.clone(),
            Elapsed = op_start.elapsed()
        );

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

    pub fn assert_has_permission(&self, permission: Permission) -> trc::Result<bool> {
        match &self.state {
            State::Authenticated { data } | State::Selected { data, .. } => {
                data.access_token.assert_has_permission(permission)
            }
            State::NotAuthenticated { .. } => Ok(false),
        }
    }
}

impl<T: SessionStream> SessionData<T> {
    async fn get_acl_mailbox(
        &self,
        arguments: &Arguments,
        validate: bool,
    ) -> trc::Result<(MailboxId, Archive<AlignedBytes>, Arc<AccessToken>)> {
        if let Some(mailbox) = self.get_mailbox_by_name(&arguments.mailbox_name) {
            if let Some(values) = self
                .server
                .get_archive(mailbox.account_id, Collection::Mailbox, mailbox.mailbox_id)
                .await
                .caused_by(trc::location!())?
            {
                let access_token = self.get_access_token().await.caused_by(trc::location!())?;
                if !validate
                    || access_token.is_member(mailbox.account_id)
                    || values
                        .unarchive::<email::mailbox::Mailbox>()
                        .caused_by(trc::location!())?
                        .acls
                        .effective_acl(&access_token)
                        .contains(Acl::Administer)
                {
                    Ok((mailbox, values, access_token))
                } else {
                    Err(trc::ImapEvent::Error
                        .into_err()
                        .details("You do not have enough permissions to perform this operation.")
                        .code(ResponseCode::NoPerm))
                }
            } else {
                Err(trc::ImapEvent::Error
                    .caused_by(trc::location!())
                    .details("Mailbox does not exist."))
            }
        } else {
            Err(trc::ImapEvent::Error
                .into_err()
                .details("Mailbox does not exist."))
        }
    }
}
