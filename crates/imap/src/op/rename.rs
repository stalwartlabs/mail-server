/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use crate::{
    core::{Session, SessionData},
    spawn_op,
};
use common::{listener::SessionStream, sharing::EffectiveAcl, storage::index::ObjectIndexBuilder};
use directory::Permission;
use imap_proto::{
    Command, ResponseCode, StatusResponse, protocol::rename::Arguments, receiver::Request,
};
use jmap_proto::types::{acl::Acl, collection::Collection};
use store::write::BatchBuilder;
use trc::AddContext;

use super::ImapContext;

impl<T: SessionStream> Session<T> {
    pub async fn handle_rename(&mut self, request: Request<Command>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapRename)?;

        let op_start = Instant::now();
        let arguments = request.parse_rename(self.version)?;
        let data = self.state.session_data();

        spawn_op!(data, {
            let response = data.rename_folder(arguments, op_start).await?;
            data.write_bytes(response.into_bytes()).await
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn rename_folder(
        &self,
        arguments: Arguments,
        op_start: Instant,
    ) -> trc::Result<StatusResponse> {
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
        let mailbox_ = self
            .server
            .get_archive(params.account_id, Collection::Mailbox, mailbox_id)
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
        let mailbox = mailbox_
            .to_unarchived::<email::mailbox::Mailbox>()
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Validate ACL
        let access_token = self
            .get_access_token()
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;
        if access_token.is_shared(params.account_id)
            && !mailbox
                .inner
                .acls
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
        let mut parent_id = params.parent_mailbox_id.map(|id| id + 1).unwrap_or(0);
        let mut create_ids = Vec::with_capacity(params.path.len());
        let mut next_document_id = self
            .server
            .store()
            .assign_document_ids(
                params.account_id,
                Collection::Mailbox,
                params.path.len() as u64,
            )
            .await
            .caused_by(trc::location!())?;
        let mut batch = BatchBuilder::new();

        for &path_item in params.path.iter() {
            let mailbox_id = next_document_id;
            next_document_id -= 1;

            batch
                .with_account_id(params.account_id)
                .with_collection(Collection::Mailbox)
                .create_document(mailbox_id)
                .custom(ObjectIndexBuilder::<(), _>::new().with_changes(
                    email::mailbox::Mailbox::new(path_item).with_parent_id(parent_id),
                ))
                .imap_ctx(&arguments.tag, trc::location!())?
                .commit_point();

            parent_id = mailbox_id + 1;
            create_ids.push(mailbox_id);
        }

        let mut new_mailbox = mailbox
            .deserialize::<email::mailbox::Mailbox>()
            .caused_by(trc::location!())?;
        new_mailbox.name = new_mailbox_name.into();
        new_mailbox.parent_id = parent_id;
        new_mailbox.uid_validity = rand::random::<u32>();
        batch
            .with_account_id(params.account_id)
            .with_collection(Collection::Mailbox)
            .update_document(mailbox_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(mailbox)
                    .with_changes(new_mailbox),
            )
            .imap_ctx(&arguments.tag, trc::location!())?;
        self.server
            .commit_batch(batch)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        trc::event!(
            Imap(trc::ImapEvent::RenameMailbox),
            SpanId = self.session_id,
            AccountId = params.account_id,
            MailboxName = arguments.new_mailbox_name,
            MailboxId = mailbox_id,
            Elapsed = op_start.elapsed()
        );

        Ok(StatusResponse::completed(Command::Rename).with_tag(arguments.tag))
    }
}
