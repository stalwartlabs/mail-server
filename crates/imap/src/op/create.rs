/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    core::{Session, SessionData},
    op::ImapContext,
    spawn_op,
};
use common::{
    config::jmap::settings::SpecialUse, listener::SessionStream, storage::index::ObjectIndexBuilder,
};
use directory::Permission;
use email::cache::{MessageCacheFetch, mailbox::MailboxCacheAccess};
use imap_proto::{
    Command, ResponseCode, StatusResponse,
    protocol::{create::Arguments, list::Attribute},
    receiver::Request,
};
use jmap_proto::types::{acl::Acl, collection::Collection, id::Id};
use std::time::Instant;
use store::write::BatchBuilder;
use trc::AddContext;

impl<T: SessionStream> Session<T> {
    pub async fn handle_create(&mut self, requests: Vec<Request<Command>>) -> trc::Result<()> {
        // Validate access
        self.assert_has_permission(Permission::ImapCreate)?;

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
        let op_start = Instant::now();

        // Refresh mailboxes
        self.synchronize_mailboxes(false)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Validate mailbox name
        let params = self
            .validate_mailbox_create(&arguments.mailbox_name, arguments.mailbox_role)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;
        debug_assert!(!params.path.is_empty());

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
        for (pos, &path_item) in params.path.iter().enumerate() {
            let mut mailbox = email::mailbox::Mailbox::new(path_item).with_parent_id(parent_id);

            if pos == params.path.len() - 1 {
                if let Some(mailbox_role) = arguments.mailbox_role.map(attr_to_role) {
                    mailbox.role = mailbox_role;
                }
            }
            let mailbox_id = next_document_id;
            next_document_id -= 1;
            batch
                .with_account_id(params.account_id)
                .with_collection(Collection::Mailbox)
                .create_document(mailbox_id)
                .custom(ObjectIndexBuilder::<(), _>::new().with_changes(mailbox))
                .imap_ctx(&arguments.tag, trc::location!())?
                .commit_point();
            parent_id = mailbox_id + 1;
            create_ids.push(mailbox_id);
        }

        self.server
            .commit_batch(batch)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        trc::event!(
            Imap(trc::ImapEvent::CreateMailbox),
            SpanId = self.session_id,
            MailboxName = arguments.mailbox_name.clone(),
            AccountId = params.account_id,
            MailboxId = create_ids
                .iter()
                .map(|&id| trc::Value::from(id))
                .collect::<Vec<_>>(),
            Elapsed = op_start.elapsed()
        );

        // Build response
        Ok(StatusResponse::ok("Mailbox created.")
            .with_code(ResponseCode::MailboxId {
                mailbox_id: Id::from_parts(params.account_id, parent_id - 1).to_string(),
            })
            .with_tag(arguments.tag))
    }

    pub async fn validate_mailbox_create<'x>(
        &self,
        mailbox_name: &'x str,
        mailbox_role: Option<Attribute>,
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
                } else if path_item.len() > self.server.core.jmap.mailbox_name_max_len {
                    return Err(trc::ImapEvent::Error
                        .into_err()
                        .details("Mailbox name is too long."));
                }
                path.push(path_item);
            }

            if path.len() > self.server.core.jmap.mailbox_max_depth {
                return Err(trc::ImapEvent::Error
                    .into_err()
                    .details("Mailbox path is too deep."));
            }
        } else {
            path.push(name);
        }

        // Validate special folders
        let mut parent_mailbox_id = None;
        let mut parent_mailbox_name = None;
        let (account_id, path) = {
            let mailboxes = self.mailboxes.lock();
            let (account, full_path) =
                if path.first() == Some(&self.server.core.jmap.shared_folder.as_str()) {
                    // Shared Folders/<username>/<folder>
                    if path.len() < 3 {
                        return Err(trc::ImapEvent::Error
                            .into_err()
                            .details("Mailboxes under root shared folders are not allowed.")
                            .code(ResponseCode::Cannot));
                    }
                    // Build path
                    let root = &mut path[2];
                    if root.eq_ignore_ascii_case("INBOX") {
                        *root = "INBOX";
                    }
                    let full_path = path.join("/");
                    let prefix = Some(format!("{}/{}", path.remove(0), path.remove(0)));

                    // Locate account
                    if let Some(account) = mailboxes
                        .iter()
                        .skip(1)
                        .find(|account| account.prefix == prefix)
                    {
                        (account, full_path)
                    } else {
                        #[allow(clippy::unnecessary_literal_unwrap)]
                        return Err(trc::ImapEvent::Error.into_err().details(format!(
                            "Shared account '{}' not found.",
                            prefix.unwrap_or_default()
                        )));
                    }
                } else if let Some(account) = mailboxes.first() {
                    let root = &mut path[0];
                    if root.eq_ignore_ascii_case("INBOX") {
                        *root = "INBOX";
                    }

                    (account, path.join("/"))
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
                        let mailbox_name: String = path.join("/");
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
            parent_mailbox_id,
            parent_mailbox_name,
            special_use: if let Some(mailbox_role) = mailbox_role {
                // Make sure role is unique
                let special_use = attr_to_role(mailbox_role);
                if self
                    .server
                    .get_cached_messages(account_id)
                    .await
                    .caused_by(trc::location!())?
                    .mailbox_by_role(&special_use)
                    .is_some()
                {
                    return Err(trc::ImapEvent::Error
                        .into_err()
                        .details(format!(
                            "A mailbox with role '{}' already exists.",
                            special_use.as_str().unwrap_or_default()
                        ))
                        .code(ResponseCode::UseAttr));
                }
                Some(mailbox_role)
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
    pub parent_mailbox_id: Option<u32>,
    pub parent_mailbox_name: Option<String>,
    pub special_use: Option<Attribute>,
    pub is_rename: bool,
}

#[inline]
fn attr_to_role(attr: Attribute) -> SpecialUse {
    match attr {
        Attribute::Archive => SpecialUse::Archive,
        Attribute::Drafts => SpecialUse::Drafts,
        Attribute::Junk => SpecialUse::Junk,
        Attribute::Sent => SpecialUse::Sent,
        Attribute::Trash => SpecialUse::Trash,
        Attribute::Important => SpecialUse::Important,
        _ => SpecialUse::None,
    }
}
