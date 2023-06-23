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
    protocol::create::Arguments, receiver::Request, Command, ResponseCode, StatusResponse,
};
use tokio::io::AsyncRead;

use crate::core::{Session, SessionData};

impl<T: AsyncRead> Session<T> {
    pub async fn handle_create(&mut self, requests: Vec<Request<Command>>) -> Result<(), ()> {
        let mut arguments = Vec::with_capacity(requests.len());

        for request in requests {
            match request.parse_create(self.version) {
                Ok(argument) => {
                    arguments.push(argument);
                }
                Err(response) => self.write_bytes(response.into_bytes()).await?,
            }
        }

        if !arguments.is_empty() {
            let data = self.state.session_data();
            tokio::spawn(async move {
                for argument in arguments {
                    data.write_bytes(data.create_folder(argument).await.into_bytes())
                        .await;
                }
            });
        }
        Ok(())
    }
}

impl SessionData {
    pub async fn create_folder(&self, arguments: Arguments) -> StatusResponse {
        // Refresh mailboxes
        if let Err(err) = self.synchronize_mailboxes(false).await {
            return err.with_tag(arguments.tag);
        }

        // Validate mailbox name
        let mut params = match self.validate_mailbox_create(&arguments.mailbox_name) {
            Ok(response) => response,
            Err(message) => {
                return StatusResponse::no(message).with_tag(arguments.tag);
            }
        };
        debug_assert!(!params.path.is_empty());

        // Build request
        let mut request = self.client.build();
        let mut create_ids: Vec<String> = Vec::with_capacity(params.path.len());
        let set_request = request.set_mailbox().account_id(&params.account_id);
        for (pos, path_item) in params.path.iter().enumerate() {
            let create_item = set_request.create().name(*path_item);
            if let Some(create_id) = create_ids.last() {
                create_item.parent_id_ref(create_id);
            } else {
                create_item.parent_id(params.parent_mailbox_id.as_ref());
            }
            if arguments.mailbox_role != Role::None && pos == params.path.len() - 1 {
                create_item.role(arguments.mailbox_role);
            }
            create_ids.push(create_item.create_id().unwrap());
        }

        match request.send_set_mailbox().await {
            Ok(mut response) => {
                match self.add_created_mailboxes(&mut params, create_ids, &mut response) {
                    Ok((_, mailbox_id)) => StatusResponse::ok("Mailbox created.")
                        .with_code(ResponseCode::MailboxId { mailbox_id }),
                    Err(message) => StatusResponse::no(message),
                }
            }
            Err(err) => err.into_status_response(),
        }
        .with_tag(arguments.tag)
    }

    pub fn add_created_mailboxes(
        &self,
        params: &mut CreateParams<'_>,
        create_ids: Vec<String>,
        response: &mut SetResponse<jmap_client::mailbox::Mailbox>,
    ) -> Result<(parking_lot::MutexGuard<'_, Vec<Account>>, String), Cow<'static, str>> {
        // Obtain created mailbox ids
        let mut mailbox_ids = Vec::new();
        for create_id in create_ids {
            match response.created(&create_id) {
                Ok(mut mailbox) => {
                    mailbox_ids.push(mailbox.take_id());
                }
                Err(err) => {
                    return Err(err.to_string().into());
                }
            }
        }

        // Lock mailboxes
        let mut mailboxes = self.mailboxes.lock();
        let account = if let Some(account) = mailboxes
            .iter_mut()
            .find(|account| account.account_id == params.account_id)
        {
            account
        } else {
            return Err(Cow::from("Account no longer available."));
        };

        // Update state
        account.mailbox_state = response.take_new_state();

        // Add mailboxes
        if mailbox_ids.len() != params.path.len() {
            return Err(Cow::from("Some mailboxes could not be created."));
        }
        let mut mailbox_name = if let Some(parent_mailbox_name) = params.parent_mailbox_name.take()
        {
            if let Some(parent_mailbox) = account
                .mailbox_data
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

        let new_mailbox_id = format!("{}-{}", account.account_id, mailbox_ids.last().unwrap());
        let has_updated = response.has_updated();
        for (pos, (mailbox_id, path_item)) in
            mailbox_ids.into_iter().zip(params.path.iter()).enumerate()
        {
            mailbox_name = if !mailbox_name.is_empty() {
                format!("{}/{}", mailbox_name, path_item)
            } else {
                path_item.to_string()
            };

            account
                .mailbox_names
                .insert(mailbox_name.clone(), mailbox_id.clone());
            account.mailbox_data.insert(
                mailbox_id,
                Mailbox {
                    has_children: pos < params.path.len() - 1 || has_updated,
                    is_subscribed: false,
                    role: Role::None,
                    total_messages: 0.into(),
                    total_unseen: 0.into(),
                    total_deleted: 0.into(),
                    uid_validity: None,
                    uid_next: None,
                    size: 0.into(),
                },
            );
        }
        Ok((mailboxes, new_mailbox_id))
    }

    pub fn validate_mailbox_create<'x>(
        &self,
        mailbox_name: &'x str,
    ) -> Result<CreateParams<'x>, Cow<'static, str>> {
        // Remove leading and trailing separators
        let mut name = mailbox_name.trim();
        if let Some(suffix) = name.strip_prefix('/') {
            name = suffix.trim();
        };
        if let Some(prefix) = name.strip_suffix('/') {
            name = prefix.trim();
        }
        if name.is_empty() {
            return Err(Cow::from(format!(
                "Invalid folder name '{}'.",
                mailbox_name
            )));
        }

        // Build path
        let mut path = Vec::new();
        if name.contains('/') {
            // Locate parent mailbox
            for path_item in name.split('/') {
                let path_item = path_item.trim();
                if path_item.is_empty() {
                    return Err(Cow::from("Invalid empty path item."));
                }
                path.push(path_item);
            }

            if path.len() > MAX_MAILBOX_DEPTH {
                return Err(Cow::from("Mailbox path is too deep."));
            }
        } else {
            path.push(name);
        }

        // Validate special folders
        let mut parent_mailbox_id = None;
        let mut parent_mailbox_name = None;
        let mailboxes = self.mailboxes.lock();
        let first_path_item = path.first().unwrap();
        let account = if first_path_item == &self.core.folder_all {
            return Err(Cow::from(
                "Mailboxes cannot be created under virtual folders.",
            ));
        } else if first_path_item == &self.core.folder_shared {
            // Shared Folders/<username>/<folder>
            if path.len() < 3 {
                return Err(Cow::from(
                    "Mailboxes under root shared folders are not allowed.",
                ));
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
                return Err(Cow::from(format!(
                    "Shared account '{}' not found.",
                    prefix.unwrap_or_default()
                )));
            }
        } else if let Some(account) = mailboxes.first() {
            account
        } else {
            return Err(Cow::from("Internal error."));
        };

        // Locate parent mailbox
        let full_path = path.join("/");
        if account.mailbox_names.contains_key(&full_path) {
            return Err(Cow::from(format!(
                "Mailbox '{}' already exists.",
                full_path
            )));
        }
        let path = if path.len() > 1 {
            let mut create_path = Vec::with_capacity(path.len());
            while !path.is_empty() {
                let mailbox_name = path.join("/");
                if let Some(mailbox_id) = account.mailbox_names.get(&mailbox_name) {
                    parent_mailbox_id = mailbox_id.to_string().into();
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
        };

        Ok(CreateParams {
            account_id: account.account_id.to_string(),
            path,
            full_path,
            parent_mailbox_id,
            parent_mailbox_name,
        })
    }
}

#[derive(Debug)]
pub struct CreateParams<'x> {
    pub account_id: String,
    pub path: Vec<&'x str>,
    pub full_path: String,
    pub parent_mailbox_id: Option<String>,
    pub parent_mailbox_name: Option<String>,
}
