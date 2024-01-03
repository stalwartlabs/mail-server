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
    protocol::{
        thread::{Arguments, Response},
        ImapResponse,
    },
    receiver::Request,
    Command, StatusResponse,
};

use jmap_proto::types::{collection::Collection, property::Property};
use store::{write::ValueClass, ValueKey};
use tokio::io::AsyncRead;

use crate::core::{SelectedMailbox, Session, SessionData};

impl<T: AsyncRead> Session<T> {
    pub async fn handle_thread(
        &mut self,
        request: Request<Command>,
        is_uid: bool,
    ) -> crate::OpResult {
        let command = request.command;
        match request.parse_thread() {
            Ok(mut arguments) => {
                let (data, mailbox) = self.state.mailbox_state();

                tokio::spawn(async move {
                    let tag = std::mem::take(&mut arguments.tag);
                    let bytes = match data.thread(arguments, mailbox, is_uid).await {
                        Ok(response) => StatusResponse::completed(command)
                            .with_tag(tag)
                            .serialize(response.serialize()),
                        Err(response) => response.with_tag(tag).into_bytes(),
                    };
                    data.write_bytes(bytes).await;
                });
                Ok(())
            }
            Err(response) => self.write_bytes(response.into_bytes()).await,
        }
    }
}

impl SessionData {
    pub async fn thread(
        &self,
        arguments: Arguments,
        mailbox: Arc<SelectedMailbox>,
        is_uid: bool,
    ) -> Result<Response, StatusResponse> {
        // Run query
        let (result_set, _) = self.query(arguments.filter, &mailbox, &None).await?;

        // Synchronize mailbox
        if !result_set.results.is_empty() {
            self.synchronize_messages(&mailbox).await?;
        }

        // Obtain threadIds for matching messages
        let thread_ids = self
            .jmap
            .store
            .get_values::<u32>(
                result_set
                    .results
                    .iter()
                    .map(|document_id| ValueKey {
                        account_id: mailbox.id.account_id,
                        collection: Collection::Email.into(),
                        document_id,
                        class: ValueClass::Property(Property::ThreadId.into()),
                    })
                    .collect(),
            )
            .await
            .map_err(|err| {
                tracing::error!(
                event = "error",
                context = "thread_query",
                error = ?err,
                "Failed to obtain threadIds.");
                StatusResponse::database_failure()
            })?;

        // Group messages by thread
        let mut threads: AHashMap<u32, Vec<u32>> = AHashMap::new();
        let state = mailbox.state.lock();
        for (document_id, thread_id) in result_set.results.into_iter().zip(thread_ids) {
            if let (Some(thread_id), Some((imap_id, _))) =
                (thread_id, state.map_result_id(document_id, is_uid))
            {
                threads.entry(thread_id).or_default().push(imap_id);
            }
        }

        let mut threads = threads
            .into_iter()
            .map(|(_, messages)| messages)
            .collect::<Vec<_>>();
        threads.sort_unstable();

        // Build response
        Ok(Response { is_uid, threads })
    }
}
