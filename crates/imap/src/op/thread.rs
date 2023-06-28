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
use store::ValueKey;
use tokio::io::AsyncRead;

use crate::core::{SelectedMailbox, Session, SessionData};

impl<T: AsyncRead> Session<T> {
    pub async fn handle_thread(
        &mut self,
        mut request: Request<Command>,
        is_uid: bool,
    ) -> Result<(), ()> {
        let command = request.command;
        let tag = std::mem::take(&mut request.tag);
        match request.parse_thread() {
            Ok(arguments) => {
                let (data, mailbox) = self.state.mailbox_state();

                tokio::spawn(async move {
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
        let (result_set, _) = self
            .query(arguments.filter, &mailbox, &None, is_uid)
            .await?;

        // Obtain threadIds for matching messages
        let thread_ids = self
            .jmap
            .store
            .get_values::<u32>(
                result_set
                    .results
                    .iter()
                    .map(|document_id| {
                        ValueKey::new(
                            mailbox.id.account_id,
                            Collection::Email,
                            document_id,
                            Property::ThreadId,
                        )
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
            if let (Some(thread_id), Some(imap_id)) =
                (thread_id, state.id_to_imap.get(&document_id))
            {
                threads
                    .entry(thread_id)
                    .or_insert_with(|| Vec::new())
                    .push(if is_uid { imap_id.uid } else { imap_id.seqnum });
            }
        }

        // Build response
        Ok(Response {
            is_uid,
            threads: threads.into_iter().map(|(_, messages)| messages).collect(),
        })
    }
}
