/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use crate::core::{SelectedMailbox, Session, SessionData};
use ahash::AHashMap;
use common::listener::SessionStream;
use imap_proto::{
    protocol::{
        thread::{Arguments, Response},
        ImapResponse,
    },
    receiver::Request,
    Command, StatusResponse,
};

impl<T: SessionStream> Session<T> {
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

impl<T: SessionStream> SessionData<T> {
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
        } else {
            return Ok(Response {
                is_uid,
                threads: vec![],
            });
        }

        // Lock the cache
        let thread_ids = self
            .jmap
            .get_cached_thread_ids(mailbox.id.account_id, result_set.results.iter())
            .await
            .map_err(|err| {
                tracing::error!(
                event = "error",
                context = "thread_query",
                error = ?err,
                "Failed to obtain threadId.");
                StatusResponse::database_failure()
            })?;

        // Group messages by thread
        let mut threads: AHashMap<u32, Vec<u32>> = AHashMap::new();
        let state = mailbox.state.lock();
        for (document_id, thread_id) in thread_ids {
            if let Some((imap_id, _)) = state.map_result_id(document_id, is_uid) {
                threads.entry(thread_id).or_default().push(imap_id);
            }
        }

        let mut threads = threads
            .into_iter()
            .map(|(_, mut messages)| {
                messages.sort_unstable();
                messages
            })
            .collect::<Vec<_>>();
        threads.sort_unstable();

        // Build response
        Ok(Response { is_uid, threads })
    }
}
