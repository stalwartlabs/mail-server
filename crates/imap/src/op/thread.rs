/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::Instant};

use crate::{
    core::{SelectedMailbox, Session, SessionData},
    spawn_op,
};
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
use trc::AddContext;

impl<T: SessionStream> Session<T> {
    pub async fn handle_thread(
        &mut self,
        request: Request<Command>,
        is_uid: bool,
    ) -> trc::Result<()> {
        let op_start = Instant::now();
        let command = request.command;
        let mut arguments = request.parse_thread()?;
        let (data, mailbox) = self.state.mailbox_state();

        spawn_op!(data, {
            let tag = std::mem::take(&mut arguments.tag);

            match data.thread(arguments, mailbox, is_uid, op_start).await {
                Ok(response) => {
                    data.write_bytes(
                        StatusResponse::completed(command)
                            .with_tag(tag)
                            .serialize(response.serialize()),
                    )
                    .await
                }
                Err(err) => Err(err.id(tag)),
            }
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn thread(
        &self,
        arguments: Arguments,
        mailbox: Arc<SelectedMailbox>,
        is_uid: bool,
        op_start: Instant,
    ) -> trc::Result<Response> {
        // Run query
        let (result_set, _) = self.query(arguments.filter, &mailbox, &None).await?;

        // Synchronize mailbox
        if !result_set.results.is_empty() {
            self.synchronize_messages(&mailbox)
                .await
                .caused_by(trc::location!())?;
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
            .caused_by(trc::location!())?;

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

        trc::event!(
            Imap(trc::ImapEvent::Thread),
            SpanId = self.session_id,
            AccountId = mailbox.id.account_id,
            MailboxId = mailbox.id.mailbox_id,
            Total = threads.len(),
            Elapsed = op_start.elapsed()
        );

        // Build response
        Ok(Response { is_uid, threads })
    }
}
