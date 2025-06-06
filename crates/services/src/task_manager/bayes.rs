/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Instant;

use common::Server;
use email::message::bayes::EmailBayesTrain;
use jmap_proto::types::collection::Collection;
use mail_parser::MessageParser;
use trc::{SpamEvent, TaskQueueEvent};
use utils::BlobHash;

use super::Task;

pub trait BayesTrainTask: Sync + Send {
    fn bayes_train(
        &self,
        task: &Task,
        hash: &BlobHash,
        learn_spam: bool,
    ) -> impl Future<Output = bool> + Send;
}

impl BayesTrainTask for Server {
    async fn bayes_train(&self, task: &Task, hash: &BlobHash, learn_spam: bool) -> bool {
        let op_start = Instant::now();
        // Obtain raw message
        if let Ok(Some(raw_message)) = self
            .blob_store()
            .get_blob(hash.as_slice(), 0..usize::MAX)
            .await
        {
            // Train bayes classifier for account
            self.email_bayes_train(
                task.account_id,
                0,
                MessageParser::new().parse(&raw_message).unwrap_or_default(),
                learn_spam,
            )
            .await;

            trc::event!(
                Spam(SpamEvent::TrainAccount),
                AccountId = task.account_id,
                Collection = Collection::Email,
                DocumentId = task.document_id,
                Details = if learn_spam { "spam" } else { "ham" },
                Elapsed = op_start.elapsed(),
            );
            true
        } else {
            trc::event!(
                TaskQueue(TaskQueueEvent::BlobNotFound),
                AccountId = task.account_id,
                DocumentId = task.document_id,
                BlobId = hash.as_slice(),
            );
            false
        }
    }
}
