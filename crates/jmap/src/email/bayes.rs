/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::{auth::AccessToken, Server};
use directory::Permission;
use jmap_proto::types::{collection::Collection, property::Property};
use mail_parser::Message;
use spam_filter::{
    analysis::init::SpamFilterInit, modules::bayes::BayesClassifier, SpamFilterInput,
};
use store::write::{Bincode, TaskQueueClass};
use trc::StoreEvent;

use crate::{changes::write::ChangeLog, JmapMethods};

use super::metadata::MessageMetadata;

pub trait EmailBayesTrain: Sync + Send {
    fn email_bayes_train(
        &self,
        account_id: u32,
        span_id: u64,
        message: Message<'_>,
        learn_spam: bool,
    ) -> impl Future<Output = ()> + Send;

    fn email_bayes_queue_task_build(
        &self,
        account_id: u32,
        document_id: u32,
        learn_spam: bool,
    ) -> impl Future<Output = trc::Result<TaskQueueClass>> + Send;

    fn email_bayes_can_train(&self, access_token: &AccessToken) -> bool;
}

impl EmailBayesTrain for Server {
    async fn email_bayes_train(
        &self,
        account_id: u32,
        span_id: u64,
        message: Message<'_>,
        learn_spam: bool,
    ) {
        self.bayes_train_if_balanced(
            &self.spam_filter_init(SpamFilterInput::from_account_message(
                &message, account_id, span_id,
            )),
            learn_spam,
        )
        .await
    }

    async fn email_bayes_queue_task_build(
        &self,
        account_id: u32,
        document_id: u32,
        learn_spam: bool,
    ) -> trc::Result<TaskQueueClass> {
        let metadata = self
            .get_property::<Bincode<MessageMetadata>>(
                account_id,
                Collection::Email,
                document_id,
                Property::BodyStructure,
            )
            .await?
            .ok_or_else(|| {
                StoreEvent::NotFound
                    .into_err()
                    .account_id(account_id)
                    .document_id(document_id)
            })?;

        Ok(TaskQueueClass::BayesTrain {
            seq: self.generate_snowflake_id()?,
            hash: metadata.inner.blob_hash,
            learn_spam,
        })
    }

    fn email_bayes_can_train(&self, access_token: &AccessToken) -> bool {
        self.core.spam.bayes.as_ref().map_or(false, |bayes| {
            bayes.account_classify && access_token.has_permission(Permission::SpamFilterTrain)
        })
    }
}
