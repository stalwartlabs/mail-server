/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::{KV_TRUSTED_REPLY, Server};
use mail_parser::{HeaderName, HeaderValue};
use store::dispatch::lookup::KeyValue;

use crate::{SpamFilterContext, modules::bayes::BayesClassifier};

pub trait SpamFilterAnalyzeTrustedReply: Sync + Send {
    fn spam_filter_analyze_reply_in(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;

    fn spam_filter_analyze_reply_out(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;
}

impl SpamFilterAnalyzeTrustedReply for Server {
    async fn spam_filter_analyze_reply_in(&self, ctx: &mut SpamFilterContext<'_>) {
        if self.core.spam.expiry.trusted_reply.is_some() {
            for header in ctx.input.message.headers() {
                if let HeaderName::InReplyTo | HeaderName::References = &header.name {
                    let ids: Box<dyn Iterator<Item = &str> + Send> = match &header.value {
                        HeaderValue::Text(cow) => Box::new(std::iter::once(cow.as_ref())),
                        HeaderValue::TextList(vec) => Box::new(vec.iter().map(|s| s.as_ref())),
                        _ => {
                            continue;
                        }
                    };

                    for id in ids {
                        match self
                            .in_memory_store()
                            .key_exists(KeyValue::<()>::build_key(KV_TRUSTED_REPLY, id.as_bytes()))
                            .await
                        {
                            Ok(true) => {
                                ctx.result.add_tag("TRUSTED_REPLY");
                                return;
                            }
                            Err(err) => {
                                trc::error!(
                                    err.span_id(ctx.input.span_id).caused_by(trc::location!())
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    async fn spam_filter_analyze_reply_out(&self, ctx: &mut SpamFilterContext<'_>) {
        if let (Some(hold_time), Some(message_id)) = (
            self.core.spam.expiry.trusted_reply,
            ctx.input.message.message_id(),
        ) {
            if let Err(err) = self
                .in_memory_store()
                .key_set(
                    KeyValue::with_prefix(KV_TRUSTED_REPLY, message_id.as_bytes(), vec![])
                        .expires(hold_time),
                )
                .await
            {
                trc::error!(err.span_id(ctx.input.span_id).caused_by(trc::location!()));
            }
        }

        if self
            .core
            .spam
            .bayes
            .as_ref()
            .is_some_and(|config| config.auto_learn_reply_ham)
        {
            self.bayes_train_if_balanced(ctx, false).await;
        }
    }
}
