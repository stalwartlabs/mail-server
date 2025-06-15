/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;

use common::Server;

use crate::{SpamFilterContext, modules::bayes::BayesClassifier};

pub trait SpamFilterAnalyzeBayes: Sync + Send {
    fn spam_filter_analyze_bayes_classify(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = ()> + Send;

    fn spam_filter_analyze_spam_trap(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = bool> + Send;
}

impl SpamFilterAnalyzeBayes for Server {
    async fn spam_filter_analyze_bayes_classify(&self, ctx: &mut SpamFilterContext<'_>) {
        if let Some(config) = &self.core.spam.bayes {
            if !ctx.result.has_tag("SPAM_TRAP") && !ctx.result.has_tag("TRUSTED_REPLY") {
                match self.bayes_classify(ctx).await {
                    Ok(Some(score)) => {
                        if score > config.score_spam {
                            ctx.result.add_tag("BAYES_SPAM");
                        } else if score < config.score_ham {
                            ctx.result.add_tag("BAYES_HAM");
                        }
                    }
                    Ok(None) => (),
                    Err(err) => {
                        trc::error!(err.span_id(ctx.input.span_id).caused_by(trc::location!()));
                    }
                }
            }
        }
    }

    async fn spam_filter_analyze_spam_trap(&self, ctx: &mut SpamFilterContext<'_>) -> bool {
        if let Some(store) = self.get_in_memory_store("spam-traps") {
            for addr in &ctx.output.env_to_addr {
                match store.key_exists(addr.address.as_str()).await {
                    Ok(true) => {
                        ctx.result.add_tag("SPAM_TRAP");
                        return true;
                    }
                    Ok(false) => (),
                    Err(err) => {
                        trc::error!(err.span_id(ctx.input.span_id).caused_by(trc::location!()));
                    }
                }
            }
        }

        false
    }
}
