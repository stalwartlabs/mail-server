use common::{config::spamfilter::SpamFilterAction, Server};
use std::{fmt::Write, future::Future, vec};

use crate::{modules::bayes::bayes_train_if_balanced, SpamFilterContext};

pub trait SpamFilterAnalyzeScore: Sync + Send {
    fn spam_filter_score(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = SpamFilterAction<String>> + Send;

    fn spam_filter_finalize(
        &self,
        ctx: &mut SpamFilterContext<'_>,
        header: String,
    ) -> impl Future<Output = SpamFilterAction<String>> + Send;
}

impl SpamFilterAnalyzeScore for Server {
    async fn spam_filter_score(&self, ctx: &mut SpamFilterContext<'_>) -> SpamFilterAction<String> {
        let mut results = vec![];
        let mut header_len = 60;

        for tag in &ctx.result.tags {
            let score = match self.core.spam.list_scores.get(tag) {
                Some(SpamFilterAction::Allow(score)) => *score,
                Some(SpamFilterAction::Discard) => {
                    return SpamFilterAction::Discard;
                }
                Some(SpamFilterAction::Reject) => {
                    return SpamFilterAction::Reject;
                }
                None => 0.0,
            };
            ctx.result.score += score;
            header_len += tag.len() + 10;
            results.push((tag.as_str(), score));
        }

        // Sort by score
        let mut header = String::with_capacity(header_len);
        results.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap().then_with(|| a.0.cmp(b.0)));
        header.push_str("X-Spam-Result: ");
        for (idx, (tag, score)) in results.into_iter().enumerate() {
            if idx > 0 {
                header.push_str(",\r\n\t");
            }
            let _ = write!(&mut header, "{} ({:.2})", tag, score);
        }
        header.push_str("\r\n");

        SpamFilterAction::Allow(header)
    }

    async fn spam_filter_finalize(
        &self,
        ctx: &mut SpamFilterContext<'_>,
        mut header: String,
    ) -> SpamFilterAction<String> {
        // Train Bayes classifier
        if let Some(config) = self.core.spam.bayes.as_ref().filter(|c| c.auto_learn) {
            let was_classified =
                ctx.result.has_tag("BAYES_SPAM") || ctx.result.has_tag("BAYES_HAM");
            if ctx.result.has_tag("SPAM_TRAP")
                || (ctx.result.score >= config.auto_learn_spam_threshold && !was_classified)
            {
                bayes_train_if_balanced(self, ctx, true).await;
            } else if ctx.result.has_tag("TRUSTED_REPLY")
                || (ctx.result.score <= config.auto_learn_ham_threshold && !was_classified)
            {
                bayes_train_if_balanced(self, ctx, false).await;
            }
        }

        if self.core.spam.score_reject_threshold > 0.0
            && ctx.result.score >= self.core.spam.score_reject_threshold
        {
            SpamFilterAction::Reject
        } else if self.core.spam.score_discard_threshold > 0.0
            && ctx.result.score >= self.core.spam.score_discard_threshold
        {
            SpamFilterAction::Discard
        } else {
            let _ = write!(
                &mut header,
                "X-Spam-Status: {}, score={:.2}\r\n",
                if ctx.result.score >= self.core.spam.score_spam_threshold {
                    "Yes"
                } else {
                    "No"
                },
                ctx.result.score
            );
            SpamFilterAction::Allow(header)
        }
    }
}
