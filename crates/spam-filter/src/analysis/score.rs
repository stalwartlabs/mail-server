/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, config::spamfilter::SpamFilterAction};
use std::{fmt::Write, future::Future, vec};

use crate::{
    SpamFilterContext,
    analysis::{
        bayes::SpamFilterAnalyzeBayes, date::SpamFilterAnalyzeDate, dmarc::SpamFilterAnalyzeDmarc,
        domain::SpamFilterAnalyzeDomain, ehlo::SpamFilterAnalyzeEhlo, from::SpamFilterAnalyzeFrom,
        headers::SpamFilterAnalyzeHeaders, html::SpamFilterAnalyzeHtml, ip::SpamFilterAnalyzeIp,
        messageid::SpamFilterAnalyzeMid, mime::SpamFilterAnalyzeMime,
        pyzor::SpamFilterAnalyzePyzor, received::SpamFilterAnalyzeReceived,
        recipient::SpamFilterAnalyzeRecipient, replyto::SpamFilterAnalyzeReplyTo,
        reputation::SpamFilterAnalyzeReputation, rules::SpamFilterAnalyzeRules,
        subject::SpamFilterAnalyzeSubject, trusted_reply::SpamFilterAnalyzeTrustedReply,
        url::SpamFilterAnalyzeUrl,
    },
    modules::bayes::BayesClassifier,
};

#[cfg(feature = "enterprise")]
use crate::analysis::llm::SpamFilterAnalyzeLlm;

pub trait SpamFilterAnalyzeScore: Sync + Send {
    fn spam_filter_score(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = SpamFilterAction<()>> + Send;

    fn spam_filter_finalize(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = SpamFilterAction<String>> + Send;

    fn spam_filter_classify(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> impl Future<Output = SpamFilterAction<String>> + Send;
}

impl SpamFilterAnalyzeScore for Server {
    async fn spam_filter_score(&self, ctx: &mut SpamFilterContext<'_>) -> SpamFilterAction<()> {
        let mut results = vec![];
        let mut header_len = 60;

        for tag in &ctx.result.tags {
            let score = match self.core.spam.lists.scores.get(tag) {
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
            if score != 0.0 || !tag.starts_with("X_") {
                results.push((tag.as_str(), score));
            }
        }

        // Write results header sorted by score
        if let Some(header_name) = &self.core.spam.headers.result {
            let mut header = ctx
                .result
                .header
                .get_or_insert_with(|| String::with_capacity(header_name.len() + header_len + 2));
            results.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap().then_with(|| a.0.cmp(b.0)));
            header.push_str(header_name);
            header.push_str(": ");
            for (idx, (tag, score)) in results.into_iter().enumerate() {
                if idx > 0 {
                    header.push_str(",\r\n\t");
                }
                let _ = write!(&mut header, "{} ({:.2})", tag, score);
            }
            header.push_str("\r\n");

            SpamFilterAction::Allow(())
        } else {
            SpamFilterAction::Allow(())
        }
    }

    async fn spam_filter_finalize(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> SpamFilterAction<String> {
        // Train Bayes classifier
        if let Some(config) = self
            .core
            .spam
            .bayes
            .as_ref()
            .filter(|c| c.auto_learn && !ctx.input.is_test)
        {
            let was_classified =
                ctx.result.has_tag("BAYES_SPAM") || ctx.result.has_tag("BAYES_HAM");
            if ctx.result.has_tag("SPAM_TRAP")
                || (ctx.result.score >= config.auto_learn_spam_threshold && !was_classified)
            {
                self.bayes_train_if_balanced(ctx, true).await;
            } else if ctx.result.has_tag("TRUSTED_REPLY")
                || (ctx.result.score <= config.auto_learn_ham_threshold && !was_classified)
            {
                self.bayes_train_if_balanced(ctx, false).await;
            }
        }

        if self.core.spam.scores.reject_threshold > 0.0
            && ctx.result.score >= self.core.spam.scores.reject_threshold
        {
            SpamFilterAction::Reject
        } else if self.core.spam.scores.discard_threshold > 0.0
            && ctx.result.score >= self.core.spam.scores.discard_threshold
        {
            SpamFilterAction::Discard
        } else {
            let mut header = std::mem::take(&mut ctx.result.header).unwrap_or_default();
            if let Some(header_name) = &self.core.spam.headers.status {
                let _ = write!(
                    &mut header,
                    "{}: {}, score={:.2}\r\n",
                    header_name,
                    if ctx.result.score >= self.core.spam.scores.spam_threshold {
                        "Yes"
                    } else {
                        "No"
                    },
                    ctx.result.score
                );
            }
            SpamFilterAction::Allow(header)
        }
    }

    async fn spam_filter_classify(
        &self,
        ctx: &mut SpamFilterContext<'_>,
    ) -> SpamFilterAction<String> {
        // IP address analysis
        self.spam_filter_analyze_ip(ctx).await;

        // DMARC/SPF/DKIM/ARC analysis
        self.spam_filter_analyze_dmarc(ctx).await;

        // EHLO hostname analysis
        self.spam_filter_analyze_ehlo(ctx).await;

        // Generic header analysis
        self.spam_filter_analyze_headers(ctx).await;

        // Received headers analysis
        self.spam_filter_analyze_received(ctx).await;

        // Message-ID analysis
        self.spam_filter_analyze_message_id(ctx).await;

        // Date header analysis
        self.spam_filter_analyze_date(ctx).await;

        // Subject analysis
        self.spam_filter_analyze_subject(ctx).await;

        // From and Envelope From analysis
        self.spam_filter_analyze_from(ctx).await;

        // Reply-To analysis
        self.spam_filter_analyze_reply_to(ctx).await;

        // Recipient analysis
        self.spam_filter_analyze_recipient(ctx).await;

        // E-mail and domain analysis
        self.spam_filter_analyze_domain(ctx).await;

        // URL analysis
        self.spam_filter_analyze_url(ctx).await;

        // MIME part analysis
        self.spam_filter_analyze_mime(ctx).await;

        // HTML content analysis
        self.spam_filter_analyze_html(ctx).await;

        // LLM classification
        #[cfg(feature = "enterprise")]
        self.spam_filter_analyze_llm(ctx).await;

        // Trusted reply analysis
        self.spam_filter_analyze_reply_in(ctx).await;

        // Spam trap
        self.spam_filter_analyze_spam_trap(ctx).await;

        // Pyzor checks
        self.spam_filter_analyze_pyzor(ctx).await;

        // Bayes classification
        self.spam_filter_analyze_bayes_classify(ctx).await;

        // User-defined rules
        self.spam_filter_analyze_rules(ctx).await;

        // Calculate score
        match self.spam_filter_score(ctx).await {
            SpamFilterAction::Allow(_) => (),
            SpamFilterAction::Discard => return SpamFilterAction::Discard,
            SpamFilterAction::Reject => return SpamFilterAction::Reject,
        }

        // Reputation tracking and adjust score
        self.spam_filter_analyze_reputation(ctx).await;

        // Final score calculation
        self.spam_filter_finalize(ctx).await
    }
}
