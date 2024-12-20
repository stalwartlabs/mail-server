/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{config::spamfilter::SpamFilterAction, listener::SessionStream};
use mail_auth::{dmarc::Policy, ArcOutput, DkimOutput, DmarcResult};
use mail_parser::Message;
use spam_filter::{
    analysis::{
        bayes::SpamFilterAnalyzeBayes, date::SpamFilterAnalyzeDate, dmarc::SpamFilterAnalyzeDmarc,
        domain::SpamFilterAnalyzeDomain, ehlo::SpamFilterAnalyzeEhlo, from::SpamFilterAnalyzeFrom,
        headers::SpamFilterAnalyzeHeaders, html::SpamFilterAnalyzeHtml, init::SpamFilterInit,
        ip::SpamFilterAnalyzeIp, llm::SpamFilterAnalyzeLlm, messageid::SpamFilterAnalyzeMid,
        mime::SpamFilterAnalyzeMime, pyzor::SpamFilterAnalyzePyzor,
        received::SpamFilterAnalyzeReceived, recipient::SpamFilterAnalyzeRecipient,
        replyto::SpamFilterAnalyzeReplyTo, reputation::SpamFilterAnalyzeReputation,
        rules::SpamFilterAnalyzeRules, score::SpamFilterAnalyzeScore,
        subject::SpamFilterAnalyzeSubject, trusted_reply::SpamFilterAnalyzeTrustedReply,
        url::SpamFilterAnalyzeUrl,
    },
    SpamFilterInput,
};

use crate::core::Session;

impl<T: SessionStream> Session<T> {
    pub async fn spam_classify<'x>(
        &'x self,
        message: &'x Message<'x>,
        dkim_result: &'x [DkimOutput<'x>],
        arc_result: Option<&'x ArcOutput<'x>>,
        dmarc_result: Option<&'x DmarcResult>,
        dmarc_policy: Option<&'x Policy>,
    ) -> SpamFilterAction<String> {
        let server = &self.server;
        let mut ctx = server.spam_filter_init(self.build_spam_input(
            message,
            dkim_result,
            arc_result,
            dmarc_result,
            dmarc_policy,
        ));

        if !self.is_authenticated() {
            // IP address analysis
            server.spam_filter_analyze_ip(&mut ctx).await;

            // DMARC/SPF/DKIM/ARC analysis
            server.spam_filter_analyze_dmarc(&mut ctx).await;

            // EHLO hostname analysis
            server.spam_filter_analyze_ehlo(&mut ctx).await;

            // Generic header analysis
            server.spam_filter_analyze_headers(&mut ctx).await;

            // Received headers analysis
            server.spam_filter_analyze_received(&mut ctx).await;

            // Message-ID analysis
            server.spam_filter_analyze_message_id(&mut ctx).await;

            // Date header analysis
            server.spam_filter_analyze_date(&mut ctx).await;

            // Subject analysis
            server.spam_filter_analyze_subject(&mut ctx).await;

            // From and Envelope From analysis
            server.spam_filter_analyze_from(&mut ctx).await;

            // Reply-To analysis
            server.spam_filter_analyze_reply_to(&mut ctx).await;

            // Recipient analysis
            server.spam_filter_analyze_recipient(&mut ctx).await;

            // E-mail and domain analysis
            server.spam_filter_analyze_domain(&mut ctx).await;

            // URL analysis
            server.spam_filter_analyze_url(&mut ctx).await;

            // MIME part analysis
            server.spam_filter_analyze_mime(&mut ctx).await;

            // HTML content analysis
            server.spam_filter_analyze_html(&mut ctx).await;

            // LLM classification
            server.spam_filter_analyze_llm(&mut ctx).await;

            // Trusted reply analysis
            server.spam_filter_analyze_reply_in(&mut ctx).await;

            // Spam trap
            server.spam_filter_analyze_spam_trap(&mut ctx).await;

            // Pyzor checks
            server.spam_filter_analyze_pyzor(&mut ctx).await;

            // Bayes classification
            server.spam_filter_analyze_bayes_classify(&mut ctx).await;

            // User-defined rules
            server.spam_filter_analyze_rules(&mut ctx).await;

            // Calculate score
            match server.spam_filter_score(&mut ctx).await {
                SpamFilterAction::Allow(_) => (),
                SpamFilterAction::Discard => return SpamFilterAction::Discard,
                SpamFilterAction::Reject => return SpamFilterAction::Reject,
            }

            // Reputation tracking and adjust score
            server.spam_filter_analyze_reputation(&mut ctx).await;

            // Final score calculation
            server.spam_filter_finalize(&mut ctx).await
        } else {
            // Trusted reply tracking
            server.spam_filter_analyze_reply_out(&mut ctx).await;
            SpamFilterAction::Allow(String::new())
        }
    }

    pub fn build_spam_input<'x>(
        &'x self,
        message: &'x Message<'x>,
        dkim_result: &'x [DkimOutput<'x>],
        arc_result: Option<&'x ArcOutput>,
        dmarc_result: Option<&'x DmarcResult>,
        dmarc_policy: Option<&'x Policy>,
    ) -> SpamFilterInput<'x> {
        SpamFilterInput {
            message,
            span_id: self.data.session_id,
            arc_result,
            spf_ehlo_result: self.data.spf_ehlo.as_ref(),
            spf_mail_from_result: self.data.spf_mail_from.as_ref(),
            dkim_result,
            dmarc_result,
            dmarc_policy,
            iprev_result: self.data.iprev.as_ref(),
            remote_ip: self.data.remote_ip,
            ehlo_domain: self.data.helo_domain.as_str().into(),
            authenticated_as: self.data.authenticated_as.as_ref().map(|a| a.name.as_str()),
            asn: self.data.asn_geo_data.asn.as_ref().map(|a| a.id),
            country: self.data.asn_geo_data.country.as_ref().map(|c| c.as_str()),
            is_tls: self.stream.is_tls(),
            env_from: self
                .data
                .mail_from
                .as_ref()
                .map(|m| m.address_lcase.as_str())
                .unwrap_or_default(),
            env_from_flags: self
                .data
                .mail_from
                .as_ref()
                .map(|m| m.flags)
                .unwrap_or_default(),
            env_rcpt_to: self
                .data
                .rcpt_to
                .iter()
                .map(|r| r.address_lcase.as_str())
                .collect(),
            account_id: None,
            is_test: false,
        }
    }
}
