/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{config::spamfilter::SpamFilterAction, listener::SessionStream};
use mail_auth::{ArcOutput, DkimOutput, DmarcResult, dmarc::Policy};
use mail_parser::Message;
use spam_filter::{
    SpamFilterInput,
    analysis::{
        init::SpamFilterInit, score::SpamFilterAnalyzeScore,
        trusted_reply::SpamFilterAnalyzeTrustedReply,
    },
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
            // Spam classification
            server.spam_filter_classify(&mut ctx).await
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
