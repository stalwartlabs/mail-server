/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::SessionStream;
use mail_auth::{report::AuthFailureType, AuthenticationResults, SpfOutput};
use trc::OutgoingReportEvent;
use utils::config::Rate;

use crate::core::Session;

impl<T: SessionStream> Session<T> {
    pub async fn send_spf_report(
        &self,
        rcpt: &str,
        rate: &Rate,
        rejected: bool,
        output: &SpfOutput,
    ) {
        // Throttle recipient
        if !self.throttle_rcpt(rcpt, rate, "spf").await {
            trc::event!(
                OutgoingReport(OutgoingReportEvent::SpfRateLimited),
                SpanId = self.data.session_id,
                To = rcpt.to_string(),
                Limit = rate.requests,
                Interval = rate.period
            );

            return;
        }

        // Generate report
        let config = &self.core.core.smtp.report.spf;
        let from_addr = self
            .core
            .core
            .eval_if(&config.address, self, self.data.session_id)
            .await
            .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string());
        let mut report = Vec::with_capacity(128);
        self.new_auth_failure(AuthFailureType::Spf, rejected)
            .with_authentication_results(
                if let Some(mail_from) = &self.data.mail_from {
                    AuthenticationResults::new(&self.hostname).with_spf_mailfrom_result(
                        output,
                        self.data.remote_ip,
                        &mail_from.address,
                        &self.data.helo_domain,
                    )
                } else {
                    AuthenticationResults::new(&self.hostname).with_spf_ehlo_result(
                        output,
                        self.data.remote_ip,
                        &self.data.helo_domain,
                    )
                }
                .to_string(),
            )
            .with_spf_dns(format!("txt : {} : v=SPF1", output.domain())) // TODO use DNS record
            .write_rfc5322(
                (
                    self.core
                        .core
                        .eval_if(&config.name, self, self.data.session_id)
                        .await
                        .unwrap_or_else(|| "Mailer Daemon".to_string())
                        .as_str(),
                    from_addr.as_str(),
                ),
                rcpt,
                &self
                    .core
                    .core
                    .eval_if(&config.subject, self, self.data.session_id)
                    .await
                    .unwrap_or_else(|| "SPF Report".to_string()),
                &mut report,
            )
            .ok();

        trc::event!(
            OutgoingReport(OutgoingReportEvent::SpfReport),
            SpanId = self.data.session_id,
            To = rcpt.to_string(),
        );

        // Send report
        self.core
            .send_report(
                &from_addr,
                [rcpt].into_iter(),
                report,
                &config.sign,
                true,
                self.data.session_id,
            )
            .await;
    }
}
