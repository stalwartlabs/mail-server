/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::listener::SessionStream;
use mail_auth::{
    common::verify::VerifySignature, AuthenticatedMessage, AuthenticationResults, DkimOutput,
};
use trc::OutgoingReportEvent;
use utils::config::Rate;

use crate::core::Session;

impl<T: SessionStream> Session<T> {
    pub async fn send_dkim_report(
        &self,
        rcpt: &str,
        message: &AuthenticatedMessage<'_>,
        rate: &Rate,
        rejected: bool,
        output: &DkimOutput<'_>,
    ) {
        // Generate report
        let signature = if let Some(signature) = output.signature() {
            signature
        } else {
            return;
        };

        // Throttle recipient
        if !self.throttle_rcpt(rcpt, rate, "dkim").await {
            trc::event!(
                OutgoingReport(OutgoingReportEvent::DkimRateLimited),
                SpanId = self.data.session_id,
                To = rcpt.to_string(),
                Limit = rate.requests,
                Interval = rate.period
            );

            return;
        }

        let config = &self.core.core.smtp.report.dkim;
        let from_addr = self
            .core
            .core
            .eval_if(&config.address, self, self.data.session_id)
            .await
            .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string());
        let mut report = Vec::with_capacity(128);
        self.new_auth_failure(output.result().into(), rejected)
            .with_authentication_results(
                AuthenticationResults::new(&self.hostname)
                    .with_dkim_result(output, message.from())
                    .to_string(),
            )
            .with_dkim_domain(signature.domain())
            .with_dkim_selector(signature.selector())
            .with_dkim_identity(signature.identity())
            .with_headers(std::str::from_utf8(message.raw_headers()).unwrap_or_default())
            .write_rfc5322(
                (
                    self.core
                        .core
                        .eval_if(&config.name, self, self.data.session_id)
                        .await
                        .unwrap_or_else(|| "Mail Delivery Subsystem".to_string())
                        .as_str(),
                    from_addr.as_str(),
                ),
                rcpt,
                &self
                    .core
                    .core
                    .eval_if(&config.subject, self, self.data.session_id)
                    .await
                    .unwrap_or_else(|| "DKIM Report".to_string()),
                &mut report,
            )
            .ok();

        trc::event!(
            OutgoingReport(OutgoingReportEvent::DkimReport),
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
