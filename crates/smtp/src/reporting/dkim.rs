/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use mail_auth::{
    common::verify::VerifySignature, AuthenticatedMessage, AuthenticationResults, DkimOutput,
};
use tokio::io::{AsyncRead, AsyncWrite};
use utils::config::Rate;

use crate::core::Session;

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
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
            tracing::debug!(
                parent: &self.span,
                context = "report",
                report = "dkim",
                event = "throttle",
                rcpt = rcpt,
            );
            return;
        }

        let config = &self.core.report.config.dkim;
        let from_addr = self
            .core
            .eval_if(&config.address, self)
            .await
            .unwrap_or_else(|| "MAILER-DAEMON@localhost".to_string());
        let mut report = Vec::with_capacity(128);
        self.new_auth_failure(output.result().into(), rejected)
            .with_authentication_results(
                AuthenticationResults::new(&self.instance.hostname)
                    .with_dkim_result(output, message.from())
                    .to_string(),
            )
            .with_dkim_domain(signature.domain())
            .with_dkim_selector(signature.selector())
            .with_dkim_identity(signature.identity())
            .with_headers(message.raw_headers())
            .write_rfc5322(
                (
                    self.core
                        .eval_if(&config.name, self)
                        .await
                        .unwrap_or_else(|| "Mail Delivery Subsystem".to_string())
                        .as_str(),
                    from_addr.as_str(),
                ),
                rcpt,
                &self
                    .core
                    .eval_if(&config.subject, self)
                    .await
                    .unwrap_or_else(|| "DKIM Report".to_string()),
                &mut report,
            )
            .ok();

        tracing::info!(
            parent: &self.span,
            context = "report",
            report = "dkim",
            event = "queue",
            rcpt = rcpt,
            "Queueing DKIM authentication failure report."
        );

        // Send report
        self.core
            .send_report(
                &from_addr,
                [rcpt].into_iter(),
                report,
                &config.sign,
                &self.span,
                true,
            )
            .await;
    }
}
