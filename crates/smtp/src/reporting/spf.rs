/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use mail_auth::{report::AuthFailureType, AuthenticationResults, SpfOutput};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{config::Rate, core::Session};

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn send_spf_report(
        &self,
        rcpt: &str,
        rate: &Rate,
        rejected: bool,
        output: &SpfOutput,
    ) {
        // Throttle recipient
        if !self.throttle_rcpt(rcpt, rate, "spf") {
            tracing::debug!(
                parent: &self.span,
                context = "report",
                report = "spf",
                event = "throttle",
                rcpt = rcpt,
            );
            return;
        }

        // Generate report
        let config = &self.core.report.config.spf;
        let from_addr = config.address.eval(self).await;
        let mut report = Vec::with_capacity(128);
        self.new_auth_failure(AuthFailureType::Spf, rejected)
            .with_authentication_results(
                if let Some(mail_from) = &self.data.mail_from {
                    AuthenticationResults::new(&self.instance.hostname).with_spf_mailfrom_result(
                        output,
                        self.data.remote_ip,
                        &mail_from.address,
                        &self.data.helo_domain,
                    )
                } else {
                    AuthenticationResults::new(&self.instance.hostname).with_spf_ehlo_result(
                        output,
                        self.data.remote_ip,
                        &self.data.helo_domain,
                    )
                }
                .to_string(),
            )
            .with_spf_dns(format!("txt : {} : v=SPF1", output.domain())) // TODO use DNS record
            .write_rfc5322(
                (config.name.eval(self).await.as_str(), from_addr.as_str()),
                rcpt,
                config.subject.eval(self).await,
                &mut report,
            )
            .ok();

        tracing::info!(
            parent: &self.span,
            context = "report",
            report = "spf",
            event = "queue",
            rcpt = rcpt,
            "Queueing SPF authentication failure report."
        );

        // Send report
        self.core
            .send_report(
                from_addr,
                [rcpt].into_iter(),
                report,
                &config.sign,
                &self.span,
                true,
            )
            .await;
    }
}
