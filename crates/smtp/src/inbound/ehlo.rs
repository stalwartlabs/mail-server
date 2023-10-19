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

use std::time::SystemTime;

use crate::{core::Session, scripts::ScriptResult};
use mail_auth::spf::verify::HasLabels;
use smtp_proto::*;
use tokio::io::{AsyncRead, AsyncWrite};

use super::IsTls;

impl<T: AsyncWrite + AsyncRead + IsTls + Unpin> Session<T> {
    pub async fn handle_ehlo(&mut self, domain: String) -> Result<(), ()> {
        // Set EHLO domain

        if domain != self.data.helo_domain {
            // Reject non-FQDN EHLO domains - simply checks that the hostname has at least one dot
            if self.params.ehlo_reject_non_fqdn && !domain.as_str().has_labels() {
                tracing::info!(parent: &self.span,
                    context = "ehlo",
                    event = "reject",
                    reason = "invalid",
                    domain = domain,
                );

                return self.write(b"550 5.5.0 Invalid EHLO domain.\r\n").await;
            }

            // SPF check
            let prev_helo_domain = std::mem::replace(&mut self.data.helo_domain, domain);
            if self.params.spf_ehlo.verify() {
                let spf_output = self
                    .core
                    .resolvers
                    .dns
                    .verify_spf_helo(
                        self.data.remote_ip,
                        &self.data.helo_domain,
                        &self.instance.hostname,
                    )
                    .await;

                tracing::debug!(parent: &self.span,
                        context = "spf",
                        event = "lookup",
                        identity = "ehlo",
                        domain = self.data.helo_domain,
                        result = %spf_output.result(),
                );

                if self
                    .handle_spf(&spf_output, self.params.spf_ehlo.is_strict())
                    .await?
                {
                    self.data.spf_ehlo = spf_output.into();
                } else {
                    self.data.mail_from = None;
                    self.data.helo_domain = prev_helo_domain;
                    return Ok(());
                }
            }

            // Sieve filtering
            if let Some(script) = self.core.session.config.ehlo.script.eval(self).await {
                if let ScriptResult::Reject(message) = self
                    .run_script(script.clone(), self.build_script_parameters("ehlo"))
                    .await
                {
                    tracing::info!(parent: &self.span,
                        context = "sieve",
                        event = "reject",
                        domain = &self.data.helo_domain,
                        reason = message);

                    self.data.mail_from = None;
                    self.data.helo_domain = prev_helo_domain;
                    self.data.spf_ehlo = None;
                    return self.write(message.as_bytes()).await;
                }
            }

            tracing::debug!(parent: &self.span,
                context = "ehlo",
                event = "ehlo",
                domain = self.data.helo_domain,
            );
        }

        // Reset
        if self.data.mail_from.is_some() {
            self.reset();
        }

        let mut response = EhloResponse::new(self.instance.hostname.as_str());
        response.capabilities =
            EXT_ENHANCED_STATUS_CODES | EXT_8BIT_MIME | EXT_BINARY_MIME | EXT_SMTP_UTF8;
        if !self.stream.is_tls() {
            response.capabilities |= EXT_START_TLS;
        }
        let ec = &self.core.session.config.extensions;
        let ac = &self.core.session.config.auth;
        let dc = &self.core.session.config.data;

        // Pipelining
        if *ec.pipelining.eval(self).await {
            response.capabilities |= EXT_PIPELINING;
        }

        // Chunking
        if *ec.chunking.eval(self).await {
            response.capabilities |= EXT_CHUNKING;
        }

        // Address Expansion
        if *ec.expn.eval(self).await {
            response.capabilities |= EXT_EXPN;
        }

        // Recipient Verification
        if *ec.vrfy.eval(self).await {
            response.capabilities |= EXT_VRFY;
        }

        // Require TLS
        if *ec.requiretls.eval(self).await {
            response.capabilities |= EXT_REQUIRE_TLS;
        }

        // DSN
        if *ec.dsn.eval(self).await {
            response.capabilities |= EXT_DSN;
        }

        // Authentication
        if self.data.authenticated_as.is_empty() {
            response.auth_mechanisms = *ac.mechanisms.eval(self).await;
            if response.auth_mechanisms != 0 {
                if !self.stream.is_tls() && !self.params.auth_plain_text {
                    response.auth_mechanisms &= !(AUTH_PLAIN | AUTH_LOGIN);
                }
                if response.auth_mechanisms != 0 {
                    response.capabilities |= EXT_AUTH;
                }
            }
        }

        // Future release
        if let Some(value) = ec.future_release.eval(self).await {
            response.capabilities |= EXT_FUTURE_RELEASE;
            response.future_release_interval = value.as_secs();
            response.future_release_datetime = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                + value.as_secs();
        }

        // Deliver By
        if let Some(value) = ec.deliver_by.eval(self).await {
            response.capabilities |= EXT_DELIVER_BY;
            response.deliver_by = value.as_secs();
        }

        // Priority
        if let Some(value) = ec.mt_priority.eval(self).await {
            response.capabilities |= EXT_MT_PRIORITY;
            response.mt_priority = *value;
        }

        // Size
        response.size = *dc.max_message_size.eval(self).await;
        if response.size > 0 {
            response.capabilities |= EXT_SIZE;
        }

        // No soliciting
        if let Some(value) = ec.no_soliciting.eval(self).await {
            response.capabilities |= EXT_NO_SOLICITING;
            response.no_soliciting = if !value.is_empty() {
                value.to_string().into()
            } else {
                None
            };
        }

        // Generate response
        let mut buf = Vec::with_capacity(64);
        response.write(&mut buf).ok();
        self.write(&buf).await
    }
}
