/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, SystemTime};

use crate::{core::Session, scripts::ScriptResult};
use common::{
    config::smtp::session::{Mechanism, Stage},
    listener::SessionStream,
};
use mail_auth::spf::verify::HasValidLabels;
use smtp_proto::*;

impl<T: SessionStream> Session<T> {
    pub async fn handle_ehlo(&mut self, domain: String, is_extended: bool) -> Result<(), ()> {
        // Set EHLO domain

        if domain != self.data.helo_domain {
            // Reject non-FQDN EHLO domains - simply checks that the hostname has at least one dot
            if self.params.ehlo_reject_non_fqdn && !domain.as_str().has_valid_labels() {
                tracing::info!(
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
                    .core
                    .smtp
                    .resolvers
                    .dns
                    .verify_spf_helo(self.data.remote_ip, &self.data.helo_domain, &self.hostname)
                    .await;

                tracing::debug!(
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
            if let Some(script) = self
                .core
                .core
                .eval_if::<String, _>(
                    &self.core.core.smtp.session.ehlo.script,
                    self,
                    self.data.session_id,
                )
                .await
                .and_then(|name| self.core.core.get_sieve_script(&name))
            {
                if let ScriptResult::Reject(message) = self
                    .run_script(script.clone(), self.build_script_parameters("ehlo"))
                    .await
                {
                    tracing::info!(
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

            // Milter filtering
            if let Err(message) = self.run_milters(Stage::Ehlo, None).await {
                tracing::info!(
                    context = "milter",
                    event = "reject",
                    domain = &self.data.helo_domain,
                    reason = message.message.as_ref());

                self.data.mail_from = None;
                self.data.helo_domain = prev_helo_domain;
                self.data.spf_ehlo = None;
                return self.write(message.message.as_bytes()).await;
            }

            // MTAHook filtering
            if let Err(message) = self.run_mta_hooks(Stage::Ehlo, None).await {
                tracing::info!(
                                context = "mta_hook",
                                event = "reject",
                                domain = &self.data.helo_domain,
                                reason = message.message.as_ref());

                self.data.mail_from = None;
                self.data.helo_domain = prev_helo_domain;
                self.data.spf_ehlo = None;
                return self.write(message.message.as_bytes()).await;
            }

            tracing::debug!(
                context = "ehlo",
                event = "ehlo",
                domain = self.data.helo_domain,
            );
        }

        // Reset
        if self.data.mail_from.is_some() {
            self.reset();
        }

        if !is_extended {
            return self
                .write(format!("250 {} you had me at HELO\r\n", self.hostname).as_bytes())
                .await;
        }

        let mut response = EhloResponse::new(self.hostname.as_str());
        response.capabilities =
            EXT_ENHANCED_STATUS_CODES | EXT_8BIT_MIME | EXT_BINARY_MIME | EXT_SMTP_UTF8;
        if !self.stream.is_tls() && self.instance.acceptor.is_tls() {
            response.capabilities |= EXT_START_TLS;
        }
        let ec = &self.core.core.smtp.session.extensions;
        let ac = &self.core.core.smtp.session.auth;
        let dc = &self.core.core.smtp.session.data;

        // Pipelining
        if self
            .core
            .core
            .eval_if(&ec.pipelining, self, self.data.session_id)
            .await
            .unwrap_or(true)
        {
            response.capabilities |= EXT_PIPELINING;
        }

        // Chunking
        if self
            .core
            .core
            .eval_if(&ec.chunking, self, self.data.session_id)
            .await
            .unwrap_or(true)
        {
            response.capabilities |= EXT_CHUNKING;
        }

        // Address Expansion
        if self
            .core
            .core
            .eval_if(&ec.expn, self, self.data.session_id)
            .await
            .unwrap_or(false)
        {
            response.capabilities |= EXT_EXPN;
        }

        // Recipient Verification
        if self
            .core
            .core
            .eval_if(&ec.vrfy, self, self.data.session_id)
            .await
            .unwrap_or(false)
        {
            response.capabilities |= EXT_VRFY;
        }

        // Require TLS
        if self
            .core
            .core
            .eval_if(&ec.requiretls, self, self.data.session_id)
            .await
            .unwrap_or(true)
        {
            response.capabilities |= EXT_REQUIRE_TLS;
        }

        // DSN
        if self
            .core
            .core
            .eval_if(&ec.dsn, self, self.data.session_id)
            .await
            .unwrap_or(false)
        {
            response.capabilities |= EXT_DSN;
        }

        // Authentication
        if self.data.authenticated_as.is_empty() {
            response.auth_mechanisms = self
                .core
                .core
                .eval_if::<Mechanism, _>(&ac.mechanisms, self, self.data.session_id)
                .await
                .unwrap_or_default()
                .into();
            if response.auth_mechanisms != 0 {
                response.capabilities |= EXT_AUTH;
            }
        }

        // Future release
        if let Some(value) = self
            .core
            .core
            .eval_if::<Duration, _>(&ec.future_release, self, self.data.session_id)
            .await
        {
            response.capabilities |= EXT_FUTURE_RELEASE;
            response.future_release_interval = value.as_secs();
            response.future_release_datetime = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                + value.as_secs();
        }

        // Deliver By
        if let Some(value) = self
            .core
            .core
            .eval_if::<Duration, _>(&ec.deliver_by, self, self.data.session_id)
            .await
        {
            response.capabilities |= EXT_DELIVER_BY;
            response.deliver_by = value.as_secs();
        }

        // Priority
        if let Some(value) = self
            .core
            .core
            .eval_if::<MtPriority, _>(&ec.mt_priority, self, self.data.session_id)
            .await
        {
            response.capabilities |= EXT_MT_PRIORITY;
            response.mt_priority = value;
        }

        // Size
        response.size = self
            .core
            .core
            .eval_if(&dc.max_message_size, self, self.data.session_id)
            .await
            .unwrap_or(25 * 1024 * 1024);
        if response.size > 0 {
            response.capabilities |= EXT_SIZE;
        }

        // No soliciting
        if let Some(value) = self
            .core
            .core
            .eval_if::<String, _>(&ec.no_soliciting, self, self.data.session_id)
            .await
        {
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
