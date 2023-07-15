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

use mail_auth::{IprevOutput, IprevResult, SpfOutput, SpfResult};
use smtp_proto::{MailFrom, MAIL_BY_NOTIFY, MAIL_BY_RETURN, MAIL_REQUIRETLS};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    config::{DNSBL_IPREV, DNSBL_RETURN_PATH},
    core::{scripts::ScriptResult, Session, SessionAddress},
    queue::DomainPart,
};

use super::IsTls;

impl<T: AsyncWrite + AsyncRead + Unpin + IsTls> Session<T> {
    pub async fn handle_mail_from(&mut self, from: MailFrom<String>) -> Result<(), ()> {
        if self.data.helo_domain.is_empty()
            && (self.params.ehlo_require
                || self.params.spf_ehlo.verify()
                || self.params.spf_mail_from.verify())
        {
            return self
                .write(b"503 5.5.1 Polite people say EHLO first.\r\n")
                .await;
        } else if self.data.mail_from.is_some() {
            return self
                .write(b"503 5.5.1 Multiple MAIL commands not allowed.\r\n")
                .await;
        } else if self.params.auth_require && self.data.authenticated_as.is_empty() {
            return self
                .write(b"503 5.5.1 You must authenticate first.\r\n")
                .await;
        } else if self.has_dnsbl_error() {
            // There was a previous DNSBL error
            return self.write_dnsbl_error().await;
        } else if self.data.iprev.is_none()
            && (self.params.iprev.verify() || (self.params.dnsbl_policy & DNSBL_IPREV) != 0)
        {
            let iprev = self
                .core
                .resolvers
                .dns
                .verify_iprev(self.data.remote_ip)
                .await;

            tracing::debug!(parent: &self.span,
                    context = "iprev",
                    event = "lookup",
                    result = %iprev.result,
                    ptr = iprev.ptr.as_ref().and_then(|p| p.first()).map(|p| p.as_str()).unwrap_or_default()
            );

            // Validate reverse hostname against DNSBL
            if let Some(ptr) = iprev.ptr.as_ref().and_then(|l| l.first()) {
                if !self.is_domain_dnsbl_allowed(ptr, "ptr", DNSBL_IPREV).await {
                    return self.write_dnsbl_error().await;
                }
            }

            self.data.iprev = iprev.into();
        }

        // In strict mode reject messages from hosts that fail the reverse DNS lookup check
        if self.params.iprev.is_strict()
            && !matches!(
                &self.data.iprev,
                Some(IprevOutput {
                    result: IprevResult::Pass,
                    ..
                })
            )
        {
            let message = if matches!(
                &self.data.iprev,
                Some(IprevOutput {
                    result: IprevResult::TempError(_),
                    ..
                })
            ) {
                &b"451 4.7.25 Temporary error validating reverse DNS.\r\n"[..]
            } else {
                &b"550 5.7.25 Reverse DNS validation failed.\r\n"[..]
            };

            return self.write(message).await;
        }

        let (address, address_lcase, domain) = if !from.address.is_empty() {
            let address_lcase = from.address.to_lowercase();
            let domain = address_lcase.domain_part().to_string();
            (from.address, address_lcase, domain)
        } else {
            (String::new(), String::new(), String::new())
        };

        // Validate domain against DNSBL
        if !domain.is_empty()
            && !self
                .is_domain_dnsbl_allowed(&domain, "mail-from", DNSBL_RETURN_PATH)
                .await
        {
            self.write_dnsbl_error().await?;
            self.reset_dnsbl_error(); // Reset error in case a new MAIL-FROM is issued later
            return Ok(());
        }

        let has_dsn = from.env_id.is_some();
        self.data.mail_from = SessionAddress {
            address,
            address_lcase,
            domain,
            flags: from.flags,
            dsn_info: from.env_id,
        }
        .into();

        // Sieve filtering
        if let Some(script) = self.core.session.config.mail.script.eval(self).await {
            if let ScriptResult::Reject(message) = self.run_script(script.clone(), None).await {
                tracing::debug!(parent: &self.span,
                        context = "mail-from",
                        event = "sieve-reject",
                        address = &self.data.mail_from.as_ref().unwrap().address,
                        reason = message);
                self.data.mail_from = None;
                return self.write(message.as_bytes()).await;
            }
        }

        // Validate parameters
        let config = &self.core.session.config.extensions;
        let config_data = &self.core.session.config.data;
        if (from.flags & MAIL_REQUIRETLS) != 0 && !*config.requiretls.eval(self).await {
            self.data.mail_from = None;
            return self
                .write(b"501 5.5.4 REQUIRETLS has been disabled.\r\n")
                .await;
        }
        if (from.flags & (MAIL_BY_NOTIFY | MAIL_BY_RETURN)) != 0 {
            if let Some(duration) = config.deliver_by.eval(self).await {
                if from.by.checked_abs().unwrap_or(0) as u64 <= duration.as_secs()
                    && (from.by.is_positive() || (from.flags & MAIL_BY_NOTIFY) != 0)
                {
                    self.data.delivery_by = from.by;
                } else {
                    self.data.mail_from = None;
                    return self
                        .write(
                            format!(
                                "501 5.5.4 BY parameter exceeds maximum of {} seconds.\r\n",
                                duration.as_secs()
                            )
                            .as_bytes(),
                        )
                        .await;
                }
            } else {
                self.data.mail_from = None;
                return self
                    .write(b"501 5.5.4 DELIVERBY extension has been disabled.\r\n")
                    .await;
            }
        }
        if from.mt_priority != 0 {
            if config.mt_priority.eval(self).await.is_some() {
                if (-6..6).contains(&from.mt_priority) {
                    self.data.priority = from.mt_priority as i16;
                } else {
                    self.data.mail_from = None;
                    return self.write(b"501 5.5.4 Invalid priority value.\r\n").await;
                }
            } else {
                self.data.mail_from = None;
                return self
                    .write(b"501 5.5.4 MT-PRIORITY extension has been disabled.\r\n")
                    .await;
            }
        }
        if from.size > 0 && from.size > *config_data.max_message_size.eval(self).await {
            self.data.mail_from = None;
            return self
                .write(b"552 5.3.4 Message too big for system.\r\n")
                .await;
        }
        if from.hold_for != 0 || from.hold_until != 0 {
            if let Some(max_hold) = config.future_release.eval(self).await {
                let max_hold = max_hold.as_secs();
                let hold_for = if from.hold_for != 0 {
                    from.hold_for
                } else {
                    let now = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    if from.hold_until > now {
                        from.hold_until - now
                    } else {
                        0
                    }
                };
                if hold_for <= max_hold {
                    self.data.future_release = hold_for;
                } else {
                    self.data.mail_from = None;
                    return self
                        .write(
                            format!(
                                "501 5.5.4 Requested hold time exceeds maximum of {max_hold} seconds.\r\n"
                            )
                            .as_bytes(),
                        )
                        .await;
                }
            } else {
                self.data.mail_from = None;
                return self
                    .write(b"501 5.5.4 FUTURERELEASE extension has been disabled.\r\n")
                    .await;
            }
        }
        if has_dsn && !*config.dsn.eval(self).await {
            self.data.mail_from = None;
            return self
                .write(b"501 5.5.4 DSN extension has been disabled.\r\n")
                .await;
        }

        if self.is_allowed().await {
            // Verify SPF
            if self.params.spf_mail_from.verify() {
                let mail_from = self.data.mail_from.as_ref().unwrap();
                let spf_output = if !mail_from.address.is_empty() {
                    self.core
                        .resolvers
                        .dns
                        .check_host(
                            self.data.remote_ip,
                            &mail_from.domain,
                            &self.data.helo_domain,
                            &self.instance.hostname,
                            &mail_from.address_lcase,
                        )
                        .await
                } else {
                    self.core
                        .resolvers
                        .dns
                        .check_host(
                            self.data.remote_ip,
                            &self.data.helo_domain,
                            &self.data.helo_domain,
                            &self.instance.hostname,
                            &format!("postmaster@{}", self.data.helo_domain),
                        )
                        .await
                };

                tracing::debug!(parent: &self.span,
                        context = "spf",
                        event = "lookup",
                        identity = "mail-from",
                        domain = self.data.helo_domain,
                        sender = if !mail_from.address.is_empty() {mail_from.address.as_str()} else {"<>"},
                        result = %spf_output.result(),
                );

                if self
                    .handle_spf(&spf_output, self.params.spf_mail_from.is_strict())
                    .await?
                {
                    self.data.spf_mail_from = spf_output.into();
                } else {
                    self.data.mail_from = None;
                    return Ok(());
                }
            }

            tracing::debug!(parent: &self.span,
                context = "mail-from",
                event = "success",
                address = &self.data.mail_from.as_ref().unwrap().address);

            self.eval_rcpt_params().await;
            self.write(b"250 2.1.0 OK\r\n").await
        } else {
            self.data.mail_from = None;
            self.write(b"451 4.4.5 Rate limit exceeded, try again later.\r\n")
                .await
        }
    }

    pub async fn handle_spf(&mut self, spf_output: &SpfOutput, strict: bool) -> Result<bool, ()> {
        let result = match spf_output.result() {
            SpfResult::Pass => true,
            SpfResult::TempError if strict => {
                self.write(b"451 4.7.24 Temporary SPF validation error.\r\n")
                    .await?;
                false
            }
            result => {
                if strict {
                    self.write(
                        format!("550 5.7.23 SPF validation failed, status: {result}.\r\n")
                            .as_bytes(),
                    )
                    .await?;
                    false
                } else {
                    true
                }
            }
        };

        // Send report
        if let (Some(recipient), Some(rate)) = (
            spf_output.report_address(),
            self.core.report.config.spf.send.eval(self).await,
        ) {
            self.send_spf_report(recipient, rate, !result, spf_output)
                .await;
        }

        Ok(result)
    }
}
