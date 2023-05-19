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

use std::{net::IpAddr, time::SystemTime};

use crate::{
    config::{DNSBL_EHLO, DNSBL_IP},
    core::{scripts::ScriptResult, Session},
};
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
                tracing::debug!(parent: &self.span,
                    context = "ehlo",
                    event = "reject",
                    reason = "invalid",
                    domain = domain,
                );

                return self.write(b"550 5.5.0 Invalid EHLO domain.\r\n").await;
            }

            // Check DNSBL
            if !self
                .is_domain_dnsbl_allowed(&domain, "ehlo", DNSBL_EHLO)
                .await
            {
                self.write_dnsbl_error().await?;
                self.reset_dnsbl_error(); // Reset error in case a new EHLO is issued
                return Ok(());
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
                if let ScriptResult::Reject(message) = self.run_script(script.clone(), None).await {
                    tracing::debug!(parent: &self.span,
                        context = "ehlo",
                        event = "sieve-reject",
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
        let rc = &self.core.session.config.rcpt;
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
        if rc.lookup_expn.eval(self).await.is_some() {
            response.capabilities |= EXT_EXPN;
        }

        // Recipient Verification
        if rc.lookup_vrfy.eval(self).await.is_some() {
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
                if !self.stream.is_tls() {
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

    pub async fn is_domain_dnsbl_allowed(
        &mut self,
        domain: &str,
        context: &str,
        policy_type: u32,
    ) -> bool {
        let domain_ = domain.to_lowercase();
        let is_fqdn = domain.ends_with('.');
        if (self.params.dnsbl_policy & policy_type) != 0 {
            for dnsbl in &self.core.mail_auth.dnsbl.domain_lookup {
                if self
                    .is_dns_blocked(if is_fqdn {
                        format!("{domain_}{dnsbl}")
                    } else {
                        format!("{domain_}.{dnsbl}")
                    })
                    .await
                {
                    tracing::debug!(parent: &self.span,
                        context = context,
                        event = "reject",
                        reason = "dnsbl",
                        list = dnsbl,
                        domain = domain,
                    );
                    self.data.dnsbl_error = format!(
                        "554 5.7.1 Service unavailable; Domain '{domain}' blocked using {dnsbl}\r\n"
                    )
                    .into_bytes()
                    .into();
                    return false;
                }
            }
        }
        true
    }

    pub async fn verify_ip_dnsbl(&mut self) -> bool {
        if (self.params.dnsbl_policy & DNSBL_IP) != 0 {
            for dnsbl in &self.core.mail_auth.dnsbl.ip_lookup {
                if self
                    .is_dns_blocked(self.data.remote_ip.to_dnsbl(dnsbl))
                    .await
                {
                    tracing::debug!(parent: &self.span,
                        context = "connect",
                        event = "reject",
                        reason = "dnsbl",
                        list = dnsbl,
                        ip = self.data.remote_ip.to_string(),
                    );
                    self.data.dnsbl_error = format!(
                        "554 5.7.1 Service unavailable; IP address {} blocked using {}\r\n",
                        self.data.remote_ip, dnsbl
                    )
                    .into_bytes()
                    .into();
                    return false;
                }
            }
        }
        true
    }

    async fn is_dns_blocked(&self, domain: String) -> bool {
        match self.core.resolvers.dns.ipv4_lookup(&domain).await {
            Ok(ips) => {
                for ip in ips.iter() {
                    if ip.octets()[0..2] == [127, 0] {
                        return true;
                    }
                }
                tracing::debug!(parent: &self.span,
                    context = "dnsbl",
                    event = "invalid-reply",
                    query = domain,
                    reply = ?ips,
                );
            }
            Err(mail_auth::Error::DnsRecordNotFound(_)) => (),
            Err(err) => {
                tracing::debug!(parent: &self.span,
                    context = "dnsbl",
                    event = "dnserror",
                    query = domain,
                    reson = %err,
                );
            }
        }
        false
    }

    pub async fn write_dnsbl_error(&mut self) -> Result<(), ()> {
        if let Some(error) = &self.data.dnsbl_error {
            self.write(&error.to_vec()).await
        } else {
            Ok(())
        }
    }

    pub fn has_dnsbl_error(&mut self) -> bool {
        self.data.dnsbl_error.is_some()
    }

    pub fn reset_dnsbl_error(&mut self) -> Option<Vec<u8>> {
        self.data.dnsbl_error.take()
    }
}

trait ToDnsbl {
    fn to_dnsbl(&self, host: &str) -> String;
}

impl ToDnsbl for IpAddr {
    fn to_dnsbl(&self, dnsbl: &str) -> String {
        use std::fmt::Write;

        match self {
            IpAddr::V4(ip) => {
                let mut host = String::with_capacity(dnsbl.len() + 16);
                for octet in ip.octets().iter().rev() {
                    let _ = write!(host, "{octet}.");
                }
                host.push_str(dnsbl);
                host
            }
            IpAddr::V6(ip) => {
                let mut host = Vec::with_capacity(dnsbl.len() + 64);
                for segment in ip.segments().iter().rev() {
                    for &p in format!("{segment:04x}").as_bytes().iter().rev() {
                        host.push(p);
                        host.push(b'.');
                    }
                }
                host.extend_from_slice(dnsbl.as_bytes());
                String::from_utf8(host).unwrap_or_default()
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;

    use crate::inbound::ehlo::ToDnsbl;

    #[test]
    fn ip_to_dnsbl() {
        assert_eq!(
            "2001:DB8:abc:123::42"
                .parse::<IpAddr>()
                .unwrap()
                .to_dnsbl("zen.spamhaus.org"),
            "2.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.2.1.0.c.b.a.0.8.b.d.0.1.0.0.2.zen.spamhaus.org"
        );

        assert_eq!(
            "1.2.3.4"
                .parse::<IpAddr>()
                .unwrap()
                .to_dnsbl("zen.spamhaus.org"),
            "4.3.2.1.zen.spamhaus.org"
        );
    }
}
