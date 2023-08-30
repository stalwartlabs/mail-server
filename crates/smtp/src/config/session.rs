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

use std::{net::ToSocketAddrs, time::Duration};

use smtp_proto::*;

use super::{if_block::ConfigIf, throttle::ConfigThrottle, *};
use utils::config::{
    utils::{AsKey, ParseValue},
    Config, DynValue,
};

pub trait ConfigSession {
    fn parse_session_config(&self, ctx: &ConfigContext) -> super::Result<SessionConfig>;
    fn parse_session_throttle(&self, ctx: &ConfigContext) -> super::Result<SessionThrottle>;
    fn parse_session_connect(&self, ctx: &ConfigContext) -> super::Result<Connect>;
    fn parse_extensions(&self, ctx: &ConfigContext) -> super::Result<Extensions>;
    fn parse_session_ehlo(&self, ctx: &ConfigContext) -> super::Result<Ehlo>;
    fn parse_session_auth(&self, ctx: &ConfigContext) -> super::Result<Auth>;
    fn parse_session_mail(&self, ctx: &ConfigContext) -> super::Result<Mail>;
    fn parse_session_rcpt(&self, ctx: &ConfigContext) -> super::Result<Rcpt>;
    fn parse_session_data(&self, ctx: &ConfigContext) -> super::Result<Data>;
    fn parse_pipes(
        &self,
        ctx: &ConfigContext,
        available_keys: &[EnvelopeKey],
    ) -> super::Result<Vec<Pipe>>;
    fn parse_milters(
        &self,
        ctx: &ConfigContext,
        available_keys: &[EnvelopeKey],
    ) -> super::Result<Vec<Milter>>;
}

impl ConfigSession for Config {
    fn parse_session_config(&self, ctx: &ConfigContext) -> super::Result<SessionConfig> {
        let available_keys = [
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
        ];

        Ok(SessionConfig {
            duration: self
                .parse_if_block("session.duration", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(15 * 60))),
            transfer_limit: self
                .parse_if_block("session.transfer-limit", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(250 * 1024 * 1024)),
            timeout: self
                .parse_if_block::<Option<Duration>>("session.timeout", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(Some(Duration::from_secs(5 * 60))))
                .try_unwrap("session.timeout")
                .unwrap_or_else(|_| IfBlock::new(Duration::from_secs(5 * 60))),
            throttle: self.parse_session_throttle(ctx)?,
            connect: self.parse_session_connect(ctx)?,
            ehlo: self.parse_session_ehlo(ctx)?,
            auth: self.parse_session_auth(ctx)?,
            mail: self.parse_session_mail(ctx)?,
            rcpt: self.parse_session_rcpt(ctx)?,
            data: self.parse_session_data(ctx)?,
            extensions: self.parse_extensions(ctx)?,
        })
    }

    fn parse_session_throttle(&self, ctx: &ConfigContext) -> super::Result<SessionThrottle> {
        // Parse throttle
        let mut throttle = SessionThrottle {
            connect: Vec::new(),
            mail_from: Vec::new(),
            rcpt_to: Vec::new(),
        };
        let all_throttles = self.parse_throttle(
            "session.throttle",
            ctx,
            &[
                EnvelopeKey::Sender,
                EnvelopeKey::SenderDomain,
                EnvelopeKey::Recipient,
                EnvelopeKey::RecipientDomain,
                EnvelopeKey::AuthenticatedAs,
                EnvelopeKey::Listener,
                EnvelopeKey::RemoteIp,
                EnvelopeKey::LocalIp,
                EnvelopeKey::Priority,
                EnvelopeKey::HeloDomain,
            ],
            THROTTLE_LISTENER
                | THROTTLE_REMOTE_IP
                | THROTTLE_LOCAL_IP
                | THROTTLE_AUTH_AS
                | THROTTLE_HELO_DOMAIN
                | THROTTLE_RCPT
                | THROTTLE_RCPT_DOMAIN
                | THROTTLE_SENDER
                | THROTTLE_SENDER_DOMAIN,
        )?;
        for t in all_throttles {
            if (t.keys & (THROTTLE_RCPT | THROTTLE_RCPT_DOMAIN)) != 0
                || t.conditions.conditions.iter().any(|c| {
                    matches!(
                        c,
                        Condition::Match {
                            key: EnvelopeKey::Recipient | EnvelopeKey::RecipientDomain,
                            ..
                        }
                    )
                })
            {
                throttle.rcpt_to.push(t);
            } else if (t.keys
                & (THROTTLE_SENDER
                    | THROTTLE_SENDER_DOMAIN
                    | THROTTLE_HELO_DOMAIN
                    | THROTTLE_AUTH_AS))
                != 0
                || t.conditions.conditions.iter().any(|c| {
                    matches!(
                        c,
                        Condition::Match {
                            key: EnvelopeKey::Sender
                                | EnvelopeKey::SenderDomain
                                | EnvelopeKey::HeloDomain
                                | EnvelopeKey::AuthenticatedAs,
                            ..
                        }
                    )
                })
            {
                throttle.mail_from.push(t);
            } else {
                throttle.connect.push(t);
            }
        }

        Ok(throttle)
    }

    fn parse_session_connect(&self, ctx: &ConfigContext) -> super::Result<Connect> {
        let available_keys = [
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
        ];
        Ok(Connect {
            script: self
                .parse_if_block::<Option<String>>("session.connect.script", ctx, &available_keys)?
                .unwrap_or_default()
                .map_if_block(&ctx.scripts, "session.connect.script", "script")?,
        })
    }

    fn parse_extensions(&self, ctx: &ConfigContext) -> super::Result<Extensions> {
        let available_keys = [
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::AuthenticatedAs,
        ];

        Ok(Extensions {
            pipelining: self
                .parse_if_block("session.extensions.pipelining", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(true)),
            dsn: self
                .parse_if_block("session.extensions.dsn", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(true)),
            vrfy: self
                .parse_if_block("session.extensions.vrfy", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(true)),
            expn: self
                .parse_if_block("session.extensions.expn", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(true)),
            chunking: self
                .parse_if_block("session.extensions.chunking", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(true)),
            requiretls: self
                .parse_if_block("session.extensions.requiretls", ctx, &available_keys)?
                .unwrap_or_default(),
            no_soliciting: self
                .parse_if_block("session.extensions.no-soliciting", ctx, &available_keys)?
                .unwrap_or_default(),
            future_release: self
                .parse_if_block("session.extensions.future-release", ctx, &available_keys)?
                .unwrap_or_default(),
            deliver_by: self
                .parse_if_block("session.extensions.deliver-by", ctx, &available_keys)?
                .unwrap_or_default(),
            mt_priority: self
                .parse_if_block("session.extensions.mt-priority", ctx, &available_keys)?
                .unwrap_or_default(),
        })
    }

    fn parse_session_ehlo(&self, ctx: &ConfigContext) -> super::Result<Ehlo> {
        let available_keys = [
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
        ];

        Ok(Ehlo {
            script: self
                .parse_if_block::<Option<String>>("session.ehlo.script", ctx, &available_keys)?
                .unwrap_or_default()
                .map_if_block(&ctx.scripts, "session.ehlo.script", "script")?,
            require: self
                .parse_if_block("session.ehlo.require", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(true)),
            reject_non_fqdn: self
                .parse_if_block("session.ehlo.reject-non-fqdn", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(true)),
        })
    }

    fn parse_session_auth(&self, ctx: &ConfigContext) -> super::Result<Auth> {
        let available_keys = [
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
            EnvelopeKey::HeloDomain,
        ];

        let mechanisms = self
            .parse_if_block::<Vec<Mechanism>>("session.auth.mechanisms", ctx, &available_keys)?
            .unwrap_or_default();

        Ok(Auth {
            directory: self
                .parse_if_block::<Option<DynValue<EnvelopeKey>>>(
                    "session.auth.directory",
                    ctx,
                    &available_keys,
                )?
                .unwrap_or_default()
                .map_if_block(
                    &ctx.directory.directories,
                    "session.auth.directory",
                    "lookup list",
                )?,
            mechanisms: IfBlock {
                if_then: mechanisms
                    .if_then
                    .into_iter()
                    .map(|i| IfThen {
                        conditions: i.conditions,
                        then: i.then.into_iter().fold(0, |acc, m| acc | m.mechanism),
                    })
                    .collect(),
                default: mechanisms
                    .default
                    .into_iter()
                    .fold(0, |acc, m| acc | m.mechanism),
            },
            require: self
                .parse_if_block("session.auth.require", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(false)),
            errors_max: self
                .parse_if_block("session.auth.errors.max", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(3)),
            errors_wait: self
                .parse_if_block("session.auth.errors.wait", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(30))),
        })
    }

    fn parse_session_mail(&self, ctx: &ConfigContext) -> super::Result<Mail> {
        let available_keys = [
            EnvelopeKey::AuthenticatedAs,
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
            EnvelopeKey::HeloDomain,
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
        ];
        Ok(Mail {
            script: self
                .parse_if_block::<Option<String>>("session.mail.script", ctx, &available_keys)?
                .unwrap_or_default()
                .map_if_block(&ctx.scripts, "session.mail.script", "script")?,
            rewrite: self
                .parse_if_block::<Option<DynValue<EnvelopeKey>>>(
                    "session.mail.rewrite",
                    ctx,
                    &available_keys,
                )?
                .unwrap_or_default(),
        })
    }

    fn parse_session_rcpt(&self, ctx: &ConfigContext) -> super::Result<Rcpt> {
        let available_keys = [
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::AuthenticatedAs,
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
            EnvelopeKey::HeloDomain,
        ];
        let available_keys_full = [
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Recipient,
            EnvelopeKey::RecipientDomain,
            EnvelopeKey::AuthenticatedAs,
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
            EnvelopeKey::HeloDomain,
        ];
        Ok(Rcpt {
            script: self
                .parse_if_block::<Option<String>>("session.rcpt.script", ctx, &available_keys_full)?
                .unwrap_or_default()
                .map_if_block(&ctx.scripts, "session.rcpt.script", "script")?,
            relay: self
                .parse_if_block("session.rcpt.relay", ctx, &available_keys_full)?
                .unwrap_or_else(|| IfBlock::new(false)),
            directory: self
                .parse_if_block::<Option<DynValue<EnvelopeKey>>>(
                    "session.rcpt.directory",
                    ctx,
                    &available_keys_full,
                )?
                .unwrap_or_default()
                .map_if_block(
                    &ctx.directory.directories,
                    "session.rcpt.directory",
                    "lookup list",
                )?,
            errors_max: self
                .parse_if_block("session.rcpt.errors.max", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(10)),
            errors_wait: self
                .parse_if_block("session.rcpt.errors.wait", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(30))),
            max_recipients: self
                .parse_if_block("session.rcpt.max-recipients", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(100)),
            rewrite: self
                .parse_if_block::<Option<DynValue<EnvelopeKey>>>(
                    "session.rcpt.rewrite",
                    ctx,
                    &available_keys_full,
                )?
                .unwrap_or_default(),
        })
    }

    fn parse_session_data(&self, ctx: &ConfigContext) -> super::Result<Data> {
        let available_keys = [
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::AuthenticatedAs,
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
            EnvelopeKey::Priority,
            EnvelopeKey::HeloDomain,
        ];
        Ok(Data {
            script: self
                .parse_if_block::<Option<String>>("session.data.script", ctx, &available_keys)?
                .unwrap_or_default()
                .map_if_block(&ctx.scripts, "session.data.script", "script")?,
            max_messages: self
                .parse_if_block("session.data.limits.messages", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(10)),
            max_message_size: self
                .parse_if_block("session.data.limits.size", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(25 * 1024 * 1024)),
            max_received_headers: self
                .parse_if_block("session.data.limits.received-headers", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(50)),
            add_received: self
                .parse_if_block("session.data.add-headers.received", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(true)),
            add_received_spf: self
                .parse_if_block(
                    "session.data.add-headers.received-spf",
                    ctx,
                    &available_keys,
                )?
                .unwrap_or_else(|| IfBlock::new(true)),
            add_return_path: self
                .parse_if_block("session.data.add-headers.return-path", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(true)),
            add_auth_results: self
                .parse_if_block(
                    "session.data.add-headers.auth-results",
                    ctx,
                    &available_keys,
                )?
                .unwrap_or_else(|| IfBlock::new(true)),
            add_message_id: self
                .parse_if_block("session.data.add-headers.message-id", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(true)),
            add_date: self
                .parse_if_block("session.data.add-headers.date", ctx, &available_keys)?
                .unwrap_or_else(|| IfBlock::new(true)),
            pipe_commands: self.parse_pipes(ctx, &available_keys)?,
            milters: self.parse_milters(ctx, &available_keys)?,
        })
    }

    fn parse_pipes(
        &self,
        ctx: &ConfigContext,
        available_keys: &[EnvelopeKey],
    ) -> super::Result<Vec<Pipe>> {
        let mut pipes = Vec::new();
        for id in self.sub_keys("session.data.pipe") {
            pipes.push(Pipe {
                command: self
                    .parse_if_block(("session.data.pipe", id, "command"), ctx, available_keys)?
                    .unwrap_or_default(),
                arguments: self
                    .parse_if_block(("session.data.pipe", id, "arguments"), ctx, available_keys)?
                    .unwrap_or_default(),
                timeout: self
                    .parse_if_block(("session.data.pipe", id, "timeout"), ctx, available_keys)?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(30))),
            })
        }
        Ok(pipes)
    }

    fn parse_milters(
        &self,
        ctx: &ConfigContext,
        available_keys: &[EnvelopeKey],
    ) -> super::Result<Vec<Milter>> {
        let mut milters = Vec::new();
        for id in self.sub_keys("session.data.milter") {
            let hostname = self
                .value_require(("session.data.milter", id, "hostname"))?
                .to_string();
            let port = self.property_require(("session.data.milter", id, "port"))?;
            milters.push(Milter {
                enable: self
                    .parse_if_block(("session.data.milter", id, "enable"), ctx, available_keys)?
                    .unwrap_or_default(),
                addrs: format!("{}:{}", hostname, port)
                    .to_socket_addrs()
                    .map_err(|err| format!("Unable to resolve milter hostname {hostname}: {err}"))?
                    .collect(),
                hostname,
                port,
                timeout_connect: self
                    .property_or_static(("session.data.milter", id, "timeout.connect"), "30s")?,
                timeout_command: self
                    .property_or_static(("session.data.milter", id, "timeout.command"), "30s")?,
                timeout_data: self
                    .property_or_static(("session.data.milter", id, "timeout.data"), "60s")?,
                tls: self.property_or_static(("session.data.milter", id, "tls"), "false")?,
                tls_allow_invalid_certs: self.property_or_static(
                    ("session.data.milter", id, "allow-invalid-certs"),
                    "false",
                )?,
                tempfail_on_error: self.property_or_static(
                    ("session.data.milter", id, "options.tempfail-on-error"),
                    "true",
                )?,
                max_frame_len: self.property_or_static(
                    ("session.data.milter", id, "options.max-response-size"),
                    "52428800",
                )?,
                protocol_version: match self.property_or_static::<u32>(
                    ("session.data.milter", id, "options.version"),
                    "6",
                )? {
                    6 => milter::Version::V6,
                    2 => milter::Version::V2,
                    v => return Err(format!("Unsupported milter protocol version: {}", v)),
                },
                flags_actions: self.property((
                    "session.data.milter",
                    id,
                    "options.flags.actions",
                ))?,
                flags_protocol: self.property((
                    "session.data.milter",
                    id,
                    "options.flags.protocol",
                ))?,
            })
        }
        Ok(milters)
    }
}

struct Mechanism {
    mechanism: u64,
}

impl ParseValue for Mechanism {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        Ok(Mechanism {
            mechanism: match value.to_ascii_uppercase().as_str() {
                "LOGIN" => AUTH_LOGIN,
                "PLAIN" => AUTH_PLAIN,
                "XOAUTH2" => AUTH_XOAUTH2,
                "OAUTHBEARER" => AUTH_OAUTHBEARER,
                /*"SCRAM-SHA-256-PLUS" => AUTH_SCRAM_SHA_256_PLUS,
                "SCRAM-SHA-256" => AUTH_SCRAM_SHA_256,
                "SCRAM-SHA-1-PLUS" => AUTH_SCRAM_SHA_1_PLUS,
                "SCRAM-SHA-1" => AUTH_SCRAM_SHA_1,
                "XOAUTH" => AUTH_XOAUTH,
                "9798-M-DSA-SHA1" => AUTH_9798_M_DSA_SHA1,
                "9798-M-ECDSA-SHA1" => AUTH_9798_M_ECDSA_SHA1,
                "9798-M-RSA-SHA1-ENC" => AUTH_9798_M_RSA_SHA1_ENC,
                "9798-U-DSA-SHA1" => AUTH_9798_U_DSA_SHA1,
                "9798-U-ECDSA-SHA1" => AUTH_9798_U_ECDSA_SHA1,
                "9798-U-RSA-SHA1-ENC" => AUTH_9798_U_RSA_SHA1_ENC,
                "EAP-AES128" => AUTH_EAP_AES128,
                "EAP-AES128-PLUS" => AUTH_EAP_AES128_PLUS,
                "ECDH-X25519-CHALLENGE" => AUTH_ECDH_X25519_CHALLENGE,
                "ECDSA-NIST256P-CHALLENGE" => AUTH_ECDSA_NIST256P_CHALLENGE,
                "EXTERNAL" => AUTH_EXTERNAL,
                "GS2-KRB5" => AUTH_GS2_KRB5,
                "GS2-KRB5-PLUS" => AUTH_GS2_KRB5_PLUS,
                "GSS-SPNEGO" => AUTH_GSS_SPNEGO,
                "GSSAPI" => AUTH_GSSAPI,
                "KERBEROS_V4" => AUTH_KERBEROS_V4,
                "KERBEROS_V5" => AUTH_KERBEROS_V5,
                "NMAS-SAMBA-AUTH" => AUTH_NMAS_SAMBA_AUTH,
                "NMAS_AUTHEN" => AUTH_NMAS_AUTHEN,
                "NMAS_LOGIN" => AUTH_NMAS_LOGIN,
                "NTLM" => AUTH_NTLM,
                "OAUTH10A" => AUTH_OAUTH10A,
                "OPENID20" => AUTH_OPENID20,
                "OTP" => AUTH_OTP,
                "SAML20" => AUTH_SAML20,
                "SECURID" => AUTH_SECURID,
                "SKEY" => AUTH_SKEY,
                "SPNEGO" => AUTH_SPNEGO,
                "SPNEGO-PLUS" => AUTH_SPNEGO_PLUS,
                "SXOVER-PLUS" => AUTH_SXOVER_PLUS,
                "CRAM-MD5" => AUTH_CRAM_MD5,
                "DIGEST-MD5" => AUTH_DIGEST_MD5,
                "ANONYMOUS" => AUTH_ANONYMOUS,*/
                _ => {
                    return Err(format!(
                        "Unsupported mechanism {:?} for property {:?}.",
                        value,
                        key.as_key()
                    ))
                }
            },
        })
    }
}
