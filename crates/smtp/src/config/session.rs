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

use crate::inbound::milter;

use crate::core::eval::*;

use super::{
    map_expr_token, throttle::ConfigThrottle, Auth, Connect, Data, Ehlo, Extensions, Mail, Milter,
    Pipe, Rcpt, SessionConfig, SessionThrottle, THROTTLE_AUTH_AS, THROTTLE_HELO_DOMAIN,
    THROTTLE_LISTENER, THROTTLE_LOCAL_IP, THROTTLE_RCPT, THROTTLE_RCPT_DOMAIN, THROTTLE_REMOTE_IP,
    THROTTLE_SENDER, THROTTLE_SENDER_DOMAIN,
};
use utils::{
    config::{
        if_block::IfBlock,
        utils::{AsKey, ConstantValue, NoConstants, ParseValue},
        Config,
    },
    expr::{Constant, ExpressionItem, Variable},
};

pub trait ConfigSession {
    fn parse_session_config(&self) -> super::Result<SessionConfig>;
    fn parse_session_throttle(&self) -> super::Result<SessionThrottle>;
    fn parse_session_connect(&self) -> super::Result<Connect>;
    fn parse_extensions(&self) -> super::Result<Extensions>;
    fn parse_session_ehlo(&self) -> super::Result<Ehlo>;
    fn parse_session_auth(&self) -> super::Result<Auth>;
    fn parse_session_mail(&self) -> super::Result<Mail>;
    fn parse_session_rcpt(&self) -> super::Result<Rcpt>;
    fn parse_session_data(&self) -> super::Result<Data>;
    fn parse_pipes(&self, available_keys: &[u32]) -> super::Result<Vec<Pipe>>;
    fn parse_milters(&self, available_keys: &[u32]) -> super::Result<Vec<Milter>>;
}

impl ConfigSession for Config {
    fn parse_session_config(&self) -> super::Result<SessionConfig> {
        let available_keys = &[V_LISTENER, V_REMOTE_IP, V_LOCAL_IP];

        Ok(SessionConfig {
            duration: self
                .parse_if_block("session.duration", |name| {
                    map_expr_token::<Duration>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(15 * 60))),
            transfer_limit: self
                .parse_if_block("session.transfer-limit", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(250 * 1024 * 1024)),
            timeout: self
                .parse_if_block("session.timeout", |name| {
                    map_expr_token::<Duration>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
            throttle: self.parse_session_throttle()?,
            connect: self.parse_session_connect()?,
            ehlo: self.parse_session_ehlo()?,
            auth: self.parse_session_auth()?,
            mail: self.parse_session_mail()?,
            rcpt: self.parse_session_rcpt()?,
            data: self.parse_session_data()?,
            extensions: self.parse_extensions()?,
        })
    }

    fn parse_session_throttle(&self) -> super::Result<SessionThrottle> {
        // Parse throttle
        let mut throttle = SessionThrottle {
            connect: Vec::new(),
            mail_from: Vec::new(),
            rcpt_to: Vec::new(),
        };
        let all_throttles = self.parse_throttle(
            "session.throttle",
            &[
                V_SENDER,
                V_SENDER_DOMAIN,
                V_RECIPIENT,
                V_RECIPIENT_DOMAIN,
                V_AUTHENTICATED_AS,
                V_LISTENER,
                V_REMOTE_IP,
                V_LOCAL_IP,
                V_PRIORITY,
                V_HELO_DOMAIN,
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
                || t.expr.items().iter().any(|c| {
                    matches!(
                        c,
                        ExpressionItem::Variable(V_RECIPIENT | V_RECIPIENT_DOMAIN)
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
                || t.expr.items().iter().any(|c| {
                    matches!(
                        c,
                        ExpressionItem::Variable(
                            V_SENDER | V_SENDER_DOMAIN | V_HELO_DOMAIN | V_AUTHENTICATED_AS
                        )
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

    fn parse_session_connect(&self) -> super::Result<Connect> {
        let available_keys = &[V_LISTENER, V_REMOTE_IP, V_LOCAL_IP];
        Ok(Connect {
            script: self
                .parse_if_block("session.connect.script", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_default(),
        })
    }

    fn parse_extensions(&self) -> super::Result<Extensions> {
        let available_keys = &[
            V_LISTENER,
            V_REMOTE_IP,
            V_LOCAL_IP,
            V_SENDER,
            V_SENDER_DOMAIN,
            V_AUTHENTICATED_AS,
        ];

        Ok(Extensions {
            pipelining: self
                .parse_if_block("session.extensions.pipelining", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
            dsn: self
                .parse_if_block("session.extensions.dsn", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
            vrfy: self
                .parse_if_block("session.extensions.vrfy", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
            expn: self
                .parse_if_block("session.extensions.expn", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
            chunking: self
                .parse_if_block("session.extensions.chunking", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
            requiretls: self
                .parse_if_block("session.extensions.requiretls", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
            no_soliciting: self
                .parse_if_block("session.extensions.no-soliciting", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(false)),
            future_release: self
                .parse_if_block("session.extensions.future-release", |name| {
                    map_expr_token::<Duration>(name, available_keys)
                })?
                .unwrap_or_default(),
            deliver_by: self
                .parse_if_block("session.extensions.deliver-by", |name| {
                    map_expr_token::<Duration>(name, available_keys)
                })?
                .unwrap_or_default(),
            mt_priority: self
                .parse_if_block("session.extensions.mt-priority", |name| {
                    map_expr_token::<MtPriority>(name, available_keys)
                })?
                .unwrap_or_default(),
        })
    }

    fn parse_session_ehlo(&self) -> super::Result<Ehlo> {
        let available_keys = &[V_LISTENER, V_REMOTE_IP, V_LOCAL_IP];

        Ok(Ehlo {
            script: self
                .parse_if_block("session.ehlo.script", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_default(),
            require: self
                .parse_if_block("session.ehlo.require", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
            reject_non_fqdn: self
                .parse_if_block("session.ehlo.reject-non-fqdn", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
        })
    }

    fn parse_session_auth(&self) -> super::Result<Auth> {
        let available_keys = &[V_LISTENER, V_REMOTE_IP, V_LOCAL_IP, V_HELO_DOMAIN];

        Ok(Auth {
            directory: self
                .parse_if_block("session.auth.directory", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_default(),
            mechanisms: self
                .parse_if_block("session.auth.mechanisms", |name| {
                    map_expr_token::<Mechanism>(name, available_keys)
                })?
                .unwrap_or_default(),
            require: self
                .parse_if_block("session.auth.require", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(false)),
            errors_max: self
                .parse_if_block("session.auth.errors.max", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(3)),
            errors_wait: self
                .parse_if_block("session.auth.errors.wait", |name| {
                    map_expr_token::<Duration>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(30))),
            allow_plain_text: self
                .parse_if_block("session.auth.allow-plain-text", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(false)),
            must_match_sender: self
                .parse_if_block("session.auth.must-match-sender", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
        })
    }

    fn parse_session_mail(&self) -> super::Result<Mail> {
        let available_keys = &[
            V_AUTHENTICATED_AS,
            V_LISTENER,
            V_REMOTE_IP,
            V_LOCAL_IP,
            V_HELO_DOMAIN,
            V_SENDER,
            V_SENDER_DOMAIN,
        ];
        Ok(Mail {
            script: self
                .parse_if_block("session.mail.script", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_default(),
            rewrite: self
                .parse_if_block("session.mail.rewrite", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_default(),
        })
    }

    fn parse_session_rcpt(&self) -> super::Result<Rcpt> {
        let available_keys = &[
            V_SENDER,
            V_SENDER_DOMAIN,
            V_AUTHENTICATED_AS,
            V_LISTENER,
            V_REMOTE_IP,
            V_LOCAL_IP,
            V_HELO_DOMAIN,
        ];
        let available_keys_full = &[
            V_SENDER,
            V_SENDER_DOMAIN,
            V_RECIPIENT,
            V_RECIPIENT_DOMAIN,
            V_AUTHENTICATED_AS,
            V_LISTENER,
            V_REMOTE_IP,
            V_LOCAL_IP,
            V_HELO_DOMAIN,
        ];
        Ok(Rcpt {
            script: self
                .parse_if_block("session.rcpt.script", |name| {
                    map_expr_token::<NoConstants>(name, available_keys_full)
                })?
                .unwrap_or_default(),
            relay: self
                .parse_if_block("session.rcpt.relay", |name| {
                    map_expr_token::<NoConstants>(name, available_keys_full)
                })?
                .unwrap_or_else(|| IfBlock::new(false)),
            directory: self
                .parse_if_block("session.rcpt.directory", |name| {
                    map_expr_token::<NoConstants>(name, available_keys_full)
                })?
                .unwrap_or_default(),
            errors_max: self
                .parse_if_block("session.rcpt.errors.max", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(10)),
            errors_wait: self
                .parse_if_block("session.rcpt.errors.wait", |name| {
                    map_expr_token::<Duration>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(30))),
            max_recipients: self
                .parse_if_block("session.rcpt.max-recipients", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(100)),
            rewrite: self
                .parse_if_block("session.rcpt.rewrite", |name| {
                    map_expr_token::<NoConstants>(name, available_keys_full)
                })?
                .unwrap_or_default(),
        })
    }

    fn parse_session_data(&self) -> super::Result<Data> {
        let available_keys = &[
            V_SENDER,
            V_SENDER_DOMAIN,
            V_AUTHENTICATED_AS,
            V_LISTENER,
            V_REMOTE_IP,
            V_LOCAL_IP,
            V_PRIORITY,
            V_HELO_DOMAIN,
        ];
        Ok(Data {
            script: self
                .parse_if_block("session.data.script", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_default(),
            max_messages: self
                .parse_if_block("session.data.limits.messages", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(10)),
            max_message_size: self
                .parse_if_block("session.data.limits.size", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(25 * 1024 * 1024)),
            max_received_headers: self
                .parse_if_block("session.data.limits.received-headers", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(50)),
            add_received: self
                .parse_if_block("session.data.add-headers.received", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
            add_received_spf: self
                .parse_if_block("session.data.add-headers.received-spf", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
            add_return_path: self
                .parse_if_block("session.data.add-headers.return-path", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
            add_auth_results: self
                .parse_if_block("session.data.add-headers.auth-results", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
            add_message_id: self
                .parse_if_block("session.data.add-headers.message-id", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
            add_date: self
                .parse_if_block("session.data.add-headers.date", |name| {
                    map_expr_token::<NoConstants>(name, available_keys)
                })?
                .unwrap_or_else(|| IfBlock::new(true)),
            pipe_commands: self.parse_pipes(available_keys)?,
            milters: self.parse_milters(available_keys)?,
        })
    }

    fn parse_pipes(&self, available_keys: &[u32]) -> super::Result<Vec<Pipe>> {
        let mut pipes = Vec::new();
        for id in self.sub_keys("session.data.pipe", "") {
            pipes.push(Pipe {
                command: self
                    .parse_if_block(("session.data.pipe", id, "command"), |name| {
                        map_expr_token::<NoConstants>(name, available_keys)
                    })?
                    .unwrap_or_default(),
                arguments: self
                    .parse_if_block(("session.data.pipe", id, "arguments"), |name| {
                        map_expr_token::<NoConstants>(name, available_keys)
                    })?
                    .unwrap_or_default(),
                timeout: self
                    .parse_if_block(("session.data.pipe", id, "timeout"), |name| {
                        map_expr_token::<Duration>(name, available_keys)
                    })?
                    .unwrap_or_else(|| IfBlock::new(Duration::from_secs(30))),
            })
        }
        Ok(pipes)
    }

    fn parse_milters(&self, available_keys: &[u32]) -> super::Result<Vec<Milter>> {
        let mut milters = Vec::new();
        for id in self.sub_keys("session.data.milter", "") {
            let hostname = self
                .value_require(("session.data.milter", id, "hostname"))?
                .to_string();
            let port = self.property_require(("session.data.milter", id, "port"))?;
            milters.push(Milter {
                enable: self
                    .parse_if_block(("session.data.milter", id, "enable"), |name| {
                        map_expr_token::<NoConstants>(name, available_keys)
                    })?
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

#[derive(Default)]
pub struct Mechanism(u64);

impl ParseValue for Mechanism {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        Ok(Mechanism(match value.to_ascii_uppercase().as_str() {
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
        }))
    }
}

impl<'x> TryFrom<Variable<'x>> for Mechanism {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::Integer(value) => Ok(Mechanism(value as u64)),
            Variable::Array(items) => {
                let mut mechanism = 0;

                for item in items {
                    match item {
                        Variable::Integer(value) => mechanism |= value as u64,
                        _ => return Err(()),
                    }
                }

                Ok(Mechanism(mechanism))
            }
            _ => Err(()),
        }
    }
}

impl From<Mechanism> for Constant {
    fn from(value: Mechanism) -> Self {
        Constant::Integer(value.0 as i64)
    }
}

impl ConstantValue for Mechanism {}

impl From<Mechanism> for u64 {
    fn from(value: Mechanism) -> Self {
        value.0
    }
}

impl From<u64> for Mechanism {
    fn from(value: u64) -> Self {
        Mechanism(value)
    }
}
