use std::{
    net::{SocketAddr, ToSocketAddrs},
    time::Duration,
};

use smtp_proto::*;
use utils::config::{
    utils::{AsKey, ParseValue},
    Config,
};

use crate::expr::{if_block::IfBlock, tokenizer::TokenMap, Constant, ConstantValue, Variable};

use self::throttle::parse_throttle;

use super::*;

pub struct SessionConfig {
    pub timeout: IfBlock,
    pub duration: IfBlock,
    pub transfer_limit: IfBlock,
    pub throttle: SessionThrottle,

    pub connect: Connect,
    pub ehlo: Ehlo,
    pub auth: Auth,
    pub mail: Mail,
    pub rcpt: Rcpt,
    pub data: Data,
    pub extensions: Extensions,
}

#[derive(Default)]
pub struct SessionThrottle {
    pub connect: Vec<Throttle>,
    pub mail_from: Vec<Throttle>,
    pub rcpt_to: Vec<Throttle>,
}

pub struct Connect {
    pub script: IfBlock,
    pub greeting: IfBlock,
}

pub struct Ehlo {
    pub script: IfBlock,
    pub require: IfBlock,
    pub reject_non_fqdn: IfBlock,
}

pub struct Extensions {
    pub pipelining: IfBlock,
    pub chunking: IfBlock,
    pub requiretls: IfBlock,
    pub dsn: IfBlock,
    pub vrfy: IfBlock,
    pub expn: IfBlock,
    pub no_soliciting: IfBlock,
    pub future_release: IfBlock,
    pub deliver_by: IfBlock,
    pub mt_priority: IfBlock,
}

pub struct Auth {
    pub directory: IfBlock,
    pub mechanisms: IfBlock,
    pub require: IfBlock,
    pub allow_plain_text: IfBlock,
    pub must_match_sender: IfBlock,
    pub errors_max: IfBlock,
    pub errors_wait: IfBlock,
}

pub struct Mail {
    pub script: IfBlock,
    pub rewrite: IfBlock,
}

pub struct Rcpt {
    pub script: IfBlock,
    pub relay: IfBlock,
    pub directory: IfBlock,
    pub rewrite: IfBlock,

    // Errors
    pub errors_max: IfBlock,
    pub errors_wait: IfBlock,

    // Limits
    pub max_recipients: IfBlock,

    // Catch-all and sub-adressing
    pub catch_all: AddressMapping,
    pub subaddressing: AddressMapping,
}

#[derive(Debug, Default)]
pub enum AddressMapping {
    Enable,
    Custom(IfBlock),
    #[default]
    Disable,
}

pub struct Data {
    pub script: IfBlock,
    pub pipe_commands: Vec<Pipe>,
    pub milters: Vec<Milter>,

    // Limits
    pub max_messages: IfBlock,
    pub max_message_size: IfBlock,
    pub max_received_headers: IfBlock,

    // Headers
    pub add_received: IfBlock,
    pub add_received_spf: IfBlock,
    pub add_return_path: IfBlock,
    pub add_auth_results: IfBlock,
    pub add_message_id: IfBlock,
    pub add_date: IfBlock,
}

// Ceci n'est pas une pipe
pub struct Pipe {
    pub command: IfBlock,
    pub arguments: IfBlock,
    pub timeout: IfBlock,
}

pub struct Milter {
    pub enable: IfBlock,
    pub addrs: Vec<SocketAddr>,
    pub hostname: String,
    pub port: u16,
    pub timeout_connect: Duration,
    pub timeout_command: Duration,
    pub timeout_data: Duration,
    pub tls: bool,
    pub tls_allow_invalid_certs: bool,
    pub tempfail_on_error: bool,
    pub max_frame_len: usize,
    pub protocol_version: MilterVersion,
    pub flags_actions: Option<u32>,
    pub flags_protocol: Option<u32>,
}

#[derive(Clone, Copy)]
pub enum MilterVersion {
    V2,
    V6,
}

impl SessionConfig {
    pub fn parse(config: &mut Config) -> Self {
        let has_conn_vars =
            TokenMap::default().with_smtp_variables(&[V_LISTENER, V_REMOTE_IP, V_LOCAL_IP]);
        let has_ehlo_hars = TokenMap::default().with_smtp_variables(&[
            V_LISTENER,
            V_REMOTE_IP,
            V_LOCAL_IP,
            V_HELO_DOMAIN,
        ]);
        let has_sender_vars = TokenMap::default().with_smtp_variables(&[
            V_LISTENER,
            V_REMOTE_IP,
            V_LOCAL_IP,
            V_SENDER,
            V_SENDER_DOMAIN,
            V_AUTHENTICATED_AS,
        ]);
        let has_rcpt_vars = TokenMap::default().with_smtp_variables(&[
            V_SENDER,
            V_SENDER_DOMAIN,
            V_RECIPIENT,
            V_RECIPIENT_DOMAIN,
            V_AUTHENTICATED_AS,
            V_LISTENER,
            V_REMOTE_IP,
            V_LOCAL_IP,
            V_HELO_DOMAIN,
        ]);

        let mut session = SessionConfig::default();
        session.rcpt.catch_all = AddressMapping::parse(config, "session.rcpt.catch-all");
        session.rcpt.subaddressing = AddressMapping::parse(config, "session.rcpt.sub-addressing");
        session.data.milters = config
            .sub_keys("session.data.milter", "")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|id| parse_milter(config, &id, &has_rcpt_vars))
            .collect();
        session.data.pipe_commands = config
            .sub_keys("session.data.pipe", "")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|id| parse_pipe(config, &id, &has_rcpt_vars))
            .collect();
        session.throttle = SessionThrottle::parse(config);

        session
    }
}

impl SessionThrottle {
    pub fn parse(config: &mut Config) -> Self {
        let mut throttle = SessionThrottle::default();
        let all_throttles = parse_throttle(
            config,
            "session.throttle",
            &TokenMap::default().with_smtp_variables(&[
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
            ]),
            THROTTLE_LISTENER
                | THROTTLE_REMOTE_IP
                | THROTTLE_LOCAL_IP
                | THROTTLE_AUTH_AS
                | THROTTLE_HELO_DOMAIN
                | THROTTLE_RCPT
                | THROTTLE_RCPT_DOMAIN
                | THROTTLE_SENDER
                | THROTTLE_SENDER_DOMAIN,
        );
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

        throttle
    }
}

fn parse_pipe(config: &mut Config, id: &str, token_map: &TokenMap) -> Option<Pipe> {
    Some(Pipe {
        command: IfBlock::try_parse(config, ("session.data.pipe", id, "command"), token_map)?,
        arguments: IfBlock::try_parse(config, ("session.data.pipe", id, "arguments"), token_map)?,
        timeout: IfBlock::try_parse(config, ("session.data.pipe", id, "timeout"), token_map)
            .unwrap_or_else(|| IfBlock::new(Duration::from_secs(30))),
    })
}

fn parse_milter(config: &mut Config, id: &str, token_map: &TokenMap) -> Option<Milter> {
    let hostname = config
        .value_require_(("session.data.milter", id, "hostname"))?
        .to_string();
    let port = config.property_require_(("session.data.milter", id, "port"))?;
    Some(Milter {
        enable: IfBlock::try_parse(config, ("session.data.milter", id, "enable"), token_map)
            .unwrap_or_default(),
        addrs: format!("{}:{}", hostname, port)
            .to_socket_addrs()
            .map_err(|err| {
                config.new_build_error(
                    ("session.data.milter", id, "hostname"),
                    format!("Unable to resolve milter hostname {hostname}: {err}"),
                )
            })
            .ok()?
            .collect(),
        hostname,
        port,
        timeout_connect: config
            .property_or_default_(("session.data.milter", id, "timeout.connect"), "30s")
            .unwrap_or_else(|| Duration::from_secs(30)),
        timeout_command: config
            .property_or_default_(("session.data.milter", id, "timeout.command"), "30s")
            .unwrap_or_else(|| Duration::from_secs(30)),
        timeout_data: config
            .property_or_default_(("session.data.milter", id, "timeout.data"), "60s")
            .unwrap_or_else(|| Duration::from_secs(60)),
        tls: config
            .property_or_default_(("session.data.milter", id, "tls"), "false")
            .unwrap_or_default(),
        tls_allow_invalid_certs: config
            .property_or_default_(("session.data.milter", id, "allow-invalid-certs"), "false")
            .unwrap_or_default(),
        tempfail_on_error: config
            .property_or_default_(
                ("session.data.milter", id, "options.tempfail-on-error"),
                "true",
            )
            .unwrap_or(true),
        max_frame_len: config
            .property_or_default_(
                ("session.data.milter", id, "options.max-response-size"),
                "52428800",
            )
            .unwrap_or(52428800),
        protocol_version: match config
            .property_or_default::<u32>(("session.data.milter", id, "options.version"), "6")
            .unwrap_or(6)
        {
            6 => MilterVersion::V6,
            2 => MilterVersion::V2,
            v => {
                config.new_parse_error(
                    ("session.data.milter", id, "options.version"),
                    format!("Unsupported milter protocol version {v}"),
                );
                MilterVersion::V6
            }
        },
        flags_actions: config.property_(("session.data.milter", id, "options.flags.actions")),
        flags_protocol: config.property_(("session.data.milter", id, "options.flags.protocol")),
    })
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout: IfBlock::new(Duration::from_secs(15 * 60)),
            duration: IfBlock::new(Duration::from_secs(5 * 60)),
            transfer_limit: IfBlock::new(250 * 1024 * 1024),
            throttle: SessionThrottle {
                connect: Default::default(),
                mail_from: Default::default(),
                rcpt_to: Default::default(),
            },
            connect: Connect {
                script: Default::default(),
                greeting: IfBlock::new("Stalwart ESMTP at your service".to_string()),
            },
            ehlo: Ehlo {
                script: Default::default(),
                require: IfBlock::new(true),
                reject_non_fqdn: IfBlock::new(true),
            },
            auth: Auth {
                directory: Default::default(),
                mechanisms: Default::default(),
                require: IfBlock::new(false),
                allow_plain_text: IfBlock::new(false),
                must_match_sender: IfBlock::new(true),
                errors_max: IfBlock::new(3),
                errors_wait: IfBlock::new(Duration::from_secs(30)),
            },
            mail: Mail {
                script: Default::default(),
                rewrite: Default::default(),
            },
            rcpt: Rcpt {
                script: Default::default(),
                relay: IfBlock::new(false),
                directory: Default::default(),
                rewrite: Default::default(),
                errors_max: IfBlock::new(10),
                errors_wait: IfBlock::new(Duration::from_secs(30)),
                max_recipients: IfBlock::new(100),
                catch_all: AddressMapping::Disable,
                subaddressing: AddressMapping::Disable,
            },
            data: Data {
                script: Default::default(),
                pipe_commands: Default::default(),
                milters: Default::default(),
                max_messages: IfBlock::new(10),
                max_message_size: IfBlock::new(25 * 1024 * 1024),
                max_received_headers: IfBlock::new(50),
                add_received: IfBlock::new(true),
                add_received_spf: IfBlock::new(true),
                add_return_path: IfBlock::new(true),
                add_auth_results: IfBlock::new(true),
                add_message_id: IfBlock::new(true),
                add_date: IfBlock::new(true),
            },
            extensions: Extensions {
                pipelining: IfBlock::new(true),
                chunking: IfBlock::new(true),
                requiretls: IfBlock::new(true),
                dsn: IfBlock::new(false),
                vrfy: IfBlock::new(false),
                expn: IfBlock::new(false),
                no_soliciting: IfBlock::new(false),
                future_release: Default::default(),
                deliver_by: Default::default(),
                mt_priority: Default::default(),
            },
        }
    }
}

#[derive(Default)]
pub struct Mechanism(u64);

impl ParseValue for Mechanism {
    fn parse_value(key: impl AsKey, value: &str) -> utils::config::Result<Self> {
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

impl ConstantValue for Mechanism {
    fn add_constants(token_map: &mut crate::expr::tokenizer::TokenMap) {
        todo!()
    }
}

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
