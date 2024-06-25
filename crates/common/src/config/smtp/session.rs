/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    net::{SocketAddr, ToSocketAddrs},
    str::FromStr,
    time::Duration,
};

use ahash::AHashSet;
use base64::{engine::general_purpose::STANDARD, Engine};
use hyper::{
    header::{HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    HeaderMap,
};
use smtp_proto::*;
use utils::config::{utils::ParseValue, Config};

use crate::{
    config::CONNECTION_VARS,
    expr::{if_block::IfBlock, tokenizer::TokenMap, *},
};

use self::{resolver::Policy, throttle::parse_throttle};

use super::*;

#[derive(Clone)]
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
    pub mta_sts_policy: Option<Policy>,

    pub milters: Vec<Milter>,
    pub hooks: Vec<MTAHook>,
}

#[derive(Default, Debug, Clone)]
pub struct SessionThrottle {
    pub connect: Vec<Throttle>,
    pub mail_from: Vec<Throttle>,
    pub rcpt_to: Vec<Throttle>,
}

#[derive(Clone)]
pub struct Connect {
    pub hostname: IfBlock,
    pub script: IfBlock,
    pub greeting: IfBlock,
}

#[derive(Clone)]
pub struct Ehlo {
    pub script: IfBlock,
    pub require: IfBlock,
    pub reject_non_fqdn: IfBlock,
}

#[derive(Clone)]
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

#[derive(Clone)]
pub struct Auth {
    pub directory: IfBlock,
    pub mechanisms: IfBlock,
    pub require: IfBlock,
    pub must_match_sender: IfBlock,
    pub errors_max: IfBlock,
    pub errors_wait: IfBlock,
}

#[derive(Clone)]
pub struct Mail {
    pub script: IfBlock,
    pub rewrite: IfBlock,
}

#[derive(Clone)]
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

#[derive(Debug, Default, Clone)]
pub enum AddressMapping {
    Enable,
    Custom(IfBlock),
    #[default]
    Disable,
}

#[derive(Clone)]
pub struct Data {
    pub script: IfBlock,
    pub pipe_commands: Vec<Pipe>,

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
#[derive(Clone)]
pub struct Pipe {
    pub command: IfBlock,
    pub arguments: IfBlock,
    pub timeout: IfBlock,
}

#[derive(Clone)]
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
    pub run_on_stage: AHashSet<Stage>,
}

#[derive(Clone, Copy)]
pub enum MilterVersion {
    V2,
    V6,
}

#[derive(Clone)]
pub struct MTAHook {
    pub enable: IfBlock,
    pub url: String,
    pub timeout: Duration,
    pub headers: HeaderMap,
    pub tls_allow_invalid_certs: bool,
    pub tempfail_on_error: bool,
    pub run_on_stage: AHashSet<Stage>,
    pub max_response_size: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    Connect,
    Ehlo,
    Auth,
    Mail,
    Rcpt,
    Data,
}

impl SessionConfig {
    pub fn parse(config: &mut Config) -> Self {
        let has_conn_vars = TokenMap::default().with_variables(CONNECTION_VARS);
        let has_ehlo_hars = TokenMap::default().with_variables(SMTP_EHLO_VARS);
        let has_sender_vars = TokenMap::default().with_variables(SMTP_MAIL_FROM_VARS);
        let has_rcpt_vars = TokenMap::default().with_variables(SMTP_RCPT_TO_VARS);
        let mt_priority_vars = has_sender_vars.clone().with_constants::<MtPriority>();
        let mechanisms_vars = has_ehlo_hars.clone().with_constants::<Mechanism>();

        let mut session = SessionConfig::default();
        session.rcpt.catch_all = AddressMapping::parse(config, "session.rcpt.catch-all");
        session.rcpt.subaddressing = AddressMapping::parse(config, "session.rcpt.sub-addressing");
        session.milters = config
            .sub_keys("session.milter", ".hostname")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|id| parse_milter(config, &id, &has_rcpt_vars))
            .collect();
        session.hooks = config
            .sub_keys("session.hook", ".url")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|id| parse_hooks(config, &id, &has_rcpt_vars))
            .collect();
        session.data.pipe_commands = config
            .sub_keys("session.data.pipe", "")
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|id| parse_pipe(config, &id, &has_rcpt_vars))
            .collect();
        session.throttle = SessionThrottle::parse(config);
        session.mta_sts_policy = Policy::try_parse(config);

        for (value, key, token_map) in [
            (&mut session.duration, "session.duration", &has_conn_vars),
            (
                &mut session.transfer_limit,
                "session.transfer-limit",
                &has_conn_vars,
            ),
            (&mut session.timeout, "session.timeout", &has_conn_vars),
            (
                &mut session.connect.script,
                "session.connect.script",
                &has_conn_vars,
            ),
            (
                &mut session.connect.hostname,
                "session.connect.hostname",
                &has_conn_vars,
            ),
            (
                &mut session.connect.greeting,
                "session.connect.greeting",
                &has_conn_vars,
            ),
            (
                &mut session.extensions.pipelining,
                "session.extensions.pipelining",
                &has_sender_vars,
            ),
            (
                &mut session.extensions.dsn,
                "session.extensions.dsn",
                &has_sender_vars,
            ),
            (
                &mut session.extensions.vrfy,
                "session.extensions.vrfy",
                &has_sender_vars,
            ),
            (
                &mut session.extensions.expn,
                "session.extensions.expn",
                &has_sender_vars,
            ),
            (
                &mut session.extensions.chunking,
                "session.extensions.chunking",
                &has_sender_vars,
            ),
            (
                &mut session.extensions.requiretls,
                "session.extensions.requiretls",
                &has_sender_vars,
            ),
            (
                &mut session.extensions.no_soliciting,
                "session.extensions.no-soliciting",
                &has_sender_vars,
            ),
            (
                &mut session.extensions.future_release,
                "session.extensions.future-release",
                &has_sender_vars,
            ),
            (
                &mut session.extensions.deliver_by,
                "session.extensions.deliver-by",
                &has_sender_vars,
            ),
            (
                &mut session.extensions.mt_priority,
                "session.extensions.mt-priority",
                &mt_priority_vars,
            ),
            (
                &mut session.ehlo.script,
                "session.ehlo.script",
                &has_conn_vars,
            ),
            (
                &mut session.ehlo.require,
                "session.ehlo.require",
                &has_conn_vars,
            ),
            (
                &mut session.ehlo.reject_non_fqdn,
                "session.ehlo.reject-non-fqdn",
                &has_conn_vars,
            ),
            (
                &mut session.auth.directory,
                "session.auth.directory",
                &has_ehlo_hars,
            ),
            (
                &mut session.auth.mechanisms,
                "session.auth.mechanisms",
                &mechanisms_vars,
            ),
            (
                &mut session.auth.require,
                "session.auth.require",
                &has_ehlo_hars,
            ),
            (
                &mut session.auth.errors_max,
                "session.auth.errors.total",
                &has_ehlo_hars,
            ),
            (
                &mut session.auth.errors_wait,
                "session.auth.errors.wait",
                &has_ehlo_hars,
            ),
            (
                &mut session.auth.must_match_sender,
                "session.auth.must-match-sender",
                &has_sender_vars,
            ),
            (
                &mut session.mail.script,
                "session.mail.script",
                &has_sender_vars,
            ),
            (
                &mut session.mail.rewrite,
                "session.mail.rewrite",
                &has_sender_vars,
            ),
            (
                &mut session.rcpt.script,
                "session.rcpt.script",
                &has_rcpt_vars,
            ),
            (
                &mut session.rcpt.relay,
                "session.rcpt.relay",
                &has_rcpt_vars,
            ),
            (
                &mut session.rcpt.directory,
                "session.rcpt.directory",
                &has_rcpt_vars,
            ),
            (
                &mut session.rcpt.errors_max,
                "session.rcpt.errors.total",
                &has_sender_vars,
            ),
            (
                &mut session.rcpt.errors_wait,
                "session.rcpt.errors.wait",
                &has_sender_vars,
            ),
            (
                &mut session.rcpt.max_recipients,
                "session.rcpt.max-recipients",
                &has_sender_vars,
            ),
            (
                &mut session.rcpt.rewrite,
                "session.rcpt.rewrite",
                &has_rcpt_vars,
            ),
            (
                &mut session.data.script,
                "session.data.script",
                &has_rcpt_vars,
            ),
            (
                &mut session.data.max_messages,
                "session.data.limits.messages",
                &has_rcpt_vars,
            ),
            (
                &mut session.data.max_message_size,
                "session.data.limits.size",
                &has_rcpt_vars,
            ),
            (
                &mut session.data.max_received_headers,
                "session.data.limits.received-headers",
                &has_rcpt_vars,
            ),
            (
                &mut session.data.add_received,
                "session.data.add-headers.received",
                &has_rcpt_vars,
            ),
            (
                &mut session.data.add_received_spf,
                "session.data.add-headers.received-spf",
                &has_rcpt_vars,
            ),
            (
                &mut session.data.add_return_path,
                "session.data.add-headers.return-path",
                &has_rcpt_vars,
            ),
            (
                &mut session.data.add_auth_results,
                "session.data.add-headers.auth-results",
                &has_rcpt_vars,
            ),
            (
                &mut session.data.add_message_id,
                "session.data.add-headers.message-id",
                &has_rcpt_vars,
            ),
            (
                &mut session.data.add_date,
                "session.data.add-headers.date",
                &has_rcpt_vars,
            ),
        ] {
            if let Some(if_block) = IfBlock::try_parse(config, key, token_map) {
                *value = if_block;
            }
        }

        session
    }
}

impl SessionThrottle {
    pub fn parse(config: &mut Config) -> Self {
        let mut throttle = SessionThrottle::default();
        let all_throttles = parse_throttle(
            config,
            "session.throttle",
            &TokenMap::default().with_variables(SMTP_RCPT_TO_VARS),
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
            .unwrap_or_else(|| {
                IfBlock::new::<()>(format!("session.data.pipe.{id}.timeout"), [], "30s")
            }),
    })
}

fn parse_milter(config: &mut Config, id: &str, token_map: &TokenMap) -> Option<Milter> {
    let hostname = config
        .value_require(("session.milter", id, "hostname"))?
        .to_string();
    let port = config.property_require(("session.milter", id, "port"))?;
    Some(Milter {
        enable: IfBlock::try_parse(config, ("session.milter", id, "enable"), token_map)
            .unwrap_or_else(|| {
                IfBlock::new::<()>(format!("session.milter.{id}.enable"), [], "false")
            }),
        addrs: format!("{}:{}", hostname, port)
            .to_socket_addrs()
            .map_err(|err| {
                config.new_build_error(
                    ("session.milter", id, "hostname"),
                    format!("Unable to resolve milter hostname {hostname}: {err}"),
                )
            })
            .ok()?
            .collect(),
        hostname,
        port,
        timeout_connect: config
            .property_or_default(("session.milter", id, "timeout.connect"), "30s")
            .unwrap_or_else(|| Duration::from_secs(30)),
        timeout_command: config
            .property_or_default(("session.milter", id, "timeout.command"), "30s")
            .unwrap_or_else(|| Duration::from_secs(30)),
        timeout_data: config
            .property_or_default(("session.milter", id, "timeout.data"), "60s")
            .unwrap_or_else(|| Duration::from_secs(60)),
        tls: config
            .property_or_default(("session.milter", id, "tls"), "false")
            .unwrap_or_default(),
        tls_allow_invalid_certs: config
            .property_or_default(("session.milter", id, "allow-invalid-certs"), "false")
            .unwrap_or_default(),
        tempfail_on_error: config
            .property_or_default(("session.milter", id, "options.tempfail-on-error"), "true")
            .unwrap_or(true),
        max_frame_len: config
            .property_or_default(
                ("session.milter", id, "options.max-response-size"),
                "52428800",
            )
            .unwrap_or(52428800),
        protocol_version: match config
            .property_or_default::<u32>(("session.milter", id, "options.version"), "6")
            .unwrap_or(6)
        {
            6 => MilterVersion::V6,
            2 => MilterVersion::V2,
            v => {
                config.new_parse_error(
                    ("session.milter", id, "options.version"),
                    format!("Unsupported milter protocol version {v}"),
                );
                MilterVersion::V6
            }
        },
        flags_actions: config.property(("session.milter", id, "options.flags.actions")),
        flags_protocol: config.property(("session.milter", id, "options.flags.protocol")),
        run_on_stage: parse_stages(config, "session.milter", id),
    })
}

fn parse_hooks(config: &mut Config, id: &str, token_map: &TokenMap) -> Option<MTAHook> {
    let mut headers = HeaderMap::new();

    for (header, value) in config
        .values(("session.hook", id, "headers"))
        .map(|(_, v)| {
            if let Some((k, v)) = v.split_once(':') {
                Ok((
                    HeaderName::from_str(k.trim()).map_err(|err| {
                        format!(
                            "Invalid header found in property \"session.hook.{id}.headers\": {err}",
                        )
                    })?,
                    HeaderValue::from_str(v.trim()).map_err(|err| {
                        format!(
                            "Invalid header found in property \"session.hook.{id}.headers\": {err}",
                        )
                    })?,
                ))
            } else {
                Err(format!(
                    "Invalid header found in property \"session.hook.{id}.headers\": {v}",
                ))
            }
        })
        .collect::<Result<Vec<(HeaderName, HeaderValue)>, String>>()
        .map_err(|e| config.new_parse_error(("session.hook", id, "headers"), e))
        .unwrap_or_default()
    {
        headers.insert(header, value);
    }

    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
    if let (Some(name), Some(secret)) = (
        config.value(("session.hook", id, "auth.username")),
        config.value(("session.hook", id, "auth.secret")),
    ) {
        headers.insert(
            AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{}:{}", name, secret)))
                .parse()
                .unwrap(),
        );
    }

    Some(MTAHook {
        enable: IfBlock::try_parse(config, ("session.hook", id, "enable"), token_map)
            .unwrap_or_else(|| {
                IfBlock::new::<()>(format!("session.hook.{id}.enable"), [], "false")
            }),
        url: config
            .value_require(("session.hook", id, "url"))?
            .to_string(),
        timeout: config
            .property_or_default(("session.hook", id, "timeout"), "30s")
            .unwrap_or_else(|| Duration::from_secs(30)),
        tls_allow_invalid_certs: config
            .property_or_default(("session.hook", id, "allow-invalid-certs"), "false")
            .unwrap_or_default(),
        tempfail_on_error: config
            .property_or_default(("session.hook", id, "options.tempfail-on-error"), "true")
            .unwrap_or(true),
        run_on_stage: parse_stages(config, "session.hook", id),
        max_response_size: config
            .property_or_default(
                ("session.hook", id, "options.max-response-size"),
                "52428800",
            )
            .unwrap_or(52428800),
        headers,
    })
}

fn parse_stages(config: &mut Config, prefix: &str, id: &str) -> AHashSet<Stage> {
    let mut stages = AHashSet::default();
    let mut invalid = Vec::new();
    for (_, value) in config.values((prefix, id, "stages")) {
        let value = value.to_ascii_lowercase();
        let state = match value.as_str() {
            "connect" => Stage::Connect,
            "ehlo" => Stage::Ehlo,
            "auth" => Stage::Auth,
            "mail" => Stage::Mail,
            "rcpt" => Stage::Rcpt,
            "data" => Stage::Data,
            _ => {
                invalid.push(value);
                continue;
            }
        };
        stages.insert(state);
    }

    if !invalid.is_empty() {
        config.new_parse_error(
            (prefix, id, "stages"),
            format!("Invalid stages: {}", invalid.join(", ")),
        );
    }

    if stages.is_empty() {
        stages.insert(Stage::Data);
    }

    stages
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout: IfBlock::new::<()>("session.timeout", [], "5m"),
            duration: IfBlock::new::<()>("session.duration", [], "10m"),
            transfer_limit: IfBlock::new::<()>("session.transfer-limit", [], "262144000"),
            throttle: SessionThrottle {
                connect: Default::default(),
                mail_from: Default::default(),
                rcpt_to: Default::default(),
            },
            connect: Connect {
                hostname: IfBlock::new::<()>(
                    "server.connect.hostname",
                    [],
                    "key_get('default', 'hostname')",
                ),
                script: IfBlock::empty("session.connect.script"),
                greeting: IfBlock::new::<()>(
                    "session.connect.greeting",
                    [],
                    "key_get('default', 'hostname') + ' Stalwart ESMTP at your service'",
                ),
            },
            ehlo: Ehlo {
                script: IfBlock::empty("session.ehlo.script"),
                require: IfBlock::new::<()>("session.ehlo.require", [], "true"),
                reject_non_fqdn: IfBlock::new::<()>(
                    "session.ehlo.reject-non-fqdn",
                    [("local_port == 25", "true")],
                    "false",
                ),
            },
            auth: Auth {
                directory: IfBlock::new::<()>(
                    "session.auth.directory",
                    #[cfg(feature = "test_mode")]
                    [],
                    #[cfg(not(feature = "test_mode"))]
                    [("local_port != 25", "'*'")],
                    "false",
                ),
                mechanisms: IfBlock::new::<Mechanism>(
                    "session.auth.mechanisms",
                    [("local_port != 25 && is_tls", "[plain, login]")],
                    "false",
                ),
                require: IfBlock::new::<()>(
                    "session.auth.require",
                    #[cfg(feature = "test_mode")]
                    [],
                    #[cfg(not(feature = "test_mode"))]
                    [("local_port != 25", "true")],
                    "false",
                ),
                must_match_sender: IfBlock::new::<()>("session.auth.must-match-sender", [], "true"),
                errors_max: IfBlock::new::<()>("session.auth.errors.total", [], "3"),
                errors_wait: IfBlock::new::<()>("session.auth.errors.wait", [], "5s"),
            },
            mail: Mail {
                script: IfBlock::empty("session.mail.script"),
                rewrite: IfBlock::empty("session.mail.rewrite"),
            },
            rcpt: Rcpt {
                script: IfBlock::empty("session.rcpt.script"),
                relay: IfBlock::new::<()>(
                    "session.rcpt.relay",
                    [("!is_empty(authenticated_as)", "true")],
                    "false",
                ),
                directory: IfBlock::new::<()>(
                    "session.rcpt.directory",
                    [],
                    #[cfg(feature = "test_mode")]
                    "false",
                    #[cfg(not(feature = "test_mode"))]
                    "'*'",
                ),
                rewrite: IfBlock::empty("session.rcpt.rewrite"),
                errors_max: IfBlock::new::<()>("session.rcpt.errors.total", [], "5"),
                errors_wait: IfBlock::new::<()>("session.rcpt.errors.wait", [], "5s"),
                max_recipients: IfBlock::new::<()>("session.rcpt.max-recipients", [], "100"),
                catch_all: AddressMapping::Enable,
                subaddressing: AddressMapping::Enable,
            },
            data: Data {
                #[cfg(feature = "test_mode")]
                script: IfBlock::empty("session.data.script"),
                #[cfg(not(feature = "test_mode"))]
                script: IfBlock::new::<()>(
                    "session.data.script",
                    [("is_empty(authenticated_as)", "'spam-filter'")],
                    "'track-replies'",
                ),
                pipe_commands: Default::default(),
                max_messages: IfBlock::new::<()>("session.data.limits.messages", [], "10"),
                max_message_size: IfBlock::new::<()>("session.data.limits.size", [], "104857600"),
                max_received_headers: IfBlock::new::<()>(
                    "session.data.limits.received-headers",
                    [],
                    "50",
                ),
                add_received: IfBlock::new::<()>(
                    "session.data.add-headers.received",
                    [("local_port == 25", "true")],
                    "false",
                ),
                add_received_spf: IfBlock::new::<()>(
                    "session.data.add-headers.received-spf",
                    [("local_port == 25", "true")],
                    "false",
                ),
                add_return_path: IfBlock::new::<()>(
                    "session.data.add-headers.return-path",
                    [("local_port == 25", "true")],
                    "false",
                ),
                add_auth_results: IfBlock::new::<()>(
                    "session.data.add-headers.auth-results",
                    [("local_port == 25", "true")],
                    "false",
                ),
                add_message_id: IfBlock::new::<()>(
                    "session.data.add-headers.message-id",
                    [("local_port == 25", "true")],
                    "false",
                ),
                add_date: IfBlock::new::<()>(
                    "session.data.add-headers.date",
                    [("local_port == 25", "true")],
                    "false",
                ),
            },
            extensions: Extensions {
                pipelining: IfBlock::new::<()>("session.extensions.pipelining", [], "true"),
                chunking: IfBlock::new::<()>("session.extensions.chunking", [], "true"),
                requiretls: IfBlock::new::<()>("session.extensions.requiretls", [], "true"),
                dsn: IfBlock::new::<()>(
                    "session.extensions.dsn",
                    [("!is_empty(authenticated_as)", "true")],
                    "false",
                ),
                vrfy: IfBlock::new::<()>(
                    "session.extensions.vrfy",
                    [("!is_empty(authenticated_as)", "true")],
                    "false",
                ),
                expn: IfBlock::new::<()>(
                    "session.extensions.expn",
                    [("!is_empty(authenticated_as)", "true")],
                    "false",
                ),
                no_soliciting: IfBlock::new::<()>("session.extensions.no-soliciting", [], "''"),
                future_release: IfBlock::new::<()>(
                    "session.extensions.future-release",
                    [("!is_empty(authenticated_as)", "7d")],
                    "false",
                ),
                deliver_by: IfBlock::new::<()>(
                    "session.extensions.deliver-by",
                    [("!is_empty(authenticated_as)", "15d")],
                    "false",
                ),
                mt_priority: IfBlock::new::<MtPriority>(
                    "session.extensions.mt-priority",
                    [("!is_empty(authenticated_as)", "mixer")],
                    "false",
                ),
            },
            mta_sts_policy: None,
            milters: Default::default(),
            hooks: Default::default(),
        }
    }
}

#[derive(Default)]
pub struct Mechanism(u64);

impl ParseValue for Mechanism {
    fn parse_value(value: &str) -> utils::config::Result<Self> {
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
            _ => return Err(format!("Unsupported mechanism {:?}.", value)),
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
        token_map
            .add_constant("login", Mechanism(AUTH_LOGIN))
            .add_constant("plain", Mechanism(AUTH_PLAIN))
            .add_constant("xoauth2", Mechanism(AUTH_XOAUTH2))
            .add_constant("oauthbearer", Mechanism(AUTH_OAUTHBEARER));
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

impl<'x> TryFrom<Variable<'x>> for MtPriority {
    type Error = ();

    fn try_from(value: Variable<'x>) -> Result<Self, Self::Error> {
        match value {
            Variable::Integer(value) => match value {
                2 => Ok(MtPriority::Mixer),
                3 => Ok(MtPriority::Stanag4406),
                4 => Ok(MtPriority::Nsep),
                _ => Err(()),
            },
            Variable::String(value) => MtPriority::parse_value(&value).map_err(|_| ()),
            _ => Err(()),
        }
    }
}

impl From<MtPriority> for Constant {
    fn from(value: MtPriority) -> Self {
        Constant::Integer(match value {
            MtPriority::Mixer => 2,
            MtPriority::Stanag4406 => 3,
            MtPriority::Nsep => 4,
        })
    }
}

impl ConstantValue for MtPriority {
    fn add_constants(token_map: &mut TokenMap) {
        token_map
            .add_constant("mixer", MtPriority::Mixer)
            .add_constant("stanag4406", MtPriority::Stanag4406)
            .add_constant("nsep", MtPriority::Nsep);
    }
}
