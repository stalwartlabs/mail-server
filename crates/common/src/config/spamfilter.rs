/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use ahash::AHashSet;
use mail_auth::common::resolver::ToReverseName;
use nlp::bayes::BayesClassifier;
use tokio::net::lookup_host;
use utils::{
    cache::CacheItemWeight,
    config::{Config, utils::ParseValue},
    glob::GlobMap,
};

use super::{Variable, functions::ResolveVariable, if_block::IfBlock, tokenizer::TokenMap};

#[derive(Debug, Clone, Default)]
pub struct SpamFilterConfig {
    pub enabled: bool,
    pub card_is_ham: bool,
    pub dnsbl: DnsBlConfig,
    pub rules: SpamFilterRules,
    pub lists: SpamFilterLists,
    pub pyzor: Option<PyzorConfig>,
    pub reputation: Option<ReputationConfig>,
    pub bayes: Option<BayesConfig>,
    pub scores: SpamFilterScoreConfig,
    pub expiry: SpamFilterExpiryConfig,
    pub headers: SpamFilterHeaderConfig,
}

#[derive(Debug, Clone)]
pub struct SpamFilterHeaderConfig {
    pub status: Option<String>,
    pub result: Option<String>,
    pub bayes_result: Option<String>,
    pub llm: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct SpamFilterScoreConfig {
    pub reject_threshold: f64,
    pub discard_threshold: f64,
    pub spam_threshold: f64,
}

#[derive(Debug, Clone, Default)]
pub struct SpamFilterExpiryConfig {
    pub grey_list: Option<u64>,
    pub trusted_reply: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct DnsBlConfig {
    pub max_ip_checks: usize,
    pub max_domain_checks: usize,
    pub max_email_checks: usize,
    pub max_url_checks: usize,
    pub servers: Vec<DnsBlServer>,
}

#[derive(Debug, Clone, Default)]
pub struct SpamFilterLists {
    pub file_extensions: GlobMap<FileExtension>,
    pub scores: GlobMap<SpamFilterAction<f64>>,
}

#[derive(Debug, Clone)]
pub enum SpamFilterAction<T> {
    Allow(T),
    Discard,
    Reject,
}

#[derive(Debug, Clone, Default)]
pub struct BayesConfig {
    pub classifier: BayesClassifier,
    pub auto_learn: bool,
    pub auto_learn_reply_ham: bool,
    pub auto_learn_spam_threshold: f64,
    pub auto_learn_ham_threshold: f64,
    pub auto_learn_card_is_ham: bool,
    pub score_spam: f64,
    pub score_ham: f64,
    pub account_score_spam: f64,
    pub account_score_ham: f64,
    pub account_classify: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ReputationConfig {
    pub expiry: u64,
    pub token_score: f64,
    pub factor: f64,
    pub ip_weight: f64,
    pub domain_weight: f64,
    pub asn_weight: f64,
    pub sender_weight: f64,
}

#[derive(Debug, Clone)]
pub struct PyzorConfig {
    pub address: SocketAddr,
    pub timeout: Duration,
    pub min_count: u64,
    pub min_wl_count: u64,
    pub ratio: f64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SpamFilterRules {
    pub url: Vec<IfBlock>,
    pub domain: Vec<IfBlock>,
    pub email: Vec<IfBlock>,
    pub ip: Vec<IfBlock>,
    pub header: Vec<IfBlock>,
    pub body: Vec<IfBlock>,
    pub any: Vec<IfBlock>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileExtension {
    pub known_types: AHashSet<String>,
    pub is_bad: bool,
    pub is_archive: bool,
    pub is_nz: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Element {
    Url,
    Domain,
    Email,
    Ip,
    Header,
    Body,
    #[default]
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Location {
    EnvelopeFrom,
    EnvelopeTo,
    HeaderDkimPass,
    HeaderReceived,
    HeaderFrom,
    HeaderReplyTo,
    HeaderSubject,
    HeaderTo,
    HeaderCc,
    HeaderBcc,
    HeaderMid,
    HeaderDnt,
    Ehlo,
    BodyText,
    BodyHtml,
    Attachment,
    Tcp,
}

#[derive(Debug, Clone)]
pub struct DnsBlServer {
    pub id: String,
    pub zone: IfBlock,
    pub scope: Element,
    pub tags: IfBlock,
}

impl SpamFilterConfig {
    pub async fn parse(config: &mut Config) -> Self {
        SpamFilterConfig {
            enabled: config
                .property_or_default("spam-filter.enable", "true")
                .unwrap_or(true),
            card_is_ham: config
                .property_or_default("spam-filter.card-is-ham", "true")
                .unwrap_or(true),
            dnsbl: DnsBlConfig::parse(config),
            rules: SpamFilterRules::parse(config),
            lists: SpamFilterLists::parse(config),
            pyzor: PyzorConfig::parse(config).await,
            reputation: ReputationConfig::parse(config),
            bayes: BayesConfig::parse(config),
            scores: SpamFilterScoreConfig::parse(config),
            expiry: SpamFilterExpiryConfig::parse(config),
            headers: SpamFilterHeaderConfig::parse(config),
        }
    }
}

impl SpamFilterRules {
    pub fn parse(config: &mut Config) -> SpamFilterRules {
        let mut rules = vec![];
        for id in config
            .sub_keys("spam-filter.rule", ".scope")
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
        {
            if let Some(rule) = SpamFilterRule::parse(config, id) {
                rules.push(rule);
            }
        }
        rules.sort_by(|a, b| a.priority.cmp(&b.priority));

        let mut result = SpamFilterRules::default();

        for rule in rules {
            match rule.scope {
                Element::Url => result.url.push(rule.rule),
                Element::Domain => result.domain.push(rule.rule),
                Element::Email => result.email.push(rule.rule),
                Element::Ip => result.ip.push(rule.rule),
                Element::Header => result.header.push(rule.rule),
                Element::Body => result.body.push(rule.rule),
                Element::Any => result.any.push(rule.rule),
            }
        }

        result
    }
}

struct SpamFilterRule {
    rule: IfBlock,
    priority: i32,
    scope: Element,
}

impl SpamFilterRule {
    pub fn parse(config: &mut Config, id: String) -> Option<Self> {
        let id = id.as_str();
        if !config
            .property_or_default(("spam-filter.rule", id, "enable"), "true")
            .unwrap_or(true)
        {
            return None;
        }
        let priority = config
            .property_or_default(("spam-filter.rule", id, "priority"), "0")
            .unwrap_or(0);
        let scope = config
            .property_or_default::<Element>(("spam-filter.rule", id, "scope"), "any")
            .unwrap_or_default();

        SpamFilterRule {
            rule: IfBlock::try_parse(
                config,
                ("spam-filter.rule", id, "condition"),
                &scope.token_map(),
            )?,
            scope,
            priority,
        }
        .into()
    }
}

impl DnsBlConfig {
    pub fn parse(config: &mut Config) -> Self {
        let mut servers = vec![];
        for id in config
            .sub_keys("spam-filter.dnsbl.server", ".scope")
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
        {
            if let Some(server) = DnsBlServer::parse(config, id) {
                servers.push(server);
            }
        }

        DnsBlConfig {
            max_ip_checks: config
                .property_or_default("spam-filter.dnsbl.max-check.ip", "50")
                .unwrap_or(20),
            max_domain_checks: config
                .property_or_default("spam-filter.dnsbl.max-check.domain", "50")
                .unwrap_or(20),
            max_email_checks: config
                .property_or_default("spam-filter.dnsbl.max-check.email", "50")
                .unwrap_or(20),
            max_url_checks: config
                .property_or_default("spam-filter.dnsbl.max-check.url", "50")
                .unwrap_or(20),
            servers,
        }
    }
}

impl DnsBlServer {
    pub fn parse(config: &mut Config, id: String) -> Option<Self> {
        let id_ = id.as_str();

        if !config
            .property_or_default(("spam-filter.dnsbl.server", id_, "enable"), "true")
            .unwrap_or(true)
        {
            return None;
        }

        let scope =
            config.property_require::<Element>(("spam-filter.dnsbl.server", id_, "scope"))?;

        DnsBlServer {
            zone: IfBlock::try_parse(
                config,
                ("spam-filter.dnsbl.server", id_, "zone"),
                &scope.token_map(),
            )?,
            scope,
            tags: IfBlock::try_parse(
                config,
                ("spam-filter.dnsbl.server", id_, "tag"),
                &Element::Ip.token_map(),
            )?,
            id,
        }
        .into()
    }
}

impl SpamFilterHeaderConfig {
    pub fn parse(config: &mut Config) -> Self {
        let mut header = SpamFilterHeaderConfig::default();

        for (typ, var) in [
            ("status", &mut header.status),
            ("result", &mut header.result),
            ("llm", &mut header.llm),
            ("bayes", &mut header.bayes_result),
        ] {
            if config
                .property_or_default(("spam-filter.header", typ, "enable"), "true")
                .unwrap_or(true)
            {
                if let Some(value) = config.value(("spam-filter.header", typ, "name")) {
                    let value = value.trim();
                    if !value.is_empty() {
                        *var = value.to_string().into();
                    }
                }
            }
        }

        header
    }
}

impl SpamFilterLists {
    pub fn parse(config: &mut Config) -> Self {
        let mut lists = SpamFilterLists {
            file_extensions: GlobMap::default(),
            scores: GlobMap::default(),
        };

        // Parse local lists
        let mut errors = vec![];
        for (key, value) in config.iterate_prefix("spam-filter.list") {
            if let Some((id, key)) = key
                .split_once('.')
                .filter(|(id, key)| !id.is_empty() && !key.is_empty())
            {
                match id {
                    "scores" => {
                        let action = match value.to_lowercase().as_str() {
                            "reject" => SpamFilterAction::Reject,
                            "discard" => SpamFilterAction::Discard,
                            score => match score.parse() {
                                Ok(score) => SpamFilterAction::Allow(score),
                                Err(err) => {
                                    errors.push((
                                        format!("spam-filter.list.{id}.{key}"),
                                        format!("Invalid score: {}", err),
                                    ));
                                    continue;
                                }
                            },
                        };
                        lists.scores.insert(key, action);
                    }
                    "file-extensions" => {
                        let mut ext = FileExtension::default();

                        for part in value.split('|') {
                            let part = part.trim();
                            match part {
                                "AR" => {
                                    ext.is_archive = true;
                                }
                                "NZ" => {
                                    ext.is_nz = true;
                                }
                                "BAD" => {
                                    ext.is_bad = true;
                                }
                                other => {
                                    if other.contains('/') {
                                        ext.known_types.insert(other.to_string());
                                    } else if !other.is_empty() {
                                        errors.push((
                                            format!("spam-filter.list.{id}.{key}"),
                                            format!("Invalid file extension: {}", other),
                                        ));
                                    }
                                }
                            }
                        }

                        lists.file_extensions.insert(key, ext);
                    }
                    _ => (),
                }
            }
        }

        for (key, error) in errors {
            config.new_parse_error(key, error);
        }

        lists
    }
}

impl PyzorConfig {
    pub async fn parse(config: &mut Config) -> Option<Self> {
        if !config
            .property_or_default("spam-filter.pyzor.enable", "true")
            .unwrap_or(true)
        {
            return None;
        }

        let port = config
            .property_or_default::<u16>("spam-filter.pyzor.port", "24441")
            .unwrap_or(24441);
        let host = config
            .value("spam-filter.pyzor.host")
            .unwrap_or("public.pyzor.org");
        let address = match lookup_host(format!("{host}:{port}"))
            .await
            .map(|mut a| a.next())
        {
            Ok(Some(address)) => address,
            Ok(None) => {
                config.new_build_error(
                    "spam-filter.pyzor.host",
                    "Invalid address: No addresses found.",
                );
                return None;
            }
            Err(err) => {
                config.new_build_error(
                    "spam-filter.pyzor.host",
                    format!("Invalid address: {}", err),
                );
                return None;
            }
        };

        PyzorConfig {
            address,
            timeout: config
                .property_or_default::<Duration>("spam-filter.pyzor.timeout", "5s")
                .unwrap_or(Duration::from_secs(5)),
            min_count: config
                .property_or_default("spam-filter.pyzor.count", "5")
                .unwrap_or(5),
            min_wl_count: config
                .property_or_default("spam-filter.pyzor.wl-count", "10")
                .unwrap_or(10),
            ratio: config
                .property_or_default("spam-filter.pyzor.ratio", "0.2")
                .unwrap_or(0.2),
        }
        .into()
    }
}

impl ReputationConfig {
    pub fn parse(config: &mut Config) -> Option<Self> {
        if !config
            .property_or_default("spam-filter.reputation.enable", "false")
            .unwrap_or(false)
        {
            return None;
        }

        ReputationConfig {
            expiry: config
                .property_or_default::<Duration>("spam-filter.reputation.expiry", "30d")
                .map(|d| d.as_secs())
                .unwrap_or(2592000),
            token_score: config
                .property_or_default("spam-filter.reputation.score", "0.98")
                .unwrap_or(0.98),
            factor: config
                .property_or_default("spam-filter.reputation.factor", "0.5")
                .unwrap_or(0.5),
            ip_weight: config
                .property_or_default("spam-filter.reputation.weight.ip", "0.2")
                .unwrap_or(0.2),
            domain_weight: config
                .property_or_default("spam-filter.reputation.weight.domain", "0.2")
                .unwrap_or(0.2),
            asn_weight: config
                .property_or_default("spam-filter.reputation.weight.asn", "0.1")
                .unwrap_or(0.1),
            sender_weight: config
                .property_or_default("spam-filter.reputation.weight.sender", "0.5")
                .unwrap_or(0.5),
        }
        .into()
    }
}

impl BayesConfig {
    pub fn parse(config: &mut Config) -> Option<Self> {
        if !config
            .property_or_default("spam-filter.bayes.enable", "true")
            .unwrap_or(true)
        {
            return None;
        }

        BayesConfig {
            classifier: BayesClassifier {
                min_token_hits: config
                    .property_or_default("spam-filter.bayes.classify.tokens.hits", "2")
                    .unwrap_or(2),
                min_tokens: config
                    .property_or_default("spam-filter.bayes.classify.tokens.min", "11")
                    .unwrap_or(11),
                min_prob_strength: config
                    .property_or_default("spam-filter.bayes.classify.strength", "0.05")
                    .unwrap_or(0.05),
                min_learns: config
                    .property_or_default("spam-filter.bayes.classify.learns", "200")
                    .unwrap_or(200),
                min_balance: config
                    .property_or_default("spam-filter.bayes.classify.balance", "0.9")
                    .unwrap_or(0.9),
            },
            auto_learn: config
                .property_or_default("spam-filter.bayes.auto-learn.enable", "true")
                .unwrap_or(true),
            auto_learn_reply_ham: config
                .property_or_default("spam-filter.bayes.auto-learn.trusted-reply", "true")
                .unwrap_or(true),
            auto_learn_spam_threshold: config
                .property_or_default("spam-filter.bayes.auto-learn.threshold.spam", "6.0")
                .unwrap_or(6.0),
            auto_learn_ham_threshold: config
                .property_or_default("spam-filter.bayes.auto-learn.threshold.ham", "-1.0")
                .unwrap_or(-2.0),
            score_spam: config
                .property_or_default("spam-filter.bayes.score.spam", "0.7")
                .unwrap_or(0.7),
            score_ham: config
                .property_or_default("spam-filter.bayes.score.ham", "0.5")
                .unwrap_or(0.5),
            account_classify: config
                .property_or_default("spam-filter.bayes.account.enable", "false")
                .unwrap_or(false),
            account_score_spam: config
                .property_or_default("spam-filter.bayes.account.score.spam", "0.7")
                .unwrap_or(0.7),
            account_score_ham: config
                .property_or_default("spam-filter.bayes.account.score.ham", "0.5")
                .unwrap_or(0.5),
            auto_learn_card_is_ham: config
                .property_or_default("spam-filter.bayes.auto-learn.card-is-ham", "true")
                .unwrap_or(true),
        }
        .into()
    }
}

impl SpamFilterScoreConfig {
    pub fn parse(config: &mut Config) -> Self {
        SpamFilterScoreConfig {
            reject_threshold: config
                .property("spam-filter.score.reject")
                .unwrap_or_default(),
            discard_threshold: config
                .property("spam-filter.score.discard")
                .unwrap_or_default(),
            spam_threshold: config
                .property_or_default("spam-filter.score.spam", "5.0")
                .unwrap_or(5.0),
        }
    }
}

impl SpamFilterExpiryConfig {
    pub fn parse(config: &mut Config) -> Self {
        SpamFilterExpiryConfig {
            grey_list: config
                .property::<Option<Duration>>("spam-filter.grey-list.duration")
                .unwrap_or_default()
                .map(|d| d.as_secs()),
            trusted_reply: config
                .property_or_default::<Option<Duration>>(
                    "spam-filter.trusted-reply.duration",
                    "30d",
                )
                .unwrap_or_default()
                .map(|d| d.as_secs()),
        }
    }
}

impl ParseValue for Element {
    fn parse_value(value: &str) -> utils::config::Result<Self> {
        match value {
            "url" => Ok(Element::Url),
            "domain" => Ok(Element::Domain),
            "email" => Ok(Element::Email),
            "ip" => Ok(Element::Ip),
            "header" => Ok(Element::Header),
            "body" => Ok(Element::Body),
            "any" | "message" => Ok(Element::Any),
            other => Err(format!("Invalid type {other:?}.",)),
        }
    }
}

impl Location {
    pub fn as_str(&self) -> &'static str {
        match self {
            Location::EnvelopeFrom => "env_from",
            Location::EnvelopeTo => "env_to",
            Location::HeaderDkimPass => "dkim_pass",
            Location::HeaderReceived => "received",
            Location::HeaderFrom => "from",
            Location::HeaderReplyTo => "reply_to",
            Location::HeaderSubject => "subject",
            Location::HeaderTo => "to",
            Location::HeaderCc => "cc",
            Location::HeaderBcc => "bcc",
            Location::HeaderMid => "message_id",
            Location::HeaderDnt => "dnt",
            Location::Ehlo => "ehlo",
            Location::BodyText => "body_text",
            Location::BodyHtml => "body_html",
            Location::Attachment => "attachment",
            Location::Tcp => "tcp",
        }
    }
}

impl Default for SpamFilterHeaderConfig {
    fn default() -> Self {
        SpamFilterHeaderConfig {
            status: "X-Spam-Status".to_string().into(),
            result: "X-Spam-Result".to_string().into(),
            bayes_result: "X-Spam-Bayes".to_string().into(),
            llm: "X-Spam-LLM".to_string().into(),
        }
    }
}

pub const V_SPAM_REMOTE_IP: u32 = 100;
pub const V_SPAM_REMOTE_IP_PTR: u32 = 101;
pub const V_SPAM_EHLO_DOMAIN: u32 = 102;
pub const V_SPAM_AUTH_AS: u32 = 103;
pub const V_SPAM_ASN: u32 = 104;
pub const V_SPAM_COUNTRY: u32 = 105;
pub const V_SPAM_IS_TLS: u32 = 106;
pub const V_SPAM_ENV_FROM: u32 = 108;
pub const V_SPAM_ENV_FROM_LOCAL: u32 = 109;
pub const V_SPAM_ENV_FROM_DOMAIN: u32 = 110;
pub const V_SPAM_ENV_TO: u32 = 111;
pub const V_SPAM_FROM: u32 = 112;
pub const V_SPAM_FROM_NAME: u32 = 113;
pub const V_SPAM_FROM_LOCAL: u32 = 114;
pub const V_SPAM_FROM_DOMAIN: u32 = 115;
pub const V_SPAM_REPLY_TO: u32 = 116;
pub const V_SPAM_REPLY_TO_NAME: u32 = 117;
pub const V_SPAM_REPLY_TO_LOCAL: u32 = 118;
pub const V_SPAM_REPLY_TO_DOMAIN: u32 = 119;
pub const V_SPAM_TO: u32 = 120;
pub const V_SPAM_TO_NAME: u32 = 121;
pub const V_SPAM_TO_LOCAL: u32 = 122;
pub const V_SPAM_TO_DOMAIN: u32 = 123;
pub const V_SPAM_CC: u32 = 124;
pub const V_SPAM_CC_NAME: u32 = 125;
pub const V_SPAM_CC_LOCAL: u32 = 126;
pub const V_SPAM_CC_DOMAIN: u32 = 127;
pub const V_SPAM_BCC: u32 = 128;
pub const V_SPAM_BCC_NAME: u32 = 129;
pub const V_SPAM_BCC_LOCAL: u32 = 130;
pub const V_SPAM_BCC_DOMAIN: u32 = 131;
pub const V_SPAM_BODY_TEXT: u32 = 132;
pub const V_SPAM_BODY_HTML: u32 = 133;
pub const V_SPAM_BODY_RAW: u32 = 134;
pub const V_SPAM_SUBJECT: u32 = 135;
pub const V_SPAM_SUBJECT_THREAD: u32 = 136;
pub const V_SPAM_LOCATION: u32 = 137;
pub const V_WORDS_SUBJECT: u32 = 138;
pub const V_WORDS_BODY: u32 = 139;

pub const V_RCPT_EMAIL: u32 = 0;
pub const V_RCPT_NAME: u32 = 1;
pub const V_RCPT_LOCAL: u32 = 2;
pub const V_RCPT_DOMAIN: u32 = 3;
pub const V_RCPT_DOMAIN_SLD: u32 = 4;

pub const V_URL_FULL: u32 = 0;
pub const V_URL_PATH_QUERY: u32 = 1;
pub const V_URL_PATH: u32 = 2;
pub const V_URL_QUERY: u32 = 3;
pub const V_URL_SCHEME: u32 = 4;
pub const V_URL_AUTHORITY: u32 = 5;
pub const V_URL_HOST: u32 = 6;
pub const V_URL_HOST_SLD: u32 = 7;
pub const V_URL_PORT: u32 = 8;

pub const V_HEADER_NAME: u32 = 0;
pub const V_HEADER_NAME_LOWER: u32 = 1;
pub const V_HEADER_VALUE: u32 = 2;
pub const V_HEADER_VALUE_LOWER: u32 = 3;
pub const V_HEADER_PROPERTY: u32 = 4;
pub const V_HEADER_RAW: u32 = 5;
pub const V_HEADER_RAW_LOWER: u32 = 6;

pub const V_IP: u32 = 0;
pub const V_IP_REVERSE: u32 = 1;
pub const V_IP_OCTETS: u32 = 2;
pub const V_IP_IS_V4: u32 = 3;
pub const V_IP_IS_V6: u32 = 4;

impl Element {
    pub fn token_map(&self) -> TokenMap {
        let map = TokenMap::default().with_variables_map([
            ("remote_ip", V_SPAM_REMOTE_IP),
            ("remote_ip.ptr", V_SPAM_REMOTE_IP_PTR),
            ("ehlo_domain", V_SPAM_EHLO_DOMAIN),
            ("auth_as", V_SPAM_AUTH_AS),
            ("asn", V_SPAM_ASN),
            ("country", V_SPAM_COUNTRY),
            ("is_tls", V_SPAM_IS_TLS),
            ("env_from", V_SPAM_ENV_FROM),
            ("env_from.local", V_SPAM_ENV_FROM_LOCAL),
            ("env_from.domain", V_SPAM_ENV_FROM_DOMAIN),
            ("env_to", V_SPAM_ENV_TO),
            ("from", V_SPAM_FROM),
            ("from.name", V_SPAM_FROM_NAME),
            ("from.local", V_SPAM_FROM_LOCAL),
            ("from.domain", V_SPAM_FROM_DOMAIN),
            ("reply_to", V_SPAM_REPLY_TO),
            ("reply_to.name", V_SPAM_REPLY_TO_NAME),
            ("reply_to.local", V_SPAM_REPLY_TO_LOCAL),
            ("reply_to.domain", V_SPAM_REPLY_TO_DOMAIN),
            ("to", V_SPAM_TO),
            ("to.name", V_SPAM_TO_NAME),
            ("to.local", V_SPAM_TO_LOCAL),
            ("to.domain", V_SPAM_TO_DOMAIN),
            ("cc", V_SPAM_CC),
            ("cc.name", V_SPAM_CC_NAME),
            ("cc.local", V_SPAM_CC_LOCAL),
            ("cc.domain", V_SPAM_CC_DOMAIN),
            ("bcc", V_SPAM_BCC),
            ("bcc.name", V_SPAM_BCC_NAME),
            ("bcc.local", V_SPAM_BCC_LOCAL),
            ("bcc.domain", V_SPAM_BCC_DOMAIN),
            ("body", V_SPAM_BODY_TEXT),
            ("body.text", V_SPAM_BODY_TEXT),
            ("body.html", V_SPAM_BODY_HTML),
            ("body.words", V_WORDS_BODY),
            ("body.raw", V_SPAM_BODY_RAW),
            ("subject", V_SPAM_SUBJECT),
            ("subject.thread", V_SPAM_SUBJECT_THREAD),
            ("subject.words", V_WORDS_SUBJECT),
            ("location", V_SPAM_LOCATION),
        ]);

        match self {
            Element::Url => map.with_variables_map([
                ("url", V_URL_FULL),
                ("value", V_URL_FULL),
                ("path_query", V_URL_PATH_QUERY),
                ("path", V_URL_PATH),
                ("query", V_URL_QUERY),
                ("scheme", V_URL_SCHEME),
                ("authority", V_URL_AUTHORITY),
                ("host", V_URL_HOST),
                ("sld", V_URL_HOST_SLD),
                ("port", V_URL_PORT),
            ]),
            Element::Email => map.with_variables_map([
                ("email", V_RCPT_EMAIL),
                ("value", V_RCPT_EMAIL),
                ("name", V_RCPT_NAME),
                ("local", V_RCPT_LOCAL),
                ("domain", V_RCPT_DOMAIN),
                ("sld", V_RCPT_DOMAIN_SLD),
            ]),
            Element::Ip => map.with_variables_map([
                ("ip", V_IP),
                ("value", V_IP),
                ("input", V_IP),
                ("reverse_ip", V_IP_REVERSE),
                ("ip_reverse", V_IP_REVERSE),
                ("octets", V_IP_OCTETS),
                ("is_v4", V_IP_IS_V4),
                ("is_v6", V_IP_IS_V6),
            ]),
            Element::Header => map.with_variables_map([
                ("name", V_HEADER_NAME),
                ("name_lower", V_HEADER_NAME_LOWER),
                ("value", V_HEADER_VALUE),
                ("value_lower", V_HEADER_VALUE_LOWER),
                ("email", V_HEADER_VALUE),
                ("email_lower", V_HEADER_VALUE_LOWER),
                ("attributes", V_HEADER_PROPERTY),
                ("raw", V_HEADER_RAW),
                ("raw_lower", V_HEADER_RAW_LOWER),
            ]),
            Element::Body | Element::Domain => {
                map.with_variables_map([("input", 0), ("value", 0), ("result", 0)])
            }
            Element::Any => map,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Element::Url => "url",
            Element::Domain => "domain",
            Element::Email => "email",
            Element::Ip => "ip",
            Element::Header => "header",
            Element::Body => "body",
            Element::Any => "any",
        }
    }
}

pub struct IpResolver {
    ip: IpAddr,
    ip_string: String,
    reverse: String,
    octets: Variable<'static>,
}

impl ResolveVariable for IpResolver {
    fn resolve_variable(&self, variable: u32) -> Variable<'_> {
        match variable {
            V_IP => self.ip_string.as_str().into(),
            V_IP_REVERSE => self.reverse.as_str().into(),
            V_IP_OCTETS => self.octets.clone(),
            V_IP_IS_V4 => Variable::Integer(self.ip.is_ipv4() as _),
            V_IP_IS_V6 => Variable::Integer(self.ip.is_ipv6() as _),
            _ => Variable::Integer(0),
        }
    }

    fn resolve_global(&self, _: &str) -> Variable<'_> {
        Variable::Integer(0)
    }
}

impl IpResolver {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip_string: ip.to_string(),
            reverse: ip.to_reverse_name(),
            octets: Variable::Array(match ip {
                IpAddr::V4(ipv4_addr) => ipv4_addr
                    .octets()
                    .iter()
                    .map(|o| Variable::Integer(*o as _))
                    .collect(),
                IpAddr::V6(ipv6_addr) => ipv6_addr
                    .octets()
                    .iter()
                    .map(|o| Variable::Integer(*o as _))
                    .collect(),
            }),
            ip,
        }
    }
}

impl CacheItemWeight for IpResolver {
    fn weight(&self) -> u64 {
        (std::mem::size_of::<IpResolver>() + self.ip_string.len() + self.reverse.len()) as u64
    }
}
