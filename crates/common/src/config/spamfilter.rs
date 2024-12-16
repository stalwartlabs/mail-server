/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{net::SocketAddr, time::Duration};

use ahash::AHashSet;
use nlp::bayes::BayesClassifier;
use utils::{
    config::Config,
    glob::{GlobMap, GlobSet},
};

use super::if_block::IfBlock;

#[derive(Debug, Clone, Default)]
pub struct SpamFilterConfig {
    pub max_rbl_ip_checks: usize,
    pub max_rbl_domain_checks: usize,
    pub max_rbl_email_checks: usize,
    pub max_rbl_url_checks: usize,
    pub trusted_reply: Option<u64>,

    pub rules: Vec<SpamFilterRule>,
    pub greylist_duration: Option<Duration>,
    pub pyzor: Option<PyzorConfig>,
    pub reputation: Option<ReputationConfig>,
    pub bayes: Option<BayesConfig>,

    pub score_reject_threshold: f64,
    pub score_discard_threshold: f64,
    pub score_spam_threshold: f64,

    pub list_dmarc_allow: GlobSet,
    pub list_spf_dkim_allow: GlobSet,
    pub list_freemail_providers: GlobSet,
    pub list_disposable_providers: GlobSet,
    pub list_trusted_domains: GlobSet,
    pub list_url_redirectors: GlobSet,
    pub list_file_extensions: GlobMap<FileExtension>,
    pub list_scores: GlobMap<SpamFilterAction<f64>>,
    pub list_spamtraps: GlobSet,

    pub remote_lists: Vec<RemoteListConfig>,
    pub dnsbls: Vec<DnsblConfig>,
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
    pub score_spam: f64,
    pub score_ham: f64,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpamFilterRule {
    pub rule: IfBlock,
    pub scope: Option<Element>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileExtension {
    pub known_types: AHashSet<String>,
    pub is_bad: bool,
    pub is_archive: bool,
    pub is_nz: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Element {
    Url,
    Domain,
    Email,
    Ip,
    Header,
    Body,
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
    Ehlo,
    BodyText,
    BodyHtml,
    Attachment,
    Tcp,
}

#[derive(Debug, Clone)]
pub struct RemoteListConfig {
    pub id: String,
    pub url: String,
    pub retry: Duration,       // 1 hour
    pub refresh: Duration,     // 12h openphish, 6h phishtank
    pub timeout: Duration,     // 10s
    pub max_size: usize,       // 10MB
    pub max_entries: usize,    // 100000
    pub max_entry_size: usize, // 256
    pub format: RemoteListFormat,
    pub element: Element,
    pub tag: String,
}

#[derive(Debug, Clone)]
pub struct DnsblConfig {
    pub id: String,
    pub zone: IfBlock,
    pub element: Element,
    pub tags: IfBlock,
}

#[derive(Debug, Clone)]
pub enum RemoteListFormat {
    List,
    Csv {
        column: u32,
        separator: char,
        skip_first: bool,
    },
}

impl SpamFilterConfig {
    pub fn parse(config: &mut Config) -> Self {
        SpamFilterConfig::default()
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
            Location::Ehlo => "ehlo",
            Location::BodyText => "body_text",
            Location::BodyHtml => "body_html",
            Location::Attachment => "attachment",
            Location::Tcp => "tcp",
        }
    }
}
