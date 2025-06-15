/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod analysis;
pub mod modules;

use std::borrow::Cow;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};

use analysis::ElementLocation;
use analysis::url::UrlParts;
use compact_str::CompactString;
use mail_auth::{ArcOutput, DkimOutput, DmarcResult, IprevOutput, SpfOutput, dmarc::Policy};
use mail_parser::Message;
use modules::html::HtmlToken;
use nlp::tokenizers::types::TokenType;
use store::ahash::AHashSet;

pub struct SpamFilterInput<'x> {
    pub message: &'x Message<'x>,
    pub span_id: u64,

    // Sender authentication
    pub arc_result: Option<&'x ArcOutput<'x>>,
    pub spf_ehlo_result: Option<&'x SpfOutput>,
    pub spf_mail_from_result: Option<&'x SpfOutput>,
    pub dkim_result: &'x [DkimOutput<'x>],
    pub dmarc_result: Option<&'x DmarcResult>,
    pub dmarc_policy: Option<&'x Policy>,
    pub iprev_result: Option<&'x IprevOutput>,

    // Session details
    pub remote_ip: IpAddr,
    pub ehlo_domain: Option<&'x str>,
    pub authenticated_as: Option<&'x str>,
    pub asn: Option<u32>,
    pub country: Option<&'x str>,

    // TLS
    pub is_tls: bool,

    // Envelope
    pub env_from: &'x str,
    pub env_from_flags: u64,
    pub env_rcpt_to: Vec<&'x str>,

    pub account_id: Option<u32>,
    pub is_test: bool,
}

pub struct SpamFilterOutput<'x> {
    pub ehlo_host: Hostname,
    pub iprev_ptr: Option<CompactString>,

    pub env_from_addr: Email,
    pub env_from_postmaster: bool,
    pub env_to_addr: HashSet<Email>,
    pub from: Recipient,
    pub recipients_to: Vec<Recipient>,
    pub recipients_cc: Vec<Recipient>,
    pub recipients_bcc: Vec<Recipient>,
    pub reply_to: Option<Recipient>,

    pub subject: String,
    pub subject_lc: String,
    pub subject_thread: String,
    pub subject_thread_lc: String,
    pub subject_tokens: Vec<TokenType<Cow<'x, str>, Email, UrlParts<'x>, IpParts<'x>>>,

    pub ips: AHashSet<ElementLocation<IpAddr>>,
    pub urls: HashSet<ElementLocation<UrlParts<'x>>>,
    pub emails: HashSet<ElementLocation<Recipient>>,
    pub domains: HashSet<ElementLocation<CompactString>>,

    pub text_parts: Vec<TextPart<'x>>,
}

#[derive(Debug)]
pub struct IpParts<'x> {
    ip: Option<IpAddr>,
    text: Cow<'x, str>,
}

pub enum TextPart<'x> {
    Plain {
        text_body: &'x str,
        tokens: Vec<TokenType<Cow<'x, str>, Email, UrlParts<'x>, IpParts<'x>>>,
    },
    Html {
        html_tokens: Vec<HtmlToken>,
        text_body: String,
        tokens: Vec<TokenType<Cow<'x, str>, Email, UrlParts<'x>, IpParts<'x>>>,
    },
    None,
}

#[derive(Debug, Default)]
pub struct SpamFilterResult {
    pub tags: AHashSet<CompactString>,
    pub score: f64,
    pub rbl_ip_checks: usize,
    pub rbl_domain_checks: usize,
    pub rbl_url_checks: usize,
    pub rbl_email_checks: usize,
    pub header: Option<String>,
}

pub struct SpamFilterContext<'x> {
    pub input: SpamFilterInput<'x>,
    pub output: SpamFilterOutput<'x>,
    pub result: SpamFilterResult,
}

#[derive(Debug, Clone)]
pub struct Hostname {
    pub fqdn: CompactString,
    pub ip: Option<IpAddr>,
    pub sld: Option<CompactString>,
}

#[derive(Debug, Clone)]
pub struct Email {
    pub address: CompactString,
    pub local_part: CompactString,
    pub domain_part: Hostname,
}

#[derive(Debug, Clone)]
pub struct Recipient {
    pub email: Email,
    pub name: Option<CompactString>,
}

impl<'x> SpamFilterInput<'x> {
    pub fn from_message(message: &'x Message<'x>, span_id: u64) -> Self {
        Self {
            message,
            span_id,
            arc_result: None,
            spf_ehlo_result: None,
            spf_mail_from_result: None,
            dkim_result: &[],
            dmarc_result: None,
            dmarc_policy: None,
            iprev_result: None,
            remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ehlo_domain: None,
            authenticated_as: None,
            asn: None,
            country: None,
            is_tls: true,
            env_from: "",
            env_from_flags: 0,
            env_rcpt_to: vec![],
            account_id: None,
            is_test: false,
        }
    }

    pub fn from_account_message(message: &'x Message<'x>, account_id: u32, span_id: u64) -> Self {
        Self {
            message,
            span_id,
            arc_result: None,
            spf_ehlo_result: None,
            spf_mail_from_result: None,
            dkim_result: &[],
            dmarc_result: None,
            dmarc_policy: None,
            iprev_result: None,
            remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ehlo_domain: None,
            authenticated_as: None,
            asn: None,
            country: None,
            is_tls: true,
            env_from: "",
            env_from_flags: 0,
            env_rcpt_to: vec![],
            account_id: Some(account_id),
            is_test: false,
        }
    }
}

impl PartialEq for Hostname {
    fn eq(&self, other: &Self) -> bool {
        self.fqdn.eq(&other.fqdn)
    }
}

impl Eq for Hostname {}

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.address.eq(&other.address)
    }
}

impl Eq for Email {}

impl Hash for Hostname {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.fqdn.hash(state)
    }
}

impl Hash for Email {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.address.hash(state)
    }
}

impl Email {
    pub fn is_valid(&self) -> bool {
        self.domain_part.sld.is_some() && !self.local_part.is_empty()
    }
}

impl PartialEq for Recipient {
    fn eq(&self, other: &Self) -> bool {
        self.email.eq(&other.email)
    }
}

impl Eq for Recipient {}

impl Hash for Recipient {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.email.hash(state)
    }
}

impl PartialOrd for Email {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialOrd for Recipient {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Email {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

impl Ord for Recipient {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.email.cmp(&other.email)
    }
}
