pub mod analysis;
pub mod modules;

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

use mail_auth::{dmarc::Policy, ArcOutput, DkimOutput, DmarcResult, IprevOutput, SpfOutput};
use mail_parser::Message;
use modules::html::HtmlToken;
use nlp::tokenizers::types::TokenType;
use store::ahash::AHashSet;

pub struct SpamFilterInput<'x> {
    pub message: &'x Message<'x>,
    pub span_id: u64,

    // Sender authentication
    pub arc_result: &'x ArcOutput<'x>,
    pub spf_ehlo_result: &'x SpfOutput,
    pub spf_mail_from_result: &'x SpfOutput,
    pub dkim_result: &'x [DkimOutput<'x>],
    pub dmarc_result: &'x DmarcResult,
    pub dmarc_policy: &'x Policy,
    pub iprev_result: &'x IprevOutput,

    // Session details
    pub remote_ip: IpAddr,
    pub ehlo_domain: &'x str,
    pub authenticated_as: &'x str,

    // TLS
    pub tls_version: &'x str,
    pub tls_cipher: &'x str,

    // Envelope
    pub env_from: &'x str,
    pub env_from_flags: u64,
    pub env_rcpt_to: &'x [&'x str],
}

pub struct SpamFilterOutput<'x> {
    pub ehlo_host: Hostname,
    pub iprev_ptr: Option<String>,

    pub env_from_addr: Email,
    pub env_from_postmaster: bool,
    pub env_to_addr: HashSet<Email>,
    pub from: Recipient,
    pub recipients_to: Vec<Recipient>,
    pub recipients_cc: Vec<Recipient>,
    pub recipients_bcc: Vec<Recipient>,
    pub reply_to: Option<Recipient>,

    pub subject: String,
    pub subject_thread: String,
    pub subject_tokens: Vec<TokenType<&'x str>>,

    pub text_parts: Vec<TextPart<'x>>,
}

pub enum TextPart<'x> {
    Plain {
        text_body: &'x str,
        tokens: Vec<TokenType<&'x str>>,
    },
    Html {
        html_tokens: Vec<HtmlToken>,
        text_body: String,
        tokens: Vec<TokenType<String>>,
    },
    None,
}

#[derive(Debug, Default)]
pub struct SpamFilterResult {
    pub tags: AHashSet<String>,
    pub rbl_ip_checks: usize,
    pub rbl_domain_checks: usize,
    pub rbl_url_checks: usize,
    pub rbl_email_checks: usize,
}

pub struct SpamFilterContext<'x> {
    pub input: SpamFilterInput<'x>,
    pub output: SpamFilterOutput<'x>,
    pub result: SpamFilterResult,
}

#[derive(Debug, Clone)]
pub struct Hostname {
    pub fqdn: String,
    pub ip: Option<IpAddr>,
    pub sld: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Email {
    pub address: String,
    pub local_part: String,
    pub domain_part: Hostname,
}

#[derive(Debug, Clone)]
pub struct Recipient {
    pub email: Email,
    pub name: Option<String>,
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
