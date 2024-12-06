pub mod analysis;
pub mod modules;

use std::hash::{Hash, Hasher};
use std::net::IpAddr;

use mail_auth::{dmarc::Policy, ArcOutput, DkimOutput, DmarcResult, IprevOutput, SpfOutput};
use mail_parser::Message;
use store::ahash::AHashSet;

pub struct SpamFilterInput<'x> {
    pub message: &'x Message<'x>,

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
    pub env_mail_from: &'x str,
    pub env_rcpt_to: &'x [&'x str],
}

pub struct SpamFilterOutput {
    pub tags: AHashSet<String>,
    pub ehlo_host: Hostname,
    pub iprev_ptr: Option<String>,

    pub env_from_addr: Email,
    pub from_addr: Email,
    pub from_name: String,
    pub recipients: AHashSet<Email>,

    pub subject: String,
    pub subject_thread: String,
}

pub struct SpamFilterContext<'x> {
    pub input: SpamFilterInput<'x>,
    pub output: SpamFilterOutput,
}

#[derive(Debug)]
pub struct Hostname {
    pub fqdn: String,
    pub ip: Option<IpAddr>,
    pub sld: Option<String>,
}

#[derive(Debug)]
pub struct Email {
    pub address: String,
    pub local_part: String,
    pub domain_part: Hostname,
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
