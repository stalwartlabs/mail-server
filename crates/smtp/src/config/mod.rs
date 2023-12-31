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

pub mod auth;
pub mod condition;
pub mod if_block;
pub mod queue;
pub mod remote;
pub mod report;
pub mod resolver;
pub mod scripts;
pub mod session;
pub mod throttle;

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

use ahash::AHashMap;
use directory::{Directories, Directory};
use mail_auth::{
    common::crypto::{Ed25519Key, RsaKey, Sha256},
    dkim::{Canonicalization, Done},
    IpLookupStrategy,
};
use mail_send::Credentials;
use regex::Regex;
use sieve::Sieve;
use smtp_proto::MtPriority;
use store::Stores;
use utils::config::{DynValue, Rate, Server, ServerProtocol};

use crate::{core::Lookup, inbound::milter};

#[derive(Debug)]
pub struct Host {
    pub address: String,
    pub port: u16,
    pub protocol: ServerProtocol,
    pub concurrency: usize,
    pub timeout: Duration,
    pub tls_implicit: bool,
    pub tls_allow_invalid_certs: bool,
    pub username: Option<String>,
    pub secret: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "test_mode", derive(PartialEq, Eq))]
pub enum Condition {
    Match {
        key: EnvelopeKey,
        value: ConditionMatch,
        not: bool,
    },
    JumpIfTrue {
        positions: usize,
    },
    JumpIfFalse {
        positions: usize,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StringMatch {
    Equal(String),
    StartsWith(String),
    EndsWith(String),
}

#[derive(Clone)]
pub enum ConditionMatch {
    String(StringMatch),
    UInt(u16),
    Int(i16),
    IpAddrMask(IpAddrMask),
    Lookup(Lookup),
    Regex(Regex),
}

#[cfg(feature = "test_mode")]
impl PartialEq for ConditionMatch {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String(l0), Self::String(r0)) => l0 == r0,
            (Self::UInt(l0), Self::UInt(r0)) => l0 == r0,
            (Self::Int(l0), Self::Int(r0)) => l0 == r0,
            (Self::IpAddrMask(l0), Self::IpAddrMask(r0)) => l0 == r0,
            (Self::Lookup(l0), Self::Lookup(r0)) => l0 == r0,
            (Self::Regex(_), Self::Regex(_)) => false,
            _ => false,
        }
    }
}

impl core::fmt::Debug for ConditionMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(arg0) => f.debug_tuple("String").field(arg0).finish(),
            Self::UInt(arg0) => f.debug_tuple("UInt").field(arg0).finish(),
            Self::Int(arg0) => f.debug_tuple("Int").field(arg0).finish(),
            Self::IpAddrMask(arg0) => f.debug_tuple("IpAddrMask").field(arg0).finish(),
            Self::Lookup(_) => f.debug_tuple("Lookup").finish(),
            Self::Regex(arg0) => f.debug_tuple("Regex").field(arg0).finish(),
        }
    }
}

#[cfg(feature = "test_mode")]
impl Eq for ConditionMatch {}

impl Default for Condition {
    fn default() -> Self {
        Condition::JumpIfFalse { positions: 0 }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EnvelopeKey {
    Recipient,
    RecipientDomain,
    Sender,
    SenderDomain,
    Mx,
    HeloDomain,
    AuthenticatedAs,
    Listener,
    RemoteIp,
    LocalIp,
    Priority,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "test_mode", derive(PartialEq, Eq))]
pub struct IfThen<T: Default> {
    pub conditions: Conditions,
    pub then: T,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "test_mode", derive(PartialEq, Eq))]
pub struct Conditions {
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "test_mode", derive(PartialEq, Eq))]
pub struct IfBlock<T: Default> {
    pub if_then: Vec<IfThen<T>>,
    pub default: T,
}

#[derive(Debug, Default)]
#[cfg_attr(feature = "test_mode", derive(PartialEq, Eq))]
pub struct Throttle {
    pub conditions: Conditions,
    pub keys: u16,
    pub concurrency: Option<u64>,
    pub rate: Option<Rate>,
}

pub const THROTTLE_RCPT: u16 = 1 << 0;
pub const THROTTLE_RCPT_DOMAIN: u16 = 1 << 1;
pub const THROTTLE_SENDER: u16 = 1 << 2;
pub const THROTTLE_SENDER_DOMAIN: u16 = 1 << 3;
pub const THROTTLE_AUTH_AS: u16 = 1 << 4;
pub const THROTTLE_LISTENER: u16 = 1 << 5;
pub const THROTTLE_MX: u16 = 1 << 6;
pub const THROTTLE_REMOTE_IP: u16 = 1 << 7;
pub const THROTTLE_LOCAL_IP: u16 = 1 << 8;
pub const THROTTLE_HELO_DOMAIN: u16 = 1 << 9;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddrMask {
    V4 { addr: Ipv4Addr, mask: u32 },
    V6 { addr: Ipv6Addr, mask: u128 },
}

pub struct Connect {
    pub script: IfBlock<Option<Arc<Sieve>>>,
}

pub struct Ehlo {
    pub script: IfBlock<Option<Arc<Sieve>>>,
    pub require: IfBlock<bool>,
    pub reject_non_fqdn: IfBlock<bool>,
}

pub struct Extensions {
    pub pipelining: IfBlock<bool>,
    pub chunking: IfBlock<bool>,
    pub requiretls: IfBlock<bool>,
    pub dsn: IfBlock<bool>,
    pub vrfy: IfBlock<bool>,
    pub expn: IfBlock<bool>,
    pub no_soliciting: IfBlock<Option<String>>,
    pub future_release: IfBlock<Option<Duration>>,
    pub deliver_by: IfBlock<Option<Duration>>,
    pub mt_priority: IfBlock<Option<MtPriority>>,
}

pub struct Auth {
    pub directory: IfBlock<Option<MaybeDynValue<Directory>>>,
    pub mechanisms: IfBlock<u64>,
    pub require: IfBlock<bool>,
    pub allow_plain_text: IfBlock<bool>,
    pub must_match_sender: IfBlock<bool>,
    pub errors_max: IfBlock<usize>,
    pub errors_wait: IfBlock<Duration>,
}

pub struct Mail {
    pub script: IfBlock<Option<Arc<Sieve>>>,
    pub rewrite: IfBlock<Option<DynValue<EnvelopeKey>>>,
}

pub struct Rcpt {
    pub script: IfBlock<Option<Arc<Sieve>>>,
    pub relay: IfBlock<bool>,
    pub directory: IfBlock<Option<MaybeDynValue<Directory>>>,
    pub rewrite: IfBlock<Option<DynValue<EnvelopeKey>>>,

    // Errors
    pub errors_max: IfBlock<usize>,
    pub errors_wait: IfBlock<Duration>,

    // Limits
    pub max_recipients: IfBlock<usize>,
}

pub struct Data {
    pub script: IfBlock<Option<Arc<Sieve>>>,
    pub pipe_commands: Vec<Pipe>,
    pub milters: Vec<Milter>,

    // Limits
    pub max_messages: IfBlock<usize>,
    pub max_message_size: IfBlock<usize>,
    pub max_received_headers: IfBlock<usize>,

    // Headers
    pub add_received: IfBlock<bool>,
    pub add_received_spf: IfBlock<bool>,
    pub add_return_path: IfBlock<bool>,
    pub add_auth_results: IfBlock<bool>,
    pub add_message_id: IfBlock<bool>,
    pub add_date: IfBlock<bool>,
}

pub struct Pipe {
    pub command: IfBlock<Option<String>>,
    pub arguments: IfBlock<Vec<String>>,
    pub timeout: IfBlock<Duration>,
}

pub struct Milter {
    pub enable: IfBlock<bool>,
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
    pub protocol_version: milter::Version,
    pub flags_actions: Option<u32>,
    pub flags_protocol: Option<u32>,
}

pub struct SessionConfig {
    pub timeout: IfBlock<Duration>,
    pub duration: IfBlock<Duration>,
    pub transfer_limit: IfBlock<usize>,
    pub throttle: SessionThrottle,

    pub connect: Connect,
    pub ehlo: Ehlo,
    pub auth: Auth,
    pub mail: Mail,
    pub rcpt: Rcpt,
    pub data: Data,
    pub extensions: Extensions,
}

pub struct SessionThrottle {
    pub connect: Vec<Throttle>,
    pub mail_from: Vec<Throttle>,
    pub rcpt_to: Vec<Throttle>,
}

pub struct RelayHost {
    pub address: String,
    pub port: u16,
    pub protocol: ServerProtocol,
    pub auth: Option<Credentials<String>>,
    pub tls_implicit: bool,
    pub tls_allow_invalid_certs: bool,
}

pub struct QueueConfig {
    pub path: IfBlock<PathBuf>,
    pub hash: IfBlock<u64>,

    // Schedule
    pub retry: IfBlock<Vec<Duration>>,
    pub notify: IfBlock<Vec<Duration>>,
    pub expire: IfBlock<Duration>,

    // Outbound
    pub hostname: IfBlock<String>,
    pub next_hop: IfBlock<Option<RelayHost>>,
    pub max_mx: IfBlock<usize>,
    pub max_multihomed: IfBlock<usize>,
    pub ip_strategy: IfBlock<IpLookupStrategy>,
    pub source_ip: QueueOutboundSourceIp,
    pub tls: QueueOutboundTls,
    pub dsn: Dsn,

    // Timeouts
    pub timeout: QueueOutboundTimeout,

    // Throttle and Quotas
    pub throttle: QueueThrottle,
    pub quota: QueueQuotas,
    pub management_lookup: Arc<Directory>,
}

pub struct QueueOutboundSourceIp {
    pub ipv4: IfBlock<Vec<Ipv4Addr>>,
    pub ipv6: IfBlock<Vec<Ipv6Addr>>,
}

pub struct ReportConfig {
    pub path: IfBlock<PathBuf>,
    pub hash: IfBlock<u64>,
    pub submitter: IfBlock<String>,
    pub analysis: ReportAnalysis,

    pub dkim: Report,
    pub spf: Report,
    pub dmarc: Report,
    pub dmarc_aggregate: AggregateReport,
    pub tls: AggregateReport,
}

pub struct ReportAnalysis {
    pub addresses: Vec<AddressMatch>,
    pub forward: bool,
    pub store: Option<PathBuf>,
    pub report_id: AtomicU64,
}

pub enum AddressMatch {
    StartsWith(String),
    EndsWith(String),
    Equals(String),
}

#[derive(Clone)]
pub enum MaybeDynValue<T: ?Sized> {
    Dynamic {
        eval: DynValue<EnvelopeKey>,
        items: AHashMap<String, Arc<T>>,
    },
    Static(Arc<T>),
}

pub struct Dsn {
    pub name: IfBlock<String>,
    pub address: IfBlock<String>,
    pub sign: IfBlock<Vec<MaybeDynValue<DkimSigner>>>,
}

pub struct AggregateReport {
    pub name: IfBlock<String>,
    pub address: IfBlock<String>,
    pub org_name: IfBlock<Option<String>>,
    pub contact_info: IfBlock<Option<String>>,
    pub send: IfBlock<AggregateFrequency>,
    pub sign: IfBlock<Vec<MaybeDynValue<DkimSigner>>>,
    pub max_size: IfBlock<usize>,
}

pub struct Report {
    pub name: IfBlock<String>,
    pub address: IfBlock<String>,
    pub subject: IfBlock<String>,
    pub sign: IfBlock<Vec<MaybeDynValue<DkimSigner>>>,
    pub send: IfBlock<Option<Rate>>,
}

pub struct QueueOutboundTls {
    pub dane: IfBlock<RequireOptional>,
    pub mta_sts: IfBlock<RequireOptional>,
    pub start: IfBlock<RequireOptional>,
    pub invalid_certs: IfBlock<bool>,
}

pub struct QueueOutboundTimeout {
    pub connect: IfBlock<Duration>,
    pub greeting: IfBlock<Duration>,
    pub tls: IfBlock<Duration>,
    pub ehlo: IfBlock<Duration>,
    pub mail: IfBlock<Duration>,
    pub rcpt: IfBlock<Duration>,
    pub data: IfBlock<Duration>,
    pub mta_sts: IfBlock<Duration>,
}

#[derive(Debug)]
pub struct QueueThrottle {
    pub sender: Vec<Throttle>,
    pub rcpt: Vec<Throttle>,
    pub host: Vec<Throttle>,
}

pub struct QueueQuotas {
    pub sender: Vec<QueueQuota>,
    pub rcpt: Vec<QueueQuota>,
    pub rcpt_domain: Vec<QueueQuota>,
}

pub struct QueueQuota {
    pub conditions: Conditions,
    pub keys: u16,
    pub size: Option<usize>,
    pub messages: Option<usize>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AggregateFrequency {
    Hourly,
    Daily,
    Weekly,
    #[default]
    Never,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TlsStrategy {
    pub dane: RequireOptional,
    pub mta_sts: RequireOptional,
    pub tls: RequireOptional,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum RequireOptional {
    #[default]
    Optional,
    Require,
    Disable,
}

pub struct MailAuthConfig {
    pub dkim: DkimAuthConfig,
    pub arc: ArcAuthConfig,
    pub spf: SpfAuthConfig,
    pub dmarc: DmarcAuthConfig,
    pub iprev: IpRevAuthConfig,
}

pub enum DkimSigner {
    RsaSha256(mail_auth::dkim::DkimSigner<RsaKey<Sha256>, Done>),
    Ed25519Sha256(mail_auth::dkim::DkimSigner<Ed25519Key, Done>),
}

pub enum ArcSealer {
    RsaSha256(mail_auth::arc::ArcSealer<RsaKey<Sha256>, Done>),
    Ed25519Sha256(mail_auth::arc::ArcSealer<Ed25519Key, Done>),
}

pub struct DkimAuthConfig {
    pub verify: IfBlock<VerifyStrategy>,
    pub sign: IfBlock<Vec<MaybeDynValue<DkimSigner>>>,
}

pub struct ArcAuthConfig {
    pub verify: IfBlock<VerifyStrategy>,
    pub seal: IfBlock<Option<MaybeDynValue<ArcSealer>>>,
}

pub struct SpfAuthConfig {
    pub verify_ehlo: IfBlock<VerifyStrategy>,
    pub verify_mail_from: IfBlock<VerifyStrategy>,
}
pub struct DmarcAuthConfig {
    pub verify: IfBlock<VerifyStrategy>,
}

pub struct IpRevAuthConfig {
    pub verify: IfBlock<VerifyStrategy>,
}

#[derive(Debug, Clone)]
pub struct DkimCanonicalization {
    pub headers: Canonicalization,
    pub body: Canonicalization,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum VerifyStrategy {
    #[default]
    Relaxed,
    Strict,
    Disable,
}

#[derive(Default)]
pub struct ConfigContext<'x> {
    pub servers: &'x [Server],
    pub hosts: AHashMap<String, Host>,
    pub scripts: AHashMap<String, Arc<Sieve>>,
    pub directory: Directories,
    pub stores: Stores,
    pub signers: AHashMap<String, Arc<DkimSigner>>,
    pub sealers: AHashMap<String, Arc<ArcSealer>>,
}

impl<'x> ConfigContext<'x> {
    pub fn new(servers: &'x [Server]) -> Self {
        Self {
            servers,
            ..Default::default()
        }
    }
}

impl std::fmt::Debug for RelayHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayHost")
            .field("address", &self.address)
            .field("port", &self.port)
            .field("protocol", &self.protocol)
            .field("tls_implicit", &self.tls_implicit)
            .field("tls_allow_invalid_certs", &self.tls_allow_invalid_certs)
            .finish()
    }
}

pub type Result<T> = std::result::Result<T, String>;
