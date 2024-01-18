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
pub mod queue;
pub mod report;
pub mod resolver;
pub mod scripts;
pub mod session;
pub mod shared;
pub mod throttle;

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

use ahash::AHashMap;
use directory::Directories;
use mail_auth::{
    common::crypto::{Ed25519Key, RsaKey, Sha256},
    dkim::{Canonicalization, Done},
};
use mail_send::Credentials;
use sieve::Sieve;
use store::Stores;
use utils::{
    config::{if_block::IfBlock, utils::ConstantValue, Rate, Server, ServerProtocol},
    expr::{Expression, Token},
};

use crate::{
    core::eval::{FUNCTIONS_MAP, VARIABLES_MAP},
    inbound::milter,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum StringMatch {
    Equal(String),
    StartsWith(String),
    EndsWith(String),
}

#[derive(Debug, Default)]
#[cfg_attr(feature = "test_mode", derive(PartialEq, Eq))]
pub struct Throttle {
    pub expr: Expression,
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

pub struct Connect {
    pub script: IfBlock,
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
    pub protocol_version: milter::Version,
    pub flags_actions: Option<u32>,
    pub flags_protocol: Option<u32>,
}

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
    pub path: PathBuf,
    pub hash: IfBlock,

    // Schedule
    pub retry: IfBlock,
    pub notify: IfBlock,
    pub expire: IfBlock,

    // Outbound
    pub hostname: IfBlock,
    pub next_hop: IfBlock,
    pub max_mx: IfBlock,
    pub max_multihomed: IfBlock,
    pub ip_strategy: IfBlock,
    pub source_ip: QueueOutboundSourceIp,
    pub tls: QueueOutboundTls,
    pub dsn: Dsn,

    // Timeouts
    pub timeout: QueueOutboundTimeout,

    // Throttle and Quotas
    pub throttle: QueueThrottle,
    pub quota: QueueQuotas,
}

pub struct QueueOutboundSourceIp {
    pub ipv4: IfBlock,
    pub ipv6: IfBlock,
}

pub struct ReportConfig {
    pub path: PathBuf,
    pub hash: IfBlock,
    pub submitter: IfBlock,
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

pub struct Dsn {
    pub name: IfBlock,
    pub address: IfBlock,
    pub sign: IfBlock,
}

pub struct AggregateReport {
    pub name: IfBlock,
    pub address: IfBlock,
    pub org_name: IfBlock,
    pub contact_info: IfBlock,
    pub send: IfBlock,
    pub sign: IfBlock,
    pub max_size: IfBlock,
}

pub struct Report {
    pub name: IfBlock,
    pub address: IfBlock,
    pub subject: IfBlock,
    pub sign: IfBlock,
    pub send: IfBlock,
}

pub struct QueueOutboundTls {
    pub dane: IfBlock,
    pub mta_sts: IfBlock,
    pub start: IfBlock,
    pub invalid_certs: IfBlock,
}

pub struct QueueOutboundTimeout {
    pub connect: IfBlock,
    pub greeting: IfBlock,
    pub tls: IfBlock,
    pub ehlo: IfBlock,
    pub mail: IfBlock,
    pub rcpt: IfBlock,
    pub data: IfBlock,
    pub mta_sts: IfBlock,
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
    pub expr: Expression,
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
    pub verify: IfBlock,
    pub sign: IfBlock,
}

pub struct ArcAuthConfig {
    pub verify: IfBlock,
    pub seal: IfBlock,
}

pub struct SpfAuthConfig {
    pub verify_ehlo: IfBlock,
    pub verify_mail_from: IfBlock,
}
pub struct DmarcAuthConfig {
    pub verify: IfBlock,
}

pub struct IpRevAuthConfig {
    pub verify: IfBlock,
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
    pub directory: Directories,
    pub stores: Stores,
    pub scripts: AHashMap<String, Arc<Sieve>>,
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

pub fn map_expr_token<F: ConstantValue>(name: &str, allowed_vars: &[u32]) -> Result<Token> {
    VARIABLES_MAP
        .iter()
        .find(|(n, _)| n == &name)
        .and_then(|(_, id)| {
            if allowed_vars.contains(id) {
                Some(Token::Variable(*id))
            } else {
                None
            }
        })
        .or_else(|| {
            FUNCTIONS_MAP
                .iter()
                .find(|(n, _, _)| n == &name)
                .map(|(name, id, num_args)| Token::Function {
                    name: (*name).into(),
                    id: *id,
                    num_args: *num_args,
                })
        })
        .or_else(|| {
            F::parse_value("", name)
                .map(|v| Token::Constant(v.into()))
                .ok()
        })
        .ok_or_else(|| format!("Invalid variable: {name:?}"))
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
