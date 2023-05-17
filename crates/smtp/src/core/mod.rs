/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
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

use std::{
    borrow::Cow,
    hash::Hash,
    net::IpAddr,
    sync::{atomic::AtomicU32, Arc},
    time::{Duration, Instant},
};

use ahash::AHashMap;
use dashmap::DashMap;
use mail_auth::{common::lru::LruCache, IprevOutput, Resolver, SpfOutput};
use sieve::{Runtime, Sieve};
use smtp_proto::request::receiver::{
    BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver, LineReceiver, RequestReceiver,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};
use tokio_rustls::TlsConnector;
use tracing::Span;
use utils::{
    ipc::DeliveryEvent,
    listener::{limiter::InFlight, ServerInstance},
};

use crate::{
    config::{
        DkimSigner, EnvelopeKey, MailAuthConfig, QueueConfig, ReportConfig, SessionConfig,
        VerifyStrategy,
    },
    inbound::auth::SaslToken,
    lookup::{Lookup, SqlDatabase},
    outbound::{
        dane::{DnssecResolver, Tlsa},
        mta_sts,
    },
    queue::{self, QuotaLimiter},
    reporting,
};

use self::throttle::{Limiter, ThrottleKey, ThrottleKeyHasherBuilder};

pub mod if_block;
pub mod management;
pub mod params;
pub mod scripts;
pub mod throttle;
pub mod worker;

#[derive(Clone)]
pub struct SmtpSessionManager {
    pub inner: Arc<SMTP>,
}

#[derive(Clone)]
pub struct SmtpAdminSessionManager {
    pub inner: Arc<SMTP>,
}

impl SmtpSessionManager {
    pub fn new(inner: Arc<SMTP>) -> Self {
        Self { inner }
    }
}

impl SmtpAdminSessionManager {
    pub fn new(inner: Arc<SMTP>) -> Self {
        Self { inner }
    }
}

pub struct SMTP {
    pub worker_pool: rayon::ThreadPool,
    pub session: SessionCore,
    pub queue: QueueCore,
    pub resolvers: Resolvers,
    pub mail_auth: MailAuthConfig,
    pub report: ReportCore,
    pub sieve: SieveCore,
    #[cfg(feature = "local_delivery")]
    pub delivery_tx: mpsc::Sender<DeliveryEvent>,
}

pub struct SieveCore {
    pub runtime: Runtime,
    pub scripts: AHashMap<String, Arc<Sieve>>,
    pub lookup: AHashMap<String, Arc<Lookup>>,
    pub config: SieveConfig,
}

pub struct SieveConfig {
    pub from_addr: String,
    pub from_name: String,
    pub return_path: String,
    pub sign: Vec<Arc<DkimSigner>>,
    pub db: Option<SqlDatabase>,
}

pub struct Resolvers {
    pub dns: Resolver,
    pub dnssec: DnssecResolver,
    pub cache: DnsCache,
}

pub struct DnsCache {
    pub tlsa: LruCache<String, Arc<Tlsa>>,
    pub mta_sts: LruCache<String, Arc<mta_sts::Policy>>,
}

pub struct SessionCore {
    pub config: SessionConfig,
    pub throttle: DashMap<ThrottleKey, Limiter, ThrottleKeyHasherBuilder>,
}

pub struct QueueCore {
    pub config: QueueConfig,
    pub throttle: DashMap<ThrottleKey, Limiter, ThrottleKeyHasherBuilder>,
    pub quota: DashMap<ThrottleKey, Arc<QuotaLimiter>, ThrottleKeyHasherBuilder>,
    pub tx: mpsc::Sender<queue::Event>,
    pub id_seq: AtomicU32,
    pub connectors: TlsConnectors,
}

pub struct ReportCore {
    pub config: ReportConfig,
    pub tx: mpsc::Sender<reporting::Event>,
}

pub struct TlsConnectors {
    pub pki_verify: TlsConnector,
    pub dummy_verify: TlsConnector,
}

pub enum State {
    Request(RequestReceiver),
    Bdat(BdatReceiver),
    Data(DataReceiver),
    Sasl(LineReceiver<SaslToken>),
    DataTooLarge(DummyDataReceiver),
    RequestTooLarge(DummyLineReceiver),
    None,
}

pub struct Session<T: AsyncWrite + AsyncRead> {
    pub state: State,
    pub instance: Arc<ServerInstance>,
    pub core: Arc<SMTP>,
    pub span: Span,
    pub stream: T,
    pub data: SessionData,
    pub params: SessionParameters,
    pub in_flight: Vec<InFlight>,
}

pub struct SessionData {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub helo_domain: String,

    pub mail_from: Option<SessionAddress>,
    pub rcpt_to: Vec<SessionAddress>,
    pub rcpt_errors: usize,
    pub message: Vec<u8>,

    pub authenticated_as: String,
    pub auth_errors: usize,

    pub priority: i16,
    pub delivery_by: i64,
    pub future_release: u64,

    pub valid_until: Instant,
    pub bytes_left: usize,
    pub messages_sent: usize,

    pub iprev: Option<IprevOutput>,
    pub spf_ehlo: Option<SpfOutput>,
    pub spf_mail_from: Option<SpfOutput>,
    pub dnsbl_error: Option<Vec<u8>>,
}

#[derive(Clone)]
pub struct SessionAddress {
    pub address: String,
    pub address_lcase: String,
    pub domain: String,
    pub flags: u64,
    pub dsn_info: Option<String>,
}

#[derive(Debug, Default)]
pub struct SessionParameters {
    // Global parameters
    pub timeout: Duration,

    // Ehlo parameters
    pub ehlo_require: bool,
    pub ehlo_reject_non_fqdn: bool,

    // Auth parameters
    pub auth_lookup: Option<Arc<Lookup>>,
    pub auth_require: bool,
    pub auth_errors_max: usize,
    pub auth_errors_wait: Duration,

    // Rcpt parameters
    pub rcpt_script: Option<Arc<Sieve>>,
    pub rcpt_relay: bool,
    pub rcpt_errors_max: usize,
    pub rcpt_errors_wait: Duration,
    pub rcpt_max: usize,
    pub rcpt_dsn: bool,
    pub rcpt_lookup_domain: Option<Arc<Lookup>>,
    pub rcpt_lookup_addresses: Option<Arc<Lookup>>,
    pub rcpt_lookup_expn: Option<Arc<Lookup>>,
    pub rcpt_lookup_vrfy: Option<Arc<Lookup>>,
    pub max_message_size: usize,

    // Mail authentication parameters
    pub iprev: VerifyStrategy,
    pub spf_ehlo: VerifyStrategy,
    pub spf_mail_from: VerifyStrategy,
    pub dnsbl_policy: u32,
}

impl SessionData {
    pub fn new(local_ip: IpAddr, remote_ip: IpAddr) -> Self {
        SessionData {
            local_ip,
            remote_ip,
            helo_domain: String::new(),
            mail_from: None,
            rcpt_to: Vec::new(),
            authenticated_as: String::new(),
            priority: 0,
            valid_until: Instant::now(),
            rcpt_errors: 0,
            message: Vec::with_capacity(0),
            auth_errors: 0,
            messages_sent: 0,
            bytes_left: 0,
            delivery_by: 0,
            future_release: 0,
            iprev: None,
            spf_ehlo: None,
            spf_mail_from: None,
            dnsbl_error: None,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        State::Request(RequestReceiver::default())
    }
}

pub trait Envelope {
    fn local_ip(&self) -> IpAddr;
    fn remote_ip(&self) -> IpAddr;
    fn sender_domain(&self) -> &str;
    fn sender(&self) -> &str;
    fn rcpt_domain(&self) -> &str;
    fn rcpt(&self) -> &str;
    fn helo_domain(&self) -> &str;
    fn authenticated_as(&self) -> &str;
    fn mx(&self) -> &str;
    fn listener_id(&self) -> u16;
    fn priority(&self) -> i16;

    #[inline(always)]
    fn key_to_string(&self, key: &EnvelopeKey) -> Cow<'_, str> {
        match key {
            EnvelopeKey::Recipient => self.rcpt().into(),
            EnvelopeKey::RecipientDomain => self.rcpt_domain().into(),
            EnvelopeKey::Sender => self.sender().into(),
            EnvelopeKey::SenderDomain => self.sender_domain().into(),
            EnvelopeKey::Mx => self.mx().into(),
            EnvelopeKey::AuthenticatedAs => self.authenticated_as().into(),
            EnvelopeKey::HeloDomain => self.helo_domain().into(),
            EnvelopeKey::Listener => self.listener_id().to_string().into(),
            EnvelopeKey::RemoteIp => self.remote_ip().to_string().into(),
            EnvelopeKey::LocalIp => self.local_ip().to_string().into(),
            EnvelopeKey::Priority => self.priority().to_string().into(),
        }
    }
}

impl VerifyStrategy {
    #[inline(always)]
    pub fn verify(&self) -> bool {
        matches!(self, VerifyStrategy::Strict | VerifyStrategy::Relaxed)
    }

    #[inline(always)]
    pub fn is_strict(&self) -> bool {
        matches!(self, VerifyStrategy::Strict)
    }
}

impl PartialEq for SessionAddress {
    fn eq(&self, other: &Self) -> bool {
        self.address_lcase == other.address_lcase
    }
}

impl Eq for SessionAddress {}

impl Hash for SessionAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address_lcase.hash(state);
    }
}

impl Ord for SessionAddress {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.domain.cmp(&other.domain) {
            std::cmp::Ordering::Equal => self.address_lcase.cmp(&other.address_lcase),
            order => order,
        }
    }
}

impl PartialOrd for SessionAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.domain.partial_cmp(&other.domain) {
            Some(std::cmp::Ordering::Equal) => self.address_lcase.partial_cmp(&other.address_lcase),
            order => order,
        }
    }
}
