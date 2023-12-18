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

use std::{
    cmp::Ordering,
    hash::Hash,
    net::IpAddr,
    sync::{atomic::AtomicU32, Arc},
    time::{Duration, Instant},
};

use ahash::AHashMap;
use dashmap::DashMap;
use directory::Directory;
use mail_auth::{common::lru::LruCache, IprevOutput, Resolver, SpfOutput};
use sieve::{runtime::Variable, Runtime, Sieve};
use smtp_proto::{
    request::receiver::{
        BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver, LineReceiver,
        RequestReceiver,
    },
    IntoString,
};
use store::{LookupStore, Row, Value};
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
        scripts::SieveContext, DkimSigner, MailAuthConfig, QueueConfig, ReportConfig,
        SessionConfig, VerifyStrategy,
    },
    inbound::auth::SaslToken,
    outbound::{
        dane::{DnssecResolver, Tlsa},
        mta_sts,
    },
    queue::{self, DomainPart, QueueId, QuotaLimiter},
    reporting,
};

use self::throttle::{Limiter, ThrottleKey, ThrottleKeyHasherBuilder};

pub mod if_block;
pub mod management;
pub mod params;
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
    pub runtime: Runtime<SieveContext>,
    pub scripts: AHashMap<String, Arc<Sieve>>,

    pub from_addr: String,
    pub from_name: String,
    pub return_path: String,
    pub sign: Vec<Arc<DkimSigner>>,
    pub directories: AHashMap<String, Arc<Directory>>,
    pub lookup_stores: AHashMap<String, LookupStore>,
    pub lookup: AHashMap<String, Lookup>,
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

#[derive(Clone)]
pub struct Lookup(Arc<store::Lookup>);

pub enum State {
    Request(RequestReceiver),
    Bdat(BdatReceiver),
    Data(DataReceiver),
    Sasl(LineReceiver<SaslToken>),
    DataTooLarge(DummyDataReceiver),
    RequestTooLarge(DummyLineReceiver),
    Accepted(QueueId),
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
    pub remote_port: u16,
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
    pub auth_directory: Option<Arc<Directory>>,
    pub auth_require: bool,
    pub auth_errors_max: usize,
    pub auth_errors_wait: Duration,
    pub auth_plain_text: bool,

    // Rcpt parameters
    pub rcpt_errors_max: usize,
    pub rcpt_errors_wait: Duration,
    pub rcpt_max: usize,
    pub rcpt_dsn: bool,
    pub can_expn: bool,
    pub can_vrfy: bool,
    pub max_message_size: usize,

    // Mail authentication parameters
    pub iprev: VerifyStrategy,
    pub spf_ehlo: VerifyStrategy,
    pub spf_mail_from: VerifyStrategy,
}

impl SessionData {
    pub fn new(local_ip: IpAddr, remote_ip: IpAddr, remote_port: u16) -> Self {
        SessionData {
            local_ip,
            remote_ip,
            remote_port,
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

impl Lookup {
    pub async fn contains(&self, item: impl Into<Value<'_>>) -> Option<bool> {
        self.0
            .store
            .query::<bool>(&self.0.query, vec![item.into()])
            .await
            .ok()
    }

    pub async fn lookup(&self, items: Vec<Value<'_>>) -> Option<Variable> {
        self.0
            .store
            .query::<Option<Row>>(&self.0.query, items)
            .await
            .ok()
            .map(|row| {
                let mut row = row.map(|row| row.values).unwrap_or_default();
                match row.len().cmp(&1) {
                    Ordering::Equal if !matches!(row.first(), Some(Value::Null)) => {
                        row.pop().map(into_sieve_value).unwrap()
                    }
                    Ordering::Less => Variable::default(),
                    _ => Variable::Array(
                        row.into_iter()
                            .map(into_sieve_value)
                            .collect::<Vec<_>>()
                            .into(),
                    ),
                }
            })
    }

    pub async fn query(&self, items: Vec<Value<'_>>) -> Option<Vec<Value<'static>>> {
        self.0
            .store
            .query::<Option<Row>>(&self.0.query, items)
            .await
            .ok()
            .map(|row| row.map(|row| row.values).unwrap_or_default())
    }
}

impl PartialEq for Lookup {
    fn eq(&self, other: &Self) -> bool {
        self.0.query == other.0.query
    }
}

pub fn into_sieve_value(value: Value) -> Variable {
    match value {
        Value::Integer(v) => Variable::Integer(v),
        Value::Bool(v) => Variable::Integer(i64::from(v)),
        Value::Float(v) => Variable::Float(v),
        Value::Text(v) => Variable::String(v.into_owned().into()),
        Value::Blob(v) => Variable::String(v.into_owned().into_string().into()),
        Value::Null => Variable::default(),
    }
}

pub fn into_store_value(value: Variable) -> Value<'static> {
    match value {
        Variable::String(v) => Value::Text(v.to_string().into()),
        Variable::Integer(v) => Value::Integer(v),
        Variable::Float(v) => Value::Float(v),
        v => Value::Text(v.to_string().into_owned().into()),
    }
}

pub fn to_store_value(value: &Variable) -> Value<'static> {
    match value {
        Variable::String(v) => Value::Text(v.to_string().into()),
        Variable::Integer(v) => Value::Integer(*v),
        Variable::Float(v) => Value::Float(*v),
        v => Value::Text(v.to_string().into_owned().into()),
    }
}

impl AsRef<LookupStore> for Lookup {
    fn as_ref(&self) -> &LookupStore {
        &self.0.store
    }
}

impl From<Arc<store::Lookup>> for Lookup {
    fn from(lookup: Arc<store::Lookup>) -> Self {
        Self(lookup)
    }
}

impl Default for State {
    fn default() -> Self {
        State::Request(RequestReceiver::default())
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

#[cfg(feature = "local_delivery")]
#[derive(Default)]
pub struct NullIo {
    pub tx_buf: Vec<u8>,
}

#[cfg(feature = "local_delivery")]
impl AsyncWrite for NullIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.tx_buf.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "local_delivery")]
impl AsyncRead for NullIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        unreachable!()
    }
}

#[cfg(feature = "local_delivery")]
impl crate::inbound::IsTls for NullIo {
    fn is_tls(&self) -> bool {
        true
    }

    fn write_tls_header(&self, _headers: &mut Vec<u8>) {}

    fn tls_version_and_cipher(&self) -> (&'static str, &'static str) {
        ("", "")
    }
}

#[cfg(feature = "local_delivery")]
lazy_static::lazy_static! {
static ref SIEVE: Arc<ServerInstance> = Arc::new(utils::listener::ServerInstance {
    id: "sieve".to_string(),
    listener_id: u16::MAX,
    protocol: utils::config::ServerProtocol::Lmtp,
    hostname: "localhost".to_string(),
    data: "localhost".to_string(),
    tls_acceptor: None,
    is_tls_implicit: true,
    limiter: utils::listener::limiter::ConcurrencyLimiter::new(0),
    shutdown_rx: tokio::sync::watch::channel(false).1,
});
}

#[cfg(feature = "local_delivery")]
impl Session<NullIo> {
    pub fn local(
        core: std::sync::Arc<SMTP>,
        instance: std::sync::Arc<utils::listener::ServerInstance>,
        data: SessionData,
    ) -> Self {
        Session {
            state: State::None,
            instance,
            core,
            span: tracing::info_span!(
                "local_delivery",
                "return_path" =
                    if let Some(addr) = data.mail_from.as_ref().map(|a| a.address_lcase.as_str()) {
                        if !addr.is_empty() {
                            addr
                        } else {
                            "<>"
                        }
                    } else {
                        "<>"
                    },
                "nrcpt" = data.rcpt_to.len(),
                "size" = data.message.len(),
            ),
            stream: NullIo::default(),
            data,
            params: SessionParameters {
                timeout: Default::default(),
                ehlo_require: Default::default(),
                ehlo_reject_non_fqdn: Default::default(),
                auth_directory: Default::default(),
                auth_require: Default::default(),
                auth_errors_max: Default::default(),
                auth_errors_wait: Default::default(),
                auth_plain_text: false,
                rcpt_errors_max: Default::default(),
                rcpt_errors_wait: Default::default(),
                rcpt_max: Default::default(),
                rcpt_dsn: Default::default(),
                max_message_size: Default::default(),
                iprev: crate::config::VerifyStrategy::Disable,
                spf_ehlo: crate::config::VerifyStrategy::Disable,
                spf_mail_from: crate::config::VerifyStrategy::Disable,
                can_expn: false,
                can_vrfy: false,
            },
            in_flight: vec![],
        }
    }

    pub fn sieve(
        core: std::sync::Arc<SMTP>,
        mail_from: SessionAddress,
        rcpt_to: Vec<SessionAddress>,
        message: Vec<u8>,
    ) -> Self {
        Self::local(
            core,
            SIEVE.clone(),
            SessionData::local(mail_from.into(), rcpt_to, message),
        )
    }

    pub fn has_failed(&mut self) -> Option<String> {
        if self.stream.tx_buf.first().map_or(true, |&c| c == b'2') {
            self.stream.tx_buf.clear();
            None
        } else {
            let response = std::str::from_utf8(&self.stream.tx_buf)
                .unwrap()
                .trim()
                .to_string();
            self.stream.tx_buf.clear();
            Some(response)
        }
    }
}

#[cfg(feature = "local_delivery")]
impl SessionData {
    pub fn local(
        mail_from: Option<SessionAddress>,
        rcpt_to: Vec<SessionAddress>,
        message: Vec<u8>,
    ) -> Self {
        SessionData {
            local_ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            remote_ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            remote_port: 0,
            helo_domain: "localhost".into(),
            mail_from,
            rcpt_to,
            rcpt_errors: 0,
            message,
            authenticated_as: "local".into(),
            auth_errors: 0,
            priority: 0,
            delivery_by: 0,
            future_release: 0,
            valid_until: Instant::now(),
            bytes_left: 0,
            messages_sent: 0,
            iprev: None,
            spf_ehlo: None,
            spf_mail_from: None,
            dnsbl_error: None,
        }
    }
}

#[cfg(feature = "local_delivery")]
impl Default for SessionData {
    fn default() -> Self {
        Self::local(None, vec![], vec![])
    }
}

#[cfg(feature = "local_delivery")]
impl SessionAddress {
    pub fn new(address: String) -> Self {
        let address_lcase = address.to_lowercase();
        SessionAddress {
            domain: address_lcase.domain_part().to_string(),
            address_lcase,
            address,
            flags: 0,
            dsn_info: None,
        }
    }
}
