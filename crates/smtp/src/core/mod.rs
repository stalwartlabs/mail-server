/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    hash::Hash,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use common::{
    config::{scripts::ScriptCache, smtp::auth::VerifyStrategy},
    listener::{
        limiter::{ConcurrencyLimiter, InFlight},
        ServerInstance,
    },
    Core, Ipc, SharedCore,
};
use dashmap::DashMap;
use directory::Directory;
use mail_auth::{IprevOutput, SpfOutput};
use smtp_proto::request::receiver::{
    BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver, LineReceiver, RequestReceiver,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};
use tokio_rustls::TlsConnector;
use utils::snowflake::SnowflakeIdGenerator;

use crate::{
    inbound::auth::SaslToken,
    queue::{self, DomainPart, QueueId},
    reporting,
};

use self::throttle::{ThrottleKey, ThrottleKeyHasherBuilder};

pub mod params;
pub mod throttle;

#[derive(Clone)]
pub struct SmtpInstance {
    pub inner: Arc<Inner>,
    pub core: SharedCore,
}

impl SmtpInstance {
    pub fn new(core: SharedCore, inner: impl Into<Arc<Inner>>) -> Self {
        Self {
            core,
            inner: inner.into(),
        }
    }
}

#[derive(Clone)]
pub struct SmtpSessionManager {
    pub inner: SmtpInstance,
}

impl SmtpSessionManager {
    pub fn new(inner: SmtpInstance) -> Self {
        Self { inner }
    }
}

#[derive(Clone)]
pub struct SMTP {
    pub core: Arc<Core>,
    pub inner: Arc<Inner>,
}

pub struct Inner {
    pub session_throttle: DashMap<ThrottleKey, ConcurrencyLimiter, ThrottleKeyHasherBuilder>,
    pub queue_throttle: DashMap<ThrottleKey, ConcurrencyLimiter, ThrottleKeyHasherBuilder>,
    pub queue_tx: mpsc::Sender<queue::Event>,
    pub report_tx: mpsc::Sender<reporting::Event>,
    pub queue_id_gen: SnowflakeIdGenerator,
    pub span_id_gen: Arc<SnowflakeIdGenerator>,
    pub connectors: TlsConnectors,
    pub ipc: Ipc,
    pub script_cache: ScriptCache,
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
    Accepted(QueueId),
    None,
}

pub struct Session<T: AsyncWrite + AsyncRead> {
    pub hostname: String,
    pub state: State,
    pub instance: Arc<ServerInstance>,
    pub core: SMTP,
    pub stream: T,
    pub data: SessionData,
    pub params: SessionParameters,
    pub in_flight: Vec<InFlight>,
}

pub struct SessionData {
    pub session_id: u64,
    pub local_ip: IpAddr,
    pub local_ip_str: String,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_ip_str: String,
    pub remote_port: u16,
    pub helo_domain: String,

    pub mail_from: Option<SessionAddress>,
    pub rcpt_to: Vec<SessionAddress>,
    pub rcpt_errors: usize,
    pub message: Vec<u8>,

    pub authenticated_as: String,
    pub authenticated_emails: Vec<String>,
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
    pub auth_match_sender: bool,

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
    pub fn new(
        local_ip: IpAddr,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
        session_id: u64,
    ) -> Self {
        SessionData {
            session_id,
            local_ip,
            local_port,
            remote_ip,
            local_ip_str: local_ip.to_string(),
            remote_ip_str: remote_ip.to_string(),
            remote_port,
            helo_domain: String::new(),
            mail_from: None,
            rcpt_to: Vec::new(),
            authenticated_as: String::new(),
            authenticated_emails: Vec::new(),
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
        Some(self.cmp(other))
    }
}

impl From<SmtpInstance> for SMTP {
    fn from(value: SmtpInstance) -> Self {
        SMTP {
            core: value.core.load_full(),
            inner: value.inner,
        }
    }
}

lazy_static::lazy_static! {
static ref SIEVE: Arc<ServerInstance> = Arc::new(ServerInstance {
    id: "sieve".to_string(),
    protocol: common::config::server::ServerProtocol::Lmtp,
    acceptor: common::listener::TcpAcceptor::Plain,
    limiter: ConcurrencyLimiter::new(0),
    shutdown_rx: tokio::sync::watch::channel(false).1,
    proxy_networks: vec![],
    span_id_gen: Arc::new(SnowflakeIdGenerator::new()),
});
}

impl Session<common::listener::stream::NullIo> {
    pub fn local(core: SMTP, instance: std::sync::Arc<ServerInstance>, data: SessionData) -> Self {
        Session {
            hostname: "localhost".to_string(),
            state: State::None,
            instance,
            core,
            stream: common::listener::stream::NullIo::default(),
            data,
            params: SessionParameters {
                timeout: Default::default(),
                ehlo_require: Default::default(),
                ehlo_reject_non_fqdn: Default::default(),
                auth_directory: Default::default(),
                auth_require: Default::default(),
                auth_errors_max: Default::default(),
                auth_errors_wait: Default::default(),
                rcpt_errors_max: Default::default(),
                rcpt_errors_wait: Default::default(),
                rcpt_max: Default::default(),
                rcpt_dsn: Default::default(),
                max_message_size: Default::default(),
                auth_match_sender: false,
                iprev: VerifyStrategy::Disable,
                spf_ehlo: VerifyStrategy::Disable,
                spf_mail_from: VerifyStrategy::Disable,
                can_expn: false,
                can_vrfy: false,
            },
            in_flight: vec![],
        }
    }

    pub fn sieve(
        core: SMTP,
        mail_from: SessionAddress,
        rcpt_to: Vec<SessionAddress>,
        message: Vec<u8>,
        session_id: u64,
    ) -> Self {
        Self::local(
            core,
            SIEVE.clone(),
            SessionData::local(mail_from.into(), rcpt_to, message, session_id),
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

impl SessionData {
    pub fn local(
        mail_from: Option<SessionAddress>,
        rcpt_to: Vec<SessionAddress>,
        message: Vec<u8>,
        session_id: u64,
    ) -> Self {
        SessionData {
            local_ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            remote_ip: IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            local_ip_str: "127.0.0.1".to_string(),
            remote_ip_str: "127.0.0.1".to_string(),
            remote_port: 0,
            local_port: 0,
            session_id,
            helo_domain: "localhost".into(),
            mail_from,
            rcpt_to,
            rcpt_errors: 0,
            message,
            authenticated_as: "local".into(),
            authenticated_emails: vec![],
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

impl Default for SessionData {
    fn default() -> Self {
        Self::local(None, vec![], vec![], 0)
    }
}

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

#[cfg(feature = "test_mode")]
impl Default for Inner {
    fn default() -> Self {
        Self {
            session_throttle: Default::default(),
            queue_throttle: Default::default(),
            queue_tx: mpsc::channel(1).0,
            report_tx: mpsc::channel(1).0,
            queue_id_gen: Default::default(),
            span_id_gen: Arc::new(SnowflakeIdGenerator::new()),
            connectors: TlsConnectors {
                pki_verify: mail_send::smtp::tls::build_tls_connector(false),
                dummy_verify: mail_send::smtp::tls::build_tls_connector(true),
            },
            ipc: Ipc {
                delivery_tx: mpsc::channel(1).0,
            },
            script_cache: Default::default(),
        }
    }
}
