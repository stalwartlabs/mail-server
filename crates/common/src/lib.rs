/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::BTreeMap,
    hash::{BuildHasher, Hasher},
    net::IpAddr,
    sync::{atomic::AtomicU8, Arc},
};

use ahash::{AHashMap, AHashSet, RandomState};
use arc_swap::ArcSwap;
use auth::{oauth::config::OAuthConfig, roles::RolePermissions, AccessToken};
use config::{
    imap::ImapConfig,
    jmap::settings::JmapConfig,
    network::Network,
    scripts::{RemoteList, Scripting},
    smtp::SmtpConfig,
    storage::Storage,
    telemetry::Metrics,
};
use dashmap::DashMap;

use futures::StreamExt;
use imap_proto::protocol::list::Attribute;
use ipc::{DeliveryEvent, HousekeeperEvent, QueueEvent, ReportingEvent, StateEvent};
use listener::{blocked::Security, limiter::ConcurrencyLimiter, tls::AcmeProviders};

use manager::webadmin::{Resource, WebAdminManager};
use nlp::bayes::cache::BayesTokenCache;
use parking_lot::{Mutex, RwLock};
use reqwest::Response;
use rustls::sign::CertifiedKey;
use tokio::sync::{mpsc, Notify};
use tokio_rustls::TlsConnector;
use utils::{
    lru_cache::LruCache,
    map::ttl_dashmap::{ADashMap, TtlDashMap},
    snowflake::SnowflakeIdGenerator,
};

pub mod addresses;
pub mod auth;
pub mod config;
pub mod core;
#[cfg(feature = "enterprise")]
pub mod enterprise;
pub mod expr;
pub mod ipc;
pub mod listener;
pub mod manager;
pub mod scripts;
pub mod telemetry;

pub use psl;

pub static USER_AGENT: &str = concat!("Stalwart/", env!("CARGO_PKG_VERSION"),);
pub static DAEMON_NAME: &str = concat!("Stalwart Mail Server v", env!("CARGO_PKG_VERSION"),);

pub const IPC_CHANNEL_BUFFER: usize = 1024;

#[derive(Clone)]
pub struct Server {
    pub inner: Arc<Inner>,
    pub core: Arc<Core>,
}

pub struct Inner {
    pub shared_core: ArcSwap<Core>,
    pub data: Data,
    pub ipc: Ipc,
}

pub struct Data {
    pub tls_certificates: ArcSwap<AHashMap<String, Arc<CertifiedKey>>>,
    pub tls_self_signed_cert: Option<Arc<CertifiedKey>>,

    pub access_tokens: TtlDashMap<u32, Arc<AccessToken>>,
    pub http_auth_cache: TtlDashMap<String, u32>,

    pub blocked_ips: RwLock<AHashSet<IpAddr>>,
    pub blocked_ips_version: AtomicU8,

    pub permissions: ADashMap<u32, Arc<RolePermissions>>,
    pub permissions_version: AtomicU8,

    pub bayes_cache: BayesTokenCache,
    pub remote_lists: RwLock<AHashMap<String, RemoteList>>,

    pub jmap_id_gen: SnowflakeIdGenerator,
    pub queue_id_gen: SnowflakeIdGenerator,
    pub span_id_gen: SnowflakeIdGenerator,

    pub webadmin: WebAdminManager,
    pub config_version: AtomicU8,

    pub jmap_limiter: DashMap<u32, Arc<ConcurrencyLimiters>, RandomState>,
    pub imap_limiter: DashMap<u32, Arc<ConcurrencyLimiters>, RandomState>,

    pub account_cache: LruCache<AccountId, Arc<Account>>,
    pub mailbox_cache: LruCache<MailboxId, Arc<MailboxState>>,
    pub threads_cache: LruCache<u32, Arc<Threads>>,

    pub logos: Mutex<AHashMap<String, Option<Resource<Vec<u8>>>>>,

    pub smtp_session_throttle: DashMap<ThrottleKey, ConcurrencyLimiter, ThrottleKeyHasherBuilder>,
    pub smtp_queue_throttle: DashMap<ThrottleKey, ConcurrencyLimiter, ThrottleKeyHasherBuilder>,
    pub smtp_connectors: TlsConnectors,
}

pub struct Ipc {
    pub state_tx: mpsc::Sender<StateEvent>,
    pub housekeeper_tx: mpsc::Sender<HousekeeperEvent>,
    pub delivery_tx: mpsc::Sender<DeliveryEvent>,
    pub index_tx: Arc<Notify>,
    pub queue_tx: mpsc::Sender<QueueEvent>,
    pub report_tx: mpsc::Sender<ReportingEvent>,
}

pub struct TlsConnectors {
    pub pki_verify: TlsConnector,
    pub dummy_verify: TlsConnector,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct AccountId {
    pub account_id: u32,
    pub primary_id: u32,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct MailboxId {
    pub account_id: u32,
    pub mailbox_id: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Account {
    pub account_id: u32,
    pub prefix: Option<String>,
    pub mailbox_names: BTreeMap<String, u32>,
    pub mailbox_state: AHashMap<u32, Mailbox>,
    pub state_email: Option<u64>,
    pub state_mailbox: Option<u64>,
}

#[derive(Debug, Default, Clone)]
pub struct Mailbox {
    pub has_children: bool,
    pub is_subscribed: bool,
    pub special_use: Option<Attribute>,
    pub total_messages: Option<u32>,
    pub total_unseen: Option<u32>,
    pub total_deleted: Option<u32>,
    pub uid_validity: Option<u32>,
    pub uid_next: Option<u32>,
    pub size: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct MailboxState {
    pub uid_next: u32,
    pub uid_validity: u32,
    pub uid_max: u32,
    pub id_to_imap: AHashMap<u32, ImapId>,
    pub uid_to_id: AHashMap<u32, u32>,
    pub total_messages: usize,
    pub modseq: Option<u64>,
    pub next_state: Option<Box<NextMailboxState>>,
}

#[derive(Debug, Clone)]
pub struct NextMailboxState {
    pub next_state: MailboxState,
    pub deletions: Vec<ImapId>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ImapId {
    pub uid: u32,
    pub seqnum: u32,
}

#[derive(Debug, Default)]
pub struct Threads {
    pub threads: AHashMap<u32, u32>,
    pub modseq: Option<u64>,
}

pub struct ConcurrencyLimiters {
    pub concurrent_requests: ConcurrencyLimiter,
    pub concurrent_uploads: ConcurrencyLimiter,
}

#[derive(Clone, Default)]
pub struct Core {
    pub storage: Storage,
    pub sieve: Scripting,
    pub network: Network,
    pub acme: AcmeProviders,
    pub oauth: OAuthConfig,
    pub smtp: SmtpConfig,
    pub jmap: JmapConfig,
    pub imap: ImapConfig,
    pub metrics: Metrics,
    #[cfg(feature = "enterprise")]
    pub enterprise: Option<enterprise::Enterprise>,
}

pub trait IntoString: Sized {
    fn into_string(self) -> String;
}

impl IntoString for Vec<u8> {
    fn into_string(self) -> String {
        String::from_utf8(self)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
    }
}

#[derive(Debug, Clone, Eq)]
pub struct ThrottleKey {
    pub hash: [u8; 32],
}

impl PartialEq for ThrottleKey {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl std::hash::Hash for ThrottleKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl AsRef<[u8]> for ThrottleKey {
    fn as_ref(&self) -> &[u8] {
        &self.hash
    }
}

#[derive(Default)]
pub struct ThrottleKeyHasher {
    hash: u64,
}

impl Hasher for ThrottleKeyHasher {
    fn finish(&self) -> u64 {
        self.hash
    }

    fn write(&mut self, bytes: &[u8]) {
        self.hash = u64::from_ne_bytes((&bytes[..std::mem::size_of::<u64>()]).try_into().unwrap());
    }
}

#[derive(Clone, Default)]
pub struct ThrottleKeyHasherBuilder {}

impl BuildHasher for ThrottleKeyHasherBuilder {
    type Hasher = ThrottleKeyHasher;

    fn build_hasher(&self) -> Self::Hasher {
        ThrottleKeyHasher::default()
    }
}

pub trait HttpLimitResponse: Sync + Send {
    fn bytes_with_limit(
        self,
        limit: usize,
    ) -> impl std::future::Future<Output = reqwest::Result<Option<Vec<u8>>>> + Send;
}

impl HttpLimitResponse for Response {
    async fn bytes_with_limit(self, limit: usize) -> reqwest::Result<Option<Vec<u8>>> {
        if self
            .content_length()
            .map_or(false, |len| len as usize > limit)
        {
            return Ok(None);
        }

        let mut bytes = Vec::with_capacity(std::cmp::min(limit, 1024));
        let mut stream = self.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len() + chunk.len() > limit {
                return Ok(None);
            }
            bytes.extend_from_slice(&chunk);
        }

        Ok(Some(bytes))
    }
}

impl ConcurrencyLimiters {
    pub fn is_active(&self) -> bool {
        self.concurrent_requests.is_active() || self.concurrent_uploads.is_active()
    }
}

#[cfg(feature = "test_mode")]
#[allow(clippy::derivable_impls)]
impl Default for Server {
    fn default() -> Self {
        Self {
            inner: Default::default(),
            core: Default::default(),
        }
    }
}

#[cfg(feature = "test_mode")]
#[allow(clippy::derivable_impls)]
impl Default for Inner {
    fn default() -> Self {
        Self {
            shared_core: Default::default(),
            data: Default::default(),
            ipc: Default::default(),
        }
    }
}

#[cfg(feature = "test_mode")]
impl Default for Ipc {
    fn default() -> Self {
        Self {
            state_tx: mpsc::channel(IPC_CHANNEL_BUFFER).0,
            housekeeper_tx: mpsc::channel(IPC_CHANNEL_BUFFER).0,
            delivery_tx: mpsc::channel(IPC_CHANNEL_BUFFER).0,
            index_tx: Default::default(),
            queue_tx: mpsc::channel(IPC_CHANNEL_BUFFER).0,
            report_tx: mpsc::channel(IPC_CHANNEL_BUFFER).0,
        }
    }
}
