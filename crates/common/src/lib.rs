/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![warn(clippy::large_futures)]

use ahash::{AHashMap, AHashSet};
use arc_swap::ArcSwap;
use auth::{AccessToken, oauth::config::OAuthConfig, roles::RolePermissions};
use calcard::common::timezone::Tz;
use config::{
    groupware::GroupwareConfig,
    imap::ImapConfig,
    jmap::settings::{JmapConfig, SpecialUse},
    network::Network,
    scripts::Scripting,
    smtp::{
        SmtpConfig,
        resolver::{Policy, Tlsa},
    },
    spamfilter::{IpResolver, SpamFilterConfig},
    storage::Storage,
    telemetry::Metrics,
};
use ipc::{BroadcastEvent, HousekeeperEvent, QueueEvent, ReportingEvent, StateEvent};
use jmap_proto::types::value::AclGrant;
use listener::{asn::AsnGeoLookupData, blocked::Security, tls::AcmeProviders};
use mail_auth::{MX, Txt};
use manager::webadmin::{Resource, WebAdminManager};
use nlp::bayes::{TokenHash, Weights};
use parking_lot::{Mutex, RwLock};
use rustls::sign::CertifiedKey;
use std::{
    hash::{BuildHasher, Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
use tinyvec::TinyVec;
use tokio::sync::{Notify, Semaphore, mpsc};
use tokio_rustls::TlsConnector;
use utils::{
    cache::{Cache, CacheItemWeight, CacheWithTtl},
    snowflake::SnowflakeIdGenerator,
};

pub mod addresses;
pub mod auth;
pub mod config;
pub mod core;
pub mod dns;
#[cfg(feature = "enterprise")]
pub mod enterprise;
pub mod expr;
pub mod i18n;
pub mod ipc;
pub mod listener;
pub mod manager;
pub mod scripts;
pub mod sharing;
pub mod storage;
pub mod telemetry;

pub use psl;

pub static VERSION_PRIVATE: &str = env!("CARGO_PKG_VERSION");
pub static VERSION_PUBLIC: &str = "1.0.0";

pub static USER_AGENT: &str = "Stalwart/1.0.0";
pub static DAEMON_NAME: &str = concat!("Stalwart v", env!("CARGO_PKG_VERSION"),);
pub static PROD_ID: &str = "-//Stalwart Labs Ltd.//Stalwart Server//EN";

pub const DATABASE_SCHEMA_VERSION: u32 = 2;

pub const LONG_1D_SLUMBER: Duration = Duration::from_secs(60 * 60 * 24);
pub const LONG_1Y_SLUMBER: Duration = Duration::from_secs(60 * 60 * 24 * 365);

pub const IPC_CHANNEL_BUFFER: usize = 1024;

pub const KV_ACME: u8 = 0;
pub const KV_OAUTH: u8 = 1;
pub const KV_RATE_LIMIT_RCPT: u8 = 2;
pub const KV_RATE_LIMIT_SCAN: u8 = 3;
pub const KV_RATE_LIMIT_LOITER: u8 = 4;
pub const KV_RATE_LIMIT_AUTH: u8 = 5;
pub const KV_RATE_LIMIT_SMTP: u8 = 6;
pub const KV_RATE_LIMIT_CONTACT: u8 = 7;
pub const KV_RATE_LIMIT_HTTP_AUTHENTICATED: u8 = 8;
pub const KV_RATE_LIMIT_HTTP_ANONYMOUS: u8 = 9;
pub const KV_RATE_LIMIT_IMAP: u8 = 10;
pub const KV_TOKEN_REVISION: u8 = 11;
pub const KV_REPUTATION_IP: u8 = 12;
pub const KV_REPUTATION_FROM: u8 = 13;
pub const KV_REPUTATION_DOMAIN: u8 = 14;
pub const KV_REPUTATION_ASN: u8 = 15;
pub const KV_GREYLIST: u8 = 16;
pub const KV_BAYES_MODEL_GLOBAL: u8 = 17;
pub const KV_BAYES_MODEL_USER: u8 = 18;
pub const KV_TRUSTED_REPLY: u8 = 19;
pub const KV_LOCK_PURGE_ACCOUNT: u8 = 20;
pub const KV_LOCK_QUEUE_MESSAGE: u8 = 21;
pub const KV_LOCK_QUEUE_REPORT: u8 = 22;
pub const KV_LOCK_TASK: u8 = 23;
pub const KV_LOCK_HOUSEKEEPER: u8 = 24;
pub const KV_LOCK_DAV: u8 = 25;
pub const KV_SIEVE_ID: u8 = 26;

pub const IDX_UID: u8 = 0;
pub const IDX_EMAIL: u8 = 1;

#[derive(Clone)]
pub struct Server {
    pub inner: Arc<Inner>,
    pub core: Arc<Core>,
}

pub struct Inner {
    pub shared_core: ArcSwap<Core>,
    pub data: Data,
    pub cache: Caches,
    pub ipc: Ipc,
}

pub struct Data {
    pub tls_certificates: ArcSwap<AHashMap<String, Arc<CertifiedKey>>>,
    pub tls_self_signed_cert: Option<Arc<CertifiedKey>>,

    pub blocked_ips: RwLock<AHashSet<IpAddr>>,

    pub asn_geo_data: AsnGeoLookupData,

    pub jmap_id_gen: SnowflakeIdGenerator,
    pub queue_id_gen: SnowflakeIdGenerator,
    pub span_id_gen: SnowflakeIdGenerator,
    pub queue_status: AtomicBool,

    pub webadmin: WebAdminManager,
    pub logos: Mutex<AHashMap<String, Option<Resource<Vec<u8>>>>>,

    pub smtp_connectors: TlsConnectors,
}

pub struct Caches {
    pub access_tokens: Cache<u32, Arc<AccessToken>>,
    pub http_auth: Cache<String, HttpAuthCache>,
    pub permissions: Cache<u32, Arc<RolePermissions>>,

    pub messages: Cache<u32, CacheSwap<MessageStoreCache>>,
    pub files: Cache<u32, CacheSwap<DavResources>>,
    pub contacts: Cache<u32, CacheSwap<DavResources>>,
    pub events: Cache<u32, CacheSwap<DavResources>>,

    pub bayes: CacheWithTtl<TokenHash, Weights>,

    pub dns_txt: CacheWithTtl<String, Txt>,
    pub dns_mx: CacheWithTtl<String, Arc<Vec<MX>>>,
    pub dns_ptr: CacheWithTtl<IpAddr, Arc<Vec<String>>>,
    pub dns_ipv4: CacheWithTtl<String, Arc<Vec<Ipv4Addr>>>,
    pub dns_ipv6: CacheWithTtl<String, Arc<Vec<Ipv6Addr>>>,
    pub dns_tlsa: CacheWithTtl<String, Arc<Tlsa>>,
    pub dbs_mta_sts: CacheWithTtl<String, Arc<Policy>>,
    pub dns_rbl: CacheWithTtl<String, Option<Arc<IpResolver>>>,
}

#[derive(Debug, Clone)]
pub struct CacheSwap<T>(pub Arc<ArcSwap<T>>);

#[derive(Debug, Clone)]
pub struct MessageStoreCache {
    pub emails: Arc<MessagesCache>,
    pub mailboxes: Arc<MailboxesCache>,
    pub update_lock: Arc<Semaphore>,
    pub last_change_id: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct MailboxesCache {
    pub change_id: u64,
    pub index: AHashMap<u32, u32>,
    pub items: Vec<MailboxCache>,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct MessagesCache {
    pub change_id: u64,
    pub items: Vec<MessageCache>,
    pub index: AHashMap<u32, u32>,
    pub keywords: Vec<String>,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct MessageCache {
    pub document_id: u32,
    pub mailboxes: TinyVec<[MessageUidCache; 2]>,
    pub keywords: u128,
    pub thread_id: u32,
    pub change_id: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct MessageUidCache {
    pub mailbox_id: u32,
    pub uid: u32,
}

#[derive(Debug, Clone)]
pub struct MailboxCache {
    pub document_id: u32,
    pub name: String,
    pub path: String,
    pub role: SpecialUse,
    pub parent_id: u32,
    pub sort_order: u32,
    pub subscribers: TinyVec<[u32; 4]>,
    pub uid_validity: u32,
    pub acls: TinyVec<[AclGrant; 2]>,
}

#[derive(Debug, Clone, Default)]
pub struct HttpAuthCache {
    pub account_id: u32,
    pub revision: u64,
}

pub struct Ipc {
    pub state_tx: mpsc::Sender<StateEvent>,
    pub housekeeper_tx: mpsc::Sender<HousekeeperEvent>,
    pub task_tx: Arc<Notify>,
    pub queue_tx: mpsc::Sender<QueueEvent>,
    pub report_tx: mpsc::Sender<ReportingEvent>,
    pub broadcast_tx: Option<mpsc::Sender<BroadcastEvent>>,
    pub local_delivery_sm: Arc<Semaphore>,
}

pub struct TlsConnectors {
    pub pki_verify: TlsConnector,
    pub dummy_verify: TlsConnector,
}

pub struct NameWrapper(pub String);

#[derive(Debug, Clone)]
pub struct DavResources {
    pub base_path: String,
    pub paths: AHashSet<DavPath>,
    pub resources: Vec<DavResource>,
    pub item_change_id: u64,
    pub container_change_id: u64,
    pub highest_change_id: u64,
    pub size: u64,
    pub update_lock: Arc<Semaphore>,
}

#[derive(Debug, Clone)]
pub struct DavPath {
    pub path: String,
    pub parent_id: Option<u32>,
    pub hierarchy_seq: u32,
    pub resource_idx: usize,
}

#[derive(Debug, Clone)]
pub struct DavResource {
    pub document_id: u32,
    pub data: DavResourceMetadata,
}

#[derive(Debug, Clone, Copy)]
pub struct DavResourcePath<'x> {
    pub path: &'x DavPath,
    pub resource: &'x DavResource,
}

#[derive(Debug, Clone)]
pub enum DavResourceMetadata {
    File {
        name: String,
        size: Option<u32>,
        parent_id: Option<u32>,
        acls: TinyVec<[AclGrant; 2]>,
    },
    Calendar {
        name: String,
        acls: TinyVec<[AclGrant; 2]>,
        tz: Tz,
    },
    CalendarEvent {
        names: TinyVec<[DavName; 2]>,
        start: i64,
        duration: u32,
    },
    AddressBook {
        name: String,
        acls: TinyVec<[AclGrant; 2]>,
    },
    ContactCard {
        names: TinyVec<[DavName; 2]>,
    },
}

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct DavName {
    pub name: String,
    pub parent_id: u32,
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
    pub groupware: GroupwareConfig,
    pub spam: SpamFilterConfig,
    pub imap: ImapConfig,
    pub metrics: Metrics,
    #[cfg(feature = "enterprise")]
    pub enterprise: Option<enterprise::Enterprise>,
}

impl<T: CacheItemWeight> CacheItemWeight for CacheSwap<T> {
    fn weight(&self) -> u64 {
        std::mem::size_of::<CacheSwap<T>>() as u64 + self.0.load().weight()
    }
}

impl CacheItemWeight for MessageStoreCache {
    fn weight(&self) -> u64 {
        self.size
    }
}

impl CacheItemWeight for HttpAuthCache {
    fn weight(&self) -> u64 {
        std::mem::size_of::<HttpAuthCache>() as u64
    }
}

impl CacheItemWeight for DavResources {
    fn weight(&self) -> u64 {
        self.size
    }
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
        debug_assert!(
            bytes.len() >= std::mem::size_of::<u64>(),
            "ThrottleKeyHasher: input too short {bytes:?}"
        );
        self.hash = bytes
            .get(0..std::mem::size_of::<u64>())
            .map_or(0, |b| u64::from_ne_bytes(b.try_into().unwrap()));
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
            cache: Default::default(),
        }
    }
}

#[cfg(feature = "test_mode")]
#[allow(clippy::derivable_impls)]
impl Default for Caches {
    fn default() -> Self {
        Self {
            access_tokens: Cache::new(1024, 10 * 1024 * 1024),
            http_auth: Cache::new(1024, 10 * 1024 * 1024),
            permissions: Cache::new(1024, 10 * 1024 * 1024),
            messages: Cache::new(1024, 25 * 1024 * 1024),
            files: Cache::new(1024, 10 * 1024 * 1024),
            contacts: Cache::new(1024, 10 * 1024 * 1024),
            events: Cache::new(1024, 10 * 1024 * 1024),
            bayes: CacheWithTtl::new(1024, 10 * 1024 * 1024),
            dns_rbl: CacheWithTtl::new(1024, 10 * 1024 * 1024),
            dns_txt: CacheWithTtl::new(1024, 10 * 1024 * 1024),
            dns_mx: CacheWithTtl::new(1024, 10 * 1024 * 1024),
            dns_ptr: CacheWithTtl::new(1024, 10 * 1024 * 1024),
            dns_ipv4: CacheWithTtl::new(1024, 10 * 1024 * 1024),
            dns_ipv6: CacheWithTtl::new(1024, 10 * 1024 * 1024),
            dns_tlsa: CacheWithTtl::new(1024, 10 * 1024 * 1024),
            dbs_mta_sts: CacheWithTtl::new(1024, 10 * 1024 * 1024),
        }
    }
}

#[cfg(feature = "test_mode")]
impl Default for Ipc {
    fn default() -> Self {
        Self {
            state_tx: mpsc::channel(IPC_CHANNEL_BUFFER).0,
            housekeeper_tx: mpsc::channel(IPC_CHANNEL_BUFFER).0,
            task_tx: Default::default(),
            queue_tx: mpsc::channel(IPC_CHANNEL_BUFFER).0,
            report_tx: mpsc::channel(IPC_CHANNEL_BUFFER).0,
            broadcast_tx: None,
            local_delivery_sm: Arc::new(Semaphore::new(10)),
        }
    }
}

pub fn ip_to_bytes(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

pub fn ip_to_bytes_prefix(prefix: u8, ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(ip) => {
            let mut buf = Vec::with_capacity(5);
            buf.push(prefix);
            buf.extend_from_slice(&ip.octets());
            buf
        }
        IpAddr::V6(ip) => {
            let mut buf = Vec::with_capacity(17);
            buf.push(prefix);
            buf.extend_from_slice(&ip.octets());
            buf
        }
    }
}

impl DavResourcePath<'_> {
    #[inline(always)]
    pub fn document_id(&self) -> u32 {
        self.resource.document_id
    }

    #[inline(always)]
    pub fn parent_id(&self) -> Option<u32> {
        self.path.parent_id
    }

    #[inline(always)]
    pub fn path(&self) -> &str {
        self.path.path.as_str()
    }

    #[inline(always)]
    pub fn is_container(&self) -> bool {
        self.resource.is_container()
    }

    #[inline(always)]
    pub fn hierarchy_seq(&self) -> u32 {
        self.path.hierarchy_seq
    }

    #[inline(always)]
    pub fn size(&self) -> u32 {
        self.resource.size()
    }
}

impl DavResources {
    pub fn by_path(&self, name: &str) -> Option<DavResourcePath<'_>> {
        self.paths.get(name).map(|path| DavResourcePath {
            path,
            resource: &self.resources[path.resource_idx],
        })
    }

    pub fn container_resource_by_id(&self, id: u32) -> Option<&DavResource> {
        self.resources
            .iter()
            .find(|res| res.document_id == id && res.is_container())
    }

    pub fn subtree(&self, search_path: &str) -> impl Iterator<Item = DavResourcePath<'_>> {
        let prefix = format!("{search_path}/");
        self.paths.iter().filter_map(move |path| {
            if path.path.starts_with(&prefix) || path.path == search_path {
                Some(DavResourcePath {
                    path,
                    resource: &self.resources[path.resource_idx],
                })
            } else {
                None
            }
        })
    }

    pub fn subtree_with_depth(
        &self,
        search_path: &str,
        depth: usize,
    ) -> impl Iterator<Item = DavResourcePath<'_>> {
        let prefix = format!("{search_path}/");
        self.paths.iter().filter_map(move |path| {
            if path
                .path
                .strip_prefix(&prefix)
                .is_some_and(|name| name.as_bytes().iter().filter(|&&c| c == b'/').count() < depth)
                || path.path.as_str() == search_path
            {
                Some(DavResourcePath {
                    path,
                    resource: &self.resources[path.resource_idx],
                })
            } else {
                None
            }
        })
    }

    pub fn tree_with_depth(&self, depth: usize) -> impl Iterator<Item = DavResourcePath<'_>> {
        self.paths.iter().filter_map(move |path| {
            if path.path.as_bytes().iter().filter(|&&c| c == b'/').count() <= depth {
                Some(DavResourcePath {
                    path,
                    resource: &self.resources[path.resource_idx],
                })
            } else {
                None
            }
        })
    }

    pub fn children(&self, parent_id: u32) -> impl Iterator<Item = DavResourcePath<'_>> {
        self.paths
            .iter()
            .filter(move |item| item.parent_id.is_some_and(|id| id == parent_id))
            .map(|path| DavResourcePath {
                path,
                resource: &self.resources[path.resource_idx],
            })
    }

    pub fn format_resource(&self, resource: DavResourcePath<'_>) -> String {
        if resource.resource.is_container() {
            format!("{}{}/", self.base_path, resource.path.path)
        } else {
            format!("{}{}", self.base_path, resource.path.path)
        }
    }

    pub fn format_collection(&self, name: &str) -> String {
        format!("{}{name}/", self.base_path)
    }

    pub fn format_item(&self, name: &str) -> String {
        format!("{}{}", self.base_path, name)
    }
}

impl DavResource {
    pub fn is_child_of(&self, parent_id: u32) -> bool {
        match &self.data {
            DavResourceMetadata::File { parent_id: id, .. } => id.is_some_and(|id| id == parent_id),
            DavResourceMetadata::CalendarEvent { names, .. } => {
                names.iter().any(|name| name.parent_id == parent_id)
            }
            DavResourceMetadata::ContactCard { names } => {
                names.iter().any(|name| name.parent_id == parent_id)
            }
            _ => false,
        }
    }

    pub fn child_names(&self) -> Option<&[DavName]> {
        match &self.data {
            DavResourceMetadata::CalendarEvent { names, .. } => Some(names.as_slice()),
            DavResourceMetadata::ContactCard { names } => Some(names.as_slice()),
            _ => None,
        }
    }

    pub fn container_name(&self) -> Option<&str> {
        match &self.data {
            DavResourceMetadata::File { name, .. } => Some(name.as_str()),
            DavResourceMetadata::Calendar { name, .. } => Some(name.as_str()),
            DavResourceMetadata::AddressBook { name, .. } => Some(name.as_str()),
            _ => None,
        }
    }

    pub fn has_hierarchy_changes(&self, other: &DavResource) -> bool {
        match (&self.data, &other.data) {
            (
                DavResourceMetadata::File {
                    name: a,
                    parent_id: c,
                    ..
                },
                DavResourceMetadata::File {
                    name: b,
                    parent_id: d,
                    ..
                },
            ) => a != b || c != d,
            (
                DavResourceMetadata::Calendar { name: a, .. },
                DavResourceMetadata::Calendar { name: b, .. },
            ) => a != b,
            (
                DavResourceMetadata::AddressBook { name: a, .. },
                DavResourceMetadata::AddressBook { name: b, .. },
            ) => a != b,
            (
                DavResourceMetadata::CalendarEvent { names: a, .. },
                DavResourceMetadata::CalendarEvent { names: b, .. },
            ) => a != b,
            (
                DavResourceMetadata::ContactCard { names: a, .. },
                DavResourceMetadata::ContactCard { names: b, .. },
            ) => a != b,
            _ => unreachable!(),
        }
    }

    pub fn event_time_range(&self) -> Option<(i64, i64)> {
        match &self.data {
            DavResourceMetadata::CalendarEvent {
                start, duration, ..
            } => Some((*start, *start + *duration as i64)),
            _ => None,
        }
    }

    pub fn timezone(&self) -> Option<Tz> {
        match &self.data {
            DavResourceMetadata::Calendar { tz, .. } => Some(*tz),
            _ => None,
        }
    }

    pub fn is_container(&self) -> bool {
        match &self.data {
            DavResourceMetadata::File { size, .. } => size.is_none(),
            DavResourceMetadata::Calendar { .. } | DavResourceMetadata::AddressBook { .. } => true,
            _ => false,
        }
    }

    pub fn size(&self) -> u32 {
        match &self.data {
            DavResourceMetadata::File { size, .. } => size.unwrap_or_default(),
            _ => 0,
        }
    }

    pub fn acls(&self) -> Option<&[AclGrant]> {
        match &self.data {
            DavResourceMetadata::File { acls, .. } => Some(acls.as_slice()),
            DavResourceMetadata::Calendar { acls, .. } => Some(acls.as_slice()),
            DavResourceMetadata::AddressBook { acls, .. } => Some(acls.as_slice()),
            _ => None,
        }
    }
}

impl Hash for DavPath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}

impl PartialEq for DavPath {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Eq for DavPath {}

impl std::borrow::Borrow<str> for DavPath {
    fn borrow(&self) -> &str {
        &self.path
    }
}

impl std::hash::Hash for DavResource {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.document_id.hash(state);
    }
}

impl PartialEq for DavResource {
    fn eq(&self, other: &Self) -> bool {
        self.document_id == other.document_id
    }
}

impl Eq for DavResource {}

impl std::borrow::Borrow<u32> for DavResource {
    fn borrow(&self) -> &u32 {
        &self.document_id
    }
}

impl DavName {
    pub fn new(name: String, parent_id: u32) -> Self {
        Self { name, parent_id }
    }
}

impl<T> CacheSwap<T> {
    pub fn new(value: Arc<T>) -> Self {
        Self(Arc::new(ArcSwap::new(value)))
    }

    pub fn load_full(&self) -> Arc<T> {
        self.0.load_full()
    }

    pub fn update(&self, value: Arc<T>) {
        self.0.store(value);
    }
}

impl MailboxCache {
    pub fn parent_id(&self) -> Option<u32> {
        if self.parent_id != u32::MAX {
            Some(self.parent_id)
        } else {
            None
        }
    }

    pub fn sort_order(&self) -> Option<u32> {
        if self.sort_order != u32::MAX {
            Some(self.sort_order)
        } else {
            None
        }
    }

    pub fn is_root(&self) -> bool {
        self.parent_id == u32::MAX
    }
}

pub const DEFAULT_LOGO: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" xml:space="preserve" id="Layer_1" x="0" y="0" style="enable-background:new 0 0 680.5 252.1" version="1.1" viewBox="0 0 680.5 252.1">
<style>
 .st0{fill:#100e42}.st1{fill:#db2d54}
</style>
<path d="M227.8 143.6c.3 4.2 2.1 7.6 5.1 10.1 3.1 2.5 7.1 3.8 12.1 3.8 4.3 0 7.9-.9 10.5-2.8 2.7-1.9 4-4.5 4-7.8 0-2.4-.7-4.3-2.2-5.7-1.5-1.4-3.4-2.5-6-3.2-2.5-.7-6-1.5-10.6-2.3-4.6-.8-8.6-1.9-11.9-3.2-3.3-1.3-6-3.3-8.1-6.1-2.1-2.7-3.1-6.3-3.1-10.7 0-4.1 1.1-7.7 3.2-10.9s5.1-5.7 9-7.4c3.8-1.8 8.2-2.6 13.2-2.6 5.1 0 9.6 1 13.7 2.9 4 1.9 7.2 4.5 9.5 7.8s3.6 7.1 3.8 11.4h-11.5c-.4-3.7-2-6.6-4.8-8.9-2.8-2.2-6.3-3.4-10.6-3.4-4.1 0-7.5.9-9.9 2.7-2.5 1.8-3.7 4.3-3.7 7.6 0 2.3.7 4.1 2.2 5.5 1.5 1.4 3.4 2.4 5.9 3.1 2.4.7 5.9 1.4 10.5 2.2 4.6.8 8.6 1.9 11.9 3.3 3.3 1.4 6 3.4 8.2 6 2.1 2.6 3.2 6.1 3.2 10.5 0 4.2-1.1 8-3.4 11.3-2.2 3.3-5.4 5.9-9.4 7.8-4 1.9-8.6 2.8-13.7 2.8-5.6 0-10.6-1-14.9-3.1-4.3-2-7.6-4.9-10-8.5-2.4-3.6-3.7-7.8-3.7-12.5l11.5.3zM278.5 102.1l11-2.1v14.6h12.6v9.7h-12.6v27.2c0 2 .4 3.5 1.2 4.3.8.9 2.2 1.3 4.2 1.3h8.4v9.7h-10.6c-5 0-8.6-1.2-10.8-3.5-2.2-2.3-3.4-5.9-3.4-10.7v-50.5zM356.8 114.6v52.2h-9.7l-1.2-7.9c-1.8 2.6-4.2 4.7-7 6.2-2.9 1.6-6.2 2.3-10 2.3-4.8 0-9-1.1-12.7-3.2-3.7-2.1-6.7-5.2-8.8-9.3-2.1-4-3.2-8.8-3.2-14.2 0-5.3 1.1-10 3.2-14s5.1-7.2 8.8-9.4c3.7-2.2 7.9-3.3 12.6-3.3 3.9 0 7.2.7 10.1 2.2 2.9 1.5 5.2 3.5 6.9 6.1l1.3-7.6h9.7zm-15.1 38.7c2.8-3.2 4.2-7.3 4.2-12.4 0-5.2-1.4-9.4-4.2-12.6-2.8-3.3-6.5-4.9-11-4.9-4.6 0-8.2 1.6-11 4.8-2.8 3.2-4.2 7.4-4.2 12.5 0 5.2 1.4 9.4 4.2 12.6 2.8 3.2 6.5 4.8 11 4.8s8.2-1.6 11-4.8zM365.5 97.5l11-2.1v71.3h-11V97.5zM380.3 114.6h11.6l11.9 39.9 11.9-39.9h10.1l11.4 39.9 12.3-39.9h11.2l-17.3 52.2h-11.8l-11-35.5-11.4 35.5-11.9.1-17-52.3zM513.7 114.6v52.2H504l-1.2-7.9c-1.8 2.6-4.2 4.7-7 6.2-2.9 1.6-6.2 2.3-10 2.3-4.8 0-9-1.1-12.7-3.2-3.7-2.1-6.7-5.2-8.8-9.3-2.1-4-3.2-8.8-3.2-14.2 0-5.3 1.1-10 3.2-14s5.1-7.2 8.8-9.4c3.7-2.2 7.9-3.3 12.6-3.3 3.9 0 7.2.7 10.1 2.2 2.9 1.5 5.2 3.5 6.9 6.1l1.3-7.6h9.7zm-15.1 38.7c2.8-3.2 4.2-7.3 4.2-12.4 0-5.2-1.4-9.4-4.2-12.6-2.8-3.3-6.5-4.9-11-4.9-4.6 0-8.2 1.6-11 4.8-2.8 3.2-4.2 7.4-4.2 12.5 0 5.2 1.4 9.4 4.2 12.6 2.8 3.2 6.5 4.8 11 4.8 4.6 0 8.2-1.6 11-4.8zM551.3 114.6v10.3h-4.9c-4.6 0-7.8 1.5-9.9 4.4-2 3-3.1 6.7-3.1 11.3v26.2h-11v-52.2h9.8l1.2 7.8c1.5-2.4 3.4-4.4 5.8-5.8 2.4-1.4 5.6-2.1 9.6-2.1h2.5zM556.3 102.1l11-2.1v14.6h12.6v9.7h-12.6v27.2c0 2 .4 3.5 1.2 4.3.8.9 2.2 1.3 4.2 1.3h8.4v9.7h-10.6c-5 0-8.6-1.2-10.8-3.5s-3.4-5.9-3.4-10.7v-50.5z" class="st0"/>
<path d="M149.1 84.7h-4.8l-44.8 25.9v8.3l44.8 25.9h4.8l44.8-25.9v-8.3l-44.8-25.9zm32.9 30h-35.3V94.4l35.3 20.3zm-35.3 20.4-35.3-20.4 27-15.6v20.2l6.3 3.6h22.9l-20.9 12.2z" class="st1"/>
<path d="M99.5 129.9v11l44.8 25.9h4.8l44.8-25.9v-11l-47.2 27.3zM187.3 166.8l6.6-3.8v-11l-25.7 14.8zM99.5 163l6.6 3.8h19.1L99.5 152z" class="st1"/>
</svg>
"#;
