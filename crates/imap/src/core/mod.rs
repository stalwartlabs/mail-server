use std::{
    collections::BTreeMap,
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};

use ahash::AHashMap;
use imap_proto::{
    protocol::{list::Attribute, ProtocolVersion},
    receiver::Receiver,
    Command, ResponseCode, StatusResponse,
};
use jmap::{
    auth::{rate_limit::RemoteAddress, AccessToken},
    JMAP,
};
use tokio::{
    io::{AsyncRead, ReadHalf},
    sync::{mpsc, watch},
};
use utils::listener::{limiter::InFlight, ServerInstance};

pub mod client;
pub mod mailbox;
pub mod message;
pub mod session;
pub mod writer;

#[derive(Clone)]
pub struct ImapSessionManager {
    pub jmap: Arc<JMAP>,
    pub imap: Arc<IMAP>,
}

impl ImapSessionManager {
    pub fn new(jmap: Arc<JMAP>, imap: Arc<IMAP>) -> Self {
        Self { jmap, imap }
    }
}

pub struct IMAP {
    pub max_request_size: usize,
    pub name_shared: String,
    pub name_all: String,

    pub timeout_auth: Duration,
    pub timeout_unauth: Duration,
    pub timeout_idle: Duration,

    pub greeting_plain: Vec<u8>,
    pub greeting_tls: Vec<u8>,
}

pub struct Session<T: AsyncRead> {
    pub jmap: Arc<JMAP>,
    pub imap: Arc<IMAP>,
    pub instance: Arc<ServerInstance>,
    pub receiver: Receiver<Command>,
    pub version: ProtocolVersion,
    pub state: State,
    pub is_tls: bool,
    pub is_condstore: bool,
    pub is_qresync: bool,
    pub writer: mpsc::Sender<writer::Event>,
    pub stream_rx: ReadHalf<T>,
    pub in_flight: InFlight,
    pub remote_addr: RemoteAddress,
    pub span: tracing::Span,
}

pub struct SessionData {
    pub account_id: u32,
    pub jmap: Arc<JMAP>,
    pub imap: Arc<IMAP>,
    pub span: tracing::Span,
    pub mailboxes: parking_lot::Mutex<Vec<Account>>,
    pub writer: mpsc::Sender<writer::Event>,
    pub state: AtomicU32,
}

#[derive(Debug, Default)]
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

#[derive(Debug)]
pub struct Account {
    pub account_id: u32,
    pub prefix: Option<String>,
    pub mailbox_names: BTreeMap<String, u32>,
    pub mailbox_state: AHashMap<u32, Mailbox>,
    pub state_email: Option<u64>,
    pub state_mailbox: Option<u64>,
}

pub struct SelectedMailbox {
    pub id: MailboxId,
    pub state: parking_lot::Mutex<MailboxState>,
    pub saved_search: parking_lot::Mutex<SavedSearch>,
    pub is_select: bool,
    pub is_condstore: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct MailboxId {
    pub account_id: u32,
    pub mailbox_id: Option<u32>,
}

#[derive(Debug)]
pub struct MailboxState {
    pub uid_next: u32,
    pub uid_validity: u32,
    pub uid_max: u32,
    pub id_to_imap: AHashMap<u32, ImapId>,
    pub uid_to_id: AHashMap<u32, u32>,
    pub total_messages: usize,
    pub last_state: Option<u64>,
}

#[derive(Debug, Default)]
pub struct MailboxSync {
    pub added: Vec<String>,
    pub changed: Vec<String>,
    pub deleted: Vec<String>,
}

pub enum SavedSearch {
    InFlight {
        rx: watch::Receiver<Arc<Vec<ImapId>>>,
    },
    Results {
        items: Arc<Vec<ImapId>>,
    },
    None,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ImapId {
    pub uid: u32,
    pub seqnum: u32,
}

pub enum State {
    NotAuthenticated {
        auth_failures: u32,
    },
    Authenticated {
        data: Arc<SessionData>,
    },
    Selected {
        data: Arc<SessionData>,
        mailbox: Arc<SelectedMailbox>,
    },
}

impl SessionData {
    pub async fn get_access_token(&self) -> crate::op::Result<Arc<AccessToken>> {
        self.jmap
            .get_cached_access_token(self.account_id)
            .await
            .ok_or_else(|| {
                StatusResponse::no("Failed to obtain access token")
                    .with_code(ResponseCode::ContactAdmin)
            })
    }
}
