use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use imap_proto::{protocol::ProtocolVersion, receiver::Receiver, Command};
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
    pub in_flight: Vec<InFlight>,
    pub span: tracing::Span,
}

pub struct SessionData {
    pub core: Arc<JMAP>,
    pub writer: mpsc::Sender<writer::Event>,
    pub access_token: Arc<AccessToken>,
}

pub struct SelectedMailbox {
    pub id: MailboxId,
    pub state: parking_lot::Mutex<MailboxData>,
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
pub struct MailboxData {
    pub uid_next: u32,
    pub uid_validity: u32,
    pub jmap_ids: Vec<u32>,
    pub imap_uids: Vec<u32>,
    pub total_messages: usize,
    pub last_state: u32,
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
        remote_addr: RemoteAddress,
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
