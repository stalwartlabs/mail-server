/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{atomic::AtomicU32, Arc},
};

use ahash::AHashMap;
use common::listener::{limiter::InFlight, ServerInstance, SessionStream};
use dashmap::DashMap;
use imap_proto::{
    protocol::{list::Attribute, ProtocolVersion},
    receiver::Receiver,
    Command,
};
use jmap::{
    auth::{rate_limit::ConcurrencyLimiters, AccessToken},
    JmapInstance, JMAP,
};
use tokio::{
    io::{ReadHalf, WriteHalf},
    sync::watch,
};
use trc::AddContext;
use utils::lru_cache::LruCache;

pub mod client;
pub mod mailbox;
pub mod message;
pub mod session;

#[derive(Clone)]
pub struct ImapSessionManager {
    pub imap: ImapInstance,
}

impl ImapSessionManager {
    pub fn new(imap: ImapInstance) -> Self {
        Self { imap }
    }
}

#[derive(Clone)]
pub struct ImapInstance {
    pub jmap_instance: JmapInstance,
    pub imap_inner: Arc<Inner>,
}

pub struct Inner {
    pub greeting_plain: Vec<u8>,
    pub greeting_tls: Vec<u8>,

    pub rate_limiter: DashMap<u32, Arc<ConcurrencyLimiters>>,

    pub cache_account: LruCache<AccountId, Arc<Account>>,
    pub cache_mailbox: LruCache<MailboxId, Arc<MailboxState>>,
}

pub struct IMAP {}

pub struct Session<T: SessionStream> {
    pub jmap: JMAP,
    pub imap: Arc<Inner>,
    pub instance: Arc<ServerInstance>,
    pub receiver: Receiver<Command>,
    pub version: ProtocolVersion,
    pub state: State<T>,
    pub is_tls: bool,
    pub is_condstore: bool,
    pub is_qresync: bool,
    pub stream_rx: ReadHalf<T>,
    pub stream_tx: Arc<tokio::sync::Mutex<WriteHalf<T>>>,
    pub in_flight: InFlight,
    pub remote_addr: IpAddr,
    pub span: tracing::Span,
}

pub struct SessionData<T: SessionStream> {
    pub account_id: u32,
    pub jmap: JMAP,
    pub imap: Arc<Inner>,
    pub span: tracing::Span,
    pub mailboxes: parking_lot::Mutex<Vec<Account>>,
    pub stream_tx: Arc<tokio::sync::Mutex<WriteHalf<T>>>,
    pub state: AtomicU32,
    pub in_flight: Option<InFlight>,
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

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct MailboxId {
    pub account_id: u32,
    pub mailbox_id: u32,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct AccountId {
    pub account_id: u32,
    pub primary_id: u32,
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

#[derive(Debug, Clone, Copy, Default)]
pub struct ImapUidToId {
    pub uid: u32,
    pub id: u32,
}

pub enum State<T: SessionStream> {
    NotAuthenticated {
        auth_failures: u32,
    },
    Authenticated {
        data: Arc<SessionData<T>>,
    },
    Selected {
        data: Arc<SessionData<T>>,
        mailbox: Arc<SelectedMailbox>,
    },
}

impl<T: SessionStream> State<T> {
    pub fn try_replace_stream_tx<U: SessionStream>(
        self,
        new_stream: Arc<tokio::sync::Mutex<WriteHalf<U>>>,
    ) -> Option<State<U>> {
        match self {
            State::NotAuthenticated { auth_failures } => {
                State::NotAuthenticated { auth_failures }.into()
            }
            State::Authenticated { data } => {
                Arc::try_unwrap(data).ok().map(|data| State::Authenticated {
                    data: Arc::new(data.replace_stream_tx(new_stream)),
                })
            }
            State::Selected { data, mailbox } => {
                Arc::try_unwrap(data).ok().map(|data| State::Selected {
                    data: Arc::new(data.replace_stream_tx(new_stream)),
                    mailbox,
                })
            }
        }
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn get_access_token(&self) -> trc::Result<Arc<AccessToken>> {
        self.jmap
            .get_cached_access_token(self.account_id)
            .await
            .caused_by(trc::location!())
    }

    pub fn replace_stream_tx<U: SessionStream>(
        self,
        new_stream: Arc<tokio::sync::Mutex<WriteHalf<U>>>,
    ) -> SessionData<U> {
        SessionData {
            account_id: self.account_id,
            jmap: self.jmap,
            imap: self.imap,
            span: self.span,
            mailboxes: self.mailboxes,
            stream_tx: new_stream,
            state: self.state,
            in_flight: self.in_flight,
        }
    }
}
