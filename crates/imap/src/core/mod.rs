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
    collections::BTreeMap,
    net::IpAddr,
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};

use ahash::AHashMap;
use dashmap::DashMap;
use imap_proto::{
    protocol::{list::Attribute, ProtocolVersion},
    receiver::Receiver,
    Command, ResponseCode, StatusResponse,
};
use jmap::{
    auth::{rate_limit::ConcurrencyLimiters, AccessToken},
    JMAP,
};
use tokio::{
    io::{ReadHalf, WriteHalf},
    sync::watch,
};
use utils::{
    config::Rate,
    listener::{limiter::InFlight, ServerInstance, SessionStream},
    lru_cache::LruCache,
};

pub mod client;
pub mod mailbox;
pub mod message;
pub mod session;

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
    pub max_auth_failures: u32,
    pub name_shared: String,
    pub allow_plain_auth: bool,

    pub timeout_auth: Duration,
    pub timeout_unauth: Duration,
    pub timeout_idle: Duration,

    pub greeting_plain: Vec<u8>,
    pub greeting_tls: Vec<u8>,

    pub rate_limiter: DashMap<u32, Arc<ConcurrencyLimiters>>,
    pub rate_requests: Rate,
    pub rate_concurrent: u64,

    pub cache_account: LruCache<AccountId, Arc<Account>>,
    pub cache_mailbox: LruCache<MailboxId, Arc<MailboxState>>,
}

pub struct Session<T: SessionStream> {
    pub jmap: Arc<JMAP>,
    pub imap: Arc<IMAP>,
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
    pub jmap: Arc<JMAP>,
    pub imap: Arc<IMAP>,
    pub span: tracing::Span,
    pub mailboxes: parking_lot::Mutex<Vec<Account>>,
    pub stream_tx: Arc<tokio::sync::Mutex<WriteHalf<T>>>,
    pub state: AtomicU32,
    pub in_flight: InFlight,
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
    pub async fn get_access_token(&self) -> crate::op::Result<Arc<AccessToken>> {
        self.jmap
            .get_cached_access_token(self.account_id)
            .await
            .ok_or_else(|| {
                StatusResponse::no("Failed to obtain access token")
                    .with_code(ResponseCode::ContactAdmin)
            })
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
