/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    net::IpAddr,
    sync::{atomic::AtomicU32, Arc},
};

use common::{
    auth::AccessToken,
    listener::{limiter::InFlight, ServerInstance, SessionStream},
    Account, ImapId, Inner, MailboxId, MailboxState, Server,
};
use imap_proto::{protocol::ProtocolVersion, receiver::Receiver, Command};
use tokio::{
    io::{ReadHalf, WriteHalf},
    sync::watch,
};
use trc::AddContext;

pub mod client;
pub mod mailbox;
pub mod message;
pub mod session;

#[derive(Clone)]
pub struct ImapSessionManager {
    pub inner: Arc<Inner>,
}

impl ImapSessionManager {
    pub fn new(inner: Arc<Inner>) -> Self {
        Self { inner }
    }
}

pub struct Session<T: SessionStream> {
    pub server: Server,
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
    pub session_id: u64,
}

pub struct SessionData<T: SessionStream> {
    pub account_id: u32,
    pub access_token: Arc<AccessToken>,
    pub server: Server,
    pub session_id: u64,
    pub mailboxes: parking_lot::Mutex<Vec<Account>>,
    pub stream_tx: Arc<tokio::sync::Mutex<WriteHalf<T>>>,
    pub state: AtomicU32,
    pub in_flight: Option<InFlight>,
}

pub struct SelectedMailbox {
    pub id: MailboxId,
    pub state: parking_lot::Mutex<MailboxState>,
    pub saved_search: parking_lot::Mutex<SavedSearch>,
    pub is_select: bool,
    pub is_condstore: bool,
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
        self.server
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
            server: self.server,
            session_id: self.session_id,
            mailboxes: self.mailboxes,
            stream_tx: new_stream,
            state: self.state,
            in_flight: self.in_flight,
            access_token: self.access_token,
        }
    }
}
