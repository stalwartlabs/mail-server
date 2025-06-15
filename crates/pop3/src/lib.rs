/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{net::IpAddr, sync::Arc};

use common::{
    Inner, Server,
    auth::AccessToken,
    listener::{ServerInstance, SessionStream, limiter::InFlight},
};
use mailbox::Mailbox;
use protocol::request::Parser;

pub mod client;
pub mod mailbox;
pub mod op;
pub mod protocol;
pub mod session;

static SERVER_GREETING: &str = "+OK Stalwart POP3 at your service.\r\n";

#[derive(Clone)]
pub struct Pop3SessionManager {
    pub inner: Arc<Inner>,
}

impl Pop3SessionManager {
    pub fn new(inner: Arc<Inner>) -> Self {
        Self { inner }
    }
}

pub struct Session<T: SessionStream> {
    pub server: Server,
    pub instance: Arc<ServerInstance>,
    pub receiver: Parser,
    pub state: State,
    pub stream: T,
    pub in_flight: InFlight,
    pub remote_addr: IpAddr,
    pub session_id: u64,
}

pub enum State {
    NotAuthenticated {
        auth_failures: u32,
        username: Option<String>,
    },
    Authenticated {
        mailbox: Mailbox,
        in_flight: Option<InFlight>,
        access_token: Arc<AccessToken>,
    },
}

impl State {
    pub fn mailbox(&self) -> &Mailbox {
        match self {
            State::Authenticated { mailbox, .. } => mailbox,
            _ => unreachable!(),
        }
    }

    pub fn mailbox_mut(&mut self) -> &mut Mailbox {
        match self {
            State::Authenticated { mailbox, .. } => mailbox,
            _ => unreachable!(),
        }
    }

    pub fn access_token(&self) -> &Arc<AccessToken> {
        match self {
            State::Authenticated { access_token, .. } => access_token,
            _ => unreachable!(),
        }
    }
}
