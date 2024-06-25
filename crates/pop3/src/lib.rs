/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{net::IpAddr, sync::Arc};

use common::listener::{limiter::InFlight, ServerInstance, SessionStream};
use imap::core::{ImapInstance, Inner};
use jmap::JMAP;
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
    pub pop3: ImapInstance,
}

impl Pop3SessionManager {
    pub fn new(pop3: ImapInstance) -> Self {
        Self { pop3 }
    }
}

pub struct Session<T: SessionStream> {
    pub jmap: JMAP,
    pub imap: Arc<Inner>,
    pub instance: Arc<ServerInstance>,
    pub receiver: Parser,
    pub state: State,
    pub stream: T,
    pub in_flight: InFlight,
    pub remote_addr: IpAddr,
    pub span: tracing::Span,
}

pub enum State {
    NotAuthenticated {
        auth_failures: u32,
        username: Option<String>,
    },
    Authenticated {
        mailbox: Mailbox,
        in_flight: Option<InFlight>,
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
}
