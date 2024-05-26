/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
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
