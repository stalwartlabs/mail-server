/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart IMAP Server.
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

use std::{iter::Peekable, sync::Arc, vec::IntoIter};

use imap_proto::{
    receiver::{self, Request},
    Command, ResponseCode, StatusResponse,
};
use jmap::auth::rate_limit::AuthenticatedLimiter;
use parking_lot::Mutex;
use tokio::io::AsyncRead;
use utils::listener::limiter::{ConcurrencyLimiter, RateLimiter};

use super::{SelectedMailbox, Session, SessionData, State, IMAP};

impl<T: AsyncRead> Session<T> {
    pub async fn ingest(&mut self, bytes: &[u8]) -> crate::Result<bool> {
        /*let tmp = "dd";
        for line in String::from_utf8_lossy(bytes).split("\r\n") {
            println!("<- {:?}", &line[..std::cmp::min(line.len(), 100)]);
        }*/

        tracing::trace!(parent: &self.span,
            event = "read",
            data =  std::str::from_utf8(bytes).unwrap_or("[invalid UTF8]"),
            size = bytes.len());

        let mut bytes = bytes.iter();
        let mut requests = Vec::with_capacity(2);
        let mut needs_literal = None;

        loop {
            match self.receiver.parse(&mut bytes) {
                Ok(request) => match request.is_allowed(&self.state, self.is_tls) {
                    Ok(request) => {
                        requests.push(request);
                    }
                    Err(response) => {
                        self.write_bytes(response.into_bytes()).await?;
                    }
                },
                Err(receiver::Error::NeedsMoreData) => {
                    break;
                }
                Err(receiver::Error::NeedsLiteral { size }) => {
                    needs_literal = size.into();
                    break;
                }
                Err(receiver::Error::Error { response }) => {
                    self.write_bytes(response.into_bytes()).await?;
                    break;
                }
            }
        }

        let mut requests = requests.into_iter().peekable();
        while let Some(request) = requests.next() {
            match request.command {
                Command::List | Command::Lsub => {
                    self.handle_list(request).await?;
                }
                Command::Select | Command::Examine => {
                    self.handle_select(request).await?;
                }
                Command::Create => {
                    self.handle_create(group_requests(&mut requests, vec![request]))
                        .await?;
                }
                Command::Delete => {
                    self.handle_delete(group_requests(&mut requests, vec![request]))
                        .await?;
                }
                Command::Rename => {
                    self.handle_rename(request).await?;
                }
                Command::Status => {
                    self.handle_status(request).await?;
                }
                Command::Append => {
                    self.handle_append(request).await?;
                }
                Command::Close => {
                    self.handle_close(request).await?;
                }
                Command::Unselect => {
                    self.handle_unselect(request).await?;
                }
                Command::Expunge(is_uid) => {
                    self.handle_expunge(request, is_uid).await?;
                }
                Command::Search(is_uid) => {
                    self.handle_search(request, false, is_uid).await?;
                }
                Command::Fetch(is_uid) => {
                    self.handle_fetch(request, is_uid).await?;
                }
                Command::Store(is_uid) => {
                    self.handle_store(request, is_uid).await?;
                }
                Command::Copy(is_uid) => {
                    self.handle_copy_move(request, false, is_uid).await?;
                }
                Command::Move(is_uid) => {
                    self.handle_copy_move(request, true, is_uid).await?;
                }
                Command::Sort(is_uid) => {
                    self.handle_search(request, true, is_uid).await?;
                }
                Command::Thread(is_uid) => {
                    self.handle_thread(request, is_uid).await?;
                }
                Command::Idle => {
                    self.handle_idle(request).await?;
                }
                Command::Subscribe => {
                    self.handle_subscribe(request, true).await?;
                }
                Command::Unsubscribe => {
                    self.handle_subscribe(request, false).await?;
                }
                Command::Namespace => {
                    self.handle_namespace(request).await?;
                }
                Command::Authenticate => {
                    self.handle_authenticate(request).await?;
                }
                Command::Login => {
                    self.handle_login(request).await?;
                }
                Command::Capability => {
                    self.handle_capability(request).await?;
                }
                Command::Enable => {
                    self.handle_enable(request).await?;
                }
                Command::StartTls => {
                    return self
                        .write_bytes(
                            StatusResponse::ok("Begin TLS negotiation now")
                                .with_tag(request.tag)
                                .into_bytes(),
                        )
                        .await
                        .map(|_| true);
                }
                Command::Noop => {
                    self.handle_noop(request).await?;
                }
                Command::Check => {
                    self.handle_noop(request).await?;
                }
                Command::Logout => {
                    self.handle_logout(request).await?;
                }
                Command::SetAcl => {
                    self.handle_set_acl(request).await?;
                }
                Command::DeleteAcl => {
                    self.handle_set_acl(request).await?;
                }
                Command::GetAcl => {
                    self.handle_get_acl(request).await?;
                }
                Command::ListRights => {
                    self.handle_list_rights(request).await?;
                }
                Command::MyRights => {
                    self.handle_my_rights(request).await?;
                }
                Command::Unauthenticate => {
                    self.handle_unauthenticate(request).await?;
                }
                Command::Id => {
                    self.handle_id(request).await?;
                }
            }
        }

        if let Some(needs_literal) = needs_literal {
            self.write_bytes(format!("+ Ready for {} bytes.\r\n", needs_literal).into_bytes())
                .await?;
        }

        Ok(false)
    }
}

pub fn group_requests(
    requests: &mut Peekable<IntoIter<Request<Command>>>,
    mut grouped_requests: Vec<Request<Command>>,
) -> Vec<Request<Command>> {
    let last_command = grouped_requests.last().unwrap().command;
    loop {
        match requests.peek() {
            Some(request) if request.command == last_command => {
                grouped_requests.push(requests.next().unwrap());
            }
            _ => break,
        }
    }
    grouped_requests
}

trait IsAllowed: Sized {
    fn is_allowed(self, state: &State, is_tls: bool) -> Result<Self, StatusResponse>;
}

impl IsAllowed for Request<Command> {
    fn is_allowed(self, state: &State, is_tls: bool) -> Result<Self, StatusResponse> {
        // Rate limit request
        if let State::Authenticated { data } | State::Selected { data, .. } = state {
            if !data
                .imap
                .get_authenticated_limiter(data.account_id)
                .lock()
                .request_limiter
                .is_allowed()
            {
                return Err(StatusResponse::no("Too many requests")
                    .with_tag(self.tag)
                    .with_code(ResponseCode::Limit));
            }
        }

        match &self.command {
            Command::Capability | Command::Noop | Command::Logout | Command::Id => Ok(self),
            Command::StartTls => {
                if !is_tls {
                    Ok(self)
                } else {
                    Err(StatusResponse::no("Already in TLS mode.").with_tag(self.tag))
                }
            }
            Command::Authenticate => {
                if let State::NotAuthenticated { .. } = state {
                    Ok(self)
                } else {
                    Err(StatusResponse::no("Already authenticated.").with_tag(self.tag))
                }
            }
            Command::Login => {
                if let State::NotAuthenticated { .. } = state {
                    if is_tls {
                        Ok(self)
                    } else {
                        Err(
                            StatusResponse::no("LOGIN is disabled on the clear-text port.")
                                .with_tag(self.tag),
                        )
                    }
                } else {
                    Err(StatusResponse::no("Already authenticated.").with_tag(self.tag))
                }
            }
            Command::Enable
            | Command::Select
            | Command::Examine
            | Command::Create
            | Command::Delete
            | Command::Rename
            | Command::Subscribe
            | Command::Unsubscribe
            | Command::List
            | Command::Lsub
            | Command::Namespace
            | Command::Status
            | Command::Append
            | Command::Idle
            | Command::SetAcl
            | Command::DeleteAcl
            | Command::GetAcl
            | Command::ListRights
            | Command::MyRights
            | Command::Unauthenticate => {
                if let State::Authenticated { .. } | State::Selected { .. } = state {
                    Ok(self)
                } else {
                    Err(StatusResponse::no("Not authenticated.").with_tag(self.tag))
                }
            }
            Command::Close
            | Command::Unselect
            | Command::Expunge(_)
            | Command::Search(_)
            | Command::Fetch(_)
            | Command::Store(_)
            | Command::Copy(_)
            | Command::Move(_)
            | Command::Check
            | Command::Sort(_)
            | Command::Thread(_) => match state {
                State::Selected { mailbox, .. } => {
                    if mailbox.is_select
                        || !matches!(
                            self.command,
                            Command::Store(_) | Command::Expunge(_) | Command::Move(_),
                        )
                    {
                        Ok(self)
                    } else {
                        Err(StatusResponse::no("Not permitted in EXAMINE state.")
                            .with_tag(self.tag))
                    }
                }
                State::Authenticated { .. } => {
                    Err(StatusResponse::bad("No mailbox is selected.").with_tag(self.tag))
                }
                State::NotAuthenticated { .. } => {
                    Err(StatusResponse::no("Not authenticated.").with_tag(self.tag))
                }
            },
        }
    }
}

impl State {
    pub fn auth_failures(&self) -> u32 {
        match self {
            State::NotAuthenticated { auth_failures, .. } => *auth_failures,
            _ => unreachable!(),
        }
    }

    pub fn session_data(&self) -> Arc<SessionData> {
        match self {
            State::Authenticated { data } => data.clone(),
            State::Selected { data, .. } => data.clone(),
            _ => unreachable!(),
        }
    }

    pub fn mailbox_state(&self) -> (Arc<SessionData>, Arc<SelectedMailbox>) {
        match self {
            State::Selected { data, mailbox, .. } => (data.clone(), mailbox.clone()),
            _ => unreachable!(),
        }
    }

    pub fn session_mailbox_state(&self) -> (Arc<SessionData>, Option<Arc<SelectedMailbox>>) {
        match self {
            State::Authenticated { data } => (data.clone(), None),
            State::Selected { data, mailbox, .. } => (data.clone(), mailbox.clone().into()),
            _ => unreachable!(),
        }
    }

    pub fn select_data(&self) -> (Arc<SessionData>, Arc<SelectedMailbox>) {
        match self {
            State::Selected { data, mailbox } => (data.clone(), mailbox.clone()),
            _ => unreachable!(),
        }
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self, State::Authenticated { .. } | State::Selected { .. })
    }

    pub fn is_mailbox_selected(&self) -> bool {
        matches!(self, State::Selected { .. })
    }
}

impl IMAP {
    pub fn get_authenticated_limiter(&self, account_id: u32) -> Arc<Mutex<AuthenticatedLimiter>> {
        self.rate_limiter
            .get(&account_id)
            .map(|limiter| limiter.clone())
            .unwrap_or_else(|| {
                let limiter = Arc::new(Mutex::new(AuthenticatedLimiter {
                    request_limiter: RateLimiter::new(
                        self.rate_requests.requests,
                        self.rate_requests.period,
                    ),
                    concurrent_requests: ConcurrencyLimiter::new(self.rate_concurrent),
                    concurrent_uploads: ConcurrencyLimiter::new(self.rate_concurrent),
                }));
                self.rate_limiter.insert(account_id, limiter.clone());
                limiter
            })
    }
}
