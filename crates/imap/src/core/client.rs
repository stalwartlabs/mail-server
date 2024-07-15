/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{iter::Peekable, sync::Arc, vec::IntoIter};

use common::listener::{limiter::ConcurrencyLimiter, SessionStream};
use imap_proto::{
    receiver::{self, Request},
    Command, ResponseCode, StatusResponse,
};
use jmap::auth::rate_limit::ConcurrencyLimiters;

use super::{SelectedMailbox, Session, SessionData, State};

impl<T: SessionStream> Session<T> {
    pub async fn ingest(&mut self, bytes: &[u8]) -> trc::Result<bool> {
        /*for line in String::from_utf8_lossy(bytes).split("\r\n") {
            let c = println!("{}", line);
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
                Ok(request) => match self.is_allowed(request).await {
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
                    let todo = "disconnect";
                    //return Err(());
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

impl<T: SessionStream> Session<T> {
    async fn is_allowed(
        &self,
        request: Request<Command>,
    ) -> Result<Request<Command>, StatusResponse> {
        let state = &self.state;
        // Rate limit request
        if let State::Authenticated { data } | State::Selected { data, .. } = state {
            if let Some(rate) = &self.jmap.core.imap.rate_requests {
                match data
                    .jmap
                    .core
                    .storage
                    .lookup
                    .is_rate_allowed(format!("ireq:{}", data.account_id).as_bytes(), rate, true)
                    .await
                {
                    Ok(None) => {}
                    Ok(Some(_)) => {
                        return Err(StatusResponse::no("Too many requests")
                            .with_tag(request.tag)
                            .with_code(ResponseCode::Limit));
                    }
                    Err(_) => {
                        return Err(StatusResponse::no("Internal server error")
                            .with_tag(request.tag)
                            .with_code(ResponseCode::ContactAdmin));
                    }
                }
            }
        }

        match &request.command {
            Command::Capability | Command::Noop | Command::Logout | Command::Id => Ok(request),
            Command::StartTls => {
                if !self.is_tls {
                    if self.instance.acceptor.is_tls() {
                        Ok(request)
                    } else {
                        Err(StatusResponse::no("TLS is not available.").with_tag(request.tag))
                    }
                } else {
                    Err(StatusResponse::no("Already in TLS mode.").with_tag(request.tag))
                }
            }
            Command::Authenticate => {
                if let State::NotAuthenticated { .. } = state {
                    Ok(request)
                } else {
                    Err(StatusResponse::no("Already authenticated.").with_tag(request.tag))
                }
            }
            Command::Login => {
                if let State::NotAuthenticated { .. } = state {
                    if self.is_tls || self.jmap.core.imap.allow_plain_auth {
                        Ok(request)
                    } else {
                        Err(
                            StatusResponse::no("LOGIN is disabled on the clear-text port.")
                                .with_tag(request.tag),
                        )
                    }
                } else {
                    Err(StatusResponse::no("Already authenticated.").with_tag(request.tag))
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
                    Ok(request)
                } else {
                    Err(StatusResponse::no("Not authenticated.").with_tag(request.tag))
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
                            request.command,
                            Command::Store(_) | Command::Expunge(_) | Command::Move(_),
                        )
                    {
                        Ok(request)
                    } else {
                        Err(StatusResponse::no("Not permitted in EXAMINE state.")
                            .with_tag(request.tag))
                    }
                }
                State::Authenticated { .. } => {
                    Err(StatusResponse::bad("No mailbox is selected.").with_tag(request.tag))
                }
                State::NotAuthenticated { .. } => {
                    Err(StatusResponse::no("Not authenticated.").with_tag(request.tag))
                }
            },
        }
    }

    pub fn get_concurrency_limiter(&self, account_id: u32) -> Option<Arc<ConcurrencyLimiters>> {
        let rate = self.jmap.core.imap.rate_concurrent?;
        self.imap
            .rate_limiter
            .get(&account_id)
            .map(|limiter| limiter.clone())
            .unwrap_or_else(|| {
                let limiter = Arc::new(ConcurrencyLimiters {
                    concurrent_requests: ConcurrencyLimiter::new(rate),
                    concurrent_uploads: ConcurrencyLimiter::new(rate),
                });
                self.imap.rate_limiter.insert(account_id, limiter.clone());
                limiter
            })
            .into()
    }
}

impl<T: SessionStream> State<T> {
    pub fn auth_failures(&self) -> u32 {
        match self {
            State::NotAuthenticated { auth_failures, .. } => *auth_failures,
            _ => unreachable!(),
        }
    }

    pub fn session_data(&self) -> Arc<SessionData<T>> {
        match self {
            State::Authenticated { data } => data.clone(),
            State::Selected { data, .. } => data.clone(),
            _ => unreachable!(),
        }
    }

    pub fn mailbox_state(&self) -> (Arc<SessionData<T>>, Arc<SelectedMailbox>) {
        match self {
            State::Selected { data, mailbox, .. } => (data.clone(), mailbox.clone()),
            _ => unreachable!(),
        }
    }

    pub fn session_mailbox_state(&self) -> (Arc<SessionData<T>>, Option<Arc<SelectedMailbox>>) {
        match self {
            State::Authenticated { data } => (data.clone(), None),
            State::Selected { data, mailbox, .. } => (data.clone(), mailbox.clone().into()),
            _ => unreachable!(),
        }
    }

    pub fn select_data(&self) -> (Arc<SessionData<T>>, Arc<SelectedMailbox>) {
        match self {
            State::Selected { data, mailbox } => (data.clone(), mailbox.clone()),
            _ => unreachable!(),
        }
    }

    pub fn spawn_task<F, R, P>(&self, params: P, fnc: F) -> trc::Result<()>
    where
        F: FnOnce(P, &super::SessionData<T>) -> R + Send + 'static,
        P: Send + Sync + 'static,
        R: std::future::Future<Output = trc::Result<()>> + Send + 'static,
    {
        let data = self.session_data();

        tokio::spawn(async move {
            if let Err(err) = fnc(params, &data).await {
                let _ = data.write_error(err).await;
            }
        });

        Ok(())
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self, State::Authenticated { .. } | State::Selected { .. })
    }

    pub fn close_mailbox(&self) -> bool {
        matches!(self, State::Selected { .. })
    }
}
