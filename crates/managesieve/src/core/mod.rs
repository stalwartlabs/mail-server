/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod client;
pub mod session;

use std::{borrow::Cow, net::IpAddr, sync::Arc};

use common::listener::{limiter::InFlight, ServerInstance};
use imap::core::{ImapInstance, Inner};
use imap_proto::receiver::{CommandParser, Receiver};
use jmap::{auth::AccessToken, JMAP};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct Session<T: AsyncRead + AsyncWrite> {
    pub jmap: JMAP,
    pub imap: Arc<Inner>,
    pub instance: Arc<ServerInstance>,
    pub receiver: Receiver<Command>,
    pub state: State,
    pub remote_addr: IpAddr,
    pub stream: T,
    pub span: tracing::Span,
    pub in_flight: InFlight,
}

pub enum State {
    NotAuthenticated {
        auth_failures: u32,
    },
    Authenticated {
        access_token: Arc<AccessToken>,
        in_flight: Option<InFlight>,
    },
}

impl State {
    pub fn access_token(&self) -> &AccessToken {
        match self {
            State::Authenticated { access_token, .. } => access_token,
            State::NotAuthenticated { .. } => unreachable!("Not authenticated"),
        }
    }
}

#[derive(Clone)]
pub struct ManageSieveSessionManager {
    pub imap: ImapInstance,
}

impl ManageSieveSessionManager {
    pub fn new(imap: ImapInstance) -> Self {
        Self { imap }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Command {
    Authenticate,
    StartTls,
    Logout,
    Capability,
    HaveSpace,
    PutScript,
    ListScripts,
    SetActive,
    GetScript,
    DeleteScript,
    RenameScript,
    CheckScript,
    #[default]
    Noop,
    Unauthenticate,
}

impl CommandParser for Command {
    fn parse(value: &[u8], _is_uid: bool) -> Option<Self> {
        match value {
            b"AUTHENTICATE" => Some(Command::Authenticate),
            b"STARTTLS" => Some(Command::StartTls),
            b"LOGOUT" => Some(Command::Logout),
            b"CAPABILITY" => Some(Command::Capability),
            b"HAVESPACE" => Some(Command::HaveSpace),
            b"PUTSCRIPT" => Some(Command::PutScript),
            b"LISTSCRIPTS" => Some(Command::ListScripts),
            b"SETACTIVE" => Some(Command::SetActive),
            b"GETSCRIPT" => Some(Command::GetScript),
            b"DELETESCRIPT" => Some(Command::DeleteScript),
            b"RENAMESCRIPT" => Some(Command::RenameScript),
            b"CHECKSCRIPT" => Some(Command::CheckScript),
            b"NOOP" => Some(Command::Noop),
            b"UNAUTHENTICATE" => Some(Command::Unauthenticate),
            _ => None,
        }
    }

    fn tokenize_brackets(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusResponse {
    pub code: Option<ResponseCode>,
    pub message: Cow<'static, str>,
    pub rtype: ResponseType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseType {
    Ok,
    No,
    Bye,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseCode {
    AuthTooWeak,
    EncryptNeeded,
    Quota,
    QuotaMaxScripts,
    QuotaMaxSize,
    Referral,
    Sasl,
    TransitionNeeded,
    TryLater,
    Active,
    NonExistent,
    AlreadyExists,
    Tag(String),
    Warnings,
}

impl ResponseCode {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(match self {
            ResponseCode::AuthTooWeak => b"AUTH-TOO-WEAK",
            ResponseCode::EncryptNeeded => b"ENCRYPT-NEEDED",
            ResponseCode::Quota => b"QUOTA",
            ResponseCode::QuotaMaxScripts => b"QUOTA/MAXSCRIPTS",
            ResponseCode::QuotaMaxSize => b"QUOTA/MAXSIZE",
            ResponseCode::Referral => b"REFERRAL",
            ResponseCode::Sasl => b"SASL",
            ResponseCode::TransitionNeeded => b"TRANSITION-NEEDED",
            ResponseCode::TryLater => b"TRYLATER",
            ResponseCode::Active => b"ACTIVE",
            ResponseCode::NonExistent => b"NONEXISTENT",
            ResponseCode::AlreadyExists => b"ALREADYEXISTS",
            ResponseCode::Tag(tag) => {
                buf.extend_from_slice(b"TAG {");
                buf.extend_from_slice(tag.len().to_string().as_bytes());
                buf.extend_from_slice(b"}\r\n");
                buf.extend_from_slice(tag.as_bytes());
                return;
            }
            ResponseCode::Warnings => b"WARNINGS",
        });
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseCode::AuthTooWeak => "AUTH-TOO-WEAK",
            ResponseCode::EncryptNeeded => "ENCRYPT-NEEDED",
            ResponseCode::Quota => "QUOTA",
            ResponseCode::QuotaMaxScripts => "QUOTA/MAXSCRIPTS",
            ResponseCode::QuotaMaxSize => "QUOTA/MAXSIZE",
            ResponseCode::Referral => "REFERRAL",
            ResponseCode::Sasl => "SASL",
            ResponseCode::TransitionNeeded => "TRANSITION-NEEDED",
            ResponseCode::TryLater => "TRYLATER",
            ResponseCode::Active => "ACTIVE",
            ResponseCode::NonExistent => "NONEXISTENT",
            ResponseCode::AlreadyExists => "ALREADYEXISTS",
            ResponseCode::Tag(_) => "TAG",
            ResponseCode::Warnings => "WARNINGS",
        }
    }
}

impl ResponseType {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.as_str().as_bytes());
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseType::Ok => "OK",
            ResponseType::No => "NO",
            ResponseType::Bye => "BYE",
        }
    }
}

impl StatusResponse {
    pub fn serialize(self, mut buf: Vec<u8>) -> Vec<u8> {
        self.rtype.serialize(&mut buf);
        if let Some(code) = &self.code {
            buf.extend_from_slice(b" (");
            code.serialize(&mut buf);
            buf.push(b')');
        }
        if !self.message.is_empty() {
            buf.extend_from_slice(b" \"");
            for ch in self.message.as_bytes() {
                if [b'\"', b'\\'].contains(ch) {
                    buf.push(b'\\');
                }
                buf.push(*ch);
            }
            buf.push(b'\"');
        }
        buf.extend_from_slice(b"\r\n");
        buf
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.serialize(Vec::with_capacity(16))
    }

    pub fn with_code(mut self, code: ResponseCode) -> Self {
        self.code = Some(code);
        self
    }

    pub fn no(message: impl Into<Cow<'static, str>>) -> Self {
        StatusResponse {
            code: None,
            message: message.into(),
            rtype: ResponseType::No,
        }
    }

    pub fn ok(message: impl Into<Cow<'static, str>>) -> Self {
        StatusResponse {
            code: None,
            message: message.into(),
            rtype: ResponseType::Ok,
        }
    }

    pub fn bye(message: impl Into<Cow<'static, str>>) -> Self {
        StatusResponse {
            code: None,
            message: message.into(),
            rtype: ResponseType::Bye,
        }
    }

    pub fn database_failure() -> Self {
        StatusResponse {
            code: Some(ResponseCode::TryLater),
            message: Cow::Borrowed("Database failure"),
            rtype: ResponseType::No,
        }
    }
}

pub trait SerializeResponse {
    fn serialize(&self) -> Vec<u8>;
}

impl SerializeResponse for trc::Error {
    fn serialize(&self) -> Vec<u8> {
        let todo = "serialize messages properly in all protocols";
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(self.value_as_str(trc::Key::Type).unwrap_or("NO").as_bytes());
        if let Some(code) = self.value_as_str(trc::Key::Code) {
            buf.extend_from_slice(b" (");
            buf.extend_from_slice(code.as_bytes());
            buf.push(b')');
        }
        if let Some(message) = self
            .value_as_str(trc::Key::Details)
            .or_else(|| self.value_as_str(trc::Key::Reason))
        {
            buf.extend_from_slice(b" \"");
            for ch in message.as_bytes() {
                if [b'\"', b'\\'].contains(ch) {
                    buf.push(b'\\');
                }
                buf.push(*ch);
            }
            buf.push(b'\"');
        }
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

impl From<ResponseCode> for trc::Value {
    fn from(value: ResponseCode) -> Self {
        trc::Value::Static(value.as_str())
    }
}

impl From<ResponseType> for trc::Value {
    fn from(value: ResponseType) -> Self {
        trc::Value::Static(value.as_str())
    }
}
