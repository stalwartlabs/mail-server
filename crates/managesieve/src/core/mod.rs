pub mod client;
pub mod session;

use std::{borrow::Cow, sync::Arc};

use imap::core::IMAP;
use imap_proto::receiver::{CommandParser, Receiver};
use jmap::{
    auth::{rate_limit::RemoteAddress, AccessToken},
    JMAP,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;
use utils::listener::{limiter::InFlight, ServerInstance};

pub struct Session<T: AsyncRead + AsyncWrite> {
    pub jmap: Arc<JMAP>,
    pub imap: Arc<IMAP>,
    pub instance: Arc<ServerInstance>,
    pub receiver: Receiver<Command>,
    pub state: State,
    pub remote_addr: RemoteAddress,
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
        in_flight: InFlight,
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
    pub jmap: Arc<JMAP>,
    pub imap: Arc<IMAP>,
}

impl ManageSieveSessionManager {
    pub fn new(jmap: Arc<JMAP>, imap: Arc<IMAP>) -> Self {
        Self { jmap, imap }
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

pub trait IsTls {
    fn is_tls(&self) -> bool;
}

impl IsTls for TcpStream {
    fn is_tls(&self) -> bool {
        false
    }
}

impl IsTls for TlsStream<TcpStream> {
    fn is_tls(&self) -> bool {
        true
    }
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
}

impl ResponseType {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(match self {
            ResponseType::Ok => b"OK",
            ResponseType::No => b"NO",
            ResponseType::Bye => b"BYE",
        });
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
