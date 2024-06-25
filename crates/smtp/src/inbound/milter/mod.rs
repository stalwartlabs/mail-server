/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, fmt::Display, net::IpAddr, time::Duration};

use common::config::smtp::session::MilterVersion;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use self::receiver::Receiver;

pub mod client;
pub mod macros;
pub mod message;
pub mod protocol;
pub mod receiver;

pub struct MilterClient<T: AsyncRead + AsyncWrite> {
    stream: T,
    buf: Vec<u8>,
    bytes_read: usize,
    timeout_cmd: Duration,
    timeout_data: Duration,
    receiver: Receiver,
    version: MilterVersion,
    options: u32,
    flags_actions: u32,
    flags_protocol: u32,
    span: tracing::Span,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    FrameTooLarge(usize),
    FrameInvalid(Vec<u8>),
    Unexpected(Response),
    Timeout,
    TLSInvalidName,
    Disconnected,
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

pub enum Command<'x> {
    Abort,
    Body {
        value: &'x [u8],
    },
    EndOfBody,
    Data,
    Connect {
        hostname: &'x [u8],
        port: u16,
        address: IpAddr,
    },
    Macro {
        macros: Macros<'x>,
    },
    Header {
        name: &'x [u8],
        value: &'x [u8],
    },
    EndOfHeader,
    Helo {
        hostname: &'x [u8],
    },
    MailFrom {
        sender: &'x [u8],
        args: Option<Vec<&'x [u8]>>,
    },
    Rcpt {
        recipient: &'x [u8],
        args: Option<Vec<&'x [u8]>>,
    },
    OptionNegotiation(Options),
    Quit,
    QuitNewConnection,
}

#[derive(Debug)]
pub enum Response {
    Action(Action),
    Modification(Modification),
    Progress,
    Skip,
    SetSymbols,
    OptionNegotiation(Options),
}

#[derive(Debug)]
pub enum Action {
    Accept,
    Continue,
    Discard,
    Reject,
    TempFail,
    ReplyCode { code: [u8; 3], text: String },
    Shutdown,
    ConnectionFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Modification {
    ChangeFrom {
        sender: String,
        args: String,
    },
    AddRcpt {
        recipient: String,
        args: String,
    },
    DeleteRcpt {
        recipient: String,
    },
    ReplaceBody {
        value: Vec<u8>,
    },
    AddHeader {
        name: String,
        value: String,
    },
    InsertHeader {
        index: u32,
        name: String,
        value: String,
    },
    ChangeHeader {
        index: u32,
        name: String,
        value: String,
    },
    Quarantine {
        reason: String,
    },
}

#[derive(Debug)]
pub struct Options {
    pub version: u32,
    pub actions: u32,
    pub protocol: u32,
}

#[derive(Default)]
pub struct Macros<'x> {
    cmdcode: u8,
    macros: Vec<Macro<'x>>,
}

pub struct Macro<'x> {
    name: &'x [u8],
    value: Cow<'x, [u8]>,
}

pub const SMFIF_NONE: u32 = 0x00000000; /* no flags */
pub const SMFIF_ADDHDRS: u32 = 0x00000001; /* filter may add headers */
pub const SMFIF_CHGBODY: u32 = 0x00000002; /* filter may replace body */
pub const SMFIF_MODBODY: u32 = SMFIF_CHGBODY; /* backwards compatible */
pub const SMFIF_ADDRCPT: u32 = 0x00000004; /* filter may add recipients */
pub const SMFIF_DELRCPT: u32 = 0x00000008; /* filter may delete recipients */
pub const SMFIF_CHGHDRS: u32 = 0x00000010; /* filter may change/delete headers */
pub const SMFIF_QUARANTINE: u32 = 0x00000020; /* filter may quarantine envelope */
pub const SMFIF_CHGFROM: u32 = 0x00000040; /* filter may change "from" (envelope sender) */
pub const SMFIF_ADDRCPT_PAR: u32 = 0x00000080; /* add recipients incl. args */
pub const SMFIF_SETSYMLIST: u32 = 0x00000100; /* filter can send set of symbols (macros) that it wants */

pub const SMFIP_NOCONNECT: u32 = 0x00000001; /* MTA should not send connect info */
pub const SMFIP_NOHELO: u32 = 0x00000002; /* MTA should not send HELO info */
pub const SMFIP_NOMAIL: u32 = 0x00000004; /* MTA should not send MAIL info */
pub const SMFIP_NORCPT: u32 = 0x00000008; /* MTA should not send RCPT info */
pub const SMFIP_NOBODY: u32 = 0x00000010; /* MTA should not send body */
pub const SMFIP_NOHDRS: u32 = 0x00000020; /* MTA should not send headers */
pub const SMFIP_NOEOH: u32 = 0x00000040; /* MTA should not send EOH */
pub const SMFIP_NR_HDR: u32 = 0x00000080; /* No reply for headers */
pub const SMFIP_NOHREPL: u32 = SMFIP_NR_HDR; /* No reply for headers */
pub const SMFIP_NOUNKNOWN: u32 = 0x00000100; /* MTA should not send unknown commands */
pub const SMFIP_NODATA: u32 = 0x00000200; /* MTA should not send DATA */
pub const SMFIP_SKIP: u32 = 0x00000400; /* MTA understands SMFIS_SKIP */
pub const SMFIP_RCPT_REJ: u32 = 0x00000800; /* MTA should also send rejected RCPTs */
pub const SMFIP_NR_CONN: u32 = 0x00001000; /* No reply for connect */
pub const SMFIP_NR_HELO: u32 = 0x00002000; /* No reply for HELO */
pub const SMFIP_NR_MAIL: u32 = 0x00004000; /* No reply for MAIL */
pub const SMFIP_NR_RCPT: u32 = 0x00008000; /* No reply for RCPT */
pub const SMFIP_NR_DATA: u32 = 0x00010000; /* No reply for DATA */
pub const SMFIP_NR_UNKN: u32 = 0x00020000; /* No reply for UNKN */
pub const SMFIP_NR_EOH: u32 = 0x00040000; /* No reply for eoh */
pub const SMFIP_NR_BODY: u32 = 0x00080000; /* No reply for body chunk */
pub const SMFIP_HDR_LEADSPC: u32 = 0x00100000; /* header value leading space */
pub const SMFIP_MDS_256K: u32 = 0x10000000; /* MILTER_MAX_DATA_SIZE=256K */
pub const SMFIP_MDS_1M: u32 = 0x20000000; /* MILTER_MAX_DATA_SIZE=1M */

pub type Result<T> = std::result::Result<T, Error>;

impl Display for Command<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Abort => write!(f, "ABORT"),
            Command::Body { value } => write!(f, "BODY [{} bytes]", value.len()),
            Command::EndOfBody => write!(f, "EOB"),
            Command::Connect {
                hostname,
                port,
                address,
            } => write!(
                f,
                "CONNECT (host: {:?}, port: {}, address: {})",
                std::str::from_utf8(hostname).unwrap_or_default(),
                port,
                address
            ),
            Command::Macro { macros } => {
                write!(f, "MACRO (code: {}, params: ", macros.cmdcode)?;
                for macro_ in &macros.macros {
                    write!(
                        f,
                        "({:?}, {:?})",
                        std::str::from_utf8(macro_.name).unwrap_or_default(),
                        std::str::from_utf8(macro_.value.as_ref()).unwrap_or_default()
                    )?;
                }
                write!(f, ")")
            }
            Command::Header { name, value } => {
                write!(
                    f,
                    "HEADER ({}: {:?})",
                    std::str::from_utf8(name).unwrap_or_default(),
                    std::str::from_utf8(value).unwrap_or_default()
                )
            }
            Command::EndOfHeader => write!(f, "EOH"),
            Command::Helo { hostname } => write!(
                f,
                "HELO {:?}",
                std::str::from_utf8(hostname).unwrap_or_default()
            ),
            Command::MailFrom { sender, args } => {
                write!(
                    f,
                    "MAIL (from: {}, params: ",
                    std::str::from_utf8(sender).unwrap_or_default()
                )?;
                if let Some(args) = args {
                    for arg in args {
                        write!(f, " {}", std::str::from_utf8(arg).unwrap_or_default())?;
                    }
                }
                write!(f, ")")
            }
            Command::Rcpt { recipient, args } => {
                write!(
                    f,
                    "RCPT (to: {}, params: ",
                    std::str::from_utf8(recipient).unwrap_or_default()
                )?;
                if let Some(args) = args {
                    for arg in args {
                        write!(f, " {}", std::str::from_utf8(arg).unwrap_or_default())?;
                    }
                }
                write!(f, ")")
            }
            Command::OptionNegotiation(opt) => write!(f, "OPTNEG ({})", opt),
            Command::Quit => write!(f, "QUIT"),
            Command::Data => write!(f, "DATA"),
            Command::QuitNewConnection => write!(f, "QUIT_NC"),
        }
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Response::Action(action) => write!(f, "ACTION ({})", action),
            Response::Modification(modification) => write!(f, "MODIFICATION ({})", modification),
            Response::Progress => write!(f, "PROGRESS"),
            Response::OptionNegotiation(opt) => write!(f, "OPTNEG ({})", opt),
            Response::Skip => write!(f, "SKIP"),
            Response::SetSymbols => write!(f, "SET_SYMBOLS"),
        }
    }
}

impl Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Accept => write!(f, "ACCEPT"),
            Action::Continue => write!(f, "CONTINUE"),
            Action::Discard => write!(f, "DISCARD"),
            Action::Reject => write!(f, "REJECT"),
            Action::TempFail => write!(f, "TEMPFAIL"),
            Action::ReplyCode { code, text } => {
                write!(f, "REPLYCODE (code: {:?}, text: {})", code, text)
            }
            Action::Shutdown => write!(f, "SHUTDOWN"),
            Action::ConnectionFailure => write!(f, "CONN_FAIL"),
        }
    }
}

impl Display for Modification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Modification::AddRcpt { recipient, args } => {
                write!(f, "ADD_RCPT (recipient: {}, args: {})", recipient, args)
            }
            Modification::DeleteRcpt { recipient } => {
                write!(f, "DEL_RCPT (recipient: {})", recipient)
            }
            Modification::ReplaceBody { value } => {
                write!(f, "REPLACE_BODY ({} bytes)", value.len())
            }
            Modification::AddHeader { name, value } => {
                write!(f, "ADD_HEADER ({}: {})", name, value)
            }
            Modification::ChangeHeader { index, name, value } => {
                write!(f, "CHANGE_HEADER (index: {}, {}: {})", index, name, value)
            }
            Modification::Quarantine { reason } => write!(f, "QUARANTINE ({})", reason),
            Modification::ChangeFrom { sender, args } => {
                write!(f, "CHANGE_FROM (<{}> {})", sender, args)
            }
            Modification::InsertHeader { index, name, value } => {
                write!(f, "INSERT_HEADER (index: {}, {}: {})", index, name, value)
            }
        }
    }
}

impl Display for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "version: {}, actions: [", self.version,)?;

        if self.actions & SMFIF_ADDHDRS != 0 {
            write!(f, "ADDHDRS ")?;
        }
        if self.actions & SMFIF_CHGBODY != 0 {
            write!(f, "CHGBODY ")?;
        }
        if self.actions & SMFIF_CHGHDRS != 0 {
            write!(f, "CHGHDRS ")?;
        }
        if self.actions & SMFIF_ADDRCPT != 0 {
            write!(f, "ADDRCPT ")?;
        }
        if self.actions & SMFIF_DELRCPT != 0 {
            write!(f, "DELRCPT ")?;
        }
        if self.actions & SMFIF_CHGFROM != 0 {
            write!(f, "CHGFROM ")?;
        }
        if self.actions & SMFIF_QUARANTINE != 0 {
            write!(f, "QUARANTINE ")?;
        }
        if self.actions & SMFIF_CHGFROM != 0 {
            write!(f, "CHGFROM ")?;
        }
        if self.actions & SMFIF_ADDRCPT_PAR != 0 {
            write!(f, "ADDRCPT_PAR ")?;
        }
        if self.actions & SMFIF_SETSYMLIST != 0 {
            write!(f, "SETSYMLIST ")?;
        }
        write!(f, "], options: [",)?;

        if self.protocol & SMFIP_NOCONNECT != 0 {
            write!(f, "NOCONNECT ")?;
        }

        if self.protocol & SMFIP_NOHELO != 0 {
            write!(f, "NOHELO ")?;
        }

        if self.protocol & SMFIP_NOMAIL != 0 {
            write!(f, "NOMAIL ")?;
        }

        if self.protocol & SMFIP_NORCPT != 0 {
            write!(f, "NORCPT ")?;
        }

        if self.protocol & SMFIP_NOBODY != 0 {
            write!(f, "NOBODY ")?;
        }

        if self.protocol & SMFIP_NOHDRS != 0 {
            write!(f, "NOHDRS ")?;
        }

        if self.protocol & SMFIP_NOEOH != 0 {
            write!(f, "NOEOH ")?;
        }

        if self.protocol & SMFIP_NR_HDR != 0 {
            write!(f, "NR_HDR ")?;
        }

        if self.protocol & SMFIP_NOUNKNOWN != 0 {
            write!(f, "NOUNKNOWN ")?;
        }

        if self.protocol & SMFIP_NODATA != 0 {
            write!(f, "NODATA ")?;
        }

        if self.protocol & SMFIP_SKIP != 0 {
            write!(f, "SKIP ")?;
        }

        if self.protocol & SMFIP_RCPT_REJ != 0 {
            write!(f, "RCPT_REJ ")?;
        }

        if self.protocol & SMFIP_NR_CONN != 0 {
            write!(f, "NR_CONN ")?;
        }

        if self.protocol & SMFIP_NR_HELO != 0 {
            write!(f, "NR_HELO ")?;
        }

        if self.protocol & SMFIP_NR_MAIL != 0 {
            write!(f, "NR_MAIL ")?;
        }

        if self.protocol & SMFIP_NR_RCPT != 0 {
            write!(f, "NR_RCPT ")?;
        }

        if self.protocol & SMFIP_NR_DATA != 0 {
            write!(f, "NR_DATA ")?;
        }

        if self.protocol & SMFIP_NR_UNKN != 0 {
            write!(f, "NR_UNKN ")?;
        }

        if self.protocol & SMFIP_NR_EOH != 0 {
            write!(f, "NR_EOH ")?;
        }

        if self.protocol & SMFIP_NR_BODY != 0 {
            write!(f, "NR_BODY ")?;
        }

        if self.protocol & SMFIP_HDR_LEADSPC != 0 {
            write!(f, "HDR_LEADSPC ")?;
        }

        if self.protocol & SMFIP_MDS_256K != 0 {
            write!(f, "MDS_256K ")?;
        }

        if self.protocol & SMFIP_MDS_1M != 0 {
            write!(f, "MDS_1M ")?;
        }

        write!(f, "]")
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(err) => write!(f, "IO error: {}", err),
            Error::FrameTooLarge(size) => {
                write!(f, "Milter response of {} bytes is too large.", size)
            }
            Error::FrameInvalid(frame) => write!(
                f,
                "Invalid milter response: {:?}",
                frame.get(0..100).unwrap_or(frame.as_ref())
            ),
            Error::Unexpected(response) => write!(f, "Unexpected response: {}", response),
            Error::Timeout => write!(f, "Connection timed out"),
            Error::TLSInvalidName => write!(f, "Invalid TLS name"),
            Error::Disconnected => write!(f, "Disconnected unexpectedly"),
        }
    }
}
