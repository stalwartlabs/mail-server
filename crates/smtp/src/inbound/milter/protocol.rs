/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::IpAddr;

use crate::inbound::milter::Action;

use super::{Command, Error, Modification, Options, Response};

pub const SMFIR_ADDRCPT: u8 = b'+'; /* add recipient */
pub const SMFIR_DELRCPT: u8 = b'-'; /* remove recipient */
pub const SMFIR_ADDRCPT_PAR: u8 = b'2'; /* add recipient (incl. ESMTP args) */
pub const SMFIR_SHUTDOWN: u8 = b'4'; /* 421: shutdown (internal to MTA) */
pub const SMFIR_ACCEPT: u8 = b'a'; /* accept */
pub const SMFIR_REPLBODY: u8 = b'b'; /* replace body (chunk) */
pub const SMFIR_CONTINUE: u8 = b'c'; /* continue */
pub const SMFIR_DISCARD: u8 = b'd'; /* discard */
pub const SMFIR_CHGFROM: u8 = b'e'; /* change envelope sender (from) */
pub const SMFIR_CONN_FAIL: u8 = b'f'; /* cause a connection failure */
pub const SMFIR_ADDHEADER: u8 = b'h'; /* add header */
pub const SMFIR_INSHEADER: u8 = b'i'; /* insert header */
pub const SMFIR_SETSYMLIST: u8 = b'l'; /* set list of symbols (macros) */
pub const SMFIR_CHGHEADER: u8 = b'm'; /* change header */
pub const SMFIR_PROGRESS: u8 = b'p'; /* progress */
pub const SMFIR_QUARANTINE: u8 = b'q'; /* quarantine */
pub const SMFIR_REJECT: u8 = b'r'; /* reject */
pub const SMFIR_SKIP: u8 = b's'; /* skip */
pub const SMFIR_TEMPFAIL: u8 = b't'; /* tempfail */
pub const SMFIR_REPLYCODE: u8 = b'y'; /* reply code etc */

pub const SMFIC_ABORT: u8 = b'A'; /* Abort */
pub const SMFIC_BODY: u8 = b'B'; /* Body chunk */
pub const SMFIC_CONNECT: u8 = b'C'; /* Connection information */
pub const SMFIC_MACRO: u8 = b'D'; /* Define macro */
pub const SMFIC_BODYEOB: u8 = b'E'; /* final body chunk (End) */
pub const SMFIC_HELO: u8 = b'H'; /* HELO/EHLO */
pub const SMFIC_QUIT_NC: u8 = b'K'; /* QUIT but new connection follows */
pub const SMFIC_HEADER: u8 = b'L'; /* Header */
pub const SMFIC_MAIL: u8 = b'M'; /* MAIL from */
pub const SMFIC_EOH: u8 = b'N'; /* EOH */
pub const SMFIC_OPTNEG: u8 = b'O'; /* Option negotiation */
pub const SMFIC_QUIT: u8 = b'Q'; /* QUIT */
pub const SMFIC_RCPT: u8 = b'R'; /* RCPT to */
pub const SMFIC_DATA: u8 = b'T'; /* DATA */
pub const SMFIC_UNKNOWN: u8 = b'U'; /* Any unknown command */

impl<'x> Command<'x> {
    fn build(command: u8, len: u32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(len as usize + 1 + std::mem::size_of::<u32>());
        buf.extend_from_slice((len + 1).to_be_bytes().as_ref());
        buf.push(command);
        buf
    }

    pub fn serialize(self) -> Vec<u8> {
        match self {
            Command::Abort => Command::build(SMFIC_ABORT, 0),
            Command::Body { value } => {
                let mut buf = Command::build(SMFIC_BODY, value.len() as u32);
                buf.extend(value);
                buf
            }
            Command::EndOfBody => Command::build(SMFIC_BODYEOB, 0),
            Command::Connect {
                hostname,
                port,
                address,
            } => {
                /*

                char	hostname[]	Hostname, NUL terminated
                char	family		Protocol family (see below)
                uint16	port		Port number (SMFIA_INET or SMFIA_INET6 only)
                char	address[]	IP address (ASCII) or unix socket path, NUL terminated

                */

                let (address, family) = match address {
                    IpAddr::V4(address) => (address.to_string(), b'4'),
                    IpAddr::V6(address) => (address.to_string(), b'6'),
                };

                let mut buf = Command::build(
                    SMFIC_CONNECT,
                    hostname.len() as u32 // hostname
                        + 1 // NUL
                        + 1 // family
                        + std::mem::size_of::<u16>() as u32 // port
                        + address.len() as u32 // address
                        + 1, // NUL
                );
                buf.extend(hostname);
                buf.push(0x00);
                buf.push(family);
                buf.extend(port.to_be_bytes().as_ref());
                buf.extend(address.as_bytes());
                buf.push(0x00);
                buf
            }
            Command::Macro { macros } => {
                let mut buf = Command::build(
                    SMFIC_MACRO,
                    macros.macros.iter().fold(1, |acc, macro_| {
                        acc + macro_.name.len() as u32 + 1 + macro_.value.len() as u32 + 1
                    }),
                );
                buf.push(macros.cmdcode);
                for macro_ in macros.macros {
                    buf.extend(macro_.name);
                    buf.push(0x00);
                    buf.extend(macro_.value.as_ref());
                    buf.push(0x00);
                }
                buf
            }
            Command::Header { name, value } => {
                let mut buf =
                    Command::build(SMFIC_HEADER, name.len() as u32 + 1 + value.len() as u32 + 1);
                buf.extend(name);
                buf.push(0x00);
                buf.extend(value);
                buf.push(0x00);
                buf
            }
            Command::EndOfHeader => Command::build(SMFIC_EOH, 0),
            Command::Helo { hostname } => {
                let mut buf = Command::build(SMFIC_HELO, hostname.len() as u32 + 1);
                buf.extend(hostname);
                buf.push(0x00);
                buf
            }
            Command::MailFrom { sender, args } => {
                let mut buf = Command::build(
                    SMFIC_MAIL,
                    sender.len() as u32 // sender
                        + 1 // NUL
                        + args.as_ref().map_or(0, |args| args.iter().fold(0, |acc, arg| acc + arg.len() as u32) + 1), // args
                );
                buf.extend(sender);
                buf.push(0x00);
                if let Some(args) = args {
                    for arg in args {
                        buf.extend(arg);
                        buf.push(0x00);
                    }
                }
                buf
            }
            Command::Rcpt { recipient, args } => {
                let mut buf = Command::build(
                    SMFIC_RCPT,
                    recipient.len() as u32 // recipient
                        + 1 // NUL
                        + args.as_ref().map_or(0, |args| args.iter().fold(0, |acc, arg| acc + arg.len() as u32) + 1), // args
                );
                buf.extend(recipient);
                buf.push(0x00);
                if let Some(args) = args {
                    for arg in args {
                        buf.extend(arg);
                        buf.push(0x00);
                    }
                }
                buf
            }
            Command::OptionNegotiation(opt) => {
                let mut buf = Command::build(SMFIC_OPTNEG, 3 * std::mem::size_of::<u32>() as u32);
                buf.extend(opt.version.to_be_bytes().as_ref());
                buf.extend(opt.actions.to_be_bytes().as_ref());
                buf.extend(opt.protocol.to_be_bytes().as_ref());
                buf
            }
            Command::Quit => Command::build(SMFIC_QUIT, 0),

            // Version 6
            Command::Data => Command::build(SMFIC_DATA, 0),
            Command::QuitNewConnection => Command::build(SMFIC_QUIT_NC, 0),
        }
    }

    #[cfg(feature = "test_mode")]
    pub fn deserialize(bytes: &'x [u8]) -> Command<'x> {
        let mut reader = PacketReader::new(bytes);
        match reader.byte() {
            SMFIC_ABORT => Command::Abort,
            SMFIC_BODY => Command::Body { value: &bytes[1..] },
            SMFIC_BODYEOB => Command::EndOfBody,
            SMFIC_CONNECT => {
                let hostname = reader.read_nul_terminated().unwrap();
                let family = reader.byte();
                let port = reader.read_u16();
                let address = std::str::from_utf8(reader.read_nul_terminated().unwrap()).unwrap();
                Command::Connect {
                    hostname,
                    port,
                    address: match family {
                        b'4' => IpAddr::V4(address.parse().unwrap()),
                        b'6' => IpAddr::V6(address.parse().unwrap()),
                        _ => unreachable!(),
                    },
                }
            }
            SMFIC_MACRO => {
                let cmdcode = reader.byte();
                let mut macros = Vec::new();
                while let Some(name) = reader.read_nul_terminated() {
                    let value = reader.read_nul_terminated().unwrap();
                    macros.push(super::Macro {
                        name,
                        value: value.into(),
                    });
                }
                Command::Macro {
                    macros: super::Macros { cmdcode, macros },
                }
            }
            SMFIC_HEADER => {
                let name = reader.read_nul_terminated().unwrap();
                let value = reader.read_nul_terminated().unwrap();
                Command::Header { name, value }
            }
            SMFIC_EOH => Command::EndOfHeader,
            SMFIC_HELO => {
                let hostname = reader.read_nul_terminated().unwrap();
                Command::Helo { hostname }
            }
            SMFIC_MAIL => {
                let sender = reader.read_nul_terminated().unwrap();
                let mut args = Vec::new();
                while let Some(arg) = reader.read_nul_terminated() {
                    args.push(arg);
                }
                Command::MailFrom {
                    sender,
                    args: Some(args),
                }
            }
            SMFIC_RCPT => {
                let recipient = reader.read_nul_terminated().unwrap();
                let mut args = Vec::new();
                while let Some(arg) = reader.read_nul_terminated() {
                    args.push(arg);
                }
                Command::Rcpt {
                    recipient,
                    args: Some(args),
                }
            }
            SMFIC_OPTNEG => Command::OptionNegotiation(super::Options {
                version: reader.read_u32(),
                actions: reader.read_u32(),
                protocol: reader.read_u32(),
            }),
            SMFIC_QUIT => Command::Quit,
            SMFIC_DATA => Command::Data,
            SMFIC_QUIT_NC => Command::QuitNewConnection,
            c => panic!("Unknown command: {}", char::from(c)),
        }
    }
}

impl Response {
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        let frame_len = bytes.len().saturating_sub(1);
        let mut bytes = bytes.iter();
        match *bytes.next()? {
            SMFIR_ADDRCPT => Response::Modification(Modification::AddRcpt {
                recipient: read_nul_terminated(&mut bytes, frame_len)?,
                args: String::new(),
            }),
            SMFIR_DELRCPT => Response::Modification(Modification::DeleteRcpt {
                recipient: read_nul_terminated(&mut bytes, frame_len)?,
            }),
            SMFIR_ACCEPT => Response::Action(Action::Accept),
            SMFIR_REPLBODY => {
                let mut body = Vec::with_capacity(frame_len);
                body.extend(bytes);
                Response::Modification(Modification::ReplaceBody { value: body })
            }
            SMFIR_CONTINUE => Response::Action(Action::Continue),
            SMFIR_DISCARD => Response::Action(Action::Discard),
            SMFIR_ADDHEADER => Response::Modification(Modification::AddHeader {
                name: read_nul_terminated(&mut bytes, 16)?,
                value: read_nul_terminated(&mut bytes, frame_len)?,
            }),
            SMFIR_CHGHEADER => Response::Modification(Modification::ChangeHeader {
                index: read_u32(&mut bytes)?,
                name: read_nul_terminated(&mut bytes, 16)?,
                value: read_nul_terminated(&mut bytes, frame_len)?,
            }),
            SMFIR_PROGRESS => Response::Progress,
            SMFIR_QUARANTINE => Response::Modification(Modification::Quarantine {
                reason: read_nul_terminated(&mut bytes, frame_len)?,
            }),
            SMFIR_REJECT => Response::Action(Action::Reject),
            SMFIR_TEMPFAIL => Response::Action(Action::TempFail),
            SMFIR_REPLYCODE => {
                let code = [*bytes.next()?, *bytes.next()?, *bytes.next()?];
                bytes.next()?; // Space
                Response::Action(Action::ReplyCode {
                    code,
                    text: read_nul_terminated(&mut bytes, frame_len)?,
                })
            }
            SMFIC_OPTNEG => Response::OptionNegotiation(Options {
                version: read_u32(&mut bytes)?,
                actions: read_u32(&mut bytes)?,
                protocol: read_u32(&mut bytes)?,
            }),

            // V6
            SMFIR_ADDRCPT_PAR => Response::Modification(Modification::AddRcpt {
                recipient: read_nul_terminated(&mut bytes, frame_len)?,
                args: read_nul_terminated(&mut bytes, frame_len)?,
            }),
            SMFIR_CHGFROM => Response::Modification(Modification::ChangeFrom {
                sender: read_nul_terminated(&mut bytes, frame_len)?,
                args: read_nul_terminated(&mut bytes, frame_len)?,
            }),
            SMFIR_SKIP => Response::Skip,
            SMFIR_SETSYMLIST => Response::SetSymbols,
            SMFIR_SHUTDOWN => Response::Action(Action::Shutdown),
            SMFIR_CONN_FAIL => Response::Action(Action::ConnectionFailure),
            SMFIR_INSHEADER => Response::Modification(Modification::InsertHeader {
                index: read_u32(&mut bytes)?,
                name: read_nul_terminated(&mut bytes, 16)?,
                value: read_nul_terminated(&mut bytes, frame_len)?,
            }),
            _ => return None,
        }
        .into()
    }

    pub fn can_continue(&self) -> bool {
        matches!(
            self,
            Response::Progress | Response::Action(Action::Accept | Action::Continue)
        )
    }

    pub fn into_action(self) -> super::Result<Action> {
        match self {
            Response::Action(action) => Ok(action),
            response => Err(Error::Unexpected(response)),
        }
    }

    #[cfg(feature = "test_mode")]
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Response::Action(action) => match action {
                Action::Accept => Command::build(SMFIR_ACCEPT, 0),
                Action::Continue => Command::build(SMFIR_CONTINUE, 0),
                Action::Discard => Command::build(SMFIR_DISCARD, 0),
                Action::Reject => Command::build(SMFIR_REJECT, 0),
                Action::TempFail => Command::build(SMFIR_TEMPFAIL, 0),
                Action::ReplyCode { code, text } => {
                    let mut buf = Command::build(SMFIR_REPLYCODE, text.len() as u32 + 4 + 1);
                    buf.extend(code);
                    buf.push(b' ');
                    buf.extend(text.as_bytes());
                    buf.push(0x00);
                    buf
                }
                Action::Shutdown => Command::build(SMFIR_SHUTDOWN, 0),
                Action::ConnectionFailure => Command::build(SMFIR_CONN_FAIL, 0),
            },
            Response::Modification(modif) => match modif {
                Modification::ChangeFrom { sender, args } => {
                    let mut buf =
                        Command::build(SMFIR_CHGFROM, sender.len() as u32 + args.len() as u32 + 2);
                    buf.extend(sender.as_bytes());
                    buf.push(0x00);
                    buf.extend(args.as_bytes());
                    buf.push(0x00);
                    buf
                }
                Modification::AddRcpt { recipient, args } => {
                    let mut buf = Command::build(
                        SMFIR_ADDRCPT_PAR,
                        recipient.len() as u32 + args.len() as u32 + 2,
                    );
                    buf.extend(recipient.as_bytes());
                    buf.push(0x00);
                    buf.extend(args.as_bytes());
                    buf.push(0x00);
                    buf
                }
                Modification::DeleteRcpt { recipient } => {
                    let mut buf = Command::build(SMFIR_DELRCPT, recipient.len() as u32 + 1);
                    buf.extend(recipient.as_bytes());
                    buf.push(0x00);
                    buf
                }
                Modification::ReplaceBody { value } => {
                    let mut buf = Command::build(SMFIR_REPLBODY, value.len() as u32);
                    buf.extend(value);
                    buf
                }
                Modification::AddHeader { name, value } => {
                    let mut buf =
                        Command::build(SMFIR_ADDHEADER, name.len() as u32 + value.len() as u32 + 2);
                    buf.extend(name.as_bytes());
                    buf.push(0x00);
                    buf.extend(value.as_bytes());
                    buf.push(0x00);
                    buf
                }
                Modification::InsertHeader { index, name, value } => {
                    let mut buf = Command::build(
                        SMFIR_INSHEADER,
                        name.len() as u32
                            + value.len() as u32
                            + std::mem::size_of::<u32>() as u32
                            + 2,
                    );
                    buf.extend(index.to_be_bytes().as_ref());
                    buf.extend(name.as_bytes());
                    buf.push(0x00);
                    buf.extend(value.as_bytes());
                    buf.push(0x00);
                    buf
                }
                Modification::ChangeHeader { index, name, value } => {
                    let mut buf = Command::build(
                        SMFIR_CHGHEADER,
                        name.len() as u32
                            + value.len() as u32
                            + std::mem::size_of::<u32>() as u32
                            + 2,
                    );
                    buf.extend(index.to_be_bytes().as_ref());
                    buf.extend(name.as_bytes());
                    buf.push(0x00);
                    buf.extend(value.as_bytes());
                    buf.push(0x00);
                    buf
                }
                Modification::Quarantine { reason } => {
                    let mut buf = Command::build(SMFIR_QUARANTINE, reason.len() as u32 + 1);
                    buf.extend(reason.as_bytes());
                    buf.push(0x00);
                    buf
                }
            },
            Response::Progress => Command::build(SMFIR_PROGRESS, 0),
            Response::Skip => Command::build(SMFIR_SKIP, 0),
            Response::SetSymbols => Command::build(SMFIR_SETSYMLIST, 0),
            Response::OptionNegotiation(opt) => {
                let mut buf = Command::build(SMFIC_OPTNEG, 3 * std::mem::size_of::<u32>() as u32);
                buf.extend(opt.version.to_be_bytes().as_ref());
                buf.extend(opt.actions.to_be_bytes().as_ref());
                buf.extend(opt.protocol.to_be_bytes().as_ref());
                buf
            }
        }
    }
}

fn read_nul_terminated(bytes: &mut std::slice::Iter<u8>, expected_len: usize) -> Option<String> {
    let mut buf = Vec::with_capacity(expected_len);
    loop {
        match bytes.next()? {
            0x00 => break,
            byte => buf.push(*byte),
        }
    }
    String::from_utf8(buf).ok()
}

fn read_u32(bytes: &mut std::slice::Iter<u8>) -> Option<u32> {
    let mut buf = [0u8; 4];
    for byte in buf.iter_mut() {
        *byte = *bytes.next()?;
    }
    Some(u32::from_be_bytes(buf))
}

#[cfg(feature = "test_mode")]
pub struct PacketReader<'x> {
    bytes: &'x [u8],
    iter: std::iter::Enumerate<std::slice::Iter<'x, u8>>,
}

#[cfg(feature = "test_mode")]
impl<'x> PacketReader<'x> {
    pub fn new(bytes: &'x [u8]) -> PacketReader<'x> {
        Self {
            bytes,
            iter: bytes.iter().enumerate(),
        }
    }

    pub fn byte(&mut self) -> u8 {
        *self.iter.next().unwrap().1
    }

    pub fn read_nul_terminated(&mut self) -> Option<&'x [u8]> {
        let (start_pos, ch) = self.iter.next()?;
        let mut end_pos = start_pos;

        if *ch != 0x00 {
            loop {
                match self.iter.next().unwrap().1 {
                    0x00 => break,
                    _ => end_pos += 1,
                }
            }
        }

        Some(&self.bytes[start_pos..end_pos + 1])
    }

    pub fn read_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        for byte in buf.iter_mut() {
            *byte = self.byte();
        }
        u32::from_be_bytes(buf)
    }

    pub fn read_u16(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        for byte in buf.iter_mut() {
            *byte = self.byte();
        }
        u16::from_be_bytes(buf)
    }
}
