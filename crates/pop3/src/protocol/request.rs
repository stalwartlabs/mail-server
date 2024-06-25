/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use super::{Command, Mechanism};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NeedsMoreData,
    Parse(Cow<'static, str>),
}

#[derive(Default, Debug)]
pub enum State {
    #[default]
    Init,
    Command {
        buf: [u8; 4],
        len: usize,
    },
    Argument {
        request: Command<Vec<u8>, Vec<u8>>,
        num: usize,
        last_is_space: bool,
    },
    Error {
        reason: Cow<'static, str>,
    },
}

#[derive(Default)]
pub struct Parser {
    pub state: State,
}

const MAX_ARG_LEN: usize = 256;

impl Parser {
    pub fn parse(
        &mut self,
        bytes: &mut std::slice::Iter<'_, u8>,
    ) -> Result<Command<String, Mechanism>, Error> {
        for &byte in bytes {
            match &mut self.state {
                State::Init => match byte {
                    b' ' | b'\t' | b'\r' | b'\n' => {}
                    b'a'..=b'z' => {
                        self.state = State::Command {
                            buf: [byte, 0, 0, 0],
                            len: 1,
                        };
                    }
                    b'A'..=b'Z' => {
                        self.state = State::Command {
                            buf: [byte | 0x20, 0, 0, 0],
                            len: 1,
                        };
                    }
                    _ => {
                        self.state = State::Error {
                            reason: "Invalid command".into(),
                        };
                    }
                },
                State::Command { buf, len } => match byte {
                    b'a'..=b'z' | b'8' if *len < 4 => {
                        buf[*len] = byte;
                        *len += 1;
                    }
                    b'A'..=b'Z' if *len < 4 => {
                        buf[*len] = byte | 0x20;
                        *len += 1;
                    }
                    b' ' | b'\t' if *len == 4 || *len == 3 => match Command::parse(buf) {
                        Ok(request) => {
                            self.state = State::Argument {
                                request,
                                num: 0,
                                last_is_space: true,
                            };
                        }
                        Err(err) => {
                            self.state = State::Error { reason: err };
                        }
                    },
                    b'\r' => {}
                    b'\n' if *len == 4 || *len == 3 => match Command::parse(buf) {
                        Ok(request) => {
                            self.state = State::Init;
                            return request.finalize(0);
                        }
                        Err(err) => {
                            self.state = State::Init;
                            return Err(Error::Parse(err));
                        }
                    },
                    _ => {
                        self.state = State::Error {
                            reason: "Invalid command".into(),
                        };
                    }
                },
                State::Argument {
                    request,
                    num,
                    last_is_space,
                } => match byte {
                    b' ' | b'\t' => {
                        *last_is_space = true;
                    }
                    b'\r' => {}
                    b'\n' => {
                        let request = std::mem::take(request).finalize(*num);
                        self.state = State::Init;
                        return request;
                    }
                    _ => {
                        if *last_is_space {
                            *num += 1;
                        }

                        match request.update_argument(*num, byte) {
                            Ok(_) => {
                                *last_is_space = false;
                            }
                            Err(err) => {
                                self.state = State::Error { reason: err };
                            }
                        }
                    }
                },
                State::Error { reason } => {
                    if byte == b'\n' {
                        let reason = std::mem::take(reason);
                        self.state = State::Init;
                        return Err(Error::Parse(reason));
                    }
                }
            }
        }

        Err(Error::NeedsMoreData)
    }
}

impl Command<Vec<u8>, Vec<u8>> {
    pub fn parse(bytes: &[u8; 4]) -> Result<Self, Cow<'static, str>> {
        match (bytes[0], bytes[1], bytes[2], bytes[3]) {
            (b'u', b's', b'e', b'r') => Ok(Self::User { name: Vec::new() }),
            (b'u', b'i', b'd', b'l') => Ok(Self::Uidl { msg: None }),
            (b'u', b't', b'f', b'8') => Ok(Self::Utf8),
            (b'p', b'a', b's', b's') => Ok(Self::Pass { string: Vec::new() }),
            (b'a', b'p', b'o', b'p') => Ok(Self::Apop {
                name: Vec::new(),
                digest: Vec::new(),
            }),
            (b'a', b'u', b't', b'h') => Ok(Self::Auth {
                mechanism: Vec::new(),
                params: Vec::new(),
            }),
            (b'q', b'u', b'i', b't') => Ok(Self::Quit),
            (b'l', b'i', b's', b't') => Ok(Self::List { msg: None }),
            (b'r', b'e', b't', b'r') => Ok(Self::Retr { msg: 0 }),
            (b'r', b's', b'e', b't') => Ok(Self::Rset),
            (b'd', b'e', b'l', b'e') => Ok(Self::Dele { msg: 0 }),
            (b'n', b'o', b'o', b'p') => Ok(Self::Noop),
            (b't', b'o', b'p', 0) => Ok(Self::Top { msg: 0, n: 0 }),
            (b'c', b'a', b'p', b'a') => Ok(Self::Capa),
            (b's', b't', b'l', b's') => Ok(Self::Stls),
            (b's', b't', b'a', b't') => Ok(Self::Stat),
            _ => Err("Invalid command".into()),
        }
    }

    pub fn update_argument(&mut self, arg_num: usize, byte: u8) -> Result<(), Cow<'static, str>> {
        match self {
            Command::User { name } if arg_num == 1 && name.len() < MAX_ARG_LEN => {
                name.push(byte);
                Ok(())
            }
            Command::Pass { string } if arg_num == 1 && string.len() < MAX_ARG_LEN => {
                string.push(byte);
                Ok(())
            }
            Command::Apop { name, digest }
                if arg_num <= 2 && name.len() < MAX_ARG_LEN && digest.len() < MAX_ARG_LEN =>
            {
                if arg_num == 1 {
                    name.push(byte);
                } else {
                    digest.push(byte);
                }
                Ok(())
            }
            Command::List { msg } if arg_num == 1 => add_digit(msg.get_or_insert(0), byte),
            Command::Retr { msg } if arg_num == 1 => add_digit(msg, byte),
            Command::Dele { msg } if arg_num == 1 => add_digit(msg, byte),
            Command::Top { msg, n } if arg_num <= 2 => {
                if arg_num == 1 {
                    add_digit(msg, byte)
                } else {
                    add_digit(n, byte)
                }
            }
            Command::Uidl { msg } if arg_num == 1 => add_digit(msg.get_or_insert(0), byte),
            Command::Auth { mechanism, params }
                if arg_num <= 4
                    && mechanism.len() < 64
                    && params.iter().map(|p| p.len()).sum::<usize>() < (MAX_ARG_LEN * 4) =>
            {
                if arg_num == 1 {
                    mechanism.push(byte);
                } else {
                    if params.len() < arg_num - 1 {
                        params.push(Vec::new());
                    }
                    params.last_mut().unwrap().push(byte);
                }
                Ok(())
            }
            _ => Err("Too many arguments".into()),
        }
    }

    pub fn finalize(self, num_args: usize) -> Result<Command<String, Mechanism>, Error> {
        match self {
            Command::User { name } if num_args == 1 => {
                into_string(name).map(|name| Command::User { name })
            }
            Command::Pass { string } if num_args == 1 => {
                into_string(string).map(|string| Command::Pass { string })
            }
            Command::Apop { name, digest } if num_args == 2 => {
                let name = into_string(name)?;
                let digest = into_string(digest)?;
                Ok(Command::Apop { name, digest })
            }
            Command::Quit => Ok(Command::Quit),
            Command::Stat => Ok(Command::Stat),
            Command::List { msg } => Ok(Command::List { msg }),
            Command::Retr { msg } if num_args == 1 => Ok(Command::Retr { msg }),
            Command::Dele { msg } if num_args == 1 => Ok(Command::Dele { msg }),
            Command::Noop => Ok(Command::Noop),
            Command::Rset => Ok(Command::Rset),
            Command::Top { msg, n } if num_args == 2 => Ok(Command::Top { msg, n }),
            Command::Uidl { msg } => Ok(Command::Uidl { msg }),
            Command::Capa => Ok(Command::Capa),
            Command::Stls => Ok(Command::Stls),
            Command::Utf8 => Ok(Command::Utf8),
            Command::Auth { mechanism, params } if num_args >= 1 => {
                let mechanism = Mechanism::parse(&mechanism)?;
                let params = params
                    .into_iter()
                    .map(into_string)
                    .collect::<Result<_, _>>()?;

                Ok(Command::Auth { mechanism, params })
            }
            _ => Err(Error::Parse("Missing arguments".into())),
        }
    }
}

#[inline(always)]
fn into_string(bytes: Vec<u8>) -> Result<String, Error> {
    String::from_utf8(bytes).map_err(|_| Error::Parse("Invalid UTF-8".into()))
}

#[inline(always)]
fn add_digit(num: &mut u32, byte: u8) -> Result<(), Cow<'static, str>> {
    if byte.is_ascii_digit() {
        *num = num
            .checked_mul(10)
            .and_then(|n| n.checked_add((byte - b'0') as u32))
            .ok_or("Numeric argument out of range")?;
        Ok(())
    } else {
        Err("Invalid digit".into())
    }
}

impl Mechanism {
    pub fn parse(value: &[u8]) -> Result<Self, Error> {
        if value.eq_ignore_ascii_case(b"PLAIN") {
            Ok(Self::Plain)
        } else if value.eq_ignore_ascii_case(b"CRAM-MD5") {
            Ok(Self::CramMd5)
        } else if value.eq_ignore_ascii_case(b"DIGEST-MD5") {
            Ok(Self::DigestMd5)
        } else if value.eq_ignore_ascii_case(b"SCRAM-SHA-1") {
            Ok(Self::ScramSha1)
        } else if value.eq_ignore_ascii_case(b"SCRAM-SHA-256") {
            Ok(Self::ScramSha256)
        } else if value.eq_ignore_ascii_case(b"APOP") {
            Ok(Self::Apop)
        } else if value.eq_ignore_ascii_case(b"NTLM") {
            Ok(Self::Ntlm)
        } else if value.eq_ignore_ascii_case(b"GSSAPI") {
            Ok(Self::Gssapi)
        } else if value.eq_ignore_ascii_case(b"ANONYMOUS") {
            Ok(Self::Anonymous)
        } else if value.eq_ignore_ascii_case(b"EXTERNAL") {
            Ok(Self::External)
        } else if value.eq_ignore_ascii_case(b"OAUTHBEARER") {
            Ok(Self::OAuthBearer)
        } else if value.eq_ignore_ascii_case(b"XOAUTH2") {
            Ok(Self::XOauth2)
        } else {
            Err(Error::Parse(
                format!(
                    "Unsupported mechanism '{}'.",
                    String::from_utf8_lossy(value)
                )
                .into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::{request::Error, Command, Mechanism};

    use super::Parser;

    #[test]
    fn parse_command() {
        let mut parser = Parser::default();
        let mut chunked = String::new();
        let mut chunked_expected = Vec::new();

        for (cmd, request) in [
            ("QuiT", Command::Quit),
            (" \r\n NOOP ", Command::Noop),
            ("STAT ", Command::Stat),
            ("LIST ", Command::List { msg: None }),
            (" list  100  ", Command::List { msg: 100.into() }),
            ("retr 55", Command::Retr { msg: 55 }),
            ("DELE 99", Command::Dele { msg: 99 }),
            (" rset ", Command::Rset),
            ("top 8000 1234", Command::Top { msg: 8000, n: 1234 }),
            ("uidl", Command::Uidl { msg: None }),
            ("uidl 000099999", Command::Uidl { msg: 99999.into() }),
            (
                "USER test",
                Command::User {
                    name: "test".to_string(),
                },
            ),
            (
                "PASS secret",
                Command::Pass {
                    string: "secret".to_string(),
                },
            ),
            (
                "APOP mrose c4c9334bac560ecc979e58001b3e22fb",
                Command::Apop {
                    name: "mrose".to_string(),
                    digest: "c4c9334bac560ecc979e58001b3e22fb".to_string(),
                },
            ),
            ("utf8", Command::Utf8),
            ("capa", Command::Capa),
            (
                "AUTH GSSAPI",
                Command::Auth {
                    mechanism: Mechanism::Gssapi,
                    params: vec![],
                },
            ),
            (
                "AUTH PLAIN dGVzdAB0ZXN0AHRlc3Q=",
                Command::Auth {
                    mechanism: Mechanism::Plain,
                    params: vec!["dGVzdAB0ZXN0AHRlc3Q=".to_string()],
                },
            ),
        ] {
            assert_eq!(
                parser.parse(&mut cmd.as_bytes().iter()),
                Err(Error::NeedsMoreData)
            );
            assert_eq!(
                parser.parse(&mut b"\r\n".iter()),
                Ok(request.clone()),
                "{:?}",
                cmd
            );
            chunked.push_str(cmd);
            chunked.push_str("\r\n");
            chunked_expected.push(request);
        }

        for chunk_size in [1, 2, 4, 8, 16, 32, 64, 128, 256, 512] {
            let mut parser = Parser::default();
            let mut requests = Vec::new();

            for chunk in chunked.as_bytes().chunks(chunk_size) {
                let mut chunk = chunk.iter();
                loop {
                    match parser.parse(&mut chunk) {
                        Ok(request) => {
                            requests.push(request);
                        }
                        Err(Error::NeedsMoreData) => break,
                        Err(err) => {
                            panic!("Unexpected error on chunk size {chunk_size}: {err:?}");
                        }
                    }
                }
            }

            assert_eq!(requests, chunked_expected, "Chunk size: {}", chunk_size);
        }

        for cmd in [
            "user",
            "pass",
            "user a b",
            "pass c d",
            "apop",
            "apop a",
            "apop a b c",
            "quit 1",
            "stat 1",
            "list 1 2",
            "retr",
            "retr 1 2",
            "dele",
            "dele 1 2",
            "noop 1",
            "rset 1",
            "top",
            "top 1 2 3",
            "uidl 1 2 3",
            "capa 1",
            "stls 1",
            "utf8 1",
            "auth",
            "auth unknown",
        ] {
            assert_eq!(
                parser.parse(&mut cmd.as_bytes().iter()),
                Err(Error::NeedsMoreData)
            );
            let result = parser.parse(&mut b"\r\n".iter());
            assert!(result.is_err(), "{:?}", result);
        }
    }
}
