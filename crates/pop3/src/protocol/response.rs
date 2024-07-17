/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, fmt::Display};

use super::Mechanism;

pub enum Response<T> {
    Ok(Cow<'static, str>),
    Err(Cow<'static, str>),
    List(Vec<T>),
    Message {
        bytes: Vec<u8>,
        lines: u32,
    },
    Capability {
        mechanisms: Vec<Mechanism>,
        stls: bool,
    },
}

impl<T: Display> Response<T> {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Response::Ok(message) => {
                let mut buf = Vec::with_capacity(message.len() + 6);
                buf.extend_from_slice(b"+OK ");
                buf.extend_from_slice(message.as_bytes());
                buf.extend_from_slice(b"\r\n");
                buf
            }
            Response::Err(message) => {
                let mut buf = Vec::with_capacity(message.len() + 6);
                buf.extend_from_slice(b"-ERR ");
                buf.extend_from_slice(message.as_bytes());
                buf.extend_from_slice(b"\r\n");
                buf
            }
            Response::List(octets) => {
                let mut buf = Vec::with_capacity(octets.len() * 8 + 10);
                buf.extend_from_slice(format!("+OK {} messages\r\n", octets.len()).as_bytes());
                for (num, octet) in octets.iter().enumerate() {
                    buf.extend_from_slice((num + 1).to_string().as_bytes());
                    buf.extend_from_slice(b" ");
                    buf.extend_from_slice(octet.to_string().as_bytes());
                    buf.extend_from_slice(b"\r\n");
                }
                buf.extend_from_slice(b".\r\n");
                buf
            }
            Response::Message { bytes, lines } => {
                let mut buf = Vec::with_capacity(bytes.len() + 10);
                buf.extend_from_slice(b"+OK ");
                buf.extend_from_slice(bytes.len().to_string().as_bytes());
                buf.extend_from_slice(b" octets\r\n");

                let mut line_count = 0;
                let mut last_byte = 0;

                // Transparency procedure
                for &byte in bytes {
                    // POP3 requires that lines end with CRLF, do this check to ensure that
                    if byte == b'\n' && last_byte != b'\r' {
                        buf.push(b'\r');
                    }

                    if byte == b'.' && last_byte == b'\n' {
                        buf.push(b'.');
                    }
                    buf.push(byte);
                    last_byte = byte;

                    if *lines > 0 && byte == b'\n' {
                        line_count += 1;
                        if line_count == *lines {
                            break;
                        }
                    }
                }

                if last_byte != b'\n' {
                    buf.extend_from_slice(b"\r\n");
                }

                buf.extend_from_slice(b".\r\n");
                buf
            }
            Response::Capability { mechanisms, stls } => {
                let mut buf = Vec::with_capacity(256);
                buf.extend_from_slice(b"+OK Capability list follows\r\n");
                if !mechanisms.is_empty() {
                    if mechanisms.contains(&Mechanism::Plain) {
                        buf.extend_from_slice(b"USER\r\n");
                    }
                    buf.extend_from_slice(b"SASL");
                    for mechanism in mechanisms {
                        buf.extend_from_slice(b" ");
                        buf.extend_from_slice(mechanism.as_str().as_bytes());
                    }
                    buf.extend_from_slice(b"\r\n");
                }

                if *stls {
                    buf.extend_from_slice(b"STLS\r\n");
                }

                for capa in [
                    "TOP",
                    "RESP-CODES",
                    "PIPELINING",
                    "EXPIRE NEVER",
                    "UIDL",
                    "UTF8",
                    "IMPLEMENTATION Stalwart Mail Server",
                ] {
                    buf.extend_from_slice(capa.as_bytes());
                    buf.extend_from_slice(b"\r\n");
                }

                buf.extend_from_slice(b".\r\n");
                buf
            }
        }
    }
}

impl Mechanism {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mechanism::Plain => "PLAIN",
            Mechanism::CramMd5 => "CRAM-MD5",
            Mechanism::DigestMd5 => "DIGEST-MD5",
            Mechanism::ScramSha1 => "SCRAM-SHA-1",
            Mechanism::ScramSha256 => "SCRAM-SHA-256",
            Mechanism::Apop => "APOP",
            Mechanism::Ntlm => "NTLM",
            Mechanism::Gssapi => "GSSAPI",
            Mechanism::Anonymous => "ANONYMOUS",
            Mechanism::External => "EXTERNAL",
            Mechanism::OAuthBearer => "OAUTHBEARER",
            Mechanism::XOauth2 => "XOAUTH2",
        }
    }
}

pub trait SerializeResponse {
    fn serialize(&self) -> Vec<u8>;
}

impl SerializeResponse for trc::Error {
    fn serialize(&self) -> Vec<u8> {
        let todo = "serialize messages properly in all protocols";
        let message = self
            .value_as_str(trc::Key::Details)
            .or_else(|| self.value_as_str(trc::Key::Reason))
            .unwrap_or("Internal Server Error");
        let mut buf = Vec::with_capacity(message.len() + 6);
        buf.extend_from_slice(b"-ERR ");
        buf.extend_from_slice(message.as_bytes());
        buf.extend_from_slice(b"\r\n");
        buf
    }
}

#[cfg(test)]
mod tests {

    use crate::protocol::Mechanism;

    use super::Response;

    #[test]
    fn serialize_response() {
        for (cmd, expected) in [
            (
                Response::Ok("message 1 deleted".into()),
                "+OK message 1 deleted\r\n",
            ),
            (
                Response::Err("permission denied".into()),
                "-ERR permission denied\r\n",
            ),
            (
                Response::List(vec![100, 200, 300]),
                "+OK 3 messages\r\n1 100\r\n2 200\r\n3 300\r\n.\r\n",
            ),
            (
                Response::Capability {
                    mechanisms: vec![Mechanism::Plain, Mechanism::CramMd5],
                    stls: true,
                },
                concat!(
                    "+OK Capability list follows\r\n",
                    "USER\r\n",
                    "SASL PLAIN CRAM-MD5\r\n",
                    "STLS\r\n",
                    "TOP\r\n",
                    "RESP-CODES\r\n",
                    "PIPELINING\r\n",
                    "EXPIRE NEVER\r\n",
                    "UIDL\r\n",
                    "UTF8\r\n",
                    "IMPLEMENTATION Stalwart Mail Server\r\n.\r\n"
                ),
            ),
            (
                Response::Message {
                    bytes: "Subject: test\r\n\r\n.\r\ntest.\r\n.test\r\na"
                        .as_bytes()
                        .to_vec(),
                    lines: 0,
                },
                "+OK 35 octets\r\nSubject: test\r\n\r\n..\r\ntest.\r\n..test\r\na\r\n.\r\n",
            ),
        ] {
            assert_eq!(expected, String::from_utf8(cmd.serialize()).unwrap());
        }
    }
}
