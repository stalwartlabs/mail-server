/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    protocol::{
        append::{self, Message},
        Flag, ProtocolVersion,
    },
    receiver::{Request, Token},
    utf7::utf7_maybe_decode,
    Command,
};

use super::parse_datetime;

enum State {
    None,
    Flags,
    UTF8,
    UTF8Data,
}

impl Request<Command> {
    pub fn parse_append(self, version: ProtocolVersion) -> crate::Result<append::Arguments> {
        match self.tokens.len() {
            0 | 1 => Err(self.into_error("Missing arguments.")),
            _ => {
                // Obtain mailbox name
                let mut tokens = self.tokens.into_iter().peekable();
                let mailbox_name = utf7_maybe_decode(
                    tokens
                        .next()
                        .unwrap()
                        .unwrap_string()
                        .map_err(|v| (self.tag.as_str(), v))?,
                    version,
                );
                let mut messages = Vec::new();

                while tokens.peek().is_some() {
                    // Parse flags
                    let mut message = Message {
                        message: vec![],
                        flags: vec![],
                        received_at: None,
                    };
                    let mut state = State::None;
                    let mut seen_flags = false;

                    while let Some(token) = tokens.next() {
                        match token {
                            Token::ParenthesisOpen => {
                                state = match state {
                                    State::None if !seen_flags => {
                                        seen_flags = true;
                                        State::Flags
                                    }
                                    State::UTF8 => State::UTF8Data,
                                    _ => {
                                        return Err((
                                            self.tag.as_str(),
                                            "Invalid opening parenthesis found.",
                                        )
                                            .into())
                                    }
                                };
                            }
                            Token::ParenthesisClose => match state {
                                State::None | State::UTF8 => {
                                    return Err((
                                        self.tag.as_str(),
                                        "Invalid closing parenthesis found.",
                                    )
                                        .into())
                                }
                                State::Flags => {
                                    state = State::None;
                                }
                                State::UTF8Data => {
                                    break;
                                }
                            },
                            Token::Argument(value) => match state {
                                State::None => {
                                    if value.eq_ignore_ascii_case(b"utf8") {
                                        state = State::UTF8;
                                    } else if matches!(tokens.peek(), Some(Token::Argument(_)))
                                        && value.len() <= 28
                                        && !value.contains(&b'\n')
                                    {
                                        if let Ok(date_time) = parse_datetime(&value) {
                                            message.received_at = Some(date_time);
                                        } else {
                                            return Err((
                                                self.tag.as_str(),
                                                "Failed to parse received time.",
                                            )
                                                .into());
                                        }
                                    } else {
                                        message.message = value;
                                        break;
                                    }
                                }
                                State::Flags => {
                                    message.flags.push(
                                        Flag::parse_imap(value)
                                            .map_err(|v| (self.tag.as_str(), v))?,
                                    );
                                }
                                State::UTF8 => {
                                    return Err((
                                        self.tag.as_str(),
                                        "Expected parenthesis after UTF8.",
                                    )
                                        .into());
                                }
                                State::UTF8Data => {
                                    if message.message.is_empty() {
                                        message.message = value;
                                    } else {
                                        return Err((
                                            self.tag.as_str(),
                                            "Invalid parameter after message literal.",
                                        )
                                            .into());
                                    }
                                }
                            },
                            _ => return Err((self.tag.as_str(), "Invalid arguments.").into()),
                        }
                    }

                    messages.push(message);
                }

                Ok(append::Arguments {
                    tag: self.tag,
                    mailbox_name,
                    messages,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        protocol::{
            append::{self, Message},
            Flag, ProtocolVersion,
        },
        receiver::{Error, Receiver},
    };

    #[test]
    fn parse_append() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "A003 APPEND saved-messages (\\Seen) {1+}\r\na\r\n",
                append::Arguments {
                    tag: "A003".to_string(),
                    mailbox_name: "saved-messages".to_string(),
                    messages: vec![Message {
                        message: vec![b'a'],
                        flags: vec![Flag::Seen],
                        received_at: None,
                    }],
                },
            ),
            (
                "A003 APPEND \"hello world\" (\\Seen \\Draft $MDNSent) {1+}\r\na\r\n",
                append::Arguments {
                    tag: "A003".to_string(),
                    mailbox_name: "hello world".to_string(),
                    messages: vec![Message {
                        message: vec![b'a'],
                        flags: vec![Flag::Seen, Flag::Draft, Flag::MDNSent],
                        received_at: None,
                    }],
                },
            ),
            (
                "A003 APPEND \"hi\" ($Junk) \"7-Feb-1994 22:43:04 -0800\" {1+}\r\na\r\n",
                append::Arguments {
                    tag: "A003".to_string(),
                    mailbox_name: "hi".to_string(),
                    messages: vec![Message {
                        message: vec![b'a'],
                        flags: vec![Flag::Junk],
                        received_at: Some(760689784),
                    }],
                },
            ),
            (
                "A003 APPEND \"hi\" \"20-Nov-2022 23:59:59 +0300\" {1+}\r\na\r\n",
                append::Arguments {
                    tag: "A003".to_string(),
                    mailbox_name: "hi".to_string(),
                    messages: vec![Message {
                        message: vec![b'a'],
                        flags: vec![],
                        received_at: Some(1668977999),
                    }],
                },
            ),
            (
                "A003 APPEND \"hi\" \"20-Nov-2022 23:59:59 +0300\" ~{1+}\r\na\r\n",
                append::Arguments {
                    tag: "A003".to_string(),
                    mailbox_name: "hi".to_string(),
                    messages: vec![Message {
                        message: vec![b'a'],
                        flags: vec![],
                        received_at: Some(1668977999),
                    }],
                },
            ),
            (
                "42 APPEND \"Drafts\" (\\Draft) UTF8 (~{5+}\r\nhello)\r\n",
                append::Arguments {
                    tag: "42".to_string(),
                    mailbox_name: "Drafts".to_string(),
                    messages: vec![Message {
                        message: vec![b'h', b'e', b'l', b'l', b'o'],
                        flags: vec![Flag::Draft],
                        received_at: None,
                    }],
                },
            ),
            (
                "42 APPEND \"Drafts\" (\\Draft) \"20-Nov-2022 23:59:59 +0300\" UTF8 (~{5+}\r\nhello)\r\n",
                append::Arguments {
                    tag: "42".to_string(),
                    mailbox_name: "Drafts".to_string(),
                    messages: vec![Message {
                        message: vec![b'h', b'e', b'l', b'l', b'o'],
                        flags: vec![Flag::Draft],
                        received_at: Some(1668977999),
                    }],
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .expect(command)
                    .parse_append(ProtocolVersion::Rev1)
                    .expect(command),
                arguments,
                "{:?}",
                command
            );
        }

        // Multiappend
        for line in [
            "A003 APPEND saved-messages (\\Seen) UTF8 ({329}\r\n",
            "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)\r\n",
            "From: Fred Foobar <foobar@Blurdybloop.example.COM>\r\n",
            "Subject: afternoon meeting\r\n",
            "To: mooch@owatagu.example.net\r\n",
            "Message-Id: <B27397-0100000@Blurdybloop.example.COM>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n",
            "\r\n",
            "Hello Joe, do you think we can meet at 3:30 tomorrow?\r\n)",
            " (\\Seen) \"7-Feb-1994 22:43:04 -0800\" {295}\r\n",
            "Date: Mon, 7 Feb 1994 22:43:04 -0800 (PST)\r\n",
            "From: Joe Mooch <mooch@OWaTaGu.example.net>\r\n",
            "Subject: Re: afternoon meeting\r\n",
            "To: foobar@blurdybloop.example.com\r\n",
            "Message-Id: <a0434793874930@OWaTaGu.example.net>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n\r\n",
            "3:30 is fine with me.\r\n\r\n",
        ] {
            match receiver.parse(&mut line.as_bytes().iter()) {
                Ok(request) => {
                    assert_eq!(
                        request.parse_append(ProtocolVersion::Rev1).unwrap(),
                        append::Arguments {
                            tag: "A003".to_string(),
                            mailbox_name: "saved-messages".to_string(),
                            messages: vec![
                                Message {
                                    message: concat!(
                                        "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)\r\n",
                                        "From: Fred Foobar <foobar@Blurdybloop.example.COM>\r\n",
                                        "Subject: afternoon meeting\r\n",
                                        "To: mooch@owatagu.example.net\r\n",
                                        "Message-Id: <B27397-0100000@Blurdybloop.example.COM>\r\n",
                                        "MIME-Version: 1.0\r\n",
                                        "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n",
                                        "\r\n",
                                        "Hello Joe, do you think we can meet at 3:30 tomorrow?\r\n",
                                    )
                                    .as_bytes()
                                    .to_vec(),
                                    flags: vec![Flag::Seen],
                                    received_at: None,
                                },
                                Message {
                                    message: concat!(
                                        "Date: Mon, 7 Feb 1994 22:43:04 -0800 (PST)\r\n",
                                        "From: Joe Mooch <mooch@OWaTaGu.example.net>\r\n",
                                        "Subject: Re: afternoon meeting\r\n",
                                        "To: foobar@blurdybloop.example.com\r\n",
                                        "Message-Id: <a0434793874930@OWaTaGu.example.net>\r\n",
                                        "MIME-Version: 1.0\r\n",
                                        "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n\r\n",
                                        "3:30 is fine with me.\r\n",
                                    )
                                    .as_bytes()
                                    .to_vec(),
                                    flags: vec![Flag::Seen],
                                    received_at: Some(760689784),
                                }
                            ],
                        },
                    );
                }
                Err(err) => match err {
                    Error::NeedsMoreData | Error::NeedsLiteral { .. } => (),
                    Error::Error { response } => panic!("{:?}", response),
                },
            }
        }
    }
}
