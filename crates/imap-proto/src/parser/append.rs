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

use crate::{
    protocol::{
        append::{self, Message},
        Flag,
    },
    receiver::{Request, Token},
    Command,
};

use super::parse_datetime;

impl Request<Command> {
    pub fn parse_append(self) -> crate::Result<append::Arguments> {
        match self.tokens.len() {
            0 | 1 => Err(self.into_error("Missing arguments.")),
            _ => {
                let mut tokens = self.tokens.into_iter().peekable();
                let mailbox_name = tokens
                    .next()
                    .unwrap()
                    .unwrap_string()
                    .map_err(|v| (self.tag.as_str(), v))?;
                let mut messages = Vec::new();

                while let Some(token) = tokens.next() {
                    let mut flags = Vec::new();
                    let token = match token {
                        Token::ParenthesisOpen => {
                            #[allow(clippy::while_let_on_iterator)]
                            while let Some(token) = tokens.next() {
                                match token {
                                    Token::ParenthesisClose => break,
                                    Token::Argument(value) => {
                                        flags.push(
                                            Flag::parse_imap(value)
                                                .map_err(|v| (self.tag.as_str(), v))?,
                                        );
                                    }
                                    _ => return Err((self.tag.as_str(), "Invalid flag.").into()),
                                }
                            }
                            tokens
                                .next()
                                .ok_or((self.tag.as_str(), "Missing paramaters after flags."))?
                        }
                        token => token,
                    };
                    let (message, received_at) = if tokens.peek().is_some() {
                        let token_bytes = token.unwrap_bytes();
                        if token_bytes.len() <= 28 {
                            if let Ok(date_time) = parse_datetime(&token_bytes) {
                                (tokens.next().unwrap().unwrap_bytes(), Some(date_time))
                            } else {
                                (token_bytes, None)
                            }
                        } else {
                            (token_bytes, None)
                        }
                    } else {
                        (token.unwrap_bytes(), None)
                    };

                    messages.push(Message {
                        message,
                        flags,
                        received_at,
                    });
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
            Flag,
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
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_append()
                    .unwrap(),
                arguments,
                "{:?}",
                command
            );
        }

        // Multiappend
        for line in [
            "A003 APPEND saved-messages (\\Seen) {329}\r\n",
            "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)\r\n",
            "From: Fred Foobar <foobar@Blurdybloop.example.COM>\r\n",
            "Subject: afternoon meeting\r\n",
            "To: mooch@owatagu.example.net\r\n",
            "Message-Id: <B27397-0100000@Blurdybloop.example.COM>\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n",
            "\r\n",
            "Hello Joe, do you think we can meet at 3:30 tomorrow?\r\n",
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
                        request.parse_append().unwrap(),
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
