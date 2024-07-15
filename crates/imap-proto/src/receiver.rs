/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, fmt::Display};

use super::{ResponseCode, ResponseType, StatusResponse};

#[derive(Debug, Clone)]
pub enum Error {
    NeedsMoreData,
    NeedsLiteral { size: u32 },
    Error { response: StatusResponse },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<T: CommandParser> {
    pub tag: String,
    pub command: T,
    pub tokens: Vec<Token>,
}

pub trait CommandParser: Sized + Default {
    fn parse(bytes: &[u8], is_uid: bool) -> Option<Self>;
    fn tokenize_brackets(&self) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Argument(Vec<u8>),
    ParenthesisOpen,  // (
    ParenthesisClose, // )
    BracketOpen,      // [
    BracketClose,     // ]
    Lt,               // <
    Gt,               // >
    Dot,              // .
    Nil,              // NIL
}

impl<T: CommandParser> Default for Request<T> {
    fn default() -> Self {
        Self {
            tag: String::with_capacity(0),
            command: T::default(),
            tokens: Vec::new(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum State {
    Start,
    Tag,
    Command { is_uid: bool },
    Argument { last_ch: u8 },
    ArgumentQuoted { escaped: bool },
    Literal { non_sync: bool },
    LiteralSeek { size: u32, non_sync: bool },
    LiteralData { remaining: u32 },
}

pub struct Receiver<T: CommandParser> {
    buf: Vec<u8>,
    pub request: Request<T>,
    pub state: State,
    pub max_request_size: usize,
    pub current_request_size: usize,
    pub start_state: State,
}

impl<T: CommandParser> Receiver<T> {
    pub fn new() -> Self {
        Receiver {
            max_request_size: 25 * 1024 * 1024, // 25MB
            ..Default::default()
        }
    }

    pub fn with_start_state(mut self, state: State) -> Self {
        self.state = state;
        self.start_state = state;
        self
    }

    pub fn with_max_request_size(max_request_size: usize) -> Self {
        Receiver {
            max_request_size,
            ..Default::default()
        }
    }

    pub fn error_reset(&mut self, message: impl Into<Cow<'static, str>>) -> Error {
        let request = std::mem::take(&mut self.request);
        let err = Error::err(
            if !request.tag.is_empty() {
                request.tag.into()
            } else {
                None
            },
            message,
        );
        self.buf = Vec::with_capacity(10);
        self.state = self.start_state;
        self.current_request_size = 0;
        err
    }

    fn push_argument(&mut self, in_quote: bool) -> Result<(), Error> {
        if !self.buf.is_empty() {
            self.current_request_size += self.buf.len();
            if self.current_request_size > self.max_request_size {
                return Err(self.error_reset(format!(
                    "Request exceeds maximum limit of {} bytes.",
                    self.max_request_size
                )));
            }
            self.request.tokens.push(Token::Argument(self.buf.clone()));
            self.buf.clear();
        } else if in_quote {
            self.request.tokens.push(Token::Nil);
        }
        Ok(())
    }

    fn push_token(&mut self, token: Token) -> Result<(), Error> {
        self.current_request_size += 1;
        if self.current_request_size > self.max_request_size {
            return Err(self.error_reset(format!(
                "Request exceeds maximum limit of {} bytes.",
                self.max_request_size
            )));
        }
        self.request.tokens.push(token);
        Ok(())
    }

    pub fn parse(&mut self, bytes: &mut std::slice::Iter<'_, u8>) -> Result<Request<T>, Error> {
        #[allow(clippy::while_let_on_iterator)]
        while let Some(&ch) = bytes.next() {
            match self.state {
                State::Start => {
                    if !ch.is_ascii_whitespace() {
                        self.buf.push(ch);
                        self.state = State::Tag;
                    }
                }
                State::Tag => match ch {
                    b' ' => {
                        if !self.buf.is_empty() {
                            self.request.tag = String::from_utf8(std::mem::replace(
                                &mut self.buf,
                                Vec::with_capacity(10),
                            ))
                            .map_err(|_| self.error_reset("Tag is not a valid UTF-8 string."))?;
                            self.state = State::Command { is_uid: false };
                        }
                    }
                    b'\t' | b'\r' => {}
                    b'\n' => {
                        return Err(self.error_reset(format!(
                            "Missing command after tag {:?}, found CRLF instead.",
                            std::str::from_utf8(&self.buf).unwrap_or_default()
                        )));
                    }
                    _ => {
                        if self.buf.len() < 128 {
                            self.buf.push(ch);
                        } else {
                            return Err(self.error_reset("Tag too long."));
                        }
                    }
                },
                State::Command { is_uid } => {
                    if ch.is_ascii_alphanumeric() {
                        if self.buf.len() < 15 {
                            self.buf.push(ch.to_ascii_uppercase());
                        } else {
                            return Err(self.error_reset("Command too long"));
                        }
                    } else if ch.is_ascii_whitespace() {
                        if !self.buf.is_empty() {
                            if !self.buf.eq_ignore_ascii_case(b"UID") {
                                self.request.command =
                                    T::parse(&self.buf, is_uid).ok_or_else(|| {
                                        let command =
                                            String::from_utf8_lossy(&self.buf).into_owned();
                                        self.error_reset(format!(
                                            "Unrecognized command '{}'.",
                                            command
                                        ))
                                    })?;
                                self.buf.clear();
                                if ch != b'\n' {
                                    self.state = State::Argument { last_ch: b' ' };
                                } else {
                                    self.state = self.start_state;
                                    self.current_request_size = 0;
                                    return Ok(std::mem::take(&mut self.request));
                                }
                            } else {
                                self.buf.clear();
                                self.state = State::Command { is_uid: true };
                            }
                        }
                    } else {
                        return Err(self.error_reset(format!(
                            "Invalid character {:?} in command name.",
                            ch as char
                        )));
                    }
                }
                State::Argument { last_ch } => match ch {
                    b'\"' if last_ch.is_ascii_whitespace() => {
                        self.push_argument(false)?;
                        self.state = State::ArgumentQuoted { escaped: false };
                    }
                    b'{' if last_ch.is_ascii_whitespace()
                        || (last_ch == b'~' && self.buf.len() == 1) =>
                    {
                        if last_ch != b'~' {
                            self.push_argument(false)?;
                        } else {
                            self.buf.clear();
                        }
                        self.state = State::Literal { non_sync: false };
                    }
                    b'(' => {
                        self.push_argument(false)?;
                        self.push_token(Token::ParenthesisOpen)?;
                    }
                    b')' => {
                        self.push_argument(false)?;
                        self.push_token(Token::ParenthesisClose)?;
                    }
                    b'[' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::BracketOpen)?;
                    }
                    b']' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::BracketClose)?;
                    }
                    b'<' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::Lt)?;
                    }
                    b'>' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::Gt)?;
                    }
                    b'.' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::Dot)?;
                    }
                    b'\n' => {
                        self.push_argument(false)?;
                        self.state = self.start_state;
                        self.current_request_size = 0;
                        return Ok(std::mem::take(&mut self.request));
                    }
                    _ if ch.is_ascii_whitespace() => {
                        self.push_argument(false)?;
                        self.state = State::Argument { last_ch: ch };
                    }
                    _ => {
                        self.buf.push(ch);
                        self.state = State::Argument { last_ch: ch };
                    }
                },
                State::ArgumentQuoted { escaped } => match ch {
                    b'\"' => {
                        if !escaped {
                            self.push_argument(true)?;
                            self.state = State::Argument { last_ch: b' ' };
                        } else if self.buf.len() < 1024 {
                            self.buf.push(ch);
                            self.state = State::ArgumentQuoted { escaped: false };
                        } else {
                            return Err(self.error_reset("Quoted argument too long."));
                        }
                    }
                    b'\\' => {
                        if escaped {
                            self.buf.push(ch);
                        }
                        self.state = State::ArgumentQuoted { escaped: !escaped };
                    }
                    b'\n' => {
                        return Err(self.error_reset("Unterminated quoted argument."));
                    }
                    _ => {
                        if self.buf.len() < 1024 {
                            if escaped {
                                self.buf.push(b'\\');
                            }
                            self.buf.push(ch);
                            self.state = State::ArgumentQuoted { escaped: false };
                        } else {
                            return Err(self.error_reset("Quoted argument too long."));
                        }
                    }
                },
                State::Literal { non_sync } => {
                    match ch {
                        b'}' => {
                            if !self.buf.is_empty() {
                                let size = std::str::from_utf8(&self.buf)
                                    .unwrap()
                                    .parse::<u32>()
                                    .map_err(|_| {
                                    self.error_reset("Literal size is not a valid number.")
                                })?;
                                if self.current_request_size + size as usize > self.max_request_size
                                {
                                    return Err(self.error_reset(format!(
                                        "Literal exceeds the maximum request size of {} bytes.",
                                        self.max_request_size
                                    )));
                                }
                                self.state = State::LiteralSeek { size, non_sync };
                                self.buf = Vec::with_capacity(size as usize);
                            } else {
                                return Err(self.error_reset("Invalid empty literal."));
                            }
                        }
                        b'+' => {
                            if !self.buf.is_empty() {
                                self.state = State::Literal { non_sync: true };
                            } else {
                                return Err(self.error_reset("Invalid non-sync literal."));
                            }
                        }
                        _ if ch.is_ascii_digit() => {
                            if !non_sync {
                                self.buf.push(ch);
                            } else {
                                // Digit found after non-sync '+' flag

                                return Err(self.error_reset("Invalid literal."));
                            }
                        }
                        _ => {
                            return Err(self.error_reset(format!(
                                "Invalid character {:?} in literal.",
                                ch as char
                            )));
                        }
                    }
                }
                State::LiteralSeek { size, non_sync } => {
                    if ch == b'\n' {
                        if size > 0 {
                            self.state = State::LiteralData { remaining: size };
                        } else {
                            self.state = State::Argument { last_ch: b' ' };
                            self.push_token(Token::Nil)?;
                        }
                        if !non_sync {
                            return Err(Error::NeedsLiteral { size });
                        }
                    } else if !ch.is_ascii_whitespace() {
                        return Err(
                            self.error_reset("Expected CRLF after literal, found an invalid char.")
                        );
                    }
                }
                State::LiteralData { remaining } => {
                    self.buf.push(ch);
                    if remaining > 1 {
                        self.state = State::LiteralData {
                            remaining: remaining - 1,
                        };
                    } else {
                        self.push_argument(false)?;
                        self.state = State::Argument { last_ch: b' ' };
                    }
                }
            }
        }

        Err(Error::NeedsMoreData)
    }
}

impl Token {
    pub fn unwrap_string(self) -> crate::parser::Result<String> {
        match self {
            Token::Argument(value) => {
                String::from_utf8(value).map_err(|_| "Invalid UTF-8 in argument.".into())
            }
            other => Ok(other.to_string()),
        }
    }

    pub fn unwrap_bytes(self) -> Vec<u8> {
        match self {
            Token::Argument(value) => value,
            other => other.to_string().into_bytes(),
        }
    }

    pub fn eq_ignore_ascii_case(&self, bytes: &[u8]) -> bool {
        match self {
            Token::Argument(argument) => argument.eq_ignore_ascii_case(bytes),
            Token::ParenthesisOpen => bytes.eq(b"("),
            Token::ParenthesisClose => bytes.eq(b")"),
            Token::BracketOpen => bytes.eq(b"["),
            Token::BracketClose => bytes.eq(b"]"),
            Token::Gt => bytes.eq(b">"),
            Token::Lt => bytes.eq(b"<"),
            Token::Dot => bytes.eq(b"."),
            Token::Nil => bytes.is_empty(),
        }
    }

    pub fn is_parenthesis_open(&self) -> bool {
        matches!(self, Token::ParenthesisOpen)
    }

    pub fn is_parenthesis_close(&self) -> bool {
        matches!(self, Token::ParenthesisClose)
    }

    pub fn is_bracket_open(&self) -> bool {
        matches!(self, Token::BracketOpen)
    }

    pub fn is_bracket_close(&self) -> bool {
        matches!(self, Token::BracketClose)
    }

    pub fn is_dot(&self) -> bool {
        matches!(self, Token::Dot)
    }

    pub fn is_lt(&self) -> bool {
        matches!(self, Token::Lt)
    }

    pub fn is_gt(&self) -> bool {
        matches!(self, Token::Gt)
    }
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Token::Argument(value) => write!(f, "{}", String::from_utf8_lossy(value)),
            Token::ParenthesisOpen => write!(f, "("),
            Token::ParenthesisClose => write!(f, ")"),
            Token::BracketOpen => write!(f, "["),
            Token::BracketClose => write!(f, "]"),
            Token::Gt => write!(f, ">"),
            Token::Lt => write!(f, "<"),
            Token::Dot => write!(f, "."),
            Token::Nil => write!(f, ""),
        }
    }
}

impl Error {
    pub fn err(tag: Option<String>, message: impl Into<Cow<'static, str>>) -> Self {
        Error::Error {
            response: StatusResponse {
                tag,
                code: ResponseCode::Parse.into(),
                message: message.into(),
                rtype: ResponseType::Bad,
            },
        }
    }
}

impl<T: CommandParser> Default for Receiver<T> {
    fn default() -> Self {
        Self {
            buf: Vec::with_capacity(10),
            request: Default::default(),
            state: State::Start,
            start_state: State::Start,
            max_request_size: 25 * 1024 * 1024,
            current_request_size: 0,
        }
    }
}

impl<T: CommandParser> Request<T> {
    pub fn into_error(self, message: impl Into<trc::Value>) -> trc::Error {
        trc::Cause::Imap
            .ctx(trc::Key::Details, message)
            .ctx(trc::Key::Id, self.tag)
    }

    pub fn into_parse_error(self, message: impl Into<trc::Value>) -> trc::Error {
        trc::Cause::Imap
            .ctx(trc::Key::Details, message)
            .ctx(trc::Key::Id, self.tag)
            .ctx(trc::Key::Code, ResponseCode::Parse)
            .ctx(trc::Key::Type, ResponseType::Bad)
    }
}

pub(crate) fn bad(tag: impl Into<trc::Value>, message: impl Into<trc::Value>) -> trc::Error {
    trc::Cause::Imap
        .ctx(trc::Key::Details, message)
        .ctx(trc::Key::Id, tag)
        .ctx(trc::Key::Type, ResponseType::Bad)
}

/*

astring         = 1*ASTRING-CHAR / string

string          = quoted / literal

literal         = "{" number64 ["+"] "}" CRLF *CHAR8

quoted          = DQUOTE *QUOTED-CHAR DQUOTE

ASTRING-CHAR   = ATOM-CHAR / resp-specials

atom            = 1*ATOM-CHAR

ATOM-CHAR       = <any CHAR except atom-specials>

atom-specials   = "(" / ")" / "{" / SP / CTL / list-wildcards /
                  quoted-specials / resp-specials

resp-specials   = "]"

list-wildcards  = "%" / "*"

quoted-specials = DQUOTE / "\"

DQUOTE         =  %x22 ; " (Double Quote)

*/

#[cfg(test)]
mod tests {

    use crate::Command;

    use super::{Error, Receiver, Request, Token};

    #[test]
    fn receiver_parse_ok() {
        let mut receiver = Receiver::new();

        for (frames, expected_requests) in [
            (
                vec!["abcd CAPABILITY\r\n"],
                vec![Request {
                    tag: "abcd".to_string(),
                    command: Command::Capability,
                    tokens: vec![],
                }],
            ),
            (
                vec!["A023 LO", "GOUT\r\n"],
                vec![Request {
                    tag: "A023".to_string(),
                    command: Command::Logout,
                    tokens: vec![],
                }],
            ),
            (
                vec!["  A001 AUTHENTICATE GSSAPI  \r\n"],
                vec![Request {
                    tag: "A001".to_string(),
                    command: Command::Authenticate,
                    tokens: vec![Token::Argument(b"GSSAPI".to_vec())],
                }],
            ),
            (
                vec!["A03   AUTHENTICATE ", "PLAIN dGVzdAB0ZXN", "0AHRlc3Q=\r\n"],
                vec![Request {
                    tag: "A03".to_string(),
                    command: Command::Authenticate,
                    tokens: vec![
                        Token::Argument(b"PLAIN".to_vec()),
                        Token::Argument(b"dGVzdAB0ZXN0AHRlc3Q=".to_vec()),
                    ],
                }],
            ),
            (
                vec!["A003 CREATE owatagusiam/\r\n"],
                vec![Request {
                    tag: "A003".to_string(),
                    command: Command::Create,
                    tokens: vec![Token::Argument(b"owatagusiam/".to_vec())],
                }],
            ),
            (
                vec!["A682 LIST \"\" *\r\n"],
                vec![Request {
                    tag: "A682".to_string(),
                    command: Command::List,
                    tokens: vec![Token::Nil, Token::Argument(b"*".to_vec())],
                }],
            ),
            (
                vec!["A03 LIST () \"\" \"%\" RETURN (CHILDREN)\r\n"],
                vec![Request {
                    tag: "A03".to_string(),
                    command: Command::List,
                    tokens: vec![
                        Token::ParenthesisOpen,
                        Token::ParenthesisClose,
                        Token::Nil,
                        Token::Argument(b"%".to_vec()),
                        Token::Argument(b"RETURN".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"CHILDREN".to_vec()),
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec!["A05 LIST (REMOTE SUBSCRIBED) \"\" \"*\"\r\n"],
                vec![Request {
                    tag: "A05".to_string(),
                    command: Command::List,
                    tokens: vec![
                        Token::ParenthesisOpen,
                        Token::Argument(b"REMOTE".to_vec()),
                        Token::Argument(b"SUBSCRIBED".to_vec()),
                        Token::ParenthesisClose,
                        Token::Nil,
                        Token::Argument(b"*".to_vec()),
                    ],
                }],
            ),
            (
                vec!["a1 list \"\" (\"foo\")\r\n"],
                vec![Request {
                    tag: "a1".to_string(),
                    command: Command::List,
                    tokens: vec![
                        Token::Nil,
                        Token::ParenthesisOpen,
                        Token::Argument(b"foo".to_vec()),
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec!["a3.1 LIST \"\" (% music/rock)\r\n"],
                vec![Request {
                    tag: "a3.1".to_string(),
                    command: Command::List,
                    tokens: vec![
                        Token::Nil,
                        Token::ParenthesisOpen,
                        Token::Argument(b"%".to_vec()),
                        Token::Argument(b"music/rock".to_vec()),
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec!["A01 LIST \"\" % RETURN (STATUS (MESSAGES UNSEEN))\r\n"],
                vec![Request {
                    tag: "A01".to_string(),
                    command: Command::List,
                    tokens: vec![
                        Token::Nil,
                        Token::Argument(b"%".to_vec()),
                        Token::Argument(b"RETURN".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"STATUS".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"MESSAGES".to_vec()),
                        Token::Argument(b"UNSEEN".to_vec()),
                        Token::ParenthesisClose,
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec![" A01 LiSt \"\"  % RETURN ( STATUS ( MESSAGES UNSEEN ) ) \r\n"],
                vec![Request {
                    tag: "A01".to_string(),
                    command: Command::List,
                    tokens: vec![
                        Token::Nil,
                        Token::Argument(b"%".to_vec()),
                        Token::Argument(b"RETURN".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"STATUS".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"MESSAGES".to_vec()),
                        Token::Argument(b"UNSEEN".to_vec()),
                        Token::ParenthesisClose,
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec!["A02 LIST (SUBSCRIBED RECURSIVEMATCH) \"\" % RETURN (STATUS (MESSAGES))\r\n"],
                vec![Request {
                    tag: "A02".to_string(),
                    command: Command::List,
                    tokens: vec![
                        Token::ParenthesisOpen,
                        Token::Argument(b"SUBSCRIBED".to_vec()),
                        Token::Argument(b"RECURSIVEMATCH".to_vec()),
                        Token::ParenthesisClose,
                        Token::Nil,
                        Token::Argument(b"%".to_vec()),
                        Token::Argument(b"RETURN".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"STATUS".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"MESSAGES".to_vec()),
                        Token::ParenthesisClose,
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec!["A002 CREATE \"INBOX.Sent Mail\"\r\n"],
                vec![Request {
                    tag: "A002".to_string(),
                    command: Command::Create,
                    tokens: vec![Token::Argument(b"INBOX.Sent Mail".to_vec())],
                }],
            ),
            (
                vec!["A002 CREATE \"Maibox \\\"quo\\\\ted\\\" \"\r\n"],
                vec![Request {
                    tag: "A002".to_string(),
                    command: Command::Create,
                    tokens: vec![Token::Argument(b"Maibox \"quo\\ted\" ".to_vec())],
                }],
            ),
            (
                vec!["A004 COPY 2:4 meeting\r\n"],
                vec![Request {
                    tag: "A004".to_string(),
                    command: Command::Copy(false),
                    tokens: vec![
                        Token::Argument(b"2:4".to_vec()),
                        Token::Argument(b"meeting".to_vec()),
                    ],
                }],
            ),
            (
                vec![
                    "A282 SEARCH RETURN (MIN COU",
                    "NT) FLAGGED SINCE 1-Feb-1994 ",
                    "NOT FROM \"Smith\"\r\n",
                ],
                vec![Request {
                    tag: "A282".to_string(),
                    command: Command::Search(false),
                    tokens: vec![
                        Token::Argument(b"RETURN".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"MIN".to_vec()),
                        Token::Argument(b"COUNT".to_vec()),
                        Token::ParenthesisClose,
                        Token::Argument(b"FLAGGED".to_vec()),
                        Token::Argument(b"SINCE".to_vec()),
                        Token::Argument(b"1-Feb-1994".to_vec()),
                        Token::Argument(b"NOT".to_vec()),
                        Token::Argument(b"FROM".to_vec()),
                        Token::Argument(b"Smith".to_vec()),
                    ],
                }],
            ),
            (
                vec!["F284 UID STORE $ +FLAGS.Silent (\\Deleted)\r\n"],
                vec![Request {
                    tag: "F284".to_string(),
                    command: Command::Store(true),
                    tokens: vec![
                        Token::Argument(b"$".to_vec()),
                        Token::Argument(b"+FLAGS.Silent".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"\\Deleted".to_vec()),
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec!["A654 FETCH 2:4 (FLAGS BODY[HEADER.FIELDS (DATE FROM)])\r\n"],
                vec![Request {
                    tag: "A654".to_string(),
                    command: Command::Fetch(false),
                    tokens: vec![
                        Token::Argument(b"2:4".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"FLAGS".to_vec()),
                        Token::Argument(b"BODY".to_vec()),
                        Token::BracketOpen,
                        Token::Argument(b"HEADER".to_vec()),
                        Token::Dot,
                        Token::Argument(b"FIELDS".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"DATE".to_vec()),
                        Token::Argument(b"FROM".to_vec()),
                        Token::ParenthesisClose,
                        Token::BracketClose,
                        Token::ParenthesisClose,
                    ],
                }],
            ),
            (
                vec![
                    "B283 UID SEARCH RETURN (SAVE) CHARSET ",
                    "KOI8-R (OR $ 1,3000:3021) TEXT \"hello world\"\r\n",
                ],
                vec![Request {
                    tag: "B283".to_string(),
                    command: Command::Search(true),
                    tokens: vec![
                        Token::Argument(b"RETURN".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"SAVE".to_vec()),
                        Token::ParenthesisClose,
                        Token::Argument(b"CHARSET".to_vec()),
                        Token::Argument(b"KOI8-R".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"OR".to_vec()),
                        Token::Argument(b"$".to_vec()),
                        Token::Argument(b"1,3000:3021".to_vec()),
                        Token::ParenthesisClose,
                        Token::Argument(b"TEXT".to_vec()),
                        Token::Argument(b"hello world".to_vec()),
                    ],
                }],
            ),
            (
                vec![
                    "P283 SEARCH CHARSET UTF-8 (OR $ 1,3000:3021) ",
                    "TEXT {8+}\r\nмать\r\n",
                ],
                vec![Request {
                    tag: "P283".to_string(),
                    command: Command::Search(false),
                    tokens: vec![
                        Token::Argument(b"CHARSET".to_vec()),
                        Token::Argument(b"UTF-8".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"OR".to_vec()),
                        Token::Argument(b"$".to_vec()),
                        Token::Argument(b"1,3000:3021".to_vec()),
                        Token::ParenthesisClose,
                        Token::Argument(b"TEXT".to_vec()),
                        Token::Argument("мать".to_string().into_bytes()),
                    ],
                }],
            ),
            (
                vec!["A001 LOGIN {11}\r\n", "FRED FOOBAR {7}\r\n", "fat man\r\n"],
                vec![Request {
                    tag: "A001".to_string(),
                    command: Command::Login,
                    tokens: vec![
                        Token::Argument(b"FRED FOOBAR".to_vec()),
                        Token::Argument(b"fat man".to_vec()),
                    ],
                }],
            ),
            (
                vec!["abc LOGIN {0}\r\n", "\r\n"],
                vec![Request {
                    tag: "abc".to_string(),
                    command: Command::Login,
                    tokens: vec![Token::Nil],
                }],
            ),
            (
                vec!["abc LOGIN {0+}\r\n\r\n"],
                vec![Request {
                    tag: "abc".to_string(),
                    command: Command::Login,
                    tokens: vec![Token::Nil],
                }],
            ),
            (
                vec![
                    "A003 APPEND saved-messages (\\Seen) {297+}\r\n",
                    "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)\r\n",
                    "From: Fred Foobar <foobar@example.com>\r\n",
                    "Subject: afternoon meeting\r\n",
                    "To: mooch@example.com\r\n",
                    "Message-Id: <B27397-0100000@example.com>\r\n",
                    "MIME-Version: 1.0\r\n",
                    "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n",
                    "\r\n",
                    "Hello Joe, do you think we can meet at 3:30 tomorrow?\r\n\r\n",
                ],
                vec![Request {
                    tag: "A003".to_string(),
                    command: Command::Append,
                    tokens: vec![
                        Token::Argument(b"saved-messages".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"\\Seen".to_vec()),
                        Token::ParenthesisClose,
                        Token::Argument(
                            concat!(
                                "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)\r\n",
                                "From: Fred Foobar <foobar@example.com>\r\n",
                                "Subject: afternoon meeting\r\n",
                                "To: mooch@example.com\r\n",
                                "Message-Id: <B27397-0100000@example.com>\r\n",
                                "MIME-Version: 1.0\r\n",
                                "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n",
                                "\r\n",
                                "Hello Joe, do you think we can meet at 3:30 tomorrow?\r\n"
                            )
                            .as_bytes()
                            .to_vec(),
                        ),
                    ],
                }],
            ),
            (
                vec![
                    "A003 APPEND saved-messages (\\Seen) {326}\r\n",
                    "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)\r\n",
                    "From: Fred Foobar <foobar@Blurdybloop.example>\r\n",
                    "Subject: afternoon meeting\r\n",
                    "To: mooch@owatagu.siam.edu.example\r\n",
                    "Message-Id: <B27397-0100000@Blurdybloop.example>\r\n",
                    "MIME-Version: 1.0\r\n",
                    "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n",
                    "\r\n",
                    "Hello Joe, do you think we can meet at 3:30 tomorrow?\r\n\r\n",
                ],
                vec![Request {
                    tag: "A003".to_string(),
                    command: Command::Append,
                    tokens: vec![
                        Token::Argument(b"saved-messages".to_vec()),
                        Token::ParenthesisOpen,
                        Token::Argument(b"\\Seen".to_vec()),
                        Token::ParenthesisClose,
                        Token::Argument(
                            concat!(
                                "Date: Mon, 7 Feb 1994 21:52:25 -0800 (PST)\r\n",
                                "From: Fred Foobar <foobar@Blurdybloop.example>\r\n",
                                "Subject: afternoon meeting\r\n",
                                "To: mooch@owatagu.siam.edu.example\r\n",
                                "Message-Id: <B27397-0100000@Blurdybloop.example>\r\n",
                                "MIME-Version: 1.0\r\n",
                                "Content-Type: TEXT/PLAIN; CHARSET=US-ASCII\r\n",
                                "\r\n",
                                "Hello Joe, do you think we can meet at 3:30 tomorrow?\r\n",
                            )
                            .as_bytes()
                            .to_vec(),
                        ),
                    ],
                }],
            ),
            (
                vec!["001 NOOP\r\n002 CAPABILITY\r\nabc LOGIN hello world\r\n"],
                vec![
                    Request {
                        tag: "001".to_string(),
                        command: Command::Noop,
                        tokens: vec![],
                    },
                    Request {
                        tag: "002".to_string(),
                        command: Command::Capability,
                        tokens: vec![],
                    },
                    Request {
                        tag: "abc".to_string(),
                        command: Command::Login,
                        tokens: vec![
                            Token::Argument(b"hello".to_vec()),
                            Token::Argument(b"world".to_vec()),
                        ],
                    },
                ],
            ),
        ] {
            let mut requests = Vec::new();
            for frame in &frames {
                let mut bytes = frame.as_bytes().iter();
                loop {
                    match receiver.parse(&mut bytes) {
                        Ok(request) => requests.push(request),
                        Err(Error::NeedsMoreData | Error::NeedsLiteral { .. }) => break,
                        Err(err) => panic!("{:?} for frames {:#?}", err, frames),
                    }
                }
            }
            assert_eq!(requests, expected_requests, "{:#?}", frames);
        }
    }

    #[test]
    fn receiver_parse_invalid() {
        let mut receiver = Receiver::<Command>::new();
        for invalid in [
            //"\r\n",
            //"  \r \n",
            "a001\r\n",
            "a001 unknown\r\n",
            "a001 login {abc}\r\n",
            "a001 login {+30}\r\n",
            "a001 login {30} junk\r\n",
        ] {
            match receiver.parse(&mut invalid.as_bytes().iter()) {
                Err(Error::Error { .. }) => {}
                result => panic!("Expecter error, got: {:?}", result),
            }
        }
    }
}
