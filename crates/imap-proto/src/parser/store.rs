/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use crate::{
    protocol::{
        store::{self, Operation},
        Flag,
    },
    receiver::{Request, Token},
    Command,
};

use super::{parse_number, parse_sequence_set};

impl Request<Command> {
    pub fn parse_store(self) -> crate::Result<store::Arguments> {
        let mut tokens = self.tokens.into_iter().peekable();

        // Sequence set
        let sequence_set = parse_sequence_set(
            &tokens
                .next()
                .ok_or((self.tag.as_str(), "Missing sequence set."))?
                .unwrap_bytes(),
        )
        .map_err(|v| (self.tag.as_str(), v))?;
        let mut unchanged_since = None;

        // CONDSTORE parameters
        if let Some(Token::ParenthesisOpen) = tokens.peek() {
            tokens.next();
            while let Some(token) = tokens.next() {
                match token {
                    Token::Argument(param) if param.eq_ignore_ascii_case(b"UNCHANGEDSINCE") => {
                        unchanged_since = parse_number::<u64>(
                            &tokens
                                .next()
                                .ok_or((self.tag.as_str(), "Missing UNCHANGEDSINCE parameter."))?
                                .unwrap_bytes(),
                        )
                        .map_err(|v| (self.tag.as_str(), v))?
                        .into();
                    }
                    Token::ParenthesisClose => {
                        break;
                    }
                    _ => {
                        return Err((
                            self.tag.as_str(),
                            Cow::from(format!("Unsupported parameter '{}'.", token)),
                        )
                            .into());
                    }
                }
            }
        }

        // Operation
        let operation = tokens
            .next()
            .ok_or((self.tag.as_str(), "Missing message data item name."))?
            .unwrap_bytes();
        let (is_silent, operation) = if operation.eq_ignore_ascii_case(b"FLAGS") {
            (false, Operation::Set)
        } else if operation.eq_ignore_ascii_case(b"FLAGS.SILENT") {
            (true, Operation::Set)
        } else if operation.eq_ignore_ascii_case(b"+FLAGS") {
            (false, Operation::Add)
        } else if operation.eq_ignore_ascii_case(b"+FLAGS.SILENT") {
            (true, Operation::Add)
        } else if operation.eq_ignore_ascii_case(b"-FLAGS") {
            (false, Operation::Clear)
        } else if operation.eq_ignore_ascii_case(b"-FLAGS.SILENT") {
            (true, Operation::Clear)
        } else {
            return Err((
                self.tag,
                format!(
                    "Unsupported message data item name: {:?}",
                    String::from_utf8_lossy(&operation)
                ),
            )
                .into());
        };

        // Flags
        let mut keywords = Vec::new();
        match tokens
            .next()
            .ok_or((self.tag.as_str(), "Missing flags to set."))?
        {
            Token::ParenthesisOpen => {
                for token in tokens {
                    match token {
                        Token::Argument(flag) => {
                            keywords
                                .push(Flag::parse_imap(flag).map_err(|v| (self.tag.as_str(), v))?);
                        }
                        Token::ParenthesisClose => {
                            break;
                        }
                        _ => {
                            return Err((self.tag.as_str(), "Unsupported flag.").into());
                        }
                    }
                }
            }
            Token::Argument(flag) => {
                keywords.push(Flag::parse_imap(flag).map_err(|v| (self.tag.as_str(), v))?);
            }
            _ => {
                return Err((self.tag, "Invalid flags parameter.").into());
            }
        }

        if !keywords.is_empty() || operation == Operation::Set {
            Ok(store::Arguments {
                tag: self.tag,
                sequence_set,
                operation,
                is_silent,
                keywords,
                unchanged_since,
            })
        } else {
            Err((self.tag.as_str(), "Missing flags to set.").into())
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        protocol::{
            store::{self, Operation},
            Flag, Sequence,
        },
        receiver::Receiver,
    };

    #[test]
    fn parse_store() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "A003 STORE 2:4 +FLAGS (\\Deleted)\r\n",
                store::Arguments {
                    sequence_set: Sequence::Range {
                        start: 2.into(),
                        end: 4.into(),
                    },
                    is_silent: false,
                    operation: Operation::Add,
                    keywords: vec![Flag::Deleted],
                    tag: "A003".to_string(),
                    unchanged_since: None,
                },
            ),
            (
                "A004 STORE *:100 -FLAGS.SILENT ($Phishing $Junk)\r\n",
                store::Arguments {
                    sequence_set: Sequence::Range {
                        start: None,
                        end: 100.into(),
                    },
                    is_silent: true,
                    operation: Operation::Clear,
                    keywords: vec![Flag::Phishing, Flag::Junk],
                    tag: "A004".to_string(),
                    unchanged_since: None,
                },
            ),
            (
                "d105 STORE 7,5,9 (UNCHANGEDSINCE 320162338) +FLAGS.SILENT \\Deleted\r\n",
                store::Arguments {
                    sequence_set: Sequence::List {
                        items: vec![
                            Sequence::Number { value: 7 },
                            Sequence::Number { value: 5 },
                            Sequence::Number { value: 9 },
                        ],
                    },
                    is_silent: true,
                    operation: Operation::Add,
                    keywords: vec![Flag::Deleted],
                    tag: "d105".to_string(),
                    unchanged_since: Some(320162338),
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_store()
                    .unwrap(),
                arguments
            );
        }
    }
}
