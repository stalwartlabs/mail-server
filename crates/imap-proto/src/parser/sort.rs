/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_parser::decoders::charsets::map::charset_decoder;

use crate::{
    protocol::search::{Arguments, Comparator, Sort},
    receiver::{bad, Request, Token},
    Command,
};

use super::search::{parse_filters, parse_result_options};

impl Request<Command> {
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse_sort(self) -> trc::Result<Arguments> {
        if self.tokens.is_empty() {
            return Err(self.into_error("Missing sort criteria."));
        }

        let mut tokens = self.tokens.into_iter().peekable();
        let mut sort = Vec::new();

        let (result_options, is_esearch) = match tokens.peek() {
            Some(Token::Argument(value)) if value.eq_ignore_ascii_case(b"return") => {
                tokens.next();
                (
                    parse_result_options(&mut tokens).map_err(|v| bad(self.tag.to_string(), v))?,
                    true,
                )
            }
            _ => (Vec::new(), false),
        };

        if tokens
            .next()
            .map_or(true, |token| !token.is_parenthesis_open())
        {
            return Err(bad(
                self.tag.to_string(),
                "Expected sort criteria between parentheses.",
            ));
        }

        let mut is_ascending = true;
        while let Some(token) = tokens.next() {
            match token {
                Token::ParenthesisClose => break,
                Token::Argument(value) => {
                    if value.eq_ignore_ascii_case(b"REVERSE") {
                        is_ascending = false;
                    } else {
                        sort.push(Comparator {
                            sort: Sort::parse(&value).map_err(|v| bad(self.tag.to_string(), v))?,
                            ascending: is_ascending,
                        });
                        is_ascending = true;
                    }
                }
                _ => return Err(bad(self.tag.to_string(), "Invalid result option argument.")),
            }
        }

        if sort.is_empty() {
            return Err(bad(self.tag.to_string(), "Missing sort criteria."));
        }

        let decoder = charset_decoder(
            &tokens
                .next()
                .ok_or_else(|| bad(self.tag.to_string(), "Missing charset."))?
                .unwrap_bytes(),
        );

        let filter =
            parse_filters(&mut tokens, decoder).map_err(|v| bad(self.tag.to_string(), v))?;
        match filter.len() {
            0 => Err(bad(self.tag.to_string(), "No filters found in command.")),
            _ => Ok(Arguments {
                sort: sort.into(),
                result_options,
                filter,
                is_esearch,
                tag: self.tag,
            }),
        }
    }
}

impl Sort {
    pub fn parse(value: &[u8]) -> super::Result<Self> {
        if value.eq_ignore_ascii_case(b"ARRIVAL") {
            Ok(Self::Arrival)
        } else if value.eq_ignore_ascii_case(b"CC") {
            Ok(Self::Cc)
        } else if value.eq_ignore_ascii_case(b"DATE") {
            Ok(Self::Date)
        } else if value.eq_ignore_ascii_case(b"FROM") {
            Ok(Self::From)
        } else if value.eq_ignore_ascii_case(b"SIZE") {
            Ok(Self::Size)
        } else if value.eq_ignore_ascii_case(b"SUBJECT") {
            Ok(Self::Subject)
        } else if value.eq_ignore_ascii_case(b"TO") {
            Ok(Self::To)
        } else if value.eq_ignore_ascii_case(b"DISPLAYFROM") {
            Ok(Self::DisplayFrom)
        } else if value.eq_ignore_ascii_case(b"DISPLAYTO") {
            Ok(Self::DisplayTo)
        } else {
            Err(format!("Invalid sort criteria {:?}", String::from_utf8_lossy(value)).into())
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        protocol::{
            search::{Arguments, Comparator, Filter, ResultOption, Sort},
            Flag,
        },
        receiver::Receiver,
    };

    #[test]
    fn parse_sort() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                b"A282 SORT (SUBJECT) UTF-8 SINCE 1-Feb-1994\r\n".to_vec(),
                Arguments {
                    sort: vec![Comparator {
                        sort: Sort::Subject,
                        ascending: true,
                    }]
                    .into(),
                    filter: vec![Filter::Since(760060800)],
                    result_options: Vec::new(),
                    is_esearch: false,
                    tag: "A282".to_string(),
                },
            ),
            (
                b"A283 SORT (SUBJECT REVERSE DATE) UTF-8 ALL\r\n".to_vec(),
                Arguments {
                    sort: vec![
                        Comparator {
                            sort: Sort::Subject,
                            ascending: true,
                        },
                        Comparator {
                            sort: Sort::Date,
                            ascending: false,
                        },
                    ]
                    .into(),
                    filter: vec![Filter::All],
                    result_options: Vec::new(),
                    is_esearch: false,
                    tag: "A283".to_string(),
                },
            ),
            (
                b"A284 SORT (SUBJECT) US-ASCII TEXT \"not in mailbox\"\r\n".to_vec(),
                Arguments {
                    sort: vec![Comparator {
                        sort: Sort::Subject,
                        ascending: true,
                    }]
                    .into(),
                    filter: vec![Filter::Text("not in mailbox".to_string())],
                    result_options: Vec::new(),
                    is_esearch: false,
                    tag: "A284".to_string(),
                },
            ),
            (
                [
                    b"A284 SORT (REVERSE ARRIVAL FROM) iso-8859-6 SUBJECT ".to_vec(),
                    b"\"\xe5\xd1\xcd\xc8\xc7 \xc8\xc7\xe4\xd9\xc7\xe4\xe5\"\r\n".to_vec(),
                ]
                .concat(),
                Arguments {
                    sort: vec![
                        Comparator {
                            sort: Sort::Arrival,
                            ascending: false,
                        },
                        Comparator {
                            sort: Sort::From,
                            ascending: true,
                        },
                    ]
                    .into(),
                    filter: vec![Filter::Subject("مرحبا بالعالم".to_string())],
                    result_options: Vec::new(),
                    is_esearch: false,
                    tag: "A284".to_string(),
                },
            ),
            (
                [
                    b"E01 UID SORT RETURN (COUNT) (REVERSE DATE) ".to_vec(),
                    b"UTF-8 UNDELETED UNKEYWORD $Junk\r\n".to_vec(),
                ]
                .concat(),
                Arguments {
                    sort: vec![Comparator {
                        sort: Sort::Date,
                        ascending: false,
                    }]
                    .into(),
                    filter: vec![Filter::Undeleted, Filter::Unkeyword(Flag::Junk)],
                    result_options: vec![ResultOption::Count],
                    is_esearch: true,
                    tag: "E01".to_string(),
                },
            ),
        ] {
            let command_str = String::from_utf8_lossy(&command).into_owned();

            assert_eq!(
                receiver
                    .parse(&mut command.iter())
                    .unwrap()
                    .parse_sort()
                    .expect(&command_str),
                arguments,
                "{}",
                command_str
            );
        }
    }
}
