/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::ToCompactString;
use mail_parser::decoders::charsets::map::charset_decoder;

use crate::{
    Command,
    protocol::search::{Arguments, Comparator, Sort},
    receiver::{Request, Token, bad},
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
                    parse_result_options(&mut tokens)
                        .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                    true,
                )
            }
            _ => (Vec::new(), false),
        };

        if tokens
            .next()
            .is_none_or(|token| !token.is_parenthesis_open())
        {
            return Err(bad(
                self.tag.to_compact_string(),
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
                            sort: Sort::parse(&value)
                                .map_err(|v| bad(self.tag.to_compact_string(), v))?,
                            ascending: is_ascending,
                        });
                        is_ascending = true;
                    }
                }
                _ => {
                    return Err(bad(
                        self.tag.to_compact_string(),
                        "Invalid result option argument.",
                    ));
                }
            }
        }

        if sort.is_empty() {
            return Err(bad(self.tag.to_compact_string(), "Missing sort criteria."));
        }

        let decoder = charset_decoder(
            &tokens
                .next()
                .ok_or_else(|| bad(self.tag.to_compact_string(), "Missing charset."))?
                .unwrap_bytes(),
        );

        let filter = parse_filters(&mut tokens, decoder)
            .map_err(|v| bad(self.tag.to_compact_string(), v))?;
        match filter.len() {
            0 => Err(bad(
                self.tag.to_compact_string(),
                "No filters found in command.",
            )),
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
        hashify::tiny_map_ignore_case!(value,
            "ARRIVAL" => Self::Arrival,
            "CC" => Self::Cc,
            "DATE" => Self::Date,
            "FROM" => Self::From,
            "SIZE" => Self::Size,
            "SUBJECT" => Self::Subject,
            "TO" => Self::To,
            "DISPLAYFROM" => Self::DisplayFrom,
            "DISPLAYTO" => Self::DisplayTo,
        )
        .ok_or_else(|| format!("Invalid sort criteria {:?}", String::from_utf8_lossy(value)).into())
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        protocol::{
            Flag,
            search::{Arguments, Comparator, Filter, ResultOption, Sort},
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
                    tag: "A282".into(),
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
                    tag: "A283".into(),
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
                    filter: vec![Filter::Text("not in mailbox".into())],
                    result_options: Vec::new(),
                    is_esearch: false,
                    tag: "A284".into(),
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
                    filter: vec![Filter::Subject("مرحبا بالعالم".into())],
                    result_options: Vec::new(),
                    is_esearch: false,
                    tag: "A284".into(),
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
                    tag: "E01".into(),
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
