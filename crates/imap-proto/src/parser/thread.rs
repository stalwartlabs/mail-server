/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_parser::decoders::charsets::map::charset_decoder;

use crate::{
    protocol::thread::{self, Algorithm},
    receiver::Request,
    Command,
};

use super::search::parse_filters;

impl Request<Command> {
    #[allow(clippy::while_let_on_iterator)]
    pub fn parse_thread(self) -> crate::Result<thread::Arguments> {
        if self.tokens.is_empty() {
            return Err(self.into_error("Missing thread criteria."));
        }

        let mut tokens = self.tokens.into_iter().peekable();
        let algorithm = Algorithm::parse(
            &tokens
                .next()
                .ok_or((self.tag.as_str(), "Missing threading algorithm."))?
                .unwrap_bytes(),
        )
        .map_err(|v| (self.tag.as_str(), v))?;

        let decoder = charset_decoder(
            &tokens
                .next()
                .ok_or((self.tag.as_str(), "Missing charset."))?
                .unwrap_bytes(),
        );

        let filter = parse_filters(&mut tokens, decoder).map_err(|v| (self.tag.as_str(), v))?;
        match filter.len() {
            0 => Err((self.tag.as_str(), "No filters found in command.").into()),
            _ => Ok(thread::Arguments {
                algorithm,
                filter,
                tag: self.tag,
            }),
        }
    }
}

impl Algorithm {
    pub fn parse(value: &[u8]) -> super::Result<Self> {
        if value.eq_ignore_ascii_case(b"ORDEREDSUBJECT") {
            Ok(Self::OrderedSubject)
        } else if value.eq_ignore_ascii_case(b"REFERENCES") {
            Ok(Self::References)
        } else {
            Err(format!(
                "Invalid threading algorithm {:?}",
                String::from_utf8_lossy(value)
            )
            .into())
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        protocol::{
            search::Filter,
            thread::{self, Algorithm},
        },
        receiver::Receiver,
    };

    #[test]
    fn parse_thread() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                b"A283 THREAD ORDEREDSUBJECT UTF-8 SINCE 5-MAR-2000\r\n".to_vec(),
                thread::Arguments {
                    algorithm: Algorithm::OrderedSubject,
                    filter: vec![Filter::Since(952214400)],
                    tag: "A283".to_string(),
                },
            ),
            (
                b"A284 THREAD REFERENCES US-ASCII TEXT \"gewp\"\r\n".to_vec(),
                thread::Arguments {
                    algorithm: Algorithm::References,
                    filter: vec![Filter::Text("gewp".to_string())],
                    tag: "A284".to_string(),
                },
            ),
        ] {
            let command_str = String::from_utf8_lossy(&command).into_owned();

            assert_eq!(
                receiver
                    .parse(&mut command.iter())
                    .unwrap()
                    .parse_thread()
                    .expect(&command_str),
                arguments,
                "{}",
                command_str
            );
        }
    }
}
