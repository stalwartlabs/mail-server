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
