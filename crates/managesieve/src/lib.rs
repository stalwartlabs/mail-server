/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
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

pub mod core;
pub mod op;

static SERVER_GREETING: &str = "Stalwart ManageSieve at your service.";

#[cfg(test)]
mod tests {
    use imap_proto::receiver::{Error, Receiver, Request, State, Token};

    use crate::core::Command;

    #[test]
    fn receiver_parse_managesieve() {
        let mut receiver = Receiver::new().with_start_state(State::Command { is_uid: false });

        for (frames, expected_requests) in [
            (
                vec!["Authenticate \"DIGEST-MD5\"\r\n"],
                vec![Request {
                    tag: "".to_string(),
                    command: Command::Authenticate,
                    tokens: vec![Token::Argument(b"DIGEST-MD5".to_vec())],
                }],
            ),
            (
                vec![
                    "  AUTHENTICATE  \"GSSAPI\"  {56+}\r\n",
                    "cnNwYXV0aD1lYTQwZjYwMzM1YzQyN2I1NTI3Yjg0ZGJhYmNkZmZmZA==\r\n",
                ],
                vec![Request {
                    tag: "".to_string(),
                    command: Command::Authenticate,
                    tokens: vec![
                        Token::Argument(b"GSSAPI".to_vec()),
                        Token::Argument(
                            b"cnNwYXV0aD1lYTQwZjYwMzM1YzQyN2I1NTI3Yjg0ZGJhYmNkZmZmZA==".to_vec(),
                        ),
                    ],
                }],
            ),
            (
                vec!["Authenticate \"PLAIN\" \"QJIrweAPyo6Q1T9xu\"\r\n"],
                vec![Request {
                    tag: "".to_string(),
                    command: Command::Authenticate,
                    tokens: vec![
                        Token::Argument(b"PLAIN".to_vec()),
                        Token::Argument(b"QJIrweAPyo6Q1T9xu".to_vec()),
                    ],
                }],
            ),
            (
                vec!["StartTls\r\n"],
                vec![Request {
                    tag: "".to_string(),
                    command: Command::StartTls,
                    tokens: vec![],
                }],
            ),
            (
                vec!["HAVESPACE \"myscript\" 999999\r\n"],
                vec![Request {
                    tag: "".to_string(),
                    command: Command::HaveSpace,
                    tokens: vec![
                        Token::Argument(b"myscript".to_vec()),
                        Token::Argument(b"999999".to_vec()),
                    ],
                }],
            ),
            (
                vec![
                    "Putscript \"foo\" {31+}\r\n",
                    "#comment\r\n",
                    "InvalidSieveCommand\r\n\r\n",
                ],
                vec![Request {
                    tag: "".to_string(),
                    command: Command::PutScript,
                    tokens: vec![
                        Token::Argument(b"foo".to_vec()),
                        Token::Argument(b"#comment\r\nInvalidSieveCommand\r\n".to_vec()),
                    ],
                }],
            ),
            (
                vec!["Listscripts\r\n"],
                vec![Request {
                    tag: "".to_string(),
                    command: Command::ListScripts,
                    tokens: vec![],
                }],
            ),
            (
                vec!["Setactive \"baz\"\r\n"],
                vec![Request {
                    tag: "".to_string(),
                    command: Command::SetActive,
                    tokens: vec![Token::Argument(b"baz".to_vec())],
                }],
            ),
            (
                vec!["Renamescript \"foo\" \"bar\"\r\n"],
                vec![Request {
                    tag: "".to_string(),
                    command: Command::RenameScript,
                    tokens: vec![
                        Token::Argument(b"foo".to_vec()),
                        Token::Argument(b"bar".to_vec()),
                    ],
                }],
            ),
            (
                vec!["NOOP \"STARTTLS-SYNC-42\"\r\n"],
                vec![Request {
                    tag: "".to_string(),
                    command: Command::Noop,
                    tokens: vec![Token::Argument(b"STARTTLS-SYNC-42".to_vec())],
                }],
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
}
