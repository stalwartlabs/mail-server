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

use crate::{protocol::login, receiver::Request, Command};

impl Request<Command> {
    pub fn parse_login(self) -> crate::Result<login::Arguments> {
        match self.tokens.len() {
            2 => {
                let mut tokens = self.tokens.into_iter();
                Ok(login::Arguments {
                    username: tokens
                        .next()
                        .unwrap()
                        .unwrap_string()
                        .map_err(|v| (self.tag.as_str(), v))?,
                    password: tokens
                        .next()
                        .unwrap()
                        .unwrap_string()
                        .map_err(|v| (self.tag.as_str(), v))?,
                    tag: self.tag,
                })
            }
            0 => Err(self.into_error("Missing arguments.")),
            _ => Err(self.into_error("Too many arguments.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{protocol::login, receiver::Receiver};

    #[test]
    fn parse_login() {
        let mut receiver = Receiver::new();

        for (command, arguments) in [
            (
                "a001 LOGIN SMITH SESAME\r\n",
                login::Arguments {
                    tag: "a001".to_string(),
                    username: "SMITH".to_string(),
                    password: "SESAME".to_string(),
                },
            ),
            (
                "A001 LOGIN {11+}\r\nFRED FOOBAR {7+}\r\nfat man\r\n",
                login::Arguments {
                    tag: "A001".to_string(),
                    username: "FRED FOOBAR".to_string(),
                    password: "fat man".to_string(),
                },
            ),
        ] {
            assert_eq!(
                receiver
                    .parse(&mut command.as_bytes().iter())
                    .unwrap()
                    .parse_login()
                    .unwrap(),
                arguments
            );
        }
    }
}
