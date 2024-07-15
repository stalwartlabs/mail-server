/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    protocol::login,
    receiver::{bad, Request},
    Command,
};

impl Request<Command> {
    pub fn parse_login(self) -> trc::Result<login::Arguments> {
        match self.tokens.len() {
            2 => {
                let mut tokens = self.tokens.into_iter();
                Ok(login::Arguments {
                    username: tokens
                        .next()
                        .unwrap()
                        .unwrap_string()
                        .map_err(|v| bad(self.tag.to_string(), v))?,
                    password: tokens
                        .next()
                        .unwrap()
                        .unwrap_string()
                        .map_err(|v| bad(self.tag.to_string(), v))?,
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
