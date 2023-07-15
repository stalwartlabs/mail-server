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

use crate::{
    error::request::RequestError,
    parser::{json::Parser, Error, JsonObjectParser},
};

#[derive(Debug, Clone, Copy, serde::Serialize, Hash, PartialEq, Eq)]
pub enum Capability {
    #[serde(rename(serialize = "urn:ietf:params:jmap:core"))]
    Core = 1 << 0,
    #[serde(rename(serialize = "urn:ietf:params:jmap:mail"))]
    Mail = 1 << 1,
    #[serde(rename(serialize = "urn:ietf:params:jmap:submission"))]
    Submission = 1 << 2,
    #[serde(rename(serialize = "urn:ietf:params:jmap:vacationresponse"))]
    VacationResponse = 1 << 3,
    #[serde(rename(serialize = "urn:ietf:params:jmap:contacts"))]
    Contacts = 1 << 4,
    #[serde(rename(serialize = "urn:ietf:params:jmap:calendars"))]
    Calendars = 1 << 5,
    #[serde(rename(serialize = "urn:ietf:params:jmap:websocket"))]
    WebSocket = 1 << 6,
    #[serde(rename(serialize = "urn:ietf:params:jmap:sieve"))]
    Sieve = 1 << 7,
}

impl JsonObjectParser for Capability {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        for ch in b"urn:ietf:params:jmap:" {
            if parser
                .next_unescaped()?
                .ok_or_else(|| parser.error_capability())?
                != *ch
            {
                return Err(parser.error_capability());
            }
        }

        match u128::parse(parser) {
            Ok(key) => match key {
                0x6572_6f63 => Ok(Capability::Core),
                0x6c69_616d => Ok(Capability::Mail),
                0x6e6f_6973_7369_6d62_7573 => Ok(Capability::Submission),
                0x6573_6e6f_7073_6572_6e6f_6974_6163_6176 => Ok(Capability::VacationResponse),
                0x7374_6361_746e_6f63 => Ok(Capability::Contacts),
                0x0073_7261_646e_656c_6163 => Ok(Capability::Calendars),
                0x0074_656b_636f_7362_6577 => Ok(Capability::WebSocket),
                0x0065_7665_6973 => Ok(Capability::Sieve),
                _ => Err(parser.error_capability()),
            },
            Err(Error::Method(_)) => Err(parser.error_capability()),
            Err(err @ Error::Request(_)) => Err(err),
        }
    }
}

impl<'x> Parser<'x> {
    fn error_capability(&mut self) -> Error {
        if self.is_eof || self.skip_string() {
            Error::Request(RequestError::unknown_capability(&String::from_utf8_lossy(
                self.bytes[self.pos_marker..self.pos - 1].as_ref(),
            )))
        } else {
            self.error_unterminated()
        }
    }
}
