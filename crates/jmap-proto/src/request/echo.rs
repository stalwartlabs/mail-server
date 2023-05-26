/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

use serde_json::value::RawValue;
use std::fmt::Write;

use crate::parser::{json::Parser, JsonObjectParser, Token};

#[derive(Debug, serde::Serialize)]
pub struct Echo {
    pub payload: Box<RawValue>,
}

impl JsonObjectParser for Echo {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let start_depth_array = parser.depth_array;
        let start_depth_dict = parser.depth_dict;
        let mut value = String::new();

        while {
            let _ = match parser.next_token::<String>()? {
                Token::String(string) => write!(value, "{string:?}"),
                token => write!(value, "{token}"),
            };
            start_depth_array != parser.depth_array || start_depth_dict != parser.depth_dict
        } {}

        Ok(Echo {
            payload: RawValue::from_string(value).unwrap(),
        })
    }
}
