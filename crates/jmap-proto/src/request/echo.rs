/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use serde_json::value::RawValue;
use std::fmt::Write;

use crate::parser::{json::Parser, JsonObjectParser, Token};

#[derive(Debug, serde::Serialize)]
pub struct Echo {
    pub payload: Box<RawValue>,
}

impl JsonObjectParser for Echo {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
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
