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

use std::borrow::Cow;

use super::{
    utils::{AsKey, ParseValue},
    DynValue,
};

impl ParseValue for DynValue {
    #[allow(clippy::while_let_on_iterator)]
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        let mut items = vec![];
        let mut buf = vec![];
        let mut iter = value.as_bytes().iter().peekable();

        while let Some(&ch) = iter.next() {
            if ch == b'$' && matches!(iter.peek(), Some(b'{')) {
                iter.next();
                if matches!(iter.peek(), Some(ch) if ch.is_ascii_digit()) {
                    if !buf.is_empty() {
                        items.push(DynValue::String(String::from_utf8(buf).unwrap()));
                        buf = vec![];
                    }

                    while let Some(&ch) = iter.next() {
                        if ch.is_ascii_digit() {
                            buf.push(ch);
                        } else if ch == b'}' && !buf.is_empty() {
                            let str_num = std::str::from_utf8(&buf).unwrap();
                            items.push(DynValue::Position(str_num.parse().map_err(|_| {
                                format!(
                                    "Failed to parse position {str_num:?} in value {value:?} for key {}",
                                    key.as_key()
                                )
                            })?));
                            buf.clear();
                            break;
                        } else {
                            return Err(format!(
                                "Invalid dynamic string {value:?} for key {}",
                                key.as_key()
                            ));
                        }
                    }
                } else {
                    buf.push(b'$');
                    buf.push(b'{');
                }
            } else {
                buf.push(ch);
            }
        }

        if !buf.is_empty() {
            let item = DynValue::String(String::from_utf8(buf).unwrap());
            if !items.is_empty() {
                items.push(item);
            } else {
                return Ok(item);
            }
        }

        Ok(match items.len() {
            0 => DynValue::String(String::new()),
            1 => items.pop().unwrap(),
            _ => DynValue::List(items),
        })
    }
}

impl DynValue {
    pub fn apply(&self, captures: Vec<String>) -> Cow<str> {
        match self {
            DynValue::String(value) => Cow::Borrowed(value.as_str()),
            DynValue::Position(pos) => captures
                .into_iter()
                .nth(*pos)
                .map(Cow::Owned)
                .unwrap_or(Cow::Borrowed("")),
            DynValue::List(items) => {
                let mut result = String::new();

                for item in items {
                    match item {
                        DynValue::String(value) => result.push_str(value),
                        DynValue::Position(pos) => {
                            if let Some(capture) = captures.get(*pos) {
                                result.push_str(capture);
                            }
                        }
                        DynValue::List(_) => unreachable!(),
                    }
                }

                Cow::Owned(result)
            }
        }
    }

    pub fn apply_borrowed<'x, 'y: 'x>(&'x self, captures: &'y [String]) -> Cow<'x, str> {
        match self {
            DynValue::String(value) => Cow::Borrowed(value.as_str()),
            DynValue::Position(pos) => captures
                .get(*pos)
                .map(|v| Cow::Borrowed(v.as_str()))
                .unwrap_or(Cow::Borrowed("")),
            DynValue::List(items) => {
                let mut result = String::new();

                for item in items {
                    match item {
                        DynValue::String(value) => result.push_str(value),
                        DynValue::Position(pos) => {
                            if let Some(capture) = captures.get(*pos) {
                                result.push_str(capture);
                            }
                        }
                        DynValue::List(_) => unreachable!(),
                    }
                }

                Cow::Owned(result)
            }
        }
    }
}
