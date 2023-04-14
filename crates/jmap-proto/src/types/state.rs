/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
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

use utils::codec::{
    base32_custom::Base32Writer,
    leb128::{Leb128Iterator, Leb128Writer},
};

use crate::parser::{base32::JsonBase32Reader, json::Parser, JsonObjectParser};

use super::ChangeId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JMAPIntermediateState {
    pub from_id: ChangeId,
    pub to_id: ChangeId,
    pub items_sent: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum State {
    #[default]
    Initial,
    Exact(ChangeId),
    Intermediate(JMAPIntermediateState),
}

impl From<ChangeId> for State {
    fn from(change_id: ChangeId) -> Self {
        State::Exact(change_id)
    }
}

impl From<Option<ChangeId>> for State {
    fn from(change_id: Option<ChangeId>) -> Self {
        match change_id {
            Some(change_id) => State::Exact(change_id),
            None => State::Initial,
        }
    }
}

impl JsonObjectParser for State {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        match parser
            .next_unescaped()?
            .ok_or_else(|| parser.error_value())?
        {
            b'n' => Ok(State::Initial),
            b's' => {
                let mut reader = JsonBase32Reader::new(parser);
                reader
                    .next_leb128::<ChangeId>()
                    .map(State::Exact)
                    .ok_or_else(|| parser.error_value())
            }
            b'r' => {
                let mut it = JsonBase32Reader::new(parser);

                if let (Some(from_id), Some(to_id), Some(items_sent)) = (
                    it.next_leb128::<ChangeId>(),
                    it.next_leb128::<ChangeId>(),
                    it.next_leb128::<usize>(),
                ) {
                    if items_sent > 0 {
                        Ok(State::Intermediate(JMAPIntermediateState {
                            from_id,
                            to_id: from_id.saturating_add(to_id),
                            items_sent,
                        }))
                    } else {
                        Err(parser.error_value())
                    }
                } else {
                    Err(parser.error_value())
                }
            }
            _ => Err(parser.error_value()),
        }
    }
}

impl State {
    pub fn new_initial() -> Self {
        State::Initial
    }

    pub fn new_exact(id: ChangeId) -> Self {
        State::Exact(id)
    }

    pub fn new_intermediate(from_id: ChangeId, to_id: ChangeId, items_sent: usize) -> Self {
        State::Intermediate(JMAPIntermediateState {
            from_id,
            to_id,
            items_sent,
        })
    }

    pub fn get_change_id(&self) -> ChangeId {
        match self {
            State::Exact(id) => *id,
            State::Intermediate(intermediate) => intermediate.to_id,
            State::Initial => ChangeId::MAX,
        }
    }
}

impl serde::Serialize for State {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut writer = Base32Writer::with_capacity(10);

        match self {
            State::Initial => {
                writer.push_char('n');
            }
            State::Exact(id) => {
                writer.push_char('s');
                writer.write_leb128(*id).unwrap();
            }
            State::Intermediate(intermediate) => {
                writer.push_char('r');
                writer.write_leb128(intermediate.from_id).unwrap();
                writer
                    .write_leb128(intermediate.to_id - intermediate.from_id)
                    .unwrap();
                writer.write_leb128(intermediate.items_sent).unwrap();
            }
        }

        f.write_str(&writer.finalize())
    }
}

#[cfg(test)]
mod tests {

    use crate::{parser::json::Parser, types::ChangeId};

    use super::State;

    #[test]
    fn test_state_id() {
        for id in [
            State::new_initial(),
            State::new_exact(0),
            State::new_exact(12345678),
            State::new_exact(ChangeId::MAX),
            State::new_intermediate(0, 0, 1),
            State::new_intermediate(1024, 2048, 100),
            State::new_intermediate(12345678, 87654321, 1),
            State::new_intermediate(0, 0, 12345678),
            State::new_intermediate(0, 87654321, 12345678),
            State::new_intermediate(12345678, 87654321, 1),
            State::new_intermediate(12345678, 87654321, 12345678),
            State::new_intermediate(ChangeId::MAX, ChangeId::MAX, ChangeId::MAX as usize),
        ] {
            assert_eq!(
                Parser::new(format!("\"{id}\"").as_bytes())
                    .next_token::<State>()
                    .unwrap()
                    .unwrap_string("")
                    .unwrap(),
                id
            );
        }
    }
}
