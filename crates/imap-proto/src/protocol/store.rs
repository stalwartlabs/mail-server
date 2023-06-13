/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart IMAP Server.
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

use super::{fetch::FetchItem, Flag, ImapResponse, Sequence};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: String,
    pub sequence_set: Sequence,
    pub operation: Operation,
    pub is_silent: bool,
    pub keywords: Vec<Flag>,
    pub unchanged_since: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Set,
    Add,
    Clear,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response<'x> {
    pub items: Vec<FetchItem<'x>>,
}

impl<'x> ImapResponse for Response<'x> {
    fn serialize(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        for item in &self.items {
            item.serialize(&mut buf);
        }
        buf
    }
}
