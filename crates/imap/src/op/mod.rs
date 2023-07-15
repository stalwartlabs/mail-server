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

use ::store::query::log::Query;
use imap_proto::StatusResponse;

pub mod acl;
pub mod append;
pub mod authenticate;
pub mod capability;
pub mod close;
pub mod copy_move;
pub mod create;
pub mod delete;
pub mod enable;
pub mod expunge;
pub mod fetch;
pub mod idle;
pub mod list;
pub mod login;
pub mod logout;
pub mod namespace;
pub mod noop;
pub mod rename;
pub mod search;
pub mod select;
pub mod status;
pub mod store;
pub mod subscribe;
pub mod thread;

trait FromModSeq {
    fn from_modseq(modseq: u64) -> Self;
}

trait ToModSeq {
    fn to_modseq(&self) -> u64;
}

impl FromModSeq for Query {
    fn from_modseq(modseq: u64) -> Self {
        if modseq > 0 {
            Query::Since(modseq - 1)
        } else {
            Query::All
        }
    }
}

impl ToModSeq for Option<u64> {
    fn to_modseq(&self) -> u64 {
        self.map(|modseq| modseq + 1).unwrap_or(0)
    }
}

pub type Result<T> = std::result::Result<T, StatusResponse>;
