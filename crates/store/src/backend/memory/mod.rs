/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

pub mod glob;
pub mod lookup;
pub mod main;

use ahash::{AHashMap, AHashSet};

use crate::Value;

use self::glob::GlobPattern;

pub enum MemoryStore {
    List(LookupList),
    Map(LookupMap),
}

#[derive(Default)]
pub struct LookupList {
    pub set: AHashSet<String>,
    pub matches: Vec<MatchType>,
}

pub type LookupMap = AHashMap<String, Value<'static>>;

pub enum MatchType {
    StartsWith(String),
    EndsWith(String),
    Glob(GlobPattern),
    Regex(regex::Regex),
}
