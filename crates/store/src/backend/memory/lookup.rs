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

use crate::{IntoRows, QueryResult, QueryType, Row, Value};

use super::{LookupList, MatchType, MemoryStore};

impl MemoryStore {
    pub(crate) fn query<T: QueryResult>(
        &self,
        _: &str,
        params: Vec<Value<'_>>,
    ) -> crate::Result<T> {
        let exists = match T::query_type() {
            QueryType::Exists => true,
            QueryType::QueryOne => false,
            QueryType::QueryAll | QueryType::Execute => {
                return Err(crate::Error::InternalError(
                    "Unsupported query type".to_string(),
                ))
            }
        };

        let needle = params.first().map(|v| v.to_str()).unwrap_or_default();

        match self {
            MemoryStore::List(list) => {
                let found = list.contains(needle.as_ref());
                if exists {
                    Ok(T::from_exists(found))
                } else {
                    Ok(T::from_query_one(Some(Row {
                        values: vec![Value::Bool(found)],
                    })))
                }
            }
            MemoryStore::Map(map) => {
                if let Some(value) = map.get(needle.as_ref()) {
                    if exists {
                        Ok(T::from_exists(true))
                    } else {
                        Ok(T::from_query_one(Some(Row {
                            values: vec![value.clone()],
                        })))
                    }
                } else if exists {
                    Ok(T::from_exists(false))
                } else {
                    Ok(T::from_query_one(None::<Row>))
                }
            }
        }
    }
}

impl IntoRows for Option<Row> {
    fn into_row(self) -> Option<Row> {
        self
    }

    fn into_rows(self) -> crate::Rows {
        unreachable!()
    }

    fn into_named_rows(self) -> crate::NamedRows {
        unreachable!()
    }
}

impl LookupList {
    pub fn contains(&self, value: &str) -> bool {
        if self.set.contains(value) {
            true
        } else {
            for match_type in &self.matches {
                let result = match match_type {
                    MatchType::StartsWith(s) => value.starts_with(s),
                    MatchType::EndsWith(s) => value.ends_with(s),
                    MatchType::Glob(g) => g.matches(value),
                    MatchType::Regex(r) => r.is_match(value),
                };
                if result {
                    return true;
                }
            }
            false
        }
    }

    pub fn extend(&mut self, other: Self) {
        self.set.extend(other.set);
        self.matches.extend(other.matches);
    }
}
