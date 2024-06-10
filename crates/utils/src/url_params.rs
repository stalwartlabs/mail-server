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

use std::{borrow::Cow, collections::HashMap};

#[derive(Default)]
pub struct UrlParams<'x> {
    params: HashMap<Cow<'x, str>, Cow<'x, str>>,
}

impl<'x> UrlParams<'x> {
    pub fn new(query: Option<&'x str>) -> Self {
        if let Some(query) = query {
            Self {
                params: form_urlencoded::parse(query.as_bytes())
                    .filter(|(_, value)| !value.is_empty())
                    .collect(),
            }
        } else {
            Self::default()
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(|v| v.as_ref())
    }

    pub fn has_key(&self, key: &str) -> bool {
        self.params.contains_key(key)
    }

    pub fn parse<T>(&self, key: &str) -> Option<T>
    where
        T: std::str::FromStr,
    {
        self.get(key).and_then(|v| v.parse().ok())
    }

    pub fn into_inner(self) -> HashMap<Cow<'x, str>, Cow<'x, str>> {
        self.params
    }
}
