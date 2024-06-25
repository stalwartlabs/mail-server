/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
