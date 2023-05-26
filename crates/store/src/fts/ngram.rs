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

use std::borrow::Cow;

use super::bloom::{BloomFilter, BloomHashGroup};

pub trait ToNgrams: Sized {
    fn new(items: usize) -> Self;
    fn insert(&mut self, item: &str);
    fn to_ngrams(tokens: &[Cow<'_, str>], n: usize) -> Self {
        let mut filter = Self::new(tokens.len().saturating_sub(1));
        for words in tokens.windows(n) {
            filter.insert(&words.join(" "));
        }
        filter
    }
}

impl ToNgrams for BloomFilter {
    fn new(items: usize) -> Self {
        BloomFilter::new(items)
    }

    fn insert(&mut self, item: &str) {
        self.insert(&item.into())
    }
}

impl ToNgrams for Vec<BloomHashGroup> {
    fn new(items: usize) -> Self {
        Vec::with_capacity(items)
    }

    fn insert(&mut self, item: &str) {
        self.push(BloomHashGroup {
            h1: item.into(),
            h2: None,
        })
    }
}
