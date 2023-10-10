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

use nohash::IsEnabled;

use crate::transformers::osb::{Gram, OsbToken};

use super::TokenHash;

pub struct BloomHasher<'x, T: Iterator<Item = OsbToken<Gram<'x>>>> {
    buf: Vec<u8>,
    tokens: T,
}

impl<'x, T: Iterator<Item = OsbToken<Gram<'x>>>> BloomHasher<'x, T> {
    pub fn new(tokens: T) -> Self {
        Self {
            buf: Vec::with_capacity(64),
            tokens,
        }
    }
}

impl<'x, T: Iterator<Item = OsbToken<Gram<'x>>>> Iterator for BloomHasher<'x, T> {
    type Item = OsbToken<TokenHash>;

    fn next(&mut self) -> Option<Self::Item> {
        self.tokens.next().map(|token| {
            let bytes = match token.inner {
                Gram::Uni { t1 } => t1.as_bytes(),
                Gram::Bi { t1, t2, .. } => {
                    self.buf.clear();
                    self.buf.extend_from_slice(t1.as_bytes());
                    self.buf.push(b' ');
                    self.buf.extend_from_slice(t2.as_bytes());
                    &self.buf
                }
            };

            OsbToken {
                inner: TokenHash {
                    h1: xxhash_rust::xxh3::xxh3_64(bytes),
                    h2: farmhash::hash64(bytes),
                },
                idx: token.idx,
            }
        })
    }
}

impl std::hash::Hash for TokenHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.h1 ^ self.h2);
    }
}

impl IsEnabled for TokenHash {}
