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

use std::str::Chars;

pub struct SpaceTokenizer<'x> {
    iterator: Chars<'x>,
    token: String,
    max_token_length: usize,
}

impl SpaceTokenizer<'_> {
    pub fn new(text: &str, max_token_length: usize) -> SpaceTokenizer {
        SpaceTokenizer {
            iterator: text.chars(),
            token: String::new(),
            max_token_length,
        }
    }
}

impl Iterator for SpaceTokenizer<'_> {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        for ch in self.iterator.by_ref() {
            if ch.is_alphanumeric() {
                if ch.is_uppercase() {
                    for ch in ch.to_lowercase() {
                        self.token.push(ch);
                    }
                } else {
                    self.token.push(ch);
                }
            } else if !self.token.is_empty() {
                if self.token.len() < self.max_token_length {
                    return Some(std::mem::take(&mut self.token));
                } else {
                    self.token.clear();
                }
            }
        }

        if !self.token.is_empty() {
            if self.token.len() < self.max_token_length {
                return Some(std::mem::take(&mut self.token));
            } else {
                self.token.clear();
            }
        }

        None
    }
}
