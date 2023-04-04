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

use std::str::CharIndices;

use super::Token;

pub struct WordTokenizer<'x> {
    text: &'x str,
    iterator: CharIndices<'x>,
}

impl<'x> WordTokenizer<'x> {
    pub fn new(text: &str) -> WordTokenizer {
        WordTokenizer {
            text,
            iterator: text.char_indices(),
        }
    }
}

/// Parses text into tokens, used by non-IndoEuropean tokenizers.
impl<'x> Iterator for WordTokenizer<'x> {
    type Item = (Token<'x>, bool);

    fn next(&mut self) -> Option<Self::Item> {
        let mut is_ascii = true;
        while let Some((token_start, ch)) = self.iterator.next() {
            if ch.is_alphanumeric() {
                let token_end = (&mut self.iterator)
                    .filter_map(|(pos, ch)| {
                        if ch.is_alphanumeric() {
                            if is_ascii && !ch.is_ascii() {
                                is_ascii = false;
                            }
                            None
                        } else {
                            pos.into()
                        }
                    })
                    .next()
                    .unwrap_or(self.text.len());

                let token_len = token_end - token_start;
                if token_end > token_start {
                    return (
                        Token::new(
                            token_start,
                            token_len,
                            self.text[token_start..token_end].into(),
                        ),
                        is_ascii,
                    )
                        .into();
                }
            }
        }
        None
    }
}
