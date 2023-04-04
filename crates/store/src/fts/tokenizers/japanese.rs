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

use std::vec::IntoIter;

use super::{word::WordTokenizer, Token};

pub struct JapaneseTokenizer<'x> {
    word_tokenizer: WordTokenizer<'x>,
    tokens: IntoIter<String>,
    token_offset: usize,
    token_len: usize,
    token_len_cur: usize,
    max_token_length: usize,
}

impl<'x> JapaneseTokenizer<'x> {
    pub fn new(text: &str, max_token_length: usize) -> JapaneseTokenizer {
        JapaneseTokenizer {
            word_tokenizer: WordTokenizer::new(text),
            tokens: Vec::new().into_iter(),
            max_token_length,
            token_offset: 0,
            token_len: 0,
            token_len_cur: 0,
        }
    }
}

impl<'x> Iterator for JapaneseTokenizer<'x> {
    type Item = Token<'x>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(jp_token) = self.tokens.next() {
                let offset_start = self.token_offset + self.token_len_cur;
                self.token_len_cur += jp_token.len();

                if jp_token.len() <= self.max_token_length {
                    return Token::new(offset_start, jp_token.len(), jp_token.into()).into();
                }
            } else {
                loop {
                    let (token, is_ascii) = self.word_tokenizer.next()?;
                    if !is_ascii {
                        self.tokens = tinysegmenter::tokenize(token.word.as_ref()).into_iter();
                        self.token_offset = token.offset as usize;
                        self.token_len = token.len as usize;
                        self.token_len_cur = 0;
                        break;
                    } else if token.len as usize <= self.max_token_length {
                        return token.into();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn japanese_tokenizer() {
        assert_eq!(
            JapaneseTokenizer::new("お先に失礼します あなたの名前は何ですか 123 abc-872", 40)
                .collect::<Vec<_>>(),
            vec![
                Token {
                    word: "お先".into(),
                    offset: 0,
                    len: 6
                },
                Token {
                    word: "に".into(),
                    offset: 6,
                    len: 3
                },
                Token {
                    word: "失礼".into(),
                    offset: 9,
                    len: 6
                },
                Token {
                    word: "し".into(),
                    offset: 15,
                    len: 3
                },
                Token {
                    word: "ます".into(),
                    offset: 18,
                    len: 6
                },
                Token {
                    word: "あなた".into(),
                    offset: 25,
                    len: 9
                },
                Token {
                    word: "の".into(),
                    offset: 34,
                    len: 3
                },
                Token {
                    word: "名前".into(),
                    offset: 37,
                    len: 6
                },
                Token {
                    word: "は".into(),
                    offset: 43,
                    len: 3
                },
                Token {
                    word: "何".into(),
                    offset: 46,
                    len: 3
                },
                Token {
                    word: "です".into(),
                    offset: 49,
                    len: 6
                },
                Token {
                    word: "か".into(),
                    offset: 55,
                    len: 3
                },
                Token {
                    word: "123".into(),
                    offset: 59,
                    len: 3
                },
                Token {
                    word: "abc".into(),
                    offset: 63,
                    len: 3
                },
                Token {
                    word: "872".into(),
                    offset: 67,
                    len: 3
                }
            ]
        );
    }
}
