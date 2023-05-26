/*
 * Copyright (c) 2023, Stalwart Labs Ltd.
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

use std::{borrow::Cow, vec::IntoIter};

use jieba_rs::Jieba;

use super::{word::WordTokenizer, Token};
use lazy_static::lazy_static;

lazy_static! {
    static ref JIEBA: Jieba = Jieba::new();
}

pub struct ChineseTokenizer<'x> {
    word_tokenizer: WordTokenizer<'x>,
    tokens: IntoIter<&'x str>,
    token_offset: usize,
    token_len: usize,
    token_len_cur: usize,
    max_token_length: usize,
}

impl<'x> ChineseTokenizer<'x> {
    pub fn new(text: &str, max_token_length: usize) -> ChineseTokenizer {
        ChineseTokenizer {
            word_tokenizer: WordTokenizer::new(text),
            tokens: Vec::new().into_iter(),
            max_token_length,
            token_offset: 0,
            token_len: 0,
            token_len_cur: 0,
        }
    }
}

impl<'x> Iterator for ChineseTokenizer<'x> {
    type Item = Token<'x>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ch_token) = self.tokens.next() {
                let offset_start = self.token_offset + self.token_len_cur;
                self.token_len_cur += ch_token.len();

                if ch_token.len() <= self.max_token_length {
                    return Token::new(offset_start, ch_token.len(), ch_token.into()).into();
                }
            } else {
                loop {
                    let (token, is_ascii) = self.word_tokenizer.next()?;
                    if !is_ascii {
                        let word = match token.word {
                            Cow::Borrowed(word) => word,
                            Cow::Owned(_) => unreachable!(),
                        };
                        self.tokens = JIEBA.cut(word, false).into_iter();
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
    fn chinese_tokenizer() {
        assert_eq!(
            ChineseTokenizer::new(
                "孫子曰：兵者，國之大事，死生之地，存亡之道，不可不察也。",
                40
            )
            .collect::<Vec<_>>(),
            vec![
                Token {
                    word: "孫".into(),
                    offset: 0,
                    len: 3
                },
                Token {
                    word: "子".into(),
                    offset: 3,
                    len: 3
                },
                Token {
                    word: "曰".into(),
                    offset: 6,
                    len: 3
                },
                Token {
                    word: "兵".into(),
                    offset: 12,
                    len: 3
                },
                Token {
                    word: "者".into(),
                    offset: 15,
                    len: 3
                },
                Token {
                    word: "國".into(),
                    offset: 21,
                    len: 3
                },
                Token {
                    word: "之".into(),
                    offset: 24,
                    len: 3
                },
                Token {
                    word: "大事".into(),
                    offset: 27,
                    len: 6
                },
                Token {
                    word: "死".into(),
                    offset: 36,
                    len: 3
                },
                Token {
                    word: "生".into(),
                    offset: 39,
                    len: 3
                },
                Token {
                    word: "之".into(),
                    offset: 42,
                    len: 3
                },
                Token {
                    word: "地".into(),
                    offset: 45,
                    len: 3
                },
                Token {
                    word: "存亡".into(),
                    offset: 51,
                    len: 6
                },
                Token {
                    word: "之".into(),
                    offset: 57,
                    len: 3
                },
                Token {
                    word: "道".into(),
                    offset: 60,
                    len: 3
                },
                Token {
                    word: "不可不".into(),
                    offset: 66,
                    len: 9
                },
                Token {
                    word: "察".into(),
                    offset: 75,
                    len: 3
                },
                Token {
                    word: "也".into(),
                    offset: 78,
                    len: 3
                }
            ]
        );
    }
}
