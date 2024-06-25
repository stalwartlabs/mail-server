/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, vec::IntoIter};

use jieba_rs::Jieba;

use super::{InnerToken, Token};
use lazy_static::lazy_static;

lazy_static! {
    pub static ref JIEBA: Jieba = Jieba::new();
}

pub struct ChineseTokenizer<'x, T, I>
where
    T: Iterator<Item = Token<I>>,
    I: InnerToken<'x>,
{
    tokenizer: T,
    tokens: IntoIter<Token<I>>,
    phantom: std::marker::PhantomData<&'x str>,
}

impl<'x, T, I> ChineseTokenizer<'x, T, I>
where
    T: Iterator<Item = Token<I>>,
    I: InnerToken<'x>,
{
    pub fn new(tokenizer: T) -> Self {
        ChineseTokenizer {
            tokenizer,
            tokens: Vec::new().into_iter(),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<'x, T, I> Iterator for ChineseTokenizer<'x, T, I>
where
    T: Iterator<Item = Token<I>>,
    I: InnerToken<'x>,
{
    type Item = Token<I>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(token) = self.tokens.next() {
                return Some(token);
            } else {
                let token = self.tokenizer.next()?;
                if token.word.is_alphabetic_8bit() {
                    let mut token_to = token.from;
                    match token.word.unwrap_alphabetic() {
                        Cow::Borrowed(word) => {
                            self.tokens = JIEBA
                                .cut(word, false)
                                .into_iter()
                                .map(|word| {
                                    let token_from = token_to;
                                    token_to += word.len();
                                    Token {
                                        word: I::new_alphabetic(word),
                                        from: token_from,
                                        to: token_to,
                                    }
                                })
                                .collect::<Vec<_>>()
                                .into_iter();
                        }
                        Cow::Owned(word) => {
                            self.tokens = JIEBA
                                .cut(&word, false)
                                .into_iter()
                                .map(|word| {
                                    let token_from = token_to;
                                    token_to += word.len();
                                    Token {
                                        word: I::new_alphabetic(word.to_string()),
                                        from: token_from,
                                        to: token_to,
                                    }
                                })
                                .collect::<Vec<_>>()
                                .into_iter();
                        }
                    }
                } else {
                    return token.into();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tokenizers::{chinese::ChineseTokenizer, word::WordTokenizer, Token};

    #[test]
    fn chinese_tokenizer() {
        assert_eq!(
            ChineseTokenizer::new(WordTokenizer::new(
                "孫子曰：兵者，國之大事，死生之地，存亡之道，不可不察也。",
                40
            ),)
            .collect::<Vec<_>>(),
            vec![
                Token {
                    word: "孫".into(),
                    from: 0,
                    to: 3
                },
                Token {
                    word: "子".into(),
                    from: 3,
                    to: 6
                },
                Token {
                    word: "曰".into(),
                    from: 6,
                    to: 9
                },
                Token {
                    word: "兵".into(),
                    from: 12,
                    to: 15
                },
                Token {
                    word: "者".into(),
                    from: 15,
                    to: 18
                },
                Token {
                    word: "國".into(),
                    from: 21,
                    to: 24
                },
                Token {
                    word: "之".into(),
                    from: 24,
                    to: 27
                },
                Token {
                    word: "大事".into(),
                    from: 27,
                    to: 33
                },
                Token {
                    word: "死".into(),
                    from: 36,
                    to: 39
                },
                Token {
                    word: "生".into(),
                    from: 39,
                    to: 42
                },
                Token {
                    word: "之".into(),
                    from: 42,
                    to: 45
                },
                Token {
                    word: "地".into(),
                    from: 45,
                    to: 48
                },
                Token {
                    word: "存亡".into(),
                    from: 51,
                    to: 57
                },
                Token {
                    word: "之".into(),
                    from: 57,
                    to: 60
                },
                Token {
                    word: "道".into(),
                    from: 60,
                    to: 63
                },
                Token {
                    word: "不可不".into(),
                    from: 66,
                    to: 75
                },
                Token {
                    word: "察".into(),
                    from: 75,
                    to: 78
                },
                Token {
                    word: "也".into(),
                    from: 78,
                    to: 81
                }
            ]
        );
    }
}
