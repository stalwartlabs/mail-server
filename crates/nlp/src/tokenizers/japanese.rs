/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::vec::IntoIter;

use super::{InnerToken, Token};

pub struct JapaneseTokenizer<'x, T, I>
where
    T: Iterator<Item = Token<I>>,
    I: InnerToken<'x>,
{
    tokenizer: T,
    tokens: IntoIter<Token<I>>,
    phantom: std::marker::PhantomData<&'x str>,
}

impl<'x, T, I> JapaneseTokenizer<'x, T, I>
where
    T: Iterator<Item = Token<I>>,
    I: InnerToken<'x>,
{
    pub fn new(tokenizer: T) -> Self {
        JapaneseTokenizer {
            tokenizer,
            tokens: Vec::new().into_iter(),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<'x, T, I> Iterator for JapaneseTokenizer<'x, T, I>
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
                    self.tokens = tinysegmenter::tokenize(token.word.unwrap_alphabetic().as_ref())
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
                } else {
                    return token.into();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tokenizers::{japanese::JapaneseTokenizer, word::WordTokenizer, Token};

    #[test]
    fn japanese_tokenizer() {
        assert_eq!(
            JapaneseTokenizer::new(WordTokenizer::new(
                "お先に失礼します あなたの名前は何ですか 123 abc-872",
                40
            ))
            .collect::<Vec<_>>(),
            vec![
                Token {
                    word: "お先".into(),
                    from: 0,
                    to: 6
                },
                Token {
                    word: "に".into(),
                    from: 6,
                    to: 9
                },
                Token {
                    word: "失礼".into(),
                    from: 9,
                    to: 15
                },
                Token {
                    word: "し".into(),
                    from: 15,
                    to: 18
                },
                Token {
                    word: "ます".into(),
                    from: 18,
                    to: 24
                },
                Token {
                    word: "あなた".into(),
                    from: 25,
                    to: 34
                },
                Token {
                    word: "の".into(),
                    from: 34,
                    to: 37
                },
                Token {
                    word: "名前".into(),
                    from: 37,
                    to: 43
                },
                Token {
                    word: "は".into(),
                    from: 43,
                    to: 46
                },
                Token {
                    word: "何".into(),
                    from: 46,
                    to: 49
                },
                Token {
                    word: "です".into(),
                    from: 49,
                    to: 55
                },
                Token {
                    word: "か".into(),
                    from: 55,
                    to: 58
                },
                Token {
                    word: "123".into(),
                    from: 59,
                    to: 62
                },
                Token {
                    word: "abc".into(),
                    from: 63,
                    to: 66
                },
                Token {
                    word: "872".into(),
                    from: 67,
                    to: 70
                }
            ]
        );
    }
}
