/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, str::CharIndices};

use super::Token;

pub struct WordTokenizer<'x> {
    max_token_length: usize,
    text: &'x str,
    iterator: CharIndices<'x>,
}

impl<'x> WordTokenizer<'x> {
    pub fn new(text: &str, max_token_length: usize) -> WordTokenizer {
        WordTokenizer {
            max_token_length,
            text,
            iterator: text.char_indices(),
        }
    }
}

/// Parses indo-european text into lowercase tokens.
impl<'x> Iterator for WordTokenizer<'x> {
    type Item = Token<Cow<'x, str>>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((token_start, ch)) = self.iterator.next() {
            if ch.is_alphanumeric() {
                let mut is_uppercase = ch.is_uppercase();
                let token_end = (&mut self.iterator)
                    .filter_map(|(pos, ch)| {
                        if ch.is_alphanumeric() {
                            if !is_uppercase && ch.is_uppercase() {
                                is_uppercase = true;
                            }
                            None
                        } else {
                            pos.into()
                        }
                    })
                    .next()
                    .unwrap_or(self.text.len());

                let token_len = token_end - token_start;
                if token_end > token_start && token_len <= self.max_token_length {
                    return Token::new(
                        token_start,
                        token_len,
                        if is_uppercase {
                            self.text[token_start..token_end].to_lowercase().into()
                        } else {
                            self.text[token_start..token_end].into()
                        },
                    )
                    .into();
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indo_european_tokenizer() {
        let inputs = [
            (
                "The quick brown fox jumps over the lazy dog",
                vec![
                    Token::new(0, 3, "the".into()),
                    Token::new(4, 5, "quick".into()),
                    Token::new(10, 5, "brown".into()),
                    Token::new(16, 3, "fox".into()),
                    Token::new(20, 5, "jumps".into()),
                    Token::new(26, 4, "over".into()),
                    Token::new(31, 3, "the".into()),
                    Token::new(35, 4, "lazy".into()),
                    Token::new(40, 3, "dog".into()),
                ],
            ),
            (
                "Jovencillo EMPONZOÑADO de whisky: ¡qué figurota exhibe!",
                vec![
                    Token::new(0, 10, "jovencillo".into()),
                    Token::new(11, 12, "emponzoñado".into()),
                    Token::new(24, 2, "de".into()),
                    Token::new(27, 6, "whisky".into()),
                    Token::new(37, 4, "qué".into()),
                    Token::new(42, 8, "figurota".into()),
                    Token::new(51, 6, "exhibe".into()),
                ],
            ),
            (
                "ZWÖLF Boxkämpfer jagten Victor quer über den großen Sylter Deich",
                vec![
                    Token::new(0, 6, "zwölf".into()),
                    Token::new(7, 11, "boxkämpfer".into()),
                    Token::new(19, 6, "jagten".into()),
                    Token::new(26, 6, "victor".into()),
                    Token::new(33, 4, "quer".into()),
                    Token::new(38, 5, "über".into()),
                    Token::new(44, 3, "den".into()),
                    Token::new(48, 7, "großen".into()),
                    Token::new(56, 6, "sylter".into()),
                    Token::new(63, 5, "deich".into()),
                ],
            ),
            (
                "Съешь ещё этих мягких французских булок, да выпей же чаю",
                vec![
                    Token::new(0, 10, "съешь".into()),
                    Token::new(11, 6, "ещё".into()),
                    Token::new(18, 8, "этих".into()),
                    Token::new(27, 12, "мягких".into()),
                    Token::new(40, 22, "французских".into()),
                    Token::new(63, 10, "булок".into()),
                    Token::new(75, 4, "да".into()),
                    Token::new(80, 10, "выпей".into()),
                    Token::new(91, 4, "же".into()),
                    Token::new(96, 6, "чаю".into()),
                ],
            ),
            (
                "Pijamalı hasta yağız şoföre çabucak güvendi",
                vec![
                    Token::new(0, 9, "pijamalı".into()),
                    Token::new(10, 5, "hasta".into()),
                    Token::new(16, 7, "yağız".into()),
                    Token::new(24, 8, "şoföre".into()),
                    Token::new(33, 8, "çabucak".into()),
                    Token::new(42, 8, "güvendi".into()),
                ],
            ),
        ];

        for (input, tokens) in inputs.iter() {
            for (pos, token) in WordTokenizer::new(input, 40).enumerate() {
                assert_eq!(token, tokens[pos]);
            }
        }
    }
}
