/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
