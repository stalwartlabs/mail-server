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

pub mod chinese;
pub mod indo_european;
pub mod japanese;
pub mod word;

use std::borrow::Cow;

use self::{
    chinese::ChineseTokenizer, indo_european::IndoEuropeanTokenizer, japanese::JapaneseTokenizer,
};

use super::Language;

#[derive(Debug, PartialEq, Eq)]
pub struct Token<'x> {
    pub word: Cow<'x, str>,
    pub offset: u32, // Word offset in the text part
    pub len: u8,     // Word length
}

impl<'x> Token<'x> {
    pub fn new(offset: usize, len: usize, word: Cow<'x, str>) -> Token<'x> {
        debug_assert!(offset <= u32::max_value() as usize);
        debug_assert!(len <= u8::max_value() as usize);
        Token {
            offset: offset as u32,
            len: len as u8,
            word,
        }
    }
}

enum LanguageTokenizer<'x> {
    IndoEuropean(IndoEuropeanTokenizer<'x>),
    Japanese(JapaneseTokenizer<'x>),
    Chinese(ChineseTokenizer<'x>),
}

pub struct Tokenizer<'x> {
    tokenizer: LanguageTokenizer<'x>,
}

impl<'x> Tokenizer<'x> {
    pub fn new(text: &'x str, language: Language, max_token_length: usize) -> Self {
        Tokenizer {
            tokenizer: match language {
                Language::Japanese => {
                    LanguageTokenizer::Japanese(JapaneseTokenizer::new(text, max_token_length))
                }
                Language::Mandarin => {
                    LanguageTokenizer::Chinese(ChineseTokenizer::new(text, max_token_length))
                }
                _ => LanguageTokenizer::IndoEuropean(IndoEuropeanTokenizer::new(
                    text,
                    max_token_length,
                )),
            },
        }
    }
}

impl<'x> Iterator for Tokenizer<'x> {
    type Item = Token<'x>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.tokenizer {
            LanguageTokenizer::IndoEuropean(tokenizer) => tokenizer.next(),
            LanguageTokenizer::Chinese(tokenizer) => tokenizer.next(),
            LanguageTokenizer::Japanese(tokenizer) => tokenizer.next(),
        }
    }
}
