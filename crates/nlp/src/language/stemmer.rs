/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use rust_stemmers::Algorithm;

use super::{Language, LanguageTokenizer};

#[derive(Debug, PartialEq, Eq)]
pub struct StemmedToken<'x> {
    pub word: Cow<'x, str>,
    pub stemmed_word: Option<Cow<'x, str>>,
    pub from: usize, // Word offset in the text part
    pub to: usize,   // Word length
}

pub struct Stemmer<'x> {
    stemmer: Option<rust_stemmers::Stemmer>,
    tokenizer: LanguageTokenizer<'x>,
}

impl<'x> Stemmer<'x> {
    pub fn new(text: &'x str, language: Language, max_token_length: usize) -> Stemmer<'x> {
        Stemmer {
            tokenizer: language.tokenize_text(text, max_token_length),
            stemmer: STEMMER_MAP[language as usize].map(rust_stemmers::Stemmer::create),
        }
    }
}

impl<'x> Iterator for Stemmer<'x> {
    type Item = StemmedToken<'x>;

    fn next(&mut self) -> Option<Self::Item> {
        let token = self.tokenizer.next()?;
        Some(StemmedToken {
            stemmed_word: self.stemmer.as_ref().and_then(|stemmer| {
                match stemmer.stem(&token.word) {
                    Cow::Owned(text) if text.len() != token.word.len() || text != token.word => {
                        Some(text.into())
                    }
                    _ => None,
                }
            }),
            word: token.word,
            from: token.from,
            to: token.to,
        })
    }
}

pub static STEMMER_MAP: &[Option<Algorithm>] = &[
    None,                        // Esperanto = 0,
    Some(Algorithm::English),    // English = 1,
    Some(Algorithm::Russian),    // Russian = 2,
    None,                        // Mandarin = 3,
    Some(Algorithm::Spanish),    // Spanish = 4,
    Some(Algorithm::Portuguese), // Portuguese = 5,
    Some(Algorithm::Italian),    // Italian = 6,
    None,                        // Bengali = 7,
    Some(Algorithm::French),     // French = 8,
    Some(Algorithm::German),     // German = 9,
    None,                        // Ukrainian = 10,
    None,                        // Georgian = 11,
    Some(Algorithm::Arabic),     // Arabic = 12,
    None,                        // Hindi = 13,
    None,                        // Japanese = 14,
    None,                        // Hebrew = 15,
    None,                        // Yiddish = 16,
    None,                        // Polish = 17,
    None,                        // Amharic = 18,
    None,                        // Javanese = 19,
    None,                        // Korean = 20,
    Some(Algorithm::Norwegian),  // Bokmal = 21,
    Some(Algorithm::Danish),     // Danish = 22,
    Some(Algorithm::Swedish),    // Swedish = 23,
    Some(Algorithm::Finnish),    // Finnish = 24,
    Some(Algorithm::Turkish),    // Turkish = 25,
    Some(Algorithm::Dutch),      // Dutch = 26,
    Some(Algorithm::Hungarian),  // Hungarian = 27,
    None,                        // Czech = 28,
    Some(Algorithm::Greek),      // Greek = 29,
    None,                        // Bulgarian = 30,
    None,                        // Belarusian = 31,
    None,                        // Marathi = 32,
    None,                        // Kannada = 33,
    Some(Algorithm::Romanian),   // Romanian = 34,
    None,                        // Slovene = 35,
    None,                        // Croatian = 36,
    None,                        // Serbian = 37,
    None,                        // Macedonian = 38,
    None,                        // Lithuanian = 39,
    None,                        // Latvian = 40,
    None,                        // Estonian = 41,
    Some(Algorithm::Tamil),      // Tamil = 42,
    None,                        // Vietnamese = 43,
    None,                        // Urdu = 44,
    None,                        // Thai = 45,
    None,                        // Gujarati = 46,
    None,                        // Uzbek = 47,
    None,                        // Punjabi = 48,
    None,                        // Azerbaijani = 49,
    None,                        // Indonesian = 50,
    None,                        // Telugu = 51,
    None,                        // Persian = 52,
    None,                        // Malayalam = 53,
    None,                        // Oriya = 54,
    None,                        // Burmese = 55,
    None,                        // Nepali = 56,
    None,                        // Sinhalese = 57,
    None,                        // Khmer = 58,
    None,                        // Turkmen = 59,
    None,                        // Akan = 60,
    None,                        // Zulu = 61,
    None,                        // Shona = 62,
    None,                        // Afrikaans = 63,
    None,                        // Latin = 64,
    None,                        // Slovak = 65,
    None,                        // Catalan = 66,
    None,                        // Tagalog = 67,
    None,                        // Armenian = 68,
    None,                        // Unknown = 69,
    None,                        // None = 70,
];

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn stemmer() {
        let inputs = [
            (
                "love loving lovingly loved lovely",
                Language::English,
                "love",
            ),
            ("querer queremos quer", Language::Spanish, "quer"),
        ];

        for (input, language, result) in inputs {
            for token in Stemmer::new(input, language, 40) {
                assert_eq!(token.stemmed_word.unwrap_or(token.word), result);
            }
        }
    }
}
