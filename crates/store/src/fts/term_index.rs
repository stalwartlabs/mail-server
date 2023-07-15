/*
 * Copyright (c) 2023, Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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

use std::convert::TryInto;

use crate::{Deserialize, Serialize};

use super::{stemmer::StemmedToken, tokenizers::Token};

use ahash::{AHashMap, AHashSet};
use bitpacking::{BitPacker, BitPacker1x, BitPacker4x, BitPacker8x};
use utils::codec::leb128::{Leb128Reader, Leb128Vec};

#[derive(Debug)]
pub enum Error {
    DataCorruption,
    Leb128DecodeError,
    BitpackDecodeError,
    InvalidArgument,
}

pub type TermId = u32;
pub type Result<T> = std::result::Result<T, Error>;

const LENGTH_SIZE: usize = std::mem::size_of::<u32>();

#[derive(Debug, PartialEq, Eq)]
pub struct Term {
    pub id: TermId,
    pub id_stemmed: TermId,
    pub offset: u32,
    pub len: u8,
}

#[derive(Debug)]
pub struct TermGroup {
    pub field_id: u8,
    pub part_id: u32,
    pub terms: Vec<Term>,
}

#[derive(Debug)]
pub struct TermIndexBuilderItem {
    field: u8,
    part_id: u32,
    terms: Vec<Term>,
}

#[derive(Debug)]
pub struct TermIndexBuilder {
    terms: AHashMap<String, u32>,
    items: Vec<TermIndexBuilderItem>,
}

#[derive(Debug)]
pub struct TermIndexItem {
    pub field_id: u8,
    pub part_id: u32,
    pub terms_len: usize,
    pub terms: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct TermIndex {
    pub token_map: AHashMap<String, u32>,
    pub items: Vec<TermIndexItem>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct MatchTerm {
    pub id: TermId,
    pub id_stemmed: TermId,
}

#[derive(Clone, Copy)]
struct TermIndexPacker {
    bitpacker_1: BitPacker1x,
    bitpacker_4: BitPacker4x,
    bitpacker_8: BitPacker8x,
    block_len: usize,
}

impl TermIndexPacker {
    pub fn with_block_len(block_len: usize) -> Self {
        TermIndexPacker {
            bitpacker_1: BitPacker1x::new(),
            bitpacker_4: BitPacker4x::new(),
            bitpacker_8: BitPacker8x::new(),
            block_len,
        }
    }

    pub fn block_len(&mut self, num: usize) {
        self.block_len = num;
    }
}

impl BitPacker for TermIndexPacker {
    const BLOCK_LEN: usize = 0;

    fn new() -> Self {
        TermIndexPacker {
            bitpacker_1: BitPacker1x::new(),
            bitpacker_4: BitPacker4x::new(),
            bitpacker_8: BitPacker8x::new(),
            block_len: 1,
        }
    }

    fn compress(&self, decompressed: &[u32], compressed: &mut [u8], num_bits: u8) -> usize {
        match self.block_len {
            BitPacker8x::BLOCK_LEN => self
                .bitpacker_8
                .compress(decompressed, compressed, num_bits),
            BitPacker4x::BLOCK_LEN => self
                .bitpacker_4
                .compress(decompressed, compressed, num_bits),
            _ => self
                .bitpacker_1
                .compress(decompressed, compressed, num_bits),
        }
    }

    fn compress_sorted(
        &self,
        initial: u32,
        decompressed: &[u32],
        compressed: &mut [u8],
        num_bits: u8,
    ) -> usize {
        match self.block_len {
            BitPacker8x::BLOCK_LEN => {
                self.bitpacker_8
                    .compress_sorted(initial, decompressed, compressed, num_bits)
            }
            BitPacker4x::BLOCK_LEN => {
                self.bitpacker_4
                    .compress_sorted(initial, decompressed, compressed, num_bits)
            }
            _ => self
                .bitpacker_1
                .compress_sorted(initial, decompressed, compressed, num_bits),
        }
    }

    fn decompress(&self, compressed: &[u8], decompressed: &mut [u32], num_bits: u8) -> usize {
        match self.block_len {
            BitPacker8x::BLOCK_LEN => {
                self.bitpacker_8
                    .decompress(compressed, decompressed, num_bits)
            }
            BitPacker4x::BLOCK_LEN => {
                self.bitpacker_4
                    .decompress(compressed, decompressed, num_bits)
            }
            _ => self
                .bitpacker_1
                .decompress(compressed, decompressed, num_bits),
        }
    }

    fn decompress_sorted(
        &self,
        initial: u32,
        compressed: &[u8],
        decompressed: &mut [u32],
        num_bits: u8,
    ) -> usize {
        match self.block_len {
            BitPacker8x::BLOCK_LEN => {
                self.bitpacker_8
                    .decompress_sorted(initial, compressed, decompressed, num_bits)
            }
            BitPacker4x::BLOCK_LEN => {
                self.bitpacker_4
                    .decompress_sorted(initial, compressed, decompressed, num_bits)
            }
            _ => self
                .bitpacker_1
                .decompress_sorted(initial, compressed, decompressed, num_bits),
        }
    }

    fn num_bits(&self, decompressed: &[u32]) -> u8 {
        match self.block_len {
            BitPacker8x::BLOCK_LEN => self.bitpacker_8.num_bits(decompressed),
            BitPacker4x::BLOCK_LEN => self.bitpacker_4.num_bits(decompressed),
            _ => self.bitpacker_1.num_bits(decompressed),
        }
    }

    fn num_bits_sorted(&self, initial: u32, decompressed: &[u32]) -> u8 {
        match self.block_len {
            BitPacker8x::BLOCK_LEN => self.bitpacker_8.num_bits_sorted(initial, decompressed),
            BitPacker4x::BLOCK_LEN => self.bitpacker_4.num_bits_sorted(initial, decompressed),
            _ => self.bitpacker_1.num_bits_sorted(initial, decompressed),
        }
    }
}

#[allow(clippy::new_without_default)]
impl TermIndexBuilder {
    pub fn new() -> TermIndexBuilder {
        TermIndexBuilder {
            items: Vec::new(),
            terms: AHashMap::default(),
        }
    }

    pub fn add_token(&mut self, token: Token) -> Term {
        let id = self.terms.len() as u32;
        let id = self
            .terms
            .entry(token.word.into_owned())
            .or_insert_with(|| id);
        Term {
            id: *id,
            id_stemmed: *id,
            offset: token.offset,
            len: token.len,
        }
    }

    pub fn add_stemmed_token(&mut self, token: StemmedToken) -> Term {
        let id = self.terms.len() as u32;
        let id = *self
            .terms
            .entry(token.word.into_owned())
            .or_insert_with(|| id);
        let id_stemmed = if let Some(stemmed_word) = token.stemmed_word {
            let id_stemmed = self.terms.len() as u32;
            *self
                .terms
                .entry(stemmed_word.into_owned())
                .or_insert_with(|| id_stemmed)
        } else {
            id
        };
        Term {
            id,
            id_stemmed,
            offset: token.offset,
            len: token.len,
        }
    }

    pub fn add_terms(&mut self, field: u8, part_id: u32, terms: Vec<Term>) {
        self.items.push(TermIndexBuilderItem {
            field,
            part_id,
            terms,
        });
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl Serialize for TermIndexBuilder {
    fn serialize(self) -> Vec<u8> {
        // Add tokens
        if self.terms.is_empty() {
            return Vec::new();
        }
        let mut terms = vec![""; self.terms.len()];
        let mut terms_len = 0;
        for (word, id) in &self.terms {
            terms[*id as usize] = word;
            terms_len += word.len() + 1;
        }

        // Serialize tokens
        let mut bytes = Vec::with_capacity(
            terms_len + ((self.items.len() / self.terms.len()) * std::mem::size_of::<u64>() * 2),
        );
        bytes.push_leb128(self.terms.len());
        for terms in terms {
            bytes.extend_from_slice(terms.as_bytes());
            bytes.push(0);
        }

        // Write terms
        let mut bitpacker = TermIndexPacker::new();
        let mut compressed = vec![0u8; 4 * BitPacker8x::BLOCK_LEN];

        for term_index in &self.items {
            let mut ids = Vec::with_capacity(term_index.terms.len() * 2);
            let mut offsets = Vec::with_capacity(term_index.terms.len());
            let mut lengths = Vec::with_capacity(term_index.terms.len());

            let header_pos = bytes.len();
            bytes.extend_from_slice(&[0u8; LENGTH_SIZE]);
            bytes.push(term_index.field);
            bytes.push_leb128(term_index.part_id);
            bytes.push_leb128(term_index.terms.len());

            let terms_pos = bytes.len();

            for term in &term_index.terms {
                ids.push(term.id);
                ids.push(term.id_stemmed);
                offsets.push(term.offset);
                lengths.push(term.len);
            }

            for (chunk, is_sorted) in [(ids, false), (offsets, true)] {
                let mut pos = 0;
                let len = chunk.len();
                let mut initial_value = 0;

                while pos < len {
                    let block_len = match len - pos {
                        0..=31 => 0,
                        32..=127 => BitPacker1x::BLOCK_LEN,
                        128..=255 => BitPacker4x::BLOCK_LEN,
                        _ => BitPacker8x::BLOCK_LEN,
                    };

                    if block_len > 0 {
                        let chunk = &chunk[pos..pos + block_len];
                        bitpacker.block_len(block_len);
                        if is_sorted {
                            let num_bits: u8 = bitpacker.num_bits_sorted(initial_value, chunk);
                            let compressed_len = bitpacker.compress_sorted(
                                initial_value,
                                chunk,
                                &mut compressed[..],
                                num_bits,
                            );
                            bytes.push(num_bits);
                            bytes.extend_from_slice(&compressed[..compressed_len]);
                            initial_value = chunk[chunk.len() - 1];
                        } else {
                            let num_bits: u8 = bitpacker.num_bits(chunk);
                            let compressed_len =
                                bitpacker.compress(chunk, &mut compressed[..], num_bits);
                            bytes.push(num_bits);
                            bytes.extend_from_slice(&compressed[..compressed_len]);
                        }

                        pos += block_len;
                    } else {
                        for val in &chunk[pos..] {
                            bytes.push_leb128(*val);
                        }
                        pos = len;
                    }
                }
            }
            bytes.append(&mut lengths);

            let len = (bytes.len() - terms_pos) as u32;
            bytes[header_pos..header_pos + LENGTH_SIZE].copy_from_slice(&len.to_le_bytes());
        }

        bytes
    }
}

impl Deserialize for TermIndex {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        TermIndex::from_bytes(bytes).ok_or_else(|| {
            crate::Error::InternalError("Failed to deserialize term index".to_string())
        })
    }
}

impl TermIndex {
    pub fn get_match_term(&self, word: &str, stemmed_word: Option<&str>) -> MatchTerm {
        let id = self.token_map.get(word).copied().unwrap_or(u32::MAX);
        let id_stemmed = stemmed_word
            .and_then(|word| self.token_map.get(word))
            .copied()
            .unwrap_or(id);

        MatchTerm { id, id_stemmed }
    }

    fn skip_items(&self, bytes: &[u8], mut remaining_items: usize) -> Result<usize> {
        let mut pos = 0;
        while remaining_items > 0 {
            let block_len = match remaining_items {
                0..=31 => 0,
                32..=127 => BitPacker1x::BLOCK_LEN,
                128..=255 => BitPacker4x::BLOCK_LEN,
                _ => BitPacker8x::BLOCK_LEN,
            };

            if block_len > 0 {
                pos +=
                    ((*bytes.get(pos).ok_or(Error::DataCorruption)? as usize) * block_len / 8) + 1;
                remaining_items -= block_len;
            } else {
                while remaining_items > 0 {
                    let bytes_read = bytes
                        .get(pos..)
                        .ok_or(Error::DataCorruption)?
                        .skip_leb128()
                        .ok_or(Error::Leb128DecodeError)?;

                    pos += bytes_read;
                    remaining_items -= 1;
                }
            }
        }
        Ok(pos)
    }

    fn uncompress_chunk(
        bytes: &[u8],
        remaining_items: usize,
        initial_value: Option<u32>,
    ) -> Result<(usize, Vec<u32>)> {
        let block_len = match remaining_items {
            0..=31 => 0,
            32..=127 => BitPacker1x::BLOCK_LEN,
            128..=255 => BitPacker4x::BLOCK_LEN,
            _ => BitPacker8x::BLOCK_LEN,
        };

        if block_len > 0 {
            let bitpacker = TermIndexPacker::with_block_len(block_len);
            let num_bits = *bytes.first().ok_or(Error::DataCorruption)?;
            let bytes_read = ((num_bits as usize) * block_len / 8) + 1;
            let mut decompressed = vec![0u32; block_len];

            if let Some(initial_value) = initial_value {
                bitpacker.decompress_sorted(
                    initial_value,
                    bytes.get(1..bytes_read).ok_or(Error::DataCorruption)?,
                    &mut decompressed[..],
                    num_bits,
                );
            } else {
                bitpacker.decompress(
                    bytes.get(1..bytes_read).ok_or(Error::DataCorruption)?,
                    &mut decompressed[..],
                    num_bits,
                );
            }

            Ok((bytes_read, decompressed))
        } else {
            let mut decompressed = Vec::with_capacity(remaining_items);
            let mut pos = 0;
            while decompressed.len() < remaining_items {
                let (val, bytes_read) = bytes
                    .get(pos..)
                    .ok_or(Error::DataCorruption)?
                    .read_leb128()
                    .ok_or(Error::Leb128DecodeError)?;
                decompressed.push(val);
                pos += bytes_read;
            }
            Ok((pos, decompressed))
        }
    }

    pub fn match_terms(
        &self,
        match_terms: &[MatchTerm],
        match_field: Option<u8>,
        match_phrase: bool,
        match_many: bool,
        include_offsets: bool,
    ) -> Result<Option<Vec<TermGroup>>> {
        let mut result = Vec::new();

        // Safety check to avoid overflowing the bit mask
        if !match_phrase && !(1..=64).contains(&match_terms.len()) {
            return Err(Error::InvalidArgument);
        }

        // Term matching is done using a bit mask, where each bit represents a word.
        // Each time a word is matched, the corresponding bit is cleared.
        // When all bits are cleared, all matching terms are added to the result list.
        let words_mask: u64 = u64::MAX >> (64 - match_terms.len());
        let mut matched_mask = words_mask;

        for item in &self.items {
            if match_field.map_or(false, |match_field| match_field != item.field_id) {
                continue;
            }

            let mut terms = Vec::new();
            let mut partial_match = Vec::new();

            let mut term_pos = 0;
            let mut byte_pos = 0;

            'term_loop: while term_pos < item.terms_len {
                let (bytes_read, chunk) = TermIndex::uncompress_chunk(
                    item.terms.get(byte_pos..).ok_or(Error::DataCorruption)?,
                    (item.terms_len * 2) - (term_pos * 2),
                    None,
                )?;

                byte_pos += bytes_read;

                for encoded_term in chunk.chunks_exact(2) {
                    let term_id = encoded_term[0];
                    let term_id_stemmed = encoded_term[1];

                    if match_phrase {
                        let match_pos = partial_match.len();
                        if match_terms[match_pos].id == term_id {
                            partial_match.push(Term {
                                id: term_id,
                                id_stemmed: term_id_stemmed,
                                offset: term_pos as u32,
                                len: 0,
                            });
                            if partial_match.len() == match_terms.len() {
                                terms.append(&mut partial_match);
                                if !match_many {
                                    break 'term_loop;
                                }
                            }
                        } else if match_pos > 0 {
                            partial_match.clear();
                        }
                    } else {
                        'match_loop: for (match_pos, match_term) in match_terms.iter().enumerate() {
                            if match_term.id == term_id
                                || match_term.id == term_id_stemmed
                                || ((match_term.id_stemmed != match_term.id)
                                    && (match_term.id_stemmed == term_id
                                        || match_term.id_stemmed == term_id_stemmed))
                            {
                                partial_match.push(Term {
                                    id: term_id,
                                    id_stemmed: term_id_stemmed,
                                    offset: term_pos as u32,
                                    len: 0,
                                });

                                // Clear the bit corresponding to the matched term
                                matched_mask &= !(1 << match_pos);
                                break 'match_loop;
                            }
                        }

                        if !match_many && matched_mask == 0 {
                            break 'term_loop;
                        }
                    }
                    term_pos += 1;
                }
            }

            if !match_phrase && !partial_match.is_empty() {
                terms.append(&mut partial_match);
            }

            if !terms.is_empty() {
                if include_offsets {
                    // Skip any term ids that were not uncompressed
                    if term_pos < item.terms_len {
                        byte_pos += self.skip_items(
                            item.terms.get(byte_pos..).ok_or(Error::DataCorruption)?,
                            (item.terms_len - term_pos) * 2,
                        )?;
                    }

                    // Uncompress offsets
                    let mut term_it = terms.iter_mut();
                    let mut term = term_it.next().unwrap();
                    let mut initial_value = 0;
                    term_pos = 0;

                    'outer: while term_pos < item.terms_len {
                        let (bytes_read, chunk) = TermIndex::uncompress_chunk(
                            item.terms.get(byte_pos..).ok_or(Error::DataCorruption)?,
                            item.terms_len - term_pos,
                            Some(initial_value),
                        )?;

                        initial_value = chunk[chunk.len() - 1];
                        byte_pos += bytes_read;

                        for offset in chunk.into_iter() {
                            if term.offset == term_pos as u32 {
                                term.len = *item
                                    .terms
                                    .get(item.terms.len() - item.terms_len + term.offset as usize)
                                    .ok_or(Error::DataCorruption)?;
                                term.offset = offset;
                                if let Some(next_term) = term_it.next() {
                                    term = next_term;
                                } else {
                                    break 'outer;
                                }
                            }
                            term_pos += 1;
                        }
                    }
                }

                result.push(TermGroup {
                    field_id: item.field_id,
                    part_id: item.part_id,
                    terms,
                });

                if !match_many {
                    break;
                }
            }
        }

        Ok(if !result.is_empty() {
            Some(result)
        } else {
            None
        })
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (num_tokens, mut pos) = bytes.read_leb128()?;
        let mut token_map = AHashMap::with_capacity(num_tokens as usize);
        for term_id in 0..num_tokens {
            let nil_pos = bytes.get(pos..)?.iter().position(|b| b == &0)?;
            token_map.insert(
                String::from_utf8(bytes.get(pos..pos + nil_pos)?.to_vec()).ok()?,
                term_id,
            );
            pos += nil_pos + 1;
        }

        let mut term_index = TermIndex {
            items: Vec::new(),
            token_map,
        };

        while pos < bytes.len() {
            let item_len =
                u32::from_le_bytes(bytes.get(pos..pos + LENGTH_SIZE)?.try_into().ok()?) as usize;
            pos += LENGTH_SIZE;

            let field = bytes.get(pos)?;
            pos += 1;

            let (part_id, bytes_read) = bytes.get(pos..)?.read_leb128()?;
            pos += bytes_read;

            let (terms_len, bytes_read) = bytes.get(pos..)?.read_leb128()?;
            pos += bytes_read;

            term_index.items.push(TermIndexItem {
                field_id: *field,
                part_id,
                terms_len,
                terms: bytes.get(pos..pos + item_len)?.to_vec(),
            });

            pos += item_len;
        }

        Some(term_index)
    }
}

#[derive(Default)]
pub struct Terms {
    pub field_id: u8,
    pub exact_terms: AHashSet<TermId>,
    pub stemmed_terms: AHashSet<TermId>,
}

pub struct TokenIndex {
    pub tokens: Vec<String>,
    pub terms: Vec<Terms>,
}

impl Deserialize for TokenIndex {
    fn deserialize(bytes: &[u8]) -> crate::Result<Self> {
        Self::from_bytes(bytes).ok_or_else(|| {
            crate::Error::InternalError("Failed to deserialize token index.".to_string())
        })
    }
}

impl TokenIndex {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if !bytes.is_empty() {
            let (num_tokens, mut pos) = bytes.read_leb128::<u32>()?;
            let mut tokens = Vec::with_capacity(num_tokens as usize);
            for _ in 0..num_tokens {
                let nil_pos = bytes.get(pos..)?.iter().position(|b| b == &0)?;
                tokens.push(String::from_utf8(bytes.get(pos..pos + nil_pos)?.to_vec()).ok()?);
                pos += nil_pos + 1;
            }

            let mut terms = Vec::new();
            while pos < bytes.len() {
                let item_len =
                    u32::from_le_bytes(bytes.get(pos..pos + LENGTH_SIZE)?.try_into().ok()?)
                        as usize;
                pos += LENGTH_SIZE;

                let mut field_terms = Terms {
                    field_id: *bytes.get(pos)?,
                    exact_terms: AHashSet::default(),
                    stemmed_terms: AHashSet::default(),
                };
                pos += 1;

                let bytes_read = bytes.get(pos..)?.skip_leb128()?;
                pos += bytes_read;

                let (terms_len, bytes_read) = bytes.get(pos..)?.read_leb128::<usize>()?;
                pos += bytes_read;

                let mut term_pos = 0;
                let mut byte_pos = pos;

                while term_pos < terms_len {
                    let (bytes_read, chunk) = TermIndex::uncompress_chunk(
                        bytes.get(byte_pos..)?,
                        (terms_len - term_pos) * 2,
                        None,
                    )
                    .ok()?;

                    byte_pos += bytes_read;

                    for encoded_term in chunk.chunks_exact(2) {
                        let term_id = encoded_term[0];
                        let term_id_stemmed = encoded_term[1];

                        field_terms.exact_terms.insert(term_id);
                        if term_id != term_id_stemmed {
                            field_terms.stemmed_terms.insert(term_id_stemmed);
                        }
                        term_pos += 1;
                    }
                }

                terms.push(field_terms);
                pos += item_len;
            }

            Some(TokenIndex { tokens, terms })
        } else {
            Some(TokenIndex {
                tokens: Vec::new(),
                terms: Vec::new(),
            })
        }
    }
}

#[cfg(test)]
mod tests {

    use ahash::AHashMap;

    use crate::{
        fts::{
            stemmer::Stemmer,
            term_index::{TermIndexBuilder, TokenIndex},
            Language,
        },
        Deserialize, Serialize,
    };

    use super::TermIndex;

    #[test]
    #[allow(clippy::bind_instead_of_map)]
    fn term_index() {
        const SUBJECT: u8 = 1;
        const BODY: u8 = 2;
        const ATTACHMENT: u8 = 3;

        let parts = [
            (
                r#"I felt happy because I saw the others were happy
            and because I knew I should feel happy, but I wasn’t
            really happy."#,
                SUBJECT,
            ),
            (
                r#"But good morning! Good morning to ye and thou! I’d
            say to all my patients, because I was the worse of the
            hypocrites, of all the hypocrites, the cruel and phony
            hypocrites, I was the very worst."#,
                BODY,
            ),
            (
                r#"So I said yes to Thomas Clinton and later thought
            that I had said yes to God and later still realized I
            had said yes only to Thomas Clinton."#,
                BODY,
            ),
            (
                r#"Even if they are djinns, I will get djinns that
            can outdjinn them."#,
                BODY,
            ),
            (
                r#"Hatred was spreading everywhere, blood was being
             spilled everywhere, wars were breaking out
             everywhere."#,
                BODY,
            ),
            (
                r#"Almost nothing was more annoying than having
            our wasted time wasted on something not worth
            wasting it on."#,
                BODY,
            ),
            (
                r#"The depressed person was in terrible and unceasing
            emotional pain, and the impossibility of sharing or
            articulating this pain was itself a component of the
            pain and a contributing factor in its essential horror."#,
                BODY,
            ),
            (
                r#"Paranoids are not paranoid because they’re paranoid,
            but because they keep putting themselves, darn idiots,
            deliberately into paranoid situations."#,
                BODY,
            ),
            (
                r#"Because the world is a place of silence, the sky at
            night when the birds have gone is a vast silent place."#,
                BODY,
            ),
            (
                r#"There are some things that are so unforgivable that
            they make other things easily forgivable."#,
                BODY,
            ),
            (
                r#"I had known loneliness before, and emptiness upon the
            moor, but I had never been a NOTHING, a nothing floating
            on a nothing, known by nothing, lonelier and colder than
            the space between the stars."#,
                ATTACHMENT,
            ),
            (
                r#"You’re an insomniac, you tell yourself: there are
            profound truths revealed only to the insomniac by night
            like those phosphorescent minerals veined and glimmering
            in the dark but coarse and ordinary otherwise; you have
            to examine such minerals in the absence of light to
            discover their beauty, you tell yourself."#,
                ATTACHMENT,
            ),
            (
                r#"Every person had a star, every star had a friend,
            and for every person carrying a star there was someone
            else who reflected it, and everyone carried this reflection
            like a secret confidante in the heart."#,
                ATTACHMENT,
            ),
            (
                r#"As my grandfather went, arm over arm, his heart making
            sour little shudders against his ribs, he kept listening
            for a sound, the sound of the tiger, the sound of anything
            but his own feet and lungs."#,
                ATTACHMENT,
            ),
            (r#"love loving lovingly loved lovely"#, ATTACHMENT),
        ];

        let mut builder = TermIndexBuilder::new();
        let mut stemmed_word_ids = AHashMap::default();

        // Build the term index
        for (part_id, (text, field_id)) in parts.iter().enumerate() {
            let mut terms = Vec::new();
            for token in Stemmer::new(text, Language::English, 40) {
                let stemmed_word = if token.stemmed_word.is_some() {
                    token.stemmed_word.clone()
                } else {
                    None
                };
                let term = builder.add_stemmed_token(token);
                if let Some(stemmed_word) = stemmed_word {
                    stemmed_word_ids.insert(term.id_stemmed, stemmed_word.into_owned());
                }
                terms.push(term);
            }
            builder.add_terms(*field_id, part_id as u32, terms);
        }

        let compressed_term_index = builder.serialize();
        let term_index = TermIndex::deserialize(&compressed_term_index[..]).unwrap();

        assert_eq!(
            15,
            TokenIndex::deserialize(&compressed_term_index[..])
                .unwrap()
                .terms
                .len()
        );

        for (words, field_id, match_phrase, match_count) in [
            (vec!["thomas", "clinton"], None, true, 4),
            (vec!["was", "the", "worse"], None, true, 3),
            (vec!["carri"], None, false, 2),
            (vec!["nothing", "floating"], None, true, 2),
            (vec!["floating", "nothing"], None, false, 6),
            (vec!["floating", "nothing"], None, true, 0),
            (vec!["noth", "floating"], None, true, 0),
            (vec!["noth", "floating"], None, false, 6),
            (vec!["realli", "happi"], None, false, 5),
            (vec!["really", "happy"], None, true, 2),
            (vec!["should", "feel", "happy", "but"], None, true, 4),
            (
                vec!["love", "loving", "lovingly", "loved", "lovely"],
                Some(ATTACHMENT),
                true,
                5,
            ),
            (vec!["love"], Some(ATTACHMENT), false, 5),
            (vec!["but"], None, false, 6),
            (vec!["but"], None, true, 6),
        ] {
            let mut match_terms = Vec::new();
            for word in &words {
                let stemmed_token = Stemmer::new(word, Language::English, 40)
                    .next()
                    .and_then(|w| w.stemmed_word);
                match_terms.push(
                    term_index.get_match_term(word, stemmed_token.as_ref().map(|w| w.as_ref())),
                );
            }

            let result = term_index
                .match_terms(&match_terms, field_id, match_phrase, true, true)
                .unwrap()
                .unwrap_or_default();

            let mut result_len = 0;
            for r in &result {
                result_len += r.terms.len();
            }

            if result_len != match_count {
                for term_group in result {
                    let part = &parts[term_group.part_id as usize].0;
                    println!("-> Part id {}", term_group.part_id);
                    for term in term_group.terms {
                        println!(
                            "[{}] ",
                            &part[term.offset as usize..term.offset as usize + term.len as usize]
                        );
                    }
                }
                panic!(
                    "Expected {}, got {} for words {:?}, match phrase {:?}.",
                    match_count, result_len, words, match_phrase
                );
            }

            for term_group in &result {
                'outer: for term in &term_group.terms {
                    let text_word = parts[term_group.part_id as usize].0
                        [term.offset as usize..term.offset as usize + term.len as usize]
                        .to_lowercase();
                    let token_stemmed_word = if term.id_stemmed != term.id {
                        stemmed_word_ids.get(&term.id_stemmed)
                    } else {
                        None
                    };

                    for word in words.iter() {
                        if word == &text_word
                            || !match_phrase
                                && word == token_stemmed_word.unwrap_or(&"".to_string())
                        {
                            continue 'outer;
                        }
                    }
                    panic!("({:?}, {}) != {:?}", words, match_phrase, result);
                }
            }
        }
    }
}
