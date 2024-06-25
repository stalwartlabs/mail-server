/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::cmp::Ordering;

use ahash::AHashSet;
use bitpacking::{BitPacker, BitPacker1x, BitPacker4x, BitPacker8x};
use utils::codec::leb128::Leb128Reader;

use crate::{write::key::KeySerializer, Serialize};

#[derive(Default)]
pub(super) struct Postings {
    fields: AHashSet<u8>,
    postings: Vec<u32>,
}

#[derive(Default)]
pub(super) struct SerializedPostings<T: AsRef<[u8]>> {
    bytes: T,
}

impl Postings {
    pub fn insert(&mut self, field: u8, posting: u32) {
        self.fields.insert(field);
        self.postings.push(posting);
    }

    pub fn insert_keyword(&mut self, field: u8) {
        self.fields.insert(field);
    }
}

impl<T: AsRef<[u8]>> SerializedPostings<T> {
    pub fn new(bytes: T) -> Self {
        SerializedPostings { bytes }
    }

    pub fn has_field(&self, field: u8) -> bool {
        for byte in self.bytes.as_ref() {
            match byte {
                0xFF => return false,
                _ if *byte == field => return true,
                _ => {}
            }
        }

        false
    }

    pub fn positions(&self) -> Vec<u32> {
        self.into_iter().collect()
    }

    pub fn matches_positions(&self, positions: &[u32], offset: u32) -> bool {
        let mut next_pos = self.into_iter().peekable();

        for expect_pos in positions.iter().map(|pos| *pos + offset) {
            while let Some(pos) = next_pos.peek() {
                match pos.cmp(&expect_pos) {
                    Ordering::Less => {
                        next_pos.next();
                    }
                    Ordering::Equal => {
                        return true;
                    }
                    Ordering::Greater => {
                        break;
                    }
                }
            }
        }

        false
    }
}

impl<'x, T: AsRef<[u8]>> IntoIterator for &'x SerializedPostings<T> {
    type Item = u32;
    type IntoIter = PostingsIterator<'x>;

    fn into_iter(self) -> Self::IntoIter {
        let bytes = self.bytes.as_ref();

        for (bytes_offset, byte) in bytes.iter().enumerate() {
            if *byte == 0xFF {
                if let Some((items_left, bytes_read)) = bytes
                    .get(bytes_offset + 1..)
                    .and_then(|bytes| bytes.read_leb128::<usize>())
                {
                    return PostingsIterator {
                        bytes,
                        bytes_offset: bytes_offset + bytes_read + 1,
                        items_left,
                        ..Default::default()
                    };
                }

                break;
            }
        }

        PostingsIterator::default()
    }
}

#[derive(Default)]
pub(super) struct PostingsIterator<'x> {
    bytes: &'x [u8],
    bytes_offset: usize,
    chunk: Vec<u32>,
    chunk_offset: usize,
    pub items_left: usize,
}

impl Iterator for PostingsIterator<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.chunk.get(self.chunk_offset) {
            self.chunk_offset += 1;
            return Some(*item);
        }
        let block_len = match self.items_left {
            0 => return None,
            1..=31 => {
                self.items_left -= 1;
                let (item, bytes_read) = self.bytes.get(self.bytes_offset..)?.read_leb128()?;
                self.bytes_offset += bytes_read;
                return Some(item);
            }
            32..=127 => BitPacker1x::BLOCK_LEN,
            128..=255 => BitPacker4x::BLOCK_LEN,
            _ => BitPacker8x::BLOCK_LEN,
        };

        let bitpacker = TermIndexPacker::with_block_len(block_len);
        let num_bits = *self.bytes.get(self.bytes_offset)?;
        let bytes_read = ((num_bits as usize) * block_len / 8) + 1;
        let initial_value = self.chunk.last().copied();

        self.chunk = vec![0u32; block_len];
        self.chunk_offset = 1;

        bitpacker.decompress_strictly_sorted(
            initial_value,
            self.bytes
                .get(self.bytes_offset + 1..self.bytes_offset + bytes_read)?,
            &mut self.chunk[..],
            num_bits,
        );

        self.bytes_offset += bytes_read;
        self.items_left -= block_len;
        self.chunk.first().copied()
    }
}

impl Serialize for Postings {
    fn serialize(self) -> Vec<u8> {
        // Serialize fields
        let mut serializer =
            KeySerializer::new((self.fields.len() + 1) + (self.postings.len() * 2));
        for field in self.fields {
            serializer = serializer.write(field);
        }
        serializer = serializer.write(u8::MAX);

        // Compress postings
        if !self.postings.is_empty() {
            let mut bitpacker = TermIndexPacker::new();
            let mut compressed = vec![0u8; 4 * BitPacker8x::BLOCK_LEN];

            let mut pos = 0;
            let len = self.postings.len();
            let mut initial_value = None;

            serializer = serializer.write_leb128(len);

            while pos < len {
                let block_len = match len - pos {
                    0..=31 => {
                        for val in &self.postings[pos..] {
                            serializer = serializer.write_leb128(*val);
                        }
                        break;
                    }
                    32..=127 => BitPacker1x::BLOCK_LEN,
                    128..=255 => BitPacker4x::BLOCK_LEN,
                    _ => BitPacker8x::BLOCK_LEN,
                };

                let chunk = &self.postings[pos..pos + block_len];
                bitpacker.block_len(block_len);
                let num_bits: u8 = bitpacker.num_bits_strictly_sorted(initial_value, chunk);
                let compressed_len = bitpacker.compress_strictly_sorted(
                    initial_value,
                    chunk,
                    &mut compressed[..],
                    num_bits,
                );
                serializer = serializer
                    .write(num_bits)
                    .write(&compressed[..compressed_len]);
                initial_value = chunk[chunk.len() - 1].into();

                pos += block_len;
            }
        }

        serializer.finalize()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TermIndexPacker {
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

    fn compress_strictly_sorted(
        &self,
        initial: Option<u32>,
        decompressed: &[u32],
        compressed: &mut [u8],
        num_bits: u8,
    ) -> usize {
        match self.block_len {
            BitPacker8x::BLOCK_LEN => self.bitpacker_8.compress_strictly_sorted(
                initial,
                decompressed,
                compressed,
                num_bits,
            ),
            BitPacker4x::BLOCK_LEN => self.bitpacker_4.compress_strictly_sorted(
                initial,
                decompressed,
                compressed,
                num_bits,
            ),
            _ => self.bitpacker_1.compress_strictly_sorted(
                initial,
                decompressed,
                compressed,
                num_bits,
            ),
        }
    }

    fn decompress_strictly_sorted(
        &self,
        initial: Option<u32>,
        compressed: &[u8],
        decompressed: &mut [u32],
        num_bits: u8,
    ) -> usize {
        match self.block_len {
            BitPacker8x::BLOCK_LEN => self.bitpacker_8.decompress_strictly_sorted(
                initial,
                compressed,
                decompressed,
                num_bits,
            ),
            BitPacker4x::BLOCK_LEN => self.bitpacker_4.decompress_strictly_sorted(
                initial,
                compressed,
                decompressed,
                num_bits,
            ),
            _ => self.bitpacker_1.decompress_strictly_sorted(
                initial,
                compressed,
                decompressed,
                num_bits,
            ),
        }
    }

    fn num_bits_strictly_sorted(&self, initial: Option<u32>, decompressed: &[u32]) -> u8 {
        match self.block_len {
            BitPacker8x::BLOCK_LEN => self
                .bitpacker_8
                .num_bits_strictly_sorted(initial, decompressed),
            BitPacker4x::BLOCK_LEN => self
                .bitpacker_4
                .num_bits_strictly_sorted(initial, decompressed),
            _ => self
                .bitpacker_1
                .num_bits_strictly_sorted(initial, decompressed),
        }
    }
}

#[cfg(test)]
mod tests {

    use ahash::AHashMap;

    use super::*;

    #[test]
    fn postings_roundtrip() {
        for num_positions in [
            1,
            10,
            BitPacker1x::BLOCK_LEN,
            BitPacker4x::BLOCK_LEN,
            BitPacker8x::BLOCK_LEN,
            BitPacker8x::BLOCK_LEN + BitPacker4x::BLOCK_LEN + BitPacker1x::BLOCK_LEN,
            BitPacker8x::BLOCK_LEN + BitPacker4x::BLOCK_LEN + BitPacker1x::BLOCK_LEN + 1,
            (BitPacker8x::BLOCK_LEN * 3)
                + (BitPacker4x::BLOCK_LEN * 3)
                + (BitPacker1x::BLOCK_LEN * 3)
                + 1,
        ] {
            println!("Testing block {num_positions}...",);
            let mut postings = Postings::default();
            for i in 0..num_positions {
                postings.postings.push((i * i) as u32);
            }
            for fields in 0..std::cmp::min(10, num_positions) as u8 {
                postings.fields.insert(fields);
            }

            let deserialized = SerializedPostings::new(postings.serialize());
            let mut iter = (&deserialized).into_iter();

            assert_eq!(
                iter.items_left, num_positions,
                "failed for num_positions: {}",
                num_positions
            );

            for i in 0..num_positions {
                assert_eq!(
                    iter.next(),
                    Some((i * i) as u32),
                    "failed for position: {}",
                    i
                );
            }
            assert_eq!(iter.next(), None, "expected end of iterator");

            for field in 0..std::cmp::min(10, num_positions) as u8 {
                assert!(deserialized.has_field(field), "failed for field: {}", field);
            }

            assert_eq!(deserialized.positions().len(), num_positions);
        }
    }

    #[test]
    fn postings_match_positions() {
        let mut maps: AHashMap<&str, Postings> = AHashMap::new();
        let tokens = [
            "the", "quick", "brown", "fox", "jumps", "over", "the", "lazy", "dog",
        ];

        for (pos, word) in tokens.into_iter().enumerate() {
            maps.entry(word).or_default().insert(0, pos as u32);
        }

        let maps: AHashMap<&str, SerializedPostings<Vec<u8>>> = maps
            .into_iter()
            .map(|(k, v)| (k, SerializedPostings::new(v.serialize())))
            .collect();

        let mut positions = Vec::new();
        for (pos, word) in tokens.into_iter().enumerate() {
            if pos > 0 {
                assert!(maps[word].matches_positions(&positions, pos as u32));
            } else {
                positions = maps[word].positions();
            }
        }
    }
}
