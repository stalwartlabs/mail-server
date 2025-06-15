/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use bitpacking::{BitPacker, BitPacker1x, BitPacker4x, BitPacker8x};
use utils::codec::leb128::Leb128Reader;

use super::key::KeySerializer;

#[derive(Default)]
pub struct BitpackIterator<'x> {
    pub(crate) bytes: &'x [u8],
    pub(crate) bytes_offset: usize,
    pub(crate) chunk: Vec<u32>,
    pub(crate) chunk_offset: usize,
    pub items_left: u32,
}

#[derive(Clone, Copy)]
pub(crate) struct BitBlockPacker {
    bitpacker_1: BitPacker1x,
    bitpacker_4: BitPacker4x,
    bitpacker_8: BitPacker8x,
    block_len: usize,
}

impl KeySerializer {
    pub fn bitpack_sorted(self, items: &[u32]) -> Self {
        let mut serializer = self;
        let mut bitpacker = BitBlockPacker::new();
        let mut compressed = vec![0u8; 4 * BitPacker8x::BLOCK_LEN];

        let mut pos = 0;
        let len = items.len();
        let mut initial_value = None;

        serializer = serializer.write_leb128(len as u32);

        while pos < len {
            let block_len = match len - pos {
                0..=31 => {
                    for val in &items[pos..] {
                        serializer = serializer.write_leb128(*val);
                    }
                    break;
                }
                32..=127 => BitPacker1x::BLOCK_LEN,
                128..=255 => BitPacker4x::BLOCK_LEN,
                _ => BitPacker8x::BLOCK_LEN,
            };

            let chunk = &items[pos..pos + block_len];
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
        serializer
    }
}

impl<'x> BitpackIterator<'x> {
    pub fn from_bytes_and_offset(bytes: &'x [u8], bytes_offset: usize, items_left: u32) -> Self {
        BitpackIterator {
            bytes,
            bytes_offset,
            items_left,
            ..Default::default()
        }
    }

    pub fn new(bytes: &'x [u8]) -> Option<Self> {
        bytes
            .read_leb128::<u32>()
            .map(|(items_left, bytes_offset)| BitpackIterator {
                bytes,
                bytes_offset,
                items_left,
                ..Default::default()
            })
    }
}

impl Iterator for BitpackIterator<'_> {
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

        let bitpacker = BitBlockPacker::with_block_len(block_len);
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
        self.items_left -= block_len as u32;
        self.chunk.first().copied()
    }
}

impl BitBlockPacker {
    pub fn with_block_len(block_len: usize) -> Self {
        BitBlockPacker {
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

impl BitPacker for BitBlockPacker {
    const BLOCK_LEN: usize = 0;

    fn new() -> Self {
        BitBlockPacker {
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

    use super::*;

    #[test]
    fn bitpack_roundtrip() {
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
            (BitPacker8x::BLOCK_LEN * 32) + 1,
        ] {
            let serialized = KeySerializer::new(num_positions * std::mem::size_of::<u32>())
                .bitpack_sorted(
                    &(0..num_positions)
                        .map(|i| (i * i) as u32)
                        .collect::<Vec<_>>(),
                )
                .finalize();

            println!(
                "Testing block {num_positions} with {} size...",
                serialized.len()
            );

            let mut iter = BitpackIterator::new(&serialized).unwrap();

            assert_eq!(
                iter.items_left, num_positions as u32,
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
        }
    }
}
