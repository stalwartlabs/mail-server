/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use ahash::AHashSet;
use roaring::RoaringBitmap;

use crate::U64_LEN;

pub const WORD_SIZE_BITS_L: u32 = (WORD_SIZE_L * 8) as u32;
pub const WORD_SIZE_L: usize = std::mem::size_of::<u128>();
pub const WORDS_PER_BLOCK_L: u32 = 8;
pub const BITS_PER_BLOCK_L: u32 = WORD_SIZE_BITS_L * WORDS_PER_BLOCK_L;
pub const BITS_MASK_L: u32 = BITS_PER_BLOCK_L - 1;

pub const WORD_SIZE_BITS_S: u32 = (WORD_SIZE_S * 8) as u32;
pub const WORD_SIZE_S: usize = U64_LEN;
pub const WORDS_PER_BLOCK_S: u32 = 16;
pub const BITS_PER_BLOCK_S: u32 = WORD_SIZE_BITS_S * WORDS_PER_BLOCK_S;
pub const BITS_MASK_S: u32 = BITS_PER_BLOCK_S - 1;

pub struct DenseBitmap {
    pub bitmap: [u8; WORD_SIZE_L * WORDS_PER_BLOCK_L as usize],
}

impl DenseBitmap {
    pub fn empty() -> Self {
        Self {
            bitmap: [0; WORD_SIZE_L * WORDS_PER_BLOCK_L as usize],
        }
    }

    pub fn full() -> Self {
        Self {
            bitmap: [u8::MAX; WORD_SIZE_L * WORDS_PER_BLOCK_L as usize],
        }
    }

    pub fn set(&mut self, index: u32) {
        let index = index & BITS_MASK_L;
        self.bitmap[(index / 8) as usize] |= 1 << (index & 7);
    }

    pub fn clear(&mut self, index: u32) {
        let index = index & BITS_MASK_L;
        self.bitmap[(index / 8) as usize] &= !(1 << (index & 7));
    }

    #[inline(always)]
    pub fn block_num(index: u32) -> u32 {
        index / BITS_PER_BLOCK_L
    }

    #[inline(always)]
    pub fn block_index(index: u32) -> u32 {
        index & BITS_MASK_L
    }
}

pub trait DeserializeBlock {
    fn deserialize_block(&mut self, bytes: &[u8], block_num: u32);
    fn deserialize_word(&mut self, word: &[u8], block_num: u32, word_num: u32);
}

pub fn next_available_index(
    bytes: &[u8],
    block_num: u32,
    reserved_ids: &AHashSet<u32>,
) -> Option<u32> {
    'outer: for (byte_pos, byte) in bytes.iter().enumerate() {
        if *byte != u8::MAX {
            let mut index = 0;
            loop {
                while (byte >> index) & 1 == 1 {
                    index += 1;
                    if index == 8 {
                        continue 'outer;
                    }
                }

                let id = (block_num * BITS_PER_BLOCK_L) + ((byte_pos * 8) + index) as u32;
                if !reserved_ids.contains(&id) {
                    return Some(id);
                } else if index < 7 {
                    index += 1;
                    continue;
                } else {
                    continue 'outer;
                }
            }
        }
    }

    None
}

pub fn block_contains(bytes: &[u8], block_num: u32, document_id: u32) -> bool {
    'outer: for (byte_pos, byte) in bytes.iter().enumerate() {
        if *byte != 0 {
            let mut index = 0;
            loop {
                while (byte >> index) & 1 == 0 {
                    index += 1;
                    if index == 8 {
                        continue 'outer;
                    }
                }

                let id = (block_num * BITS_PER_BLOCK_L) + ((byte_pos * 8) + index) as u32;
                if id == document_id {
                    return true;
                } else if index < 7 {
                    index += 1;
                    continue;
                } else {
                    continue 'outer;
                }
            }
        }
    }

    false
}

impl DeserializeBlock for RoaringBitmap {
    fn deserialize_block(&mut self, bytes: &[u8], block_num: u32) {
        debug_assert_eq!(bytes.len(), WORD_SIZE_L * WORDS_PER_BLOCK_L as usize);

        self.deserialize_word(&bytes[..WORD_SIZE_L], block_num, 0);
        self.deserialize_word(&bytes[WORD_SIZE_L..WORD_SIZE_L * 2], block_num, 1);
        self.deserialize_word(&bytes[WORD_SIZE_L * 2..WORD_SIZE_L * 3], block_num, 2);
        self.deserialize_word(&bytes[WORD_SIZE_L * 3..WORD_SIZE_L * 4], block_num, 3);
        self.deserialize_word(&bytes[WORD_SIZE_L * 4..WORD_SIZE_L * 5], block_num, 4);
        self.deserialize_word(&bytes[WORD_SIZE_L * 5..WORD_SIZE_L * 6], block_num, 5);
        self.deserialize_word(&bytes[WORD_SIZE_L * 6..WORD_SIZE_L * 7], block_num, 6);
        self.deserialize_word(&bytes[WORD_SIZE_L * 7..], block_num, 7);
    }

    #[inline(always)]
    fn deserialize_word(&mut self, word: &[u8], block_num: u32, word_num: u32) {
        match u128::from_le_bytes(word.try_into().unwrap()) {
            0 => (),
            u128::MAX => {
                self.insert_range(
                    block_num * BITS_PER_BLOCK_L + word_num * WORD_SIZE_BITS_L
                        ..(block_num * BITS_PER_BLOCK_L + word_num * WORD_SIZE_BITS_L)
                            + WORD_SIZE_BITS_L,
                );
            }
            mut word => {
                while word != 0 {
                    let trailing_zeros = word.trailing_zeros();
                    self.insert(
                        block_num * BITS_PER_BLOCK_L + word_num * WORD_SIZE_BITS_L + trailing_zeros,
                    );
                    word ^= 1 << trailing_zeros;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ahash::AHashSet;
    use roaring::RoaringBitmap;

    use super::*;

    #[test]
    fn serialize_bitmap_block() {
        for range in [(0..128), (128..256), (5076..5093), (1762..19342)] {
            let mut blocks = HashMap::new();
            let mut bitmap = RoaringBitmap::new();
            for item in range {
                bitmap.insert(item);
                blocks
                    .entry(item / BITS_PER_BLOCK_L)
                    .or_insert_with(DenseBitmap::empty)
                    .set(item);
            }
            let mut bitmap_blocks = RoaringBitmap::new();
            for (block_num, dense_bitmap) in blocks {
                bitmap_blocks.deserialize_block(&dense_bitmap.bitmap, block_num);
            }

            assert_eq!(bitmap, bitmap_blocks);
        }
    }

    #[test]
    fn get_next_available_index() {
        let eh = AHashSet::new();
        let mut uh = AHashSet::new();
        let mut bm = DenseBitmap::empty();
        for id in 0..1024 {
            uh.insert(id);
            assert_eq!(
                next_available_index(&bm.bitmap, 0, &eh),
                Some(id),
                "failed for {id}"
            );
            assert_eq!(
                next_available_index(&bm.bitmap, 0, &uh),
                if id < 1023 { Some(id + 1) } else { None },
                "reserved id failed for {id}"
            );
            bm.set(id);
        }
    }
}
