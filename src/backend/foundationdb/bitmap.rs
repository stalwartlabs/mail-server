use ahash::AHashSet;
use roaring::RoaringBitmap;

const WORD_SIZE_BITS: u32 = 128;
const WORD_SIZE: usize = std::mem::size_of::<u128>();
const WORDS_PER_BLOCK: u32 = 8;
pub const BITS_PER_BLOCK: u32 = WORD_SIZE_BITS * WORDS_PER_BLOCK;
const BITS_MASK: u32 = BITS_PER_BLOCK - 1;

pub struct DenseBitmap {
    restore_value: u8,
    restore_pos: usize,
    pub block_num: u32,
    pub bitmap: [u8; WORD_SIZE * WORDS_PER_BLOCK as usize],
}

impl DenseBitmap {
    pub fn empty() -> Self {
        Self {
            block_num: 0,
            restore_pos: 0,
            restore_value: 0,
            bitmap: [0; WORD_SIZE * WORDS_PER_BLOCK as usize],
        }
    }

    pub fn full() -> Self {
        Self {
            block_num: 0,
            restore_pos: 0,
            restore_value: u8::MAX,
            bitmap: [u8::MAX; WORD_SIZE * WORDS_PER_BLOCK as usize],
        }
    }

    pub fn set(&mut self, index: u32) {
        self.block_num = index / BITS_PER_BLOCK;
        let index = index & BITS_MASK;
        self.restore_pos = (index / 8) as usize;
        self.bitmap[self.restore_pos] = 1 << (index & 7);
    }

    #[cfg(test)]
    pub fn set_or(&mut self, index: u32) {
        let _index = index;
        self.block_num = index / BITS_PER_BLOCK;
        let index = index & BITS_MASK;
        self.restore_pos = (index / 8) as usize;
        self.bitmap[self.restore_pos] |= 1 << (index & 7);
    }

    pub fn clear(&mut self, index: u32) {
        self.block_num = index / BITS_PER_BLOCK;
        let index = BITS_MASK - (index & BITS_MASK);
        self.restore_pos = (index / 8) as usize;
        self.bitmap[self.restore_pos] = !(1 << (index & 7));
    }

    pub fn reset(&mut self) {
        self.bitmap[self.restore_pos] = self.restore_value;
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

                let id = (block_num * BITS_PER_BLOCK) + ((byte_pos * 8) + index) as u32;
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

impl DeserializeBlock for RoaringBitmap {
    fn deserialize_block(&mut self, bytes: &[u8], block_num: u32) {
        debug_assert_eq!(bytes.len(), WORD_SIZE * WORDS_PER_BLOCK as usize);

        self.deserialize_word(&bytes[..WORD_SIZE], block_num, 0);
        self.deserialize_word(&bytes[WORD_SIZE..WORD_SIZE * 2], block_num, 1);
        self.deserialize_word(&bytes[WORD_SIZE * 2..WORD_SIZE * 3], block_num, 2);
        self.deserialize_word(&bytes[WORD_SIZE * 3..WORD_SIZE * 4], block_num, 3);
        self.deserialize_word(&bytes[WORD_SIZE * 4..WORD_SIZE * 5], block_num, 4);
        self.deserialize_word(&bytes[WORD_SIZE * 5..WORD_SIZE * 6], block_num, 5);
        self.deserialize_word(&bytes[WORD_SIZE * 6..WORD_SIZE * 7], block_num, 6);
        self.deserialize_word(&bytes[WORD_SIZE * 7..], block_num, 7);
    }

    #[inline(always)]
    fn deserialize_word(&mut self, word: &[u8], block_num: u32, word_num: u32) {
        match u128::from_le_bytes(word.try_into().unwrap()) {
            0 => (),
            u128::MAX => {
                self.insert_range(
                    block_num * BITS_PER_BLOCK + word_num * WORD_SIZE_BITS
                        ..(block_num * BITS_PER_BLOCK + word_num * WORD_SIZE_BITS) + WORD_SIZE_BITS,
                );
            }
            mut word => {
                while word != 0 {
                    let trailing_zeros = word.trailing_zeros();
                    self.insert(
                        block_num * BITS_PER_BLOCK + word_num * WORD_SIZE_BITS + trailing_zeros,
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

    use crate::backend::foundationdb::bitmap::{
        next_available_index, DenseBitmap, DeserializeBlock, BITS_PER_BLOCK,
    };

    #[test]
    fn serialize_bitmap_block() {
        for range in [(0..128), (128..256), (5076..5093), (1762..19342)] {
            let mut blocks = HashMap::new();
            let mut bitmap = RoaringBitmap::new();
            for item in range {
                bitmap.insert(item);
                blocks
                    .entry(item / BITS_PER_BLOCK)
                    .or_insert_with(DenseBitmap::empty)
                    .set_or(item);
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
            bm.set_or(id);
        }
    }
}
