use roaring::RoaringBitmap;

const BITS: u32 = 128;
const WORD_SIZE: u32 = 8;
pub const BITS_PER_BLOCK: u32 = BITS * WORD_SIZE;
const BITS_MASK: u32 = BITS_PER_BLOCK - 1;

pub struct DenseBitmap {
    restore_value: u8,
    restore_pos: usize,
    pub block_num: u32,
    pub bitmap: [u8; std::mem::size_of::<u128>() * WORD_SIZE as usize],
}

impl DenseBitmap {
    pub fn empty() -> Self {
        Self {
            block_num: 0,
            restore_pos: 0,
            restore_value: 0,
            bitmap: [0; std::mem::size_of::<u128>() * WORD_SIZE as usize],
        }
    }

    pub fn full() -> Self {
        Self {
            block_num: 0,
            restore_pos: 0,
            restore_value: u8::MAX,
            bitmap: [u8::MAX; std::mem::size_of::<u128>() * WORD_SIZE as usize],
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
}

impl DeserializeBlock for RoaringBitmap {
    fn deserialize_block(&mut self, bytes: &[u8], block_num: u32) {
        debug_assert_eq!(
            bytes.len(),
            std::mem::size_of::<u128>() * WORD_SIZE as usize
        );

        for (word_num, word) in bytes.chunks_exact(std::mem::size_of::<u128>()).enumerate() {
            match u128::from_le_bytes(word.try_into().unwrap()) {
                0 => continue,
                u128::MAX => {
                    self.insert_range(
                        block_num * BITS_PER_BLOCK + word_num as u32 * 128
                            ..(block_num * BITS_PER_BLOCK + word_num as u32 * 128) + 128,
                    );
                }
                mut word => {
                    while word != 0 {
                        let trailing_zeros = word.trailing_zeros();
                        self.insert(
                            block_num * BITS_PER_BLOCK + word_num as u32 * 128 + trailing_zeros,
                        );
                        word ^= 1 << trailing_zeros;
                    }
                }
            }
        }

        //println!("deserializing block {} {}", block_num, self.len());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use roaring::RoaringBitmap;

    use crate::backend::foundationdb::bitmap::{DenseBitmap, DeserializeBlock, BITS_PER_BLOCK};

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
}
