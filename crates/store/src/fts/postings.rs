/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::cmp::Ordering;

use ahash::AHashSet;
use utils::codec::leb128::Leb128Reader;

use crate::{
    SerializeInfallible,
    write::{bitpack::BitpackIterator, key::KeySerializer},
};

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
    type IntoIter = BitpackIterator<'x>;

    fn into_iter(self) -> Self::IntoIter {
        let bytes = self.bytes.as_ref();

        for (bytes_offset, byte) in bytes.iter().enumerate() {
            if *byte == 0xFF {
                if let Some((items_left, bytes_read)) = bytes
                    .get(bytes_offset + 1..)
                    .and_then(|bytes| bytes.read_leb128::<u32>())
                {
                    return BitpackIterator {
                        bytes,
                        bytes_offset: bytes_offset + bytes_read + 1,
                        items_left,
                        ..Default::default()
                    };
                }

                break;
            }
        }

        BitpackIterator::default()
    }
}

impl SerializeInfallible for Postings {
    fn serialize(&self) -> Vec<u8> {
        // Serialize fields
        let mut serializer =
            KeySerializer::new((self.fields.len() + 1) + (self.postings.len() * 2));
        for field in &self.fields {
            serializer = serializer.write(*field);
        }
        serializer = serializer.write(u8::MAX);

        // Compress postings
        if !self.postings.is_empty() {
            serializer.bitpack_sorted(&self.postings).finalize()
        } else {
            serializer.finalize()
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use ahash::AHashMap;

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
