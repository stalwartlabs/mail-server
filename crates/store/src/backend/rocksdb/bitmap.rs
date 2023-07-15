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

use crate::{Deserialize, Serialize};
use roaring::RoaringBitmap;
use utils::codec::leb128::{Leb128Iterator, Leb128Vec};

pub const BIT_SET: u8 = 0x80;
pub const BIT_CLEAR: u8 = 0;

pub const IS_BITLIST: u8 = 0;
pub const IS_BITMAP: u8 = 1;

#[inline(always)]
pub fn deserialize_bitlist(bm: &mut RoaringBitmap, bytes: &[u8]) {
    let mut it = bytes[1..].iter();

    'inner: while let Some(header) = it.next() {
        let mut items = (header & 0x7F) + 1;
        let is_set = (header & BIT_SET) != 0;

        while items > 0 {
            if let Some(doc_id) = it.next_leb128() {
                if is_set {
                    bm.insert(doc_id);
                } else {
                    bm.remove(doc_id);
                }
                items -= 1;
            } else {
                debug_assert!(items == 0, "{:?}", bytes);
                break 'inner;
            }
        }
    }
}

#[inline(always)]
pub fn deserialize_bitmap(bytes: &[u8]) -> Option<RoaringBitmap> {
    RoaringBitmap::deserialize_unchecked_from(&bytes[1..]).ok()
}

impl Deserialize for RoaringBitmap {
    fn deserialize(bytes: &[u8]) -> Option<Self> {
        match *bytes.first()? {
            IS_BITMAP => deserialize_bitmap(bytes),
            IS_BITLIST => {
                let mut bm = RoaringBitmap::new();
                deserialize_bitlist(&mut bm, bytes);
                Some(bm)
            }
            _ => None,
        }
    }
}

impl Serialize for RoaringBitmap {
    fn serialize(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.serialized_size() + 1);
        bytes.push(IS_BITMAP);
        let _ = self.serialize_into(&mut bytes);
        bytes
    }
}

macro_rules! impl_bit {
    ($single:ident, $many:ident, $flag:ident) => {
        #[inline(always)]
        pub fn $single(document: u32) -> Vec<u8> {
            let mut buf = Vec::with_capacity(std::mem::size_of::<u32>() + 2);
            buf.push(IS_BITLIST);
            buf.push($flag);
            buf.push_leb128(document);
            buf
        }

        #[inline(always)]
        pub fn $many<T>(documents: T) -> Vec<u8>
        where
            T: Iterator<Item = u32>,
        {
            debug_assert!(documents.size_hint().0 > 0);

            let mut buf = Vec::with_capacity(
                ((std::mem::size_of::<u32>() + 1)
                    * documents
                        .size_hint()
                        .1
                        .unwrap_or_else(|| documents.size_hint().0))
                    + 2,
            );

            buf.push(IS_BITLIST);

            let mut header_pos = 0;
            let mut total_docs = 0;

            for (pos, document) in documents.enumerate() {
                if pos & 0x7F == 0 {
                    header_pos = buf.len();
                    buf.push($flag | 0x7F);
                }
                buf.push_leb128(document);
                total_docs = pos;
            }

            buf[header_pos] = $flag | ((total_docs & 0x7F) as u8);

            buf
        }
    };
}

impl_bit!(set_bit, set_bits, BIT_SET);
impl_bit!(clear_bit, clear_bits, BIT_CLEAR);

#[inline(always)]
pub fn set_clear_bits<T>(documents: T) -> Vec<u8>
where
    T: Iterator<Item = (u32, bool)>,
{
    debug_assert!(documents.size_hint().0 > 0);

    let total_docs = documents
        .size_hint()
        .1
        .unwrap_or_else(|| documents.size_hint().0);
    let buf_len = (std::mem::size_of::<u32>() * total_docs) + (total_docs / 0x7F) + 2;
    let mut set_buf = Vec::with_capacity(buf_len);
    let mut clear_buf = Vec::with_capacity(buf_len);

    let mut set_header_pos = 0;
    let mut set_total_docs = 0;

    let mut clear_header_pos = 0;
    let mut clear_total_docs = 0;

    set_buf.push(IS_BITLIST);
    clear_buf.push(IS_BITLIST);

    for (document, is_set) in documents {
        if is_set {
            if set_total_docs & 0x7F == 0 {
                set_header_pos = set_buf.len();
                set_buf.push(BIT_SET | 0x7F);
            }
            set_buf.push_leb128(document);
            set_total_docs += 1;
        } else {
            if clear_total_docs & 0x7F == 0 {
                clear_header_pos = clear_buf.len();
                clear_buf.push(BIT_CLEAR | 0x7F);
            }
            clear_buf.push_leb128(document);
            clear_total_docs += 1;
        }
    }

    if set_total_docs > 0 {
        set_buf[set_header_pos] = BIT_SET | (((set_total_docs - 1) & 0x7F) as u8);
    }

    if clear_total_docs > 0 {
        clear_buf[clear_header_pos] = BIT_CLEAR | (((clear_total_docs - 1) & 0x7F) as u8);
    }

    if set_total_docs > 0 && clear_total_docs > 0 {
        set_buf.extend_from_slice(&clear_buf[1..]);
        set_buf
    } else if set_total_docs > 0 {
        set_buf
    } else {
        clear_buf
    }
}

#[inline(always)]
pub fn bitmap_merge<'x>(
    existing_val: Option<&[u8]>,
    operands_len: usize,
    operands: impl IntoIterator<Item = &'x [u8]>,
) -> Option<Vec<u8>> {
    let mut bm = match existing_val {
        Some(existing_val) => RoaringBitmap::deserialize(existing_val)?,
        None if operands_len == 1 => {
            return Some(Vec::from(operands.into_iter().next().unwrap()));
        }
        _ => RoaringBitmap::new(),
    };

    for op in operands.into_iter() {
        match *op.first()? {
            IS_BITMAP => {
                if let Some(union_bm) = deserialize_bitmap(op) {
                    if !bm.is_empty() {
                        bm |= union_bm;
                    } else {
                        bm = union_bm;
                    }
                } else {
                    debug_assert!(false, "Failed to deserialize bitmap.");
                    return None;
                }
            }
            IS_BITLIST => {
                deserialize_bitlist(&mut bm, op);
            }
            _ => {
                debug_assert!(false, "This should not have happened");
                return None;
            }
        }
    }

    let mut bytes = Vec::with_capacity(bm.serialized_size() + 1);
    bytes.push(IS_BITMAP);
    bm.serialize_into(&mut bytes).ok()?;
    Some(bytes)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn merge_bitmaps() {
        let v1 = set_clear_bits([(1, true), (2, true), (3, false), (4, true)].into_iter());
        let v2 = set_clear_bits([(1, false), (4, false)].into_iter());
        let v3 = set_clear_bits([(5, true)].into_iter());
        assert_eq!(
            RoaringBitmap::from_iter([1, 2, 4]),
            RoaringBitmap::deserialize(&v1).unwrap()
        );
        assert_eq!(
            RoaringBitmap::from_iter([1, 2, 4]),
            RoaringBitmap::deserialize(&bitmap_merge(None, 1, [v1.as_ref()]).unwrap()).unwrap()
        );
        assert_eq!(
            RoaringBitmap::from_iter([2]),
            RoaringBitmap::deserialize(&bitmap_merge(None, 2, [v1.as_ref(), v2.as_ref()]).unwrap())
                .unwrap()
        );
        assert_eq!(
            RoaringBitmap::from_iter([2, 5]),
            RoaringBitmap::deserialize(
                &bitmap_merge(None, 3, [v1.as_ref(), v2.as_ref(), v3.as_ref()]).unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            RoaringBitmap::from_iter([2, 5]),
            RoaringBitmap::deserialize(
                &bitmap_merge(Some(v1.as_ref()), 2, [v2.as_ref(), v3.as_ref()]).unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            RoaringBitmap::from_iter([5]),
            RoaringBitmap::deserialize(&bitmap_merge(Some(v2.as_ref()), 1, [v3.as_ref()]).unwrap())
                .unwrap()
        );

        assert_eq!(
            RoaringBitmap::from_iter([1, 2, 4]),
            RoaringBitmap::deserialize(
                &bitmap_merge(
                    Some(RoaringBitmap::from_iter([1, 2, 3, 4]).serialize().as_ref()),
                    1,
                    [v1.as_ref()]
                )
                .unwrap()
            )
            .unwrap()
        );

        assert_eq!(
            RoaringBitmap::from_iter([1, 2, 3, 4, 5, 6]),
            RoaringBitmap::deserialize(
                &bitmap_merge(
                    Some(RoaringBitmap::from_iter([1, 2, 3, 4]).serialize().as_ref()),
                    1,
                    [RoaringBitmap::from_iter([5, 6]).serialize().as_ref()]
                )
                .unwrap()
            )
            .unwrap()
        );

        assert_eq!(
            RoaringBitmap::from_iter([1, 2, 4, 5, 6]),
            RoaringBitmap::deserialize(
                &bitmap_merge(
                    Some(RoaringBitmap::from_iter([1, 2, 3, 4]).serialize().as_ref()),
                    2,
                    [
                        RoaringBitmap::from_iter([5, 6]).serialize().as_ref(),
                        v1.as_ref()
                    ]
                )
                .unwrap()
            )
            .unwrap()
        );
    }
}
