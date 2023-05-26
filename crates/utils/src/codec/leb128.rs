/*
 * Copyright (c) 2023, Stalwart Labs Ltd.
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

#![allow(dead_code)]

use std::{borrow::Borrow, io::Write};

pub trait Leb128_ {
    fn to_leb128_writer(self, out: &mut impl Write) -> std::io::Result<usize>;
    fn to_leb128_bytes(self, out: &mut Vec<u8>);
    fn from_leb128_bytes(slice: &[u8]) -> Option<(Self, usize)>
    where
        Self: std::marker::Sized;
    fn from_leb128_it<T, I>(it: T) -> Option<Self>
    where
        Self: std::marker::Sized,
        T: Iterator<Item = I>,
        I: Borrow<u8>;
}

pub trait Leb128Vec<T: Leb128_> {
    fn push_leb128(&mut self, value: T);
}

pub trait Leb128Writer: Write + Sized {
    #[inline(always)]
    fn write_leb128<T: Leb128_>(&mut self, value: T) -> std::io::Result<usize> {
        T::to_leb128_writer(value, self)
    }
}

impl<T: Leb128_> Leb128Vec<T> for Vec<u8> {
    #[inline(always)]
    fn push_leb128(&mut self, value: T) {
        T::to_leb128_bytes(value, self);
    }
}

pub trait Leb128Iterator<I>: Iterator<Item = I>
where
    I: Borrow<u8>,
{
    #[inline(always)]
    fn next_leb128<T: Leb128_>(&mut self) -> Option<T> {
        T::from_leb128_it(self)
    }

    #[inline(always)]
    fn skip_leb128(&mut self) -> Option<()> {
        for byte in self {
            if (byte.borrow() & 0x80) == 0 {
                return Some(());
            }
        }
        None
    }
}

pub trait Leb128Reader: AsRef<[u8]> {
    #[inline(always)]
    fn read_leb128<T: Leb128_>(&self) -> Option<(T, usize)> {
        T::from_leb128_bytes(self.as_ref())
    }

    #[inline(always)]
    fn skip_leb128(&self) -> Option<usize> {
        for (pos, byte) in self.as_ref().iter().enumerate() {
            if (byte & 0x80) == 0 {
                return (pos + 1).into();
            }
        }
        None
    }
}

impl Leb128Reader for &[u8] {}
impl Leb128Reader for Vec<u8> {}
impl Leb128Reader for Box<[u8]> {}
impl<'x> Leb128Iterator<&'x u8> for std::slice::Iter<'x, u8> {}

// Based on leb128.rs from rustc
macro_rules! impl_unsigned_leb128 {
    ($int_ty:ident, $shifts:expr) => {
        impl Leb128_ for $int_ty {
            #[inline(always)]
            fn to_leb128_writer(self, out: &mut impl Write) -> std::io::Result<usize> {
                let mut value = self;
                let mut bytes_written = 0;
                loop {
                    if value < 0x80 {
                        bytes_written += out.write(&[value as u8])?;
                        break;
                    } else {
                        bytes_written += out.write(&[((value & 0x7f) | 0x80) as u8])?;
                        value >>= 7;
                    }
                }
                Ok(bytes_written)
            }

            #[inline(always)]
            fn to_leb128_bytes(self, out: &mut Vec<u8>) {
                let mut value = self;
                loop {
                    if value < 0x80 {
                        out.push(value as u8);
                        break;
                    } else {
                        out.push(((value & 0x7f) | 0x80) as u8);
                        value >>= 7;
                    }
                }
            }

            #[inline(always)]
            fn from_leb128_bytes(slice: &[u8]) -> Option<($int_ty, usize)> {
                let mut result = 0;

                for (shift, (pos, &byte)) in $shifts.into_iter().zip(slice.iter().enumerate()) {
                    if (byte & 0x80) == 0 {
                        result |= (byte as $int_ty) << shift;
                        return Some((result, pos + 1));
                    } else {
                        result |= ((byte & 0x7F) as $int_ty) << shift;
                    }
                }

                None
            }

            #[inline(always)]
            fn from_leb128_it<T, I>(it: T) -> Option<$int_ty>
            where
                T: Iterator<Item = I>,
                I: Borrow<u8>,
            {
                let mut result = 0;

                for (shift, byte_) in $shifts.into_iter().zip(it) {
                    let byte = byte_.borrow();

                    if (byte & 0x80) == 0 {
                        result |= (*byte as $int_ty) << shift;
                        return Some(result);
                    } else {
                        result |= ((byte & 0x7F) as $int_ty) << shift;
                    }
                }

                None
            }
        }
    };
}

impl_unsigned_leb128!(u8, [0]);
impl_unsigned_leb128!(u16, [0, 7, 14]);
impl_unsigned_leb128!(u32, [0, 7, 14, 21, 28]);
impl_unsigned_leb128!(u64, [0, 7, 14, 21, 28, 35, 42, 49, 56, 63]);
impl_unsigned_leb128!(usize, [0, 7, 14, 21, 28, 35, 42, 49, 56, 63]);

impl Leb128Writer for Vec<u8> {
    fn write_leb128<T: Leb128_>(&mut self, value: T) -> std::io::Result<usize> {
        T::to_leb128_writer(value, self)
    }
}
