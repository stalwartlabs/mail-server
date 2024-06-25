/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{io::Write, slice::Iter};

use super::leb128::{Leb128Iterator, Leb128Writer};

pub static BASE32_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz792013";
pub static BASE32_INVERSE: [u8; 256] = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 29, 30, 28, 31, 255, 255, 255, 26, 255, 27,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 10, 11,
    12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255, 255, 0, 1, 2,
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
];

pub struct Base32Writer {
    last_byte: u8,
    pos: usize,
    result: String,
}

impl Base32Writer {
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref();
        let mut writer = Base32Writer::with_capacity(bytes.len());
        writer.write_all(bytes).unwrap();
        writer
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_raw_capacity((capacity + 3) / 4 * 5)
    }

    pub fn with_raw_capacity(capacity: usize) -> Self {
        Base32Writer {
            result: String::with_capacity(capacity),
            last_byte: 0,
            pos: 0,
        }
    }

    pub fn push_char(&mut self, ch: char) {
        self.result.push(ch);
    }

    pub fn push_string(&mut self, string: &str) {
        self.result.push_str(string);
    }

    fn push_byte(&mut self, byte: u8, is_remainder: bool) {
        let (ch1, ch2) = match self.pos % 5 {
            0 => ((byte & 0xF8) >> 3, u8::MAX),
            1 => (
                (((self.last_byte & 0x07) << 2) | ((byte & 0xC0) >> 6)),
                ((byte & 0x3E) >> 1),
            ),
            2 => (
                (((self.last_byte & 0x01) << 4) | ((byte & 0xF0) >> 4)),
                u8::MAX,
            ),
            3 => (
                (((self.last_byte & 0x0F) << 1) | (byte >> 7)),
                ((byte & 0x7C) >> 2),
            ),
            4 => (
                (((self.last_byte & 0x03) << 3) | ((byte & 0xE0) >> 5)),
                (byte & 0x1F),
            ),
            _ => unreachable!(),
        };

        self.result.push(char::from(BASE32_ALPHABET[ch1 as usize]));
        if !is_remainder {
            if ch2 != u8::MAX {
                self.result.push(char::from(BASE32_ALPHABET[ch2 as usize]));
            }
            self.last_byte = byte;
            self.pos += 1;
        }
    }

    pub fn finalize(mut self) -> String {
        if self.pos % 5 != 0 {
            self.push_byte(0, true);
        }

        self.result
    }
}

impl std::io::Write for Base32Writer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let start_pos = self.pos;

        for &byte in bytes {
            self.push_byte(byte, false);
        }

        Ok(self.pos - start_pos)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct Base32Reader<'x> {
    bytes: Iter<'x, u8>,
    last_byte: u8,
    pos: usize,
}

impl<'x> Base32Reader<'x> {
    pub fn new(bytes: &'x [u8]) -> Self {
        Base32Reader {
            bytes: bytes.iter(),
            pos: 0,
            last_byte: 0,
        }
    }

    #[inline(always)]
    fn map_byte(&mut self) -> Option<u8> {
        match self.bytes.next() {
            Some(&byte) => match BASE32_INVERSE[byte as usize] {
                byte if byte != u8::MAX => {
                    self.last_byte = byte;
                    Some(byte)
                }
                _ => None,
            },
            _ => None,
        }
    }
}

impl Iterator for Base32Reader<'_> {
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        let pos = self.pos % 5;
        let last_byte = self.last_byte;
        let byte = self.map_byte()?;
        self.pos += 1;

        match pos {
            0 => ((byte << 3) | (self.map_byte().unwrap_or(0) >> 2)).into(),
            1 => ((last_byte << 6) | (byte << 1) | (self.map_byte().unwrap_or(0) >> 4)).into(),
            2 => ((last_byte << 4) | (byte >> 1)).into(),
            3 => ((last_byte << 7) | (byte << 2) | (self.map_byte().unwrap_or(0) >> 3)).into(),
            4 => ((last_byte << 5) | byte).into(),
            _ => None,
        }
    }
}

impl Leb128Iterator<u8> for Base32Reader<'_> {}
impl Leb128Writer for Base32Writer {}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use crate::codec::base32_custom::{Base32Reader, Base32Writer};

    #[test]
    fn base32_roundtrip() {
        let mut bytes = Vec::with_capacity(100);
        for byte in 0..100 {
            bytes.push((100 - byte) as u8);
            let mut writer = Base32Writer::with_capacity(10);
            writer.write_all(&bytes).unwrap();
            let result = writer.finalize();

            let mut bytes_result = Vec::new();
            for byte in Base32Reader::new(result.as_bytes()) {
                bytes_result.push(byte);
            }

            assert_eq!(bytes, bytes_result);
        }

        for bytes in [
            vec![0],
            vec![32, 43, 55, 99, 43, 55],
            vec![84, 4, 43, 77, 62, 55, 92],
            vec![84, 4, 43, 77, 62, 55, 92],
        ] {
            let mut writer = Base32Writer::with_capacity(10);
            writer.write_all(&bytes).unwrap();
            let result = writer.finalize();

            let mut bytes_result = Vec::new();
            for byte in Base32Reader::new(result.as_bytes()) {
                bytes_result.push(byte);
            }

            assert_eq!(bytes, bytes_result);
        }
    }
}
