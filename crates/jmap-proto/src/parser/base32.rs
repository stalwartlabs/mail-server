/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::codec::{base32_custom::BASE32_INVERSE, leb128::Leb128Iterator};

use super::{json::Parser, Error};

#[derive(Debug)]
pub struct JsonBase32Reader<'x, 'y> {
    bytes: &'y mut Parser<'x>,
    last_byte: u8,
    pos: usize,
}

impl<'x, 'y> JsonBase32Reader<'x, 'y> {
    pub fn new(bytes: &'y mut Parser<'x>) -> Self {
        JsonBase32Reader {
            bytes,
            pos: 0,
            last_byte: 0,
        }
    }

    #[inline(always)]
    fn map_byte(&mut self) -> Option<u8> {
        match self.bytes.next_unescaped() {
            Ok(Some(byte)) => match BASE32_INVERSE[byte as usize] {
                decoded_byte if decoded_byte != u8::MAX => {
                    self.last_byte = decoded_byte;
                    Some(decoded_byte)
                }
                _ => None,
            },
            _ => None,
        }
    }

    pub fn error(&mut self) -> Error {
        self.bytes.error_value()
    }
}

impl<'x, 'y> Iterator for JsonBase32Reader<'x, 'y> {
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

impl<'x, 'y> Leb128Iterator<u8> for JsonBase32Reader<'x, 'y> {}
