/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
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

use crate::{
    parser::{json::Parser, Ignore},
    request::{RequestProperty, RequestPropertyParser},
};

#[derive(Debug, Clone, Default)]
pub struct GetArguments {
    pub offset: Option<usize>,
    pub length: Option<usize>,
}

impl RequestPropertyParser for GetArguments {
    fn parse(
        &mut self,
        parser: &mut Parser,
        property: RequestProperty,
    ) -> crate::parser::Result<bool> {
        match &property.hash[0] {
            0x7465_7366_666f => {
                self.offset = parser
                    .next_token::<Ignore>()?
                    .unwrap_usize_or_null("offset")?;
            }
            0x6874_676e_656c => {
                self.length = parser
                    .next_token::<Ignore>()?
                    .unwrap_usize_or_null("length")?;
            }
            _ => return Ok(false),
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn gen_ids() {
        for label in ["sha-256", "sha-512"] {
            let mut iter = label.chars();
            let mut hash = [0; 2];
            let mut shift = 0;

            'outer: for hash in hash.iter_mut() {
                for ch in iter.by_ref() {
                    *hash |= (ch as u128) << shift;
                    shift += 8;
                    if shift == 128 {
                        shift = 0;
                        continue 'outer;
                    }
                }
                break;
            }

            print!(
                "0x{}",
                format!("{:032x}", hash[0])
                    .chars()
                    .collect::<Vec<_>>()
                    .chunks_exact(4)
                    .map(|chunk| chunk.iter().collect::<String>())
                    .collect::<Vec<_>>()
                    .join("_")
                    .replace("0000_", "")
            );
            if hash[1] != 0 {
                print!(
                    ", 0x{}",
                    format!("{:032x}", hash[1])
                        .chars()
                        .collect::<Vec<_>>()
                        .chunks_exact(4)
                        .map(|chunk| chunk.iter().collect::<String>())
                        .collect::<Vec<_>>()
                        .join("_")
                        .replace("0000_", "")
                );
            }
            println!(" => Property::{},", label);
        }
    }
}
