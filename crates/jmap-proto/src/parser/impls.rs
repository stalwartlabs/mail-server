/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use utils::map::{
    bitmap::{Bitmap, BitmapItem},
    vec_map::VecMap,
};

use super::{json::Parser, Ignore, JsonObjectParser, Token};

impl JsonObjectParser for u64 {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut hash = 0;
        let mut shift = 0;

        while let Some(ch) = parser.next_unescaped()? {
            if shift < 64 {
                hash |= (ch as u64) << shift;
                shift += 8;
            } else {
                hash = 0;
                break;
            }
        }

        Ok(hash)
    }
}

impl JsonObjectParser for u128 {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut hash = 0;
        let mut shift = 0;

        while let Some(ch) = parser.next_unescaped()? {
            if shift < 128 {
                hash |= (ch as u128) << shift;
                shift += 8;
            } else {
                hash = 0;
                break;
            }
        }

        Ok(hash)
    }
}

impl JsonObjectParser for String {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let start_pos = parser.pos;

        while let Some(ch) = parser.next_char() {
            match ch {
                b'\\' => {
                    let mut is_escaped = true;
                    let mut buf = Vec::with_capacity((parser.pos - start_pos) + 16);
                    buf.extend_from_slice(&parser.bytes[start_pos..parser.pos - 1]);

                    while let Some(ch) = parser.next_char() {
                        match ch {
                            b'\\' if !is_escaped => {
                                is_escaped = true;
                            }
                            b'"' if !is_escaped => {
                                parser.is_eof = true;
                                return String::from_utf8(buf)
                                    .map(Into::into)
                                    .map_err(|_| parser.error_utf8());
                            }
                            _ => {
                                if !is_escaped {
                                    buf.push(ch);
                                } else {
                                    match ch {
                                        b'"' => {
                                            buf.push(b'"');
                                        }
                                        b'\\' => {
                                            buf.push(b'\\');
                                        }
                                        b'n' => {
                                            buf.push(b'\n');
                                        }
                                        b't' => {
                                            buf.push(b'\t');
                                        }
                                        b'r' => {
                                            buf.push(b'\r');
                                        }
                                        b'b' => {
                                            buf.push(0x08);
                                        }
                                        b'f' => {
                                            buf.push(0x0c);
                                        }
                                        b'/' => {
                                            buf.push(b'/');
                                        }
                                        b'u' => {
                                            let mut code = [
                                                *parser.iter.next().ok_or_else(|| {
                                                    parser.error("Incomplete unicode sequence")
                                                })?,
                                                *parser.iter.next().ok_or_else(|| {
                                                    parser.error("Incomplete unicode sequence")
                                                })?,
                                                *parser.iter.next().ok_or_else(|| {
                                                    parser.error("Incomplete unicode sequence")
                                                })?,
                                                *parser.iter.next().ok_or_else(|| {
                                                    parser.error("Incomplete unicode sequence")
                                                })?,
                                            ];
                                            parser.pos += 4;
                                            let code_str = std::str::from_utf8(&code)
                                                .map_err(|_| parser.error_utf8())?;
                                            let code_str = char::from_u32(
                                                u32::from_str_radix(code_str, 16).map_err(
                                                    |_| {
                                                        parser.error(&format!(
                                                            "Invalid unicode sequence {code_str}"
                                                        ))
                                                    },
                                                )?,
                                            )
                                            .ok_or_else(|| {
                                                parser.error(&format!(
                                                    "Invalid unicode sequence {code_str}"
                                                ))
                                            })?
                                            .encode_utf8(&mut code);
                                            buf.extend_from_slice(code_str.as_bytes());
                                        }
                                        _ => {
                                            buf.push(ch);
                                        }
                                    }
                                    is_escaped = false;
                                }
                            }
                        }
                    }
                    break;
                }
                b'"' => {
                    parser.is_eof = true;
                    return std::str::from_utf8(
                        parser
                            .bytes
                            .get(start_pos..parser.pos - 1)
                            .unwrap_or_default(),
                    )
                    .map(Into::into)
                    .map_err(|_| parser.error_utf8());
                }
                _ => (),
            }
        }

        Err(parser.error_unterminated())
    }
}

impl<T: JsonObjectParser + Eq> JsonObjectParser for Vec<T> {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut vec = Vec::new();

        parser.next_token::<Ignore>()?.assert(Token::ArrayStart)?;
        loop {
            match parser.next_token::<T>()? {
                Token::String(item) => vec.push(item),
                Token::Comma => (),
                Token::ArrayEnd => break,
                token => return Err(token.error("", "[ or string")),
            }
        }
        Ok(vec)
    }
}

impl<T: JsonObjectParser + Eq> JsonObjectParser for Option<Vec<T>> {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        match parser.next_token::<Ignore>()? {
            Token::ArrayStart => {
                let mut vec = Vec::new();
                loop {
                    match parser.next_token::<T>()? {
                        Token::String(item) => vec.push(item),
                        Token::Comma => (),
                        Token::ArrayEnd => break,
                        token => return Err(token.error("", "string")),
                    }
                }
                Ok(Some(vec))
            }
            Token::Null => Ok(None),
            token => Err(token.error("", "array or null")),
        }
    }
}

impl<T: JsonObjectParser + Eq + BitmapItem> JsonObjectParser for Bitmap<T> {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut bm = Bitmap::new();
        match parser.next_token::<Ignore>()? {
            Token::ArrayStart => {
                loop {
                    match parser.next_token::<T>()? {
                        Token::String(item) => bm.insert(item),
                        Token::Comma => (),
                        Token::ArrayEnd => break,
                        token => return Err(token.error("", "string")),
                    }
                }
                Ok(bm)
            }
            Token::Null => Ok(bm),
            token => Err(token.error("", "array or null")),
        }
    }
}

impl<K: JsonObjectParser + Eq + Display, V: JsonObjectParser> JsonObjectParser for VecMap<K, V> {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut map = VecMap::new();

        parser.next_token::<Ignore>()?.assert(Token::DictStart)?;
        while let Some(key) = parser.next_dict_key()? {
            map.append(key, V::parse(parser)?);
        }

        Ok(map)
    }
}

impl<K: JsonObjectParser + Eq + Display, V: JsonObjectParser> JsonObjectParser
    for Option<VecMap<K, V>>
{
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        match parser.next_token::<Ignore>()? {
            Token::DictStart => {
                let mut map = VecMap::new();

                while let Some(key) = parser.next_dict_key()? {
                    map.append(key, V::parse(parser)?);
                }

                Ok(Some(map))
            }
            Token::Null => Ok(None),
            token => Err(token.error("", &token.to_string())),
        }
    }
}

impl JsonObjectParser for bool {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        match parser.next_token::<Ignore>()? {
            Token::Boolean(value) => Ok(value),
            Token::Null => Ok(false),
            token => Err(token.error("", &token.to_string())),
        }
    }
}

impl JsonObjectParser for Ignore {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        if parser.skip_string() {
            Ok(Ignore {})
        } else {
            Err(parser.error_unterminated())
        }
    }
}
