/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

// Ported from https://github.com/jstedfast/MailKit/blob/master/MailKit/Net/Imap/ImapEncoding.cs
// Author: Jeffrey Stedfast <jestedfa@microsoft.com>

use crate::protocol::ProtocolVersion;

static UTF_7_RANK: &[u8] = &[
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 62, 63, 255, 255, 255, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255,
    255, 255, 255, 255, 255, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255, 255, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 255, 255, 255, 255, 255,
];

static UTF_7_MAP: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

pub fn utf7_decode(text: &[u8]) -> Option<String> {
    let mut bytes: Vec<u16> = Vec::with_capacity(text.len());
    let mut bits = 0;
    let mut v: u32 = 0;
    let mut shifted = false;
    let mut text = text.iter().peekable();

    while let Some(&ch) = text.next() {
        if shifted {
            if ch == b'-' {
                shifted = false;
                bits = 0;
                v = 0;
            } else if ch > 127 {
                return None;
            } else {
                let rank = *UTF_7_RANK.get(ch as usize)?;

                if rank == 0xff {
                    return None;
                }

                v = (v << 6) | rank as u32;
                bits += 6;

                if bits >= 16 {
                    bytes.push(((v >> (bits - 16)) & 0xffff) as u16);
                    bits -= 16;
                }
            }
        } else if ch == b'&' {
            match text.peek() {
                Some(b'-') => {
                    bytes.push(b'&' as u16);
                    text.next();
                }
                Some(_) => {
                    shifted = true;
                }
                None => {
                    bytes.push(ch as u16);
                }
            }
        } else {
            bytes.push(ch as u16);
        }
    }

    String::from_utf16(&bytes).ok()
}

pub fn utf7_encode(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut shifted = false;
    let mut bits = 0;
    let mut u: u32 = 0;

    for ch_ in text.chars() {
        let ch = ch_ as u16;

        if (0x20..0x7f).contains(&ch) {
            if shifted {
                if bits > 0 {
                    result.push(char::from(UTF_7_MAP[((u << (6 - bits)) & 0x3f) as usize]));
                }
                result.push('-');
                shifted = false;
                bits = 0;
            }

            if ch == 0x26 {
                result.push_str("&-");
            } else {
                result.push(ch_);
            }
        } else {
            if !shifted {
                result.push('&');
                shifted = true;
            }

            u = (u << 16) | ch as u32;
            bits += 16;

            while bits >= 6 {
                result.push(char::from(UTF_7_MAP[((u >> (bits - 6)) & 0x3f) as usize]));
                bits -= 6;
            }
        }
    }

    if shifted {
        if bits > 0 {
            result.push(char::from(UTF_7_MAP[((u << (6 - bits)) & 0x3f) as usize]));
        }
        result.push('-');
    }

    result
}

#[inline(always)]
pub fn utf7_maybe_decode(text: String, version: ProtocolVersion) -> String {
    if version.is_rev2() {
        text
    } else {
        utf7_decode(text.as_bytes()).unwrap_or(text)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn utf7_decode() {
        for (input, expected_result) in [
            ("~peter/mail/&U,BTFw-/&ZeVnLIqe-", "~peter/mail/台北/日本語"),
            ("&U,BTF2XlZyyKng-", "台北日本語"),
            ("Hello, World&ACE-", "Hello, World!"),
            ("Hi Mom -&Jjo--!", "Hi Mom -☺-!"),
            ("&ZeVnLIqe-", "日本語"),
            ("Item 3 is &AKM-1.", "Item 3 is £1."),
            ("Plus minus &- -&- &--", "Plus minus & -& &-"),
            (
                "&APw-ber ihre mi&AN8-liche Lage&ADs- &ACI-wir",
                "über ihre mißliche Lage; \"wir",
            ),
            (
                concat!(
                    "&ACI-The sayings of Confucius,&ACI- James R. Ware, trans.  &U,BTFw-:\n",
                    "&ZYeB9FH6ckh5Pg-, 1980.\n",
                    "&Vttm+E6UfZM-, &W4tRQ066bOg-, &UxdOrA-:  &Ti1XC2b4Xpc-, 1990."
                ),
                concat!(
                    "\"The sayings of Confucius,\" James R. Ware, trans.  台北:\n",
                    "文致出版社, 1980.\n",
                    "四書五經, 宋元人注, 北京:  中國書店, 1990."
                ),
            ),
        ] {
            assert_eq!(
                super::utf7_decode(input.as_bytes()).expect(input),
                expected_result,
                "while decoding {:?}",
                input
            );
        }
    }

    #[test]
    fn utf7_encode() {
        for (expected_result, input) in [
            ("~peter/mail/&U,BTFw-/&ZeVnLIqe-", "~peter/mail/台北/日本語"),
            ("&U,BTF2XlZyyKng-", "台北日本語"),
            ("Hi Mom -&Jjo--!", "Hi Mom -☺-!"),
            ("&ZeVnLIqe-", "日本語"),
            ("Item 3 is &AKM-1.", "Item 3 is £1."),
            ("Plus minus &- -&- &--", "Plus minus & -& &-"),
        ] {
            assert_eq!(
                super::utf7_encode(input),
                expected_result,
                "while encoding {:?}",
                expected_result
            );
        }
    }
}
