/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod crypto;
pub mod token;

pub const DEVICE_CODE_LEN: usize = 40;
pub const USER_CODE_LEN: usize = 8;
pub const RANDOM_CODE_LEN: usize = 32;
pub const CLIENT_ID_MAX_LEN: usize = 20;

pub const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No 0, O, I, 1

pub fn extract_oauth_bearer(bytes: &[u8]) -> Option<&str> {
    let mut start_pos = 0;
    let eof = bytes.len().saturating_sub(1);

    for (pos, ch) in bytes.iter().enumerate() {
        let is_separator = *ch == 1;
        if is_separator || pos == eof {
            if bytes
                .get(start_pos..start_pos + 12)
                .map_or(false, |s| s.eq_ignore_ascii_case(b"auth=Bearer "))
            {
                return bytes
                    .get(start_pos + 12..if is_separator { pos } else { bytes.len() })
                    .and_then(|s| std::str::from_utf8(s).ok());
            }

            start_pos = pos + 1;
        }
    }

    None
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_oauth_bearer() {
        let input = b"auth=Bearer validtoken";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, Some("validtoken"));

        let input = b"auth=Invalid validtoken";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, None);

        let input = b"auth=Bearer";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, None);

        let input = b"";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, None);

        let input = b"auth=Bearer token1\x01auth=Bearer token2";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, Some("token1"));

        let input = b"auth=Bearer VALIDTOKEN";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, Some("VALIDTOKEN"));

        let input = b"auth=Bearer token with spaces";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, Some("token with spaces"));

        let input = b"auth=Bearer token_with_special_chars!@#";
        let result = extract_oauth_bearer(input);
        assert_eq!(result, Some("token_with_special_chars!@#"));

        let input = "n,a=user@example.com,\x01host=server.example.com\x01port=143\x01auth=Bearer vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==\x01\x01";
        let result = extract_oauth_bearer(input.as_bytes());
        assert_eq!(result, Some("vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg=="));
    }
}
