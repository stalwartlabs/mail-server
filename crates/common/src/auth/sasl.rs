/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_send::Credentials;

pub fn sasl_decode_challenge_plain(challenge: &[u8]) -> Option<Credentials<String>> {
    let mut username = Vec::new();
    let mut secret = Vec::new();
    let mut arg_num = 0;
    for &ch in challenge {
        if ch != 0 {
            if arg_num == 1 {
                username.push(ch);
            } else if arg_num == 2 {
                secret.push(ch);
            }
        } else {
            arg_num += 1;
        }
    }

    match (String::from_utf8(username), String::from_utf8(secret)) {
        (Ok(username), Ok(secret)) if !username.is_empty() && !secret.is_empty() => {
            Some((username, secret).into())
        }
        _ => None,
    }
}

pub fn sasl_decode_challenge_oauth(challenge: &[u8]) -> Option<Credentials<String>> {
    extract_oauth_bearer(challenge).map(|s| Credentials::OAuthBearer { token: s.into() })
}

fn extract_oauth_bearer(bytes: &[u8]) -> Option<&str> {
    let mut start_pos = 0;
    let eof = bytes.len().saturating_sub(1);

    for (pos, ch) in bytes.iter().enumerate() {
        let is_separator = *ch == 1;
        if is_separator || pos == eof {
            if bytes
                .get(start_pos..start_pos + 12)
                .is_some_and(|s| s.eq_ignore_ascii_case(b"auth=Bearer "))
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
