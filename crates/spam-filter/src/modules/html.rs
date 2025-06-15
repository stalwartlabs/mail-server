/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::CompactString;
use mail_parser::decoders::html::add_html_token;

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum HtmlToken {
    StartTag {
        name: u64,
        attributes: Vec<(u64, Option<CompactString>)>,
        is_self_closing: bool,
    },
    EndTag {
        name: u64,
    },
    Comment {
        text: CompactString,
    },
    Text {
        text: CompactString,
    },
}

pub(crate) const A: u64 = b'a' as u64;
pub(crate) const IMG: u64 = (b'i' as u64) | ((b'm' as u64) << 8) | ((b'g' as u64) << 16);
pub(crate) const HEAD: u64 =
    (b'h' as u64) | ((b'e' as u64) << 8) | ((b'a' as u64) << 16) | ((b'd' as u64) << 24);
pub(crate) const BODY: u64 =
    (b'b' as u64) | ((b'o' as u64) << 8) | ((b'd' as u64) << 16) | ((b'y' as u64) << 24);
pub(crate) const META: u64 =
    (b'm' as u64) | ((b'e' as u64) << 8) | ((b't' as u64) << 16) | ((b'a' as u64) << 24);
pub(crate) const LINK: u64 =
    (b'l' as u64) | ((b'i' as u64) << 8) | ((b'n' as u64) << 16) | ((b'k' as u64) << 24);

pub(crate) const HREF: u64 =
    (b'h' as u64) | ((b'r' as u64) << 8) | ((b'e' as u64) << 16) | ((b'f' as u64) << 24);
pub(crate) const SRC: u64 = (b's' as u64) | ((b'r' as u64) << 8) | ((b'c' as u64) << 16);
pub(crate) const WIDTH: u64 = (b'w' as u64)
    | ((b'i' as u64) << 8)
    | ((b'd' as u64) << 16)
    | ((b't' as u64) << 24)
    | ((b'h' as u64) << 32);
pub(crate) const HEIGHT: u64 = (b'h' as u64)
    | ((b'e' as u64) << 8)
    | ((b'i' as u64) << 16)
    | ((b'g' as u64) << 24)
    | ((b'h' as u64) << 32)
    | ((b't' as u64) << 40);
pub(crate) const REL: u64 = (b'r' as u64) | ((b'e' as u64) << 8) | ((b'l' as u64) << 16);
pub(crate) const CONTENT: u64 = (b'c' as u64)
    | ((b'o' as u64) << 8)
    | ((b'n' as u64) << 16)
    | ((b't' as u64) << 24)
    | ((b'e' as u64) << 32)
    | ((b'n' as u64) << 40)
    | ((b't' as u64) << 48);
pub(crate) const HTTP_EQUIV: u64 = (b'h' as u64)
    | ((b't' as u64) << 8)
    | ((b't' as u64) << 16)
    | ((b'p' as u64) << 24)
    | ((b'-' as u64) << 32)
    | ((b'e' as u64) << 40)
    | ((b'q' as u64) << 48)
    | ((b'u' as u64) << 56);

pub fn html_to_tokens(input: &str) -> Vec<HtmlToken> {
    let input = input.as_bytes();
    let mut iter = input.iter().enumerate().peekable();
    let mut tags = vec![];

    let mut is_token_start = true;
    let mut is_after_space = false;
    let mut is_new_line = true;

    let mut token_start = 0;
    let mut token_end = 0;

    let mut text = String::with_capacity(16);

    while let Some((mut pos, &ch)) = iter.next() {
        match ch {
            b'<' => {
                if !is_token_start {
                    add_html_token(
                        &mut text,
                        &input[token_start..token_end + 1],
                        is_after_space,
                    );
                    is_after_space = false;
                    is_token_start = true;
                }
                if !text.is_empty() {
                    tags.push(HtmlToken::Text {
                        text: text.as_str().into(),
                    });
                    text.clear();
                }

                while matches!(iter.peek(), Some(&(_, &ch)) if ch.is_ascii_whitespace()) {
                    pos += 1;
                    iter.next();
                }

                if matches!(input.get(pos + 1..pos + 4), Some(b"!--")) {
                    let mut comment = Vec::new();
                    let mut last_ch: u8 = 0;
                    for (_, &ch) in iter.by_ref() {
                        match ch {
                            b'>' if comment.len() > 2
                                && matches!(comment.last(), Some(b'-'))
                                && matches!(comment.get(comment.len() - 2), Some(b'-')) =>
                            {
                                break;
                            }
                            b' ' | b'\t' | b'\r' | b'\n' => {
                                if last_ch != b' ' {
                                    comment.push(b' ');
                                } else {
                                    last_ch = b' ';
                                }
                                continue;
                            }
                            _ => {
                                comment.push(ch);
                            }
                        }
                        last_ch = ch;
                    }
                    tags.push(HtmlToken::Comment {
                        text: CompactString::from_utf8(comment).unwrap_or_default(),
                    });
                } else {
                    let mut is_end_tag = false;
                    loop {
                        match iter.peek() {
                            Some(&(_, &b'/')) => {
                                is_end_tag = true;
                                pos += 1;
                                iter.next();
                            }
                            Some((_, ch)) if ch.is_ascii_whitespace() => {
                                pos += 1;
                                iter.next();
                            }
                            _ => break,
                        }
                    }

                    let mut in_quote = false;
                    let mut is_self_closing = false;

                    let mut key: u64 = 0;
                    let mut shift = 0;

                    let mut tag = 0;
                    let mut attributes: Vec<(u64, Option<CompactString>)> = vec![];

                    'outer: while let Some((_, &ch)) = iter.next() {
                        match ch {
                            b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' if shift < 64 => {
                                key |= (ch as u64) << shift;
                                shift += 8;
                            }
                            b'A'..=b'Z' if shift < 64 => {
                                key |= ((ch - b'A' + b'a') as u64) << shift;
                                shift += 8;
                            }
                            b'/' if !in_quote => {
                                is_self_closing = true;
                            }
                            b'>' if !in_quote => {
                                if shift != 0 {
                                    if tag == 0 {
                                        tag = key;
                                    } else {
                                        attributes.push((key, None));
                                    }
                                }
                                break;
                            }
                            b'"' => {
                                in_quote = !in_quote;
                            }
                            b'=' if !in_quote => {
                                while matches!(iter.peek(), Some(&(_, &ch)) if ch.is_ascii_whitespace())
                                {
                                    iter.next();
                                }

                                if shift != 0 {
                                    attributes.push((key, None));
                                    key = 0;
                                    shift = 0;
                                }

                                let mut value = vec![];

                                for (_, &ch) in iter.by_ref() {
                                    match ch {
                                        b'>' if !in_quote => {
                                            if !value.is_empty() {
                                                let value = CompactString::from_utf8(value)
                                                    .unwrap_or_default();
                                                if let Some((_, v)) = attributes.last_mut() {
                                                    *v = value.into();
                                                } else {
                                                    // Broken attribute
                                                    attributes.push((0, Some(value)));
                                                }
                                            }
                                            break 'outer;
                                        }
                                        b'"' => {
                                            if in_quote {
                                                in_quote = false;
                                                break;
                                            } else {
                                                in_quote = true;
                                            }
                                        }
                                        b' ' | b'\t' | b'\r' | b'\n' if !in_quote => {
                                            break;
                                        }
                                        _ => {
                                            value.push(ch);
                                        }
                                    }
                                }

                                if !value.is_empty() {
                                    let value = CompactString::from_utf8(value).unwrap_or_default();
                                    if let Some((_, v)) = attributes.last_mut() {
                                        *v = value.into();
                                    } else {
                                        // Broken attribute
                                        attributes.push((0, Some(value)));
                                    }
                                }
                            }
                            b' ' | b'\t' | b'\r' | b'\n' => {
                                if shift != 0 {
                                    if tag == 0 {
                                        tag = key;
                                    } else {
                                        attributes.push((key, None));
                                    }
                                    key = 0;
                                    shift = 0;
                                }
                            }
                            _ => {}
                        }
                    }

                    if tag != 0 {
                        if is_end_tag {
                            tags.push(HtmlToken::EndTag { name: tag });
                        } else {
                            tags.push(HtmlToken::StartTag {
                                name: tag,
                                attributes,
                                is_self_closing,
                            });
                        }
                    }
                }
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => {
                if !is_token_start {
                    add_html_token(
                        &mut text,
                        &input[token_start..token_end + 1],
                        is_after_space && !is_new_line,
                    );
                    is_new_line = false;
                }
                is_after_space = true;
                is_token_start = true;
                continue;
            }
            b'&' if !is_token_start => {
                add_html_token(
                    &mut text,
                    &input[token_start..token_end + 1],
                    is_after_space && !is_new_line,
                );
                is_new_line = false;
                is_token_start = true;
                is_after_space = false;
            }
            b';' if !is_token_start => {
                add_html_token(
                    &mut text,
                    &input[token_start..pos + 1],
                    is_after_space && !is_new_line,
                );
                is_token_start = true;
                is_after_space = false;
                is_new_line = false;
                continue;
            }
            _ => (),
        }

        if is_token_start {
            token_start = pos;
            is_token_start = false;
        }
        token_end = pos;
    }

    if !is_token_start {
        add_html_token(
            &mut text,
            &input[token_start..token_end + 1],
            is_after_space && !is_new_line,
        );
    }
    if !text.is_empty() {
        tags.push(HtmlToken::Text {
            text: text.as_str().into(),
        });
    }

    tags
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_to_tokens_text() {
        let input = "Hello, world!";
        let tokens = html_to_tokens(input);
        assert_eq!(
            tokens,
            vec![HtmlToken::Text {
                text: "Hello, world!".into()
            }]
        );
    }

    #[test]
    fn test_html_to_tokens_start_tag() {
        let input = "<div>";
        let tokens = html_to_tokens(input);
        assert_eq!(
            tokens,
            vec![HtmlToken::StartTag {
                name: 7760228,
                attributes: vec![],
                is_self_closing: false
            }]
        );
    }

    #[test]
    fn test_html_to_tokens_end_tag() {
        let input = "</div>";
        let tokens = html_to_tokens(input);
        assert_eq!(tokens, vec![HtmlToken::EndTag { name: 7760228 }]);
    }

    #[test]
    fn test_html_to_tokens_comment() {
        let input = "<!-- This is a comment -->";
        let tokens = html_to_tokens(input);
        assert_eq!(
            tokens,
            vec![HtmlToken::Comment {
                text: "!-- This is a comment --".into()
            }]
        );
    }

    #[test]
    fn test_html_to_tokens_mixed() {
        let input = "<div>Hello, <span>&quot; world &quot; </span>!</div>";
        let tokens = html_to_tokens(input);
        assert_eq!(
            tokens,
            vec![
                HtmlToken::StartTag {
                    name: 7760228,
                    attributes: vec![],
                    is_self_closing: false
                },
                HtmlToken::Text {
                    text: "Hello,".into()
                },
                HtmlToken::StartTag {
                    name: 1851879539,
                    attributes: vec![],
                    is_self_closing: false
                },
                HtmlToken::Text {
                    text: " \" world \"".into()
                },
                HtmlToken::EndTag { name: 1851879539 },
                HtmlToken::Text { text: " !".into() },
                HtmlToken::EndTag { name: 7760228 }
            ]
        );
    }

    #[test]
    fn test_html_to_tokens_with_attributes() {
        let input = r#"<input type="text" value="test"><single/><one attr/><a b=1 b c="123">"#;
        let tokens = html_to_tokens(input);
        assert_eq!(
            tokens,
            vec![
                HtmlToken::StartTag {
                    name: 500186508905,
                    attributes: vec![
                        (1701869940, Some("text".into())),
                        (435761734006, Some("test".into()))
                    ],
                    is_self_closing: false
                },
                HtmlToken::StartTag {
                    name: 111516266162547,
                    attributes: vec![],
                    is_self_closing: true
                },
                HtmlToken::StartTag {
                    name: 6647407,
                    attributes: vec![(1920234593, None)],
                    is_self_closing: true
                },
                HtmlToken::StartTag {
                    name: 97,
                    attributes: vec![(98, Some("1".into())), (98, None), (99, Some("123".into()))],
                    is_self_closing: false
                }
            ]
        );
    }
}
