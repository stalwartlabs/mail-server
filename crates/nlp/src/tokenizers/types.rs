/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart Mail Server.
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

use std::str::CharIndices;

use utils::suffixlist::PublicSuffix;

use super::Token;

pub struct TypesTokenizer<'x, 'y> {
    text: &'x str,
    suffixes: &'y PublicSuffix,
    iter: CharIndices<'x>,
    tokens: Vec<Token<TokenType<&'x str>>>,
    peek_pos: usize,
    last_ch_is_space: bool,
    last_token_is_dot: bool,
    eof: bool,
    tokenize_urls: bool,
    tokenize_urls_without_scheme: bool,
    tokenize_emails: bool,
    tokenize_numbers: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType<T> {
    Alphabetic(T),
    Alphanumeric(T),
    Integer(T),
    Other(char),
    Punctuation(char),
    Space,

    // Detected types
    Url(T),
    UrlNoScheme(T),
    UrlNoHost(T),
    IpAddr(T),
    Email(T),
    Float(T),
}

impl Copy for Token<TokenType<&'_ str>> {}

impl<'x, 'y> Iterator for TypesTokenizer<'x, 'y> {
    type Item = Token<TokenType<&'x str>>;

    fn next(&mut self) -> Option<Self::Item> {
        let token = self.peek()?;
        let last_is_dot = self.last_token_is_dot;
        self.last_token_is_dot = matches!(token.word, TokenType::Punctuation('.'));

        // Try parsing URL with scheme
        if self.tokenize_urls
            && matches!(
            token.word,
            TokenType::Alphabetic(t) | TokenType::Alphanumeric(t)
            if t.len() <= 8 && t.chars().all(|c| c.is_ascii()))
            && self.try_skip_url_scheme()
        {
            if let Some(url) = self.try_parse_url(token.into()) {
                self.peek_advance();
                return Some(url);
            } else {
                self.peek_rewind();
            }
        }

        // Try parsing email
        if self.tokenize_emails
            && token.word.is_email_atom()
            && self.peek_has_tokens(
                &[TokenType::Punctuation('@'), TokenType::Punctuation('.')],
                TokenType::Space,
            )
        {
            if let Some(email) = self.try_parse_email() {
                self.peek_advance();
                return Some(email);
            } else {
                self.peek_rewind();
            }
        }

        // Try parsing URL without scheme
        if self.tokenize_urls_without_scheme
            && token.word.is_domain_atom(true)
            && self.peek_has_tokens(&[TokenType::Punctuation('.')], TokenType::Space)
        {
            if let Some(url) = self.try_parse_url(None) {
                self.peek_advance();
                return Some(url);
            } else {
                self.peek_rewind();
            }
        }

        // Try parsing currencies and floating point numbers
        if self.tokenize_numbers && !last_is_dot {
            if let Some(num) = self.try_parse_number() {
                self.peek_advance();
                return Some(num);
            }
        }

        self.peek_rewind();
        self.next_()
    }
}

impl<'x, 'y> TypesTokenizer<'x, 'y> {
    pub fn new(text: &'x str, suffixes: &'y PublicSuffix) -> Self {
        Self {
            text,
            iter: text.char_indices(),
            tokens: Vec::new(),
            eof: false,
            peek_pos: 0,
            suffixes,
            last_ch_is_space: false,
            last_token_is_dot: false,
            tokenize_urls: true,
            tokenize_urls_without_scheme: true,
            tokenize_emails: true,
            tokenize_numbers: true,
        }
    }

    pub fn tokenize_urls(mut self, tokenize: bool) -> Self {
        self.tokenize_urls = tokenize;
        self
    }

    pub fn tokenize_urls_without_scheme(mut self, tokenize: bool) -> Self {
        self.tokenize_urls_without_scheme = tokenize;
        self
    }

    pub fn tokenize_emails(mut self, tokenize: bool) -> Self {
        self.tokenize_emails = tokenize;
        self
    }

    pub fn tokenize_numbers(mut self, tokenize: bool) -> Self {
        self.tokenize_numbers = tokenize;
        self
    }

    fn consume(&mut self) -> bool {
        let mut has_alpha = false;
        let mut has_number = false;

        let mut start_pos = usize::MAX;
        let mut end_pos = usize::MAX;

        let mut stop_char = None;

        for (pos, ch) in self.iter.by_ref() {
            if ch.is_alphabetic() {
                has_alpha = true;
            } else if ch.is_ascii_digit() {
                has_number = true;
            } else {
                let last_was_space = self.last_ch_is_space;
                self.last_ch_is_space = ch.is_ascii_whitespace();
                stop_char = Token {
                    word: if self.last_ch_is_space {
                        if last_was_space {
                            continue;
                        } else {
                            TokenType::Space
                        }
                    } else if ch.is_ascii() {
                        TokenType::Punctuation(ch)
                    } else {
                        TokenType::Other(ch)
                    },
                    from: pos,
                    to: pos + ch.len_utf8(),
                }
                .into();
                break;
            }
            self.last_ch_is_space = false;

            if start_pos == usize::MAX {
                start_pos = pos;
            }
            end_pos = pos + ch.len_utf8();
        }

        if start_pos != usize::MAX {
            let text = &self.text[start_pos..end_pos];

            self.tokens.push(Token {
                word: if has_alpha && has_number {
                    TokenType::Alphanumeric(text)
                } else if has_alpha {
                    TokenType::Alphabetic(text)
                } else {
                    TokenType::Integer(text)
                },
                from: start_pos,
                to: end_pos,
            });
            if let Some(stop_char) = stop_char {
                self.tokens.push(stop_char);
            }
            true
        } else if let Some(stop_char) = stop_char {
            self.tokens.push(stop_char);
            true
        } else {
            self.eof = true;
            false
        }
    }

    fn next_(&mut self) -> Option<Token<TokenType<&'x str>>> {
        if self.tokens.is_empty() && !self.eof {
            self.consume();
        }
        if !self.tokens.is_empty() {
            Some(self.tokens.remove(0))
        } else {
            None
        }
    }

    fn peek(&mut self) -> Option<Token<TokenType<&'x str>>> {
        while self.tokens.len() <= self.peek_pos && !self.eof {
            self.consume();
        }
        self.tokens.get(self.peek_pos).map(|t| {
            self.peek_pos += 1;
            *t
        })
    }

    fn peek_advance(&mut self) {
        if self.peek_pos > 0 {
            self.tokens.drain(..self.peek_pos);
            self.peek_pos = 0;
        }
    }

    fn peek_rewind(&mut self) {
        self.peek_pos = 0;
    }

    fn peek_has_tokens(
        &mut self,
        tokens: &[TokenType<&'_ str>],
        stop_token: TokenType<&'_ str>,
    ) -> bool {
        let mut tokens = tokens.iter().copied();
        let mut token = tokens.next().unwrap();
        while let Some(t) = self.peek() {
            if t.word == token {
                if let Some(next_token) = tokens.next() {
                    token = next_token;
                } else {
                    self.peek_rewind();
                    return true;
                }
            } else if t.word == stop_token {
                break;
            }
        }

        self.peek_rewind();
        false
    }

    fn try_parse_url(
        &mut self,
        scheme_token: Option<Token<TokenType<&'_ str>>>,
    ) -> Option<Token<TokenType<&'x str>>> {
        let (has_scheme, allow_blank_host) = scheme_token.as_ref().map_or((false, false), |t| {
            (
                true,
                matches!(t.word, TokenType::Alphabetic(s) if s.eq_ignore_ascii_case("file")),
            )
        });
        if has_scheme {
            let restore_pos = self.peek_pos;
            let mut has_user_info = false;
            while let Some(token) = self.peek() {
                match token.word {
                    TokenType::Punctuation('@') => {
                        has_user_info = true;
                        break;
                    }
                    TokenType::Alphabetic(_)
                    | TokenType::Alphanumeric(_)
                    | TokenType::Integer(_)
                    | TokenType::Punctuation(
                        '-' | '.' | '_' | '~' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+'
                        | ',' | ';' | '=' | ':',
                    ) => (),
                    _ => break,
                }
            }

            if !has_user_info {
                self.peek_pos = restore_pos;
            }
        }

        // Try parsing hostname
        let mut is_valid_host = true;
        let (host_start_pos, mut end_pos, is_ip) = if has_scheme {
            let mut start_pos = usize::MAX;
            let mut end_pos = usize::MAX;
            let mut restore_pos = self.peek_pos;

            let mut text_count = 0;
            let mut int_count = 0;
            let mut dot_count = 0;
            let mut is_ipv6 = false;

            let mut last_label_is_tld = false;

            while let Some(token) = self.peek() {
                match token.word {
                    TokenType::Alphabetic(text) | TokenType::Alphanumeric(text) => {
                        last_label_is_tld =
                            text.len() >= 2 && self.suffixes.contains(&text.to_ascii_lowercase());
                        text_count += 1;
                    }
                    TokenType::Integer(text) => {
                        if text.len() <= 3 {
                            int_count += 1;
                        }
                    }
                    TokenType::Punctuation('.') => {
                        dot_count += 1;
                        continue;
                    }
                    TokenType::Punctuation('[') if start_pos == usize::MAX => {
                        let (_, to) = self.try_parse_ipv6(token.from)?;
                        start_pos = token.from;
                        end_pos = to;
                        restore_pos = self.peek_pos;
                        is_ipv6 = true;
                        break;
                    }
                    TokenType::Punctuation(
                        '-' | '_' | '~' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ','
                        | ';' | '=' | ':' | '%',
                    ) => {
                        continue;
                    }
                    TokenType::Punctuation('/') if allow_blank_host => {
                        // Allow file://../ urls
                        end_pos = token.from;
                        restore_pos = self.peek_pos - 1;
                        break;
                    }
                    _ => break,
                }

                if start_pos == usize::MAX {
                    start_pos = token.from;
                }
                end_pos = token.to;
                restore_pos = self.peek_pos;
            }

            self.peek_pos = restore_pos;
            let is_ip = is_ipv6 || (int_count == 4 && dot_count == 3 && text_count == 0);
            if end_pos != usize::MAX {
                is_valid_host =
                    (last_label_is_tld && dot_count >= 1 && (text_count + int_count) >= 2) || is_ip;
                (start_pos, end_pos, is_ip)
            } else {
                return None;
            }
        } else {
            // Strict hostname parsing
            self.try_parse_hostname()?
        };

        // Try parsing port
        let start_pos = scheme_token.map(|t| t.from).unwrap_or(host_start_pos);
        let mut restore_pos = self.peek_pos;
        let mut has_port = false;
        let mut last_is_colon = false;
        let mut found_query_start = false;
        while let Some(token) = self.peek() {
            match token.word {
                TokenType::Punctuation(':') if !last_is_colon && !has_port => {
                    last_is_colon = true;
                }
                TokenType::Integer(_) if last_is_colon => {
                    has_port = true;
                    last_is_colon = false;
                    restore_pos = self.peek_pos;
                    end_pos = token.to;
                }
                TokenType::Punctuation('/' | '?') if !last_is_colon => {
                    found_query_start = true;
                    end_pos = token.to;
                    break;
                }
                _ => {
                    self.peek_pos = restore_pos;
                    break;
                }
            }
        }

        // Try parsing query
        if found_query_start {
            restore_pos = self.peek_pos;
            let mut p_count = 0;
            let mut b_count = 0;
            let mut c_count = 0;
            let mut seen_quote = false;
            while let Some(token) = self.peek() {
                match token.word {
                    TokenType::Alphabetic(_)
                    | TokenType::Alphanumeric(_)
                    | TokenType::Integer(_)
                    | TokenType::Other(_) => {}
                    TokenType::Punctuation('(') => {
                        p_count += 1;
                        continue;
                    }
                    TokenType::Punctuation('[') => {
                        b_count += 1;
                        continue;
                    }
                    TokenType::Punctuation('{') => {
                        c_count += 1;
                        continue;
                    }
                    TokenType::Punctuation(')') if p_count > 0 => {
                        p_count -= 1;
                    }
                    TokenType::Punctuation(']') if b_count > 0 => {
                        b_count -= 1;
                    }
                    TokenType::Punctuation('}') if c_count > 0 => {
                        c_count -= 1;
                    }
                    TokenType::Punctuation('\'') => {
                        if !seen_quote {
                            seen_quote = true;
                            continue;
                        } else {
                            seen_quote = false;
                        }
                    }
                    TokenType::Punctuation('/') => {}
                    TokenType::Punctuation(
                        '-' | '_' | '~' | '!' | '$' | '&' | '*' | '+' | ',' | ';' | '=' | ':' | '%'
                        | '?' | '.' | '@',
                    ) => {
                        continue;
                    }
                    _ => break,
                }
                end_pos = token.to;
                restore_pos = self.peek_pos;
            }
            self.peek_pos = restore_pos;
        }

        let word = &self.text[start_pos..end_pos];
        Token {
            word: if has_scheme {
                if is_valid_host {
                    TokenType::Url(word)
                } else {
                    TokenType::UrlNoHost(word)
                }
            } else if is_ip && !found_query_start {
                TokenType::IpAddr(word)
            } else {
                TokenType::UrlNoScheme(word)
            },
            from: start_pos,
            to: end_pos,
        }
        .into()
    }

    fn try_parse_email(&mut self) -> Option<Token<TokenType<&'x str>>> {
        // Start token is a valid local part atom
        let start_token = self.peek()?;
        let mut last_is_dot = false;

        // Find local part
        loop {
            let token = self.peek()?;
            match token.word {
                word if word.is_email_atom() => {
                    last_is_dot = false;
                }
                TokenType::Punctuation('@') if !last_is_dot => {
                    break;
                }
                TokenType::Punctuation('.') if !last_is_dot => {
                    last_is_dot = true;
                }
                _ => {
                    return None;
                }
            }
        }

        // Obtain domain part
        let (_, end_pos, _) = self.try_parse_hostname()?;

        Token {
            word: TokenType::Email(&self.text[start_token.from..end_pos]),
            from: start_token.from,
            to: end_pos,
        }
        .into()
    }

    fn try_parse_hostname(&mut self) -> Option<(usize, usize, bool)> {
        let mut last_ch = u8::MAX;
        let mut has_int = false;
        let mut has_alpha = false;
        let mut last_label_is_tld = false;

        let mut dot_count = 0;
        let mut start_pos = usize::MAX;
        let mut end_pos = usize::MAX;
        let mut restore_pos = self.peek_pos;

        while let Some(token) = self.peek() {
            match token.word {
                TokenType::Punctuation('.') if last_ch == 0 && start_pos != usize::MAX => {
                    last_ch = b'.';
                    dot_count += 1;
                    continue;
                }
                TokenType::Punctuation('-') if last_ch == 0 || last_ch == b'-' => {
                    last_ch = b'-';
                    continue;
                }
                TokenType::Punctuation('[') if start_pos == usize::MAX => {
                    return self
                        .try_parse_ipv6(token.from)
                        .map(|(from, to)| (from, to, true));
                }
                TokenType::Alphabetic(text) | TokenType::Alphanumeric(text) if text.len() <= 63 => {
                    last_label_is_tld =
                        text.len() >= 2 && self.suffixes.contains(&text.to_ascii_lowercase());
                    has_alpha = true;
                    last_ch = 0;
                }
                TokenType::Other(_) => {
                    has_alpha = true;
                    last_label_is_tld = false;
                    last_ch = 0;
                }
                TokenType::Integer(text) => {
                    if text.len() <= 3 {
                        has_int = true;
                    }
                    last_label_is_tld = false;
                    last_ch = 0;
                }
                _ => {
                    break;
                }
            }

            if start_pos == usize::MAX {
                start_pos = token.from;
            }
            end_pos = token.to;
            restore_pos = self.peek_pos;
        }
        self.peek_pos = restore_pos;

        if last_ch == b'.' {
            dot_count -= 1;
        }

        let is_ipv4 = has_int && !has_alpha && dot_count == 3;
        if end_pos != usize::MAX && dot_count >= 1 && (last_label_is_tld || is_ipv4) {
            (start_pos, end_pos, is_ipv4).into()
        } else {
            None
        }
    }

    fn try_parse_ipv6(&mut self, start_pos: usize) -> Option<(usize, usize)> {
        let mut found_colon = false;
        let mut last_ch = u8::MAX;

        while let Some(token) = self.peek() {
            match token.word {
                TokenType::Integer(_) | TokenType::Alphanumeric(_) => {
                    last_ch = 0;
                }
                TokenType::Punctuation(':') if last_ch != b'.' => {
                    found_colon = true;
                    last_ch = b':';
                }
                TokenType::Punctuation('.') if last_ch == 0 => {
                    last_ch = b'.';
                }
                TokenType::Punctuation(']') if found_colon && last_ch == 0 => {
                    return (start_pos, token.to).into();
                }
                _ => return None,
            }
        }

        None
    }

    fn try_parse_number(&mut self) -> Option<Token<TokenType<&'x str>>> {
        self.peek_rewind();
        let mut start_pos = usize::MAX;
        let mut end_pos = usize::MAX;
        let mut restore_pos = self.peek_pos;

        let mut seen_integer = 0;
        let mut seen_dot = false;

        while let Some(token) = self.peek() {
            match token.word {
                TokenType::Punctuation('-') if start_pos == usize::MAX => {}
                TokenType::Integer(_) if seen_integer == 0 || seen_dot => {
                    seen_integer += 1;
                }
                TokenType::Punctuation('.') if seen_integer != 0 => {
                    if !seen_dot {
                        seen_dot = true;
                        continue;
                    } else {
                        // Avoid parsing num.num.num as floats
                        return None;
                    }
                }
                _ => break,
            }

            if start_pos == usize::MAX {
                start_pos = token.from;
            }
            end_pos = token.to;
            restore_pos = self.peek_pos;
        }

        self.peek_pos = restore_pos;

        if seen_integer > 0 {
            let text = &self.text[start_pos..end_pos];

            Token {
                word: if seen_integer == 2 {
                    TokenType::Float(text)
                } else {
                    TokenType::Integer(text)
                },
                from: start_pos,
                to: end_pos,
            }
            .into()
        } else {
            None
        }
    }

    fn try_skip_url_scheme(&mut self) -> bool {
        enum State {
            None,
            PlusAlpha,
            Colon,
            Slash1,
            Slash2,
        }
        let mut state = State::None;

        while let Some(token) = self.peek() {
            state = match (token.word, state) {
                (TokenType::Punctuation(':'), State::None | State::Colon) => State::Slash1,
                (TokenType::Punctuation('/'), State::Slash1) => State::Slash2,
                (TokenType::Punctuation('/'), State::Slash2) => return true,
                (TokenType::Punctuation('+'), State::None) => State::PlusAlpha,
                (TokenType::Alphabetic(t) | TokenType::Alphanumeric(t), State::PlusAlpha)
                    if t.chars().all(|c| c.is_ascii()) =>
                {
                    State::Colon
                }
                _ => break,
            };
        }
        self.peek_rewind();
        false
    }
}

impl<T> TokenType<T> {
    fn is_email_atom(&self) -> bool {
        matches!(
            self,
            TokenType::Alphabetic(_)
                | TokenType::Integer(_)
                | TokenType::Alphanumeric(_)
                | TokenType::Other(_)
                | TokenType::Punctuation(
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '/'
                        | '='
                        | '?'
                        | '^'
                        | '_'
                        | '`'
                        | '{'
                        | '|'
                        | '}'
                        | '~',
                )
        )
    }

    fn is_domain_atom(&self, is_start: bool) -> bool {
        matches!(
            self,
            TokenType::Alphabetic(_)
                | TokenType::Integer(_)
                | TokenType::Alphanumeric(_)
                | TokenType::Other(_)
        ) || (!is_start && matches!(self, TokenType::Punctuation('-')))
    }
}

#[cfg(test)]
mod test {

    use utils::suffixlist::PublicSuffix;

    use super::{TokenType, TypesTokenizer};

    #[test]
    fn type_tokenizer() {
        let mut suffixes = PublicSuffix::default();
        suffixes.suffixes.insert("com".to_string());
        suffixes.suffixes.insert("co".to_string());
        suffixes.suffixes.insert("org".to_string());

        // Credits: test suite from linkify crate
        for (text, expected) in [
            ("", vec![]),
            ("foo", vec![TokenType::Alphabetic("foo")]),
            (":", vec![TokenType::Punctuation(':')]),
            (
                "://",
                vec![
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                ],
            ),
            (
                ":::",
                vec![
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation(':'),
                ],
            ),
            (
                "://foo",
                vec![
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("foo"),
                ],
            ),
            (
                "1://foo",
                vec![
                    TokenType::Integer("1"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("foo"),
                ],
            ),
            (
                "123://foo",
                vec![
                    TokenType::Integer("123"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("foo"),
                ],
            ),
            (
                "+://foo",
                vec![
                    TokenType::Punctuation('+'),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("foo"),
                ],
            ),
            (
                "-://foo",
                vec![
                    TokenType::Punctuation('-'),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("foo"),
                ],
            ),
            (
                ".://foo",
                vec![
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("foo"),
                ],
            ),
            ("1abc://foo", vec![TokenType::UrlNoHost("1abc://foo")]),
            ("a://foo", vec![TokenType::UrlNoHost("a://foo")]),
            ("a123://foo", vec![TokenType::UrlNoHost("a123://foo")]),
            ("a123b://foo", vec![TokenType::UrlNoHost("a123b://foo")]),
            ("a+b://foo", vec![TokenType::UrlNoHost("a+b://foo")]),
            (
                "a-b://foo",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('-'),
                    TokenType::UrlNoHost("b://foo"),
                ],
            ),
            (
                "a.b://foo",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('.'),
                    TokenType::UrlNoHost("b://foo"),
                ],
            ),
            ("ABC://foo", vec![TokenType::UrlNoHost("ABC://foo")]),
            (
                ".http://example.org/",
                vec![
                    TokenType::Punctuation('.'),
                    TokenType::Url("http://example.org/"),
                ],
            ),
            (
                "1.http://example.org/",
                vec![
                    TokenType::Integer("1"),
                    TokenType::Punctuation('.'),
                    TokenType::Url("http://example.org/"),
                ],
            ),
            (
                "ab://",
                vec![
                    TokenType::Alphabetic("ab"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                ],
            ),
            (
                "file://",
                vec![
                    TokenType::Alphabetic("file"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                ],
            ),
            (
                "file:// ",
                vec![
                    TokenType::Alphabetic("file"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Space,
                ],
            ),
            (
                "\"file://\"",
                vec![
                    TokenType::Punctuation('"'),
                    TokenType::Alphabetic("file"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('"'),
                ],
            ),
            (
                "\"file://...\", ",
                vec![
                    TokenType::Punctuation('"'),
                    TokenType::Alphabetic("file"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation(','),
                    TokenType::Space,
                ],
            ),
            (
                "file://somefile",
                vec![TokenType::UrlNoHost("file://somefile")],
            ),
            (
                "file://../relative",
                vec![TokenType::UrlNoHost("file://../relative")],
            ),
            (
                "http://a.",
                vec![
                    TokenType::UrlNoHost("http://a"),
                    TokenType::Punctuation('.'),
                ],
            ),
            ("http://127.0.0.1", vec![TokenType::Url("http://127.0.0.1")]),
            (
                "http://127.0.0.1/",
                vec![TokenType::Url("http://127.0.0.1/")],
            ),
            ("ab://c", vec![TokenType::UrlNoHost("ab://c")]),
            (
                "http://example.org/",
                vec![TokenType::Url("http://example.org/")],
            ),
            (
                "http://example.org/123",
                vec![TokenType::Url("http://example.org/123")],
            ),
            (
                "http://example.org/?foo=test&bar=123",
                vec![TokenType::Url("http://example.org/?foo=test&bar=123")],
            ),
            (
                "http://example.org/?foo=%20",
                vec![TokenType::Url("http://example.org/?foo=%20")],
            ),
            (
                "http://example.org/%3C",
                vec![TokenType::Url("http://example.org/%3C")],
            ),
            ("example.org/", vec![TokenType::UrlNoScheme("example.org/")]),
            (
                "example.org/123",
                vec![TokenType::UrlNoScheme("example.org/123")],
            ),
            (
                "example.org/?foo=test&bar=123",
                vec![TokenType::UrlNoScheme("example.org/?foo=test&bar=123")],
            ),
            (
                "example.org/?foo=%20",
                vec![TokenType::UrlNoScheme("example.org/?foo=%20")],
            ),
            (
                "example.org/%3C",
                vec![TokenType::UrlNoScheme("example.org/%3C")],
            ),
            (
                "foo http://example.org/",
                vec![
                    TokenType::Alphabetic("foo"),
                    TokenType::Space,
                    TokenType::Url("http://example.org/"),
                ],
            ),
            (
                "http://example.org/ bar",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "http://example.org/\tbar",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "http://example.org/\nbar",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "http://example.org/\u{b}bar",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('\u{b}'),
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "http://example.org/\u{c}bar",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "http://example.org/\rbar",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "foo example.org/",
                vec![
                    TokenType::Alphabetic("foo"),
                    TokenType::Space,
                    TokenType::UrlNoScheme("example.org/"),
                ],
            ),
            (
                "example.org/ bar",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "example.org/\tbar",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "example.org/\nbar",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "example.org/\u{b}bar",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('\u{b}'),
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "example.org/\u{c}bar",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "example.org/\rbar",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Space,
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "http://example.org/<",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('<'),
                ],
            ),
            (
                "http://example.org/>",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org/<>",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org/\0",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('\0'),
                ],
            ),
            (
                "http://example.org/\u{e}",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('\u{e}'),
                ],
            ),
            (
                "http://example.org/\u{7f}",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('\u{7f}'),
                ],
            ),
            (
                "http://example.org/\u{9f}",
                vec![TokenType::Url("http://example.org/\u{9f}")],
            ),
            (
                "http://example.org/foo|bar",
                vec![
                    TokenType::Url("http://example.org/foo"),
                    TokenType::Punctuation('|'),
                    TokenType::Alphabetic("bar"),
                ],
            ),
            (
                "example.org/<",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('<'),
                ],
            ),
            (
                "example.org/>",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org/<>",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org/\0",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('\0'),
                ],
            ),
            (
                "example.org/\u{e}",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('\u{e}'),
                ],
            ),
            (
                "example.org/\u{7f}",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('\u{7f}'),
                ],
            ),
            (
                "example.org/\u{9f}",
                vec![TokenType::UrlNoScheme("example.org/\u{9f}")],
            ),
            (
                "http://example.org/.",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "http://example.org/..",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "http://example.org/,",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(','),
                ],
            ),
            (
                "http://example.org/:",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(':'),
                ],
            ),
            (
                "http://example.org/?",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('?'),
                ],
            ),
            (
                "http://example.org/!",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('!'),
                ],
            ),
            (
                "http://example.org/;",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(';'),
                ],
            ),
            (
                "example.org/.",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "example.org/..",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "example.org/,",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(','),
                ],
            ),
            (
                "example.org/:",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(':'),
                ],
            ),
            (
                "example.org/?",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('?'),
                ],
            ),
            (
                "example.org/!",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('!'),
                ],
            ),
            (
                "example.org/;",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(';'),
                ],
            ),
            (
                "http://example.org/a(b)",
                vec![TokenType::Url("http://example.org/a(b)")],
            ),
            (
                "http://example.org/a[b]",
                vec![TokenType::Url("http://example.org/a[b]")],
            ),
            (
                "http://example.org/a{b}",
                vec![TokenType::Url("http://example.org/a{b}")],
            ),
            (
                "http://example.org/a'b'",
                vec![TokenType::Url("http://example.org/a'b'")],
            ),
            (
                "(http://example.org/)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "[http://example.org/]",
                vec![
                    TokenType::Punctuation('['),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(']'),
                ],
            ),
            (
                "{http://example.org/}",
                vec![
                    TokenType::Punctuation('{'),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('}'),
                ],
            ),
            (
                "\"http://example.org/\"",
                vec![
                    TokenType::Punctuation('"'),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('"'),
                ],
            ),
            (
                "'http://example.org/'",
                vec![
                    TokenType::Punctuation('\''),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "example.org/a(b)",
                vec![TokenType::UrlNoScheme("example.org/a(b)")],
            ),
            (
                "example.org/a[b]",
                vec![TokenType::UrlNoScheme("example.org/a[b]")],
            ),
            (
                "example.org/a{b}",
                vec![TokenType::UrlNoScheme("example.org/a{b}")],
            ),
            (
                "example.org/a'b'",
                vec![TokenType::UrlNoScheme("example.org/a'b'")],
            ),
            (
                "(example.org/)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "[example.org/]",
                vec![
                    TokenType::Punctuation('['),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(']'),
                ],
            ),
            (
                "{example.org/}",
                vec![
                    TokenType::Punctuation('{'),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('}'),
                ],
            ),
            (
                "\"example.org/\"",
                vec![
                    TokenType::Punctuation('"'),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('"'),
                ],
            ),
            (
                "'example.org/'",
                vec![
                    TokenType::Punctuation('\''),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "((http://example.org/))",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Punctuation('('),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "((http://example.org/a(b)))",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Punctuation('('),
                    TokenType::Url("http://example.org/a(b)"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "[(http://example.org/)]",
                vec![
                    TokenType::Punctuation('['),
                    TokenType::Punctuation('('),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(']'),
                ],
            ),
            (
                "(http://example.org/).",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "(http://example.org/.)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "http://example.org/>",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org/(",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('('),
                ],
            ),
            (
                "http://example.org/(.",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('('),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "http://example.org/]()",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation(']'),
                    TokenType::Punctuation('('),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "((example.org/))",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "((example.org/a(b)))",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("example.org/a(b)"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "[(example.org/)]",
                vec![
                    TokenType::Punctuation('['),
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(']'),
                ],
            ),
            (
                "(example.org/).",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "(example.org/.)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "example.org/>",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org/(",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('('),
                ],
            ),
            (
                "example.org/(.",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('('),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "example.org/]()",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation(']'),
                    TokenType::Punctuation('('),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "'https://example.org'",
                vec![
                    TokenType::Punctuation('\''),
                    TokenType::Url("https://example.org"),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "\"https://example.org\"",
                vec![
                    TokenType::Punctuation('"'),
                    TokenType::Url("https://example.org"),
                    TokenType::Punctuation('"'),
                ],
            ),
            (
                "''https://example.org''",
                vec![
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('\''),
                    TokenType::Url("https://example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "'https://example.org''",
                vec![
                    TokenType::Punctuation('\''),
                    TokenType::Url("https://example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "'https://example.org",
                vec![
                    TokenType::Punctuation('\''),
                    TokenType::Url("https://example.org"),
                ],
            ),
            (
                "http://example.org/'_(foo)",
                vec![TokenType::Url("http://example.org/'_(foo)")],
            ),
            (
                "http://example.org/'_(foo)'",
                vec![TokenType::Url("http://example.org/'_(foo)'")],
            ),
            (
                "http://example.org/''",
                vec![TokenType::Url("http://example.org/''")],
            ),
            (
                "http://example.org/'''",
                vec![
                    TokenType::Url("http://example.org/''"),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "http://example.org/'.",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "http://example.org/'a",
                vec![TokenType::Url("http://example.org/'a")],
            ),
            (
                "http://example.org/it's",
                vec![TokenType::Url("http://example.org/it's")],
            ),
            (
                "example.org/'_(foo)",
                vec![TokenType::UrlNoScheme("example.org/'_(foo)")],
            ),
            (
                "example.org/'_(foo)'",
                vec![TokenType::UrlNoScheme("example.org/'_(foo)'")],
            ),
            (
                "example.org/''",
                vec![TokenType::UrlNoScheme("example.org/''")],
            ),
            (
                "example.org/'''",
                vec![
                    TokenType::UrlNoScheme("example.org/''"),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "example.org/'.",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "example.org/'a",
                vec![TokenType::UrlNoScheme("example.org/'a")],
            ),
            (
                "example.org/it's",
                vec![TokenType::UrlNoScheme("example.org/it's")],
            ),
            (
                "http://example.org/\"a",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('"'),
                    TokenType::Alphabetic("a"),
                ],
            ),
            (
                "http://example.org/\"a\"",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('"'),
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('"'),
                ],
            ),
            (
                "http://example.org/`a",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('`'),
                    TokenType::Alphabetic("a"),
                ],
            ),
            (
                "http://example.org/`a`",
                vec![
                    TokenType::Url("http://example.org/"),
                    TokenType::Punctuation('`'),
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('`'),
                ],
            ),
            (
                "https://example.org*",
                vec![
                    TokenType::Url("https://example.org"),
                    TokenType::Punctuation('*'),
                ],
            ),
            (
                "https://example.org/*",
                vec![
                    TokenType::Url("https://example.org/"),
                    TokenType::Punctuation('*'),
                ],
            ),
            (
                "https://example.org/**",
                vec![
                    TokenType::Url("https://example.org/"),
                    TokenType::Punctuation('*'),
                    TokenType::Punctuation('*'),
                ],
            ),
            (
                "https://example.org/*/a",
                vec![TokenType::Url("https://example.org/*/a")],
            ),
            (
                "example.org/`a",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('`'),
                    TokenType::Alphabetic("a"),
                ],
            ),
            (
                "example.org/`a`",
                vec![
                    TokenType::UrlNoScheme("example.org/"),
                    TokenType::Punctuation('`'),
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('`'),
                ],
            ),
            (
                "http://example.org\">",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org'>",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org\"/>",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org'/>",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org<p>",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("p"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org</p>",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("p"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org\">",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org'>",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org\"/>",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org'/>",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org<p>",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("p"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org</p>",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("p"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "http://example.org\");",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(';'),
                ],
            ),
            (
                "http://example.org');",
                vec![
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(';'),
                ],
            ),
            (
                "<img src=\"http://example.org/test.svg\">",
                vec![
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("img"),
                    TokenType::Space,
                    TokenType::Alphabetic("src"),
                    TokenType::Punctuation('='),
                    TokenType::Punctuation('"'),
                    TokenType::Url("http://example.org/test.svg"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "<div><a href=\"http://example.org\"></a></div>",
                vec![
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("div"),
                    TokenType::Punctuation('>'),
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("a"),
                    TokenType::Space,
                    TokenType::Alphabetic("href"),
                    TokenType::Punctuation('='),
                    TokenType::Punctuation('"'),
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation('>'),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('>'),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("div"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "<div><a href=\"http://example.org\"\n        ></a></div>",
                vec![
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("div"),
                    TokenType::Punctuation('>'),
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("a"),
                    TokenType::Space,
                    TokenType::Alphabetic("href"),
                    TokenType::Punctuation('='),
                    TokenType::Punctuation('"'),
                    TokenType::Url("http://example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Space,
                    TokenType::Punctuation('>'),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('>'),
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("div"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "<div>\n       <img\n         src=\"http://example.org/test3.jpg\" />\n     </div>",
                vec![
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("div"),
                    TokenType::Punctuation('>'),
                    TokenType::Space,
                    TokenType::Punctuation('<'),
                    TokenType::Alphabetic("img"),
                    TokenType::Space,
                    TokenType::Alphabetic("src"),
                    TokenType::Punctuation('='),
                    TokenType::Punctuation('"'),
                    TokenType::Url("http://example.org/test3.jpg"),
                    TokenType::Punctuation('"'),
                    TokenType::Space,
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('>'),
                    TokenType::Space,
                    TokenType::Punctuation('<'),
                    TokenType::Punctuation('/'),
                    TokenType::Alphabetic("div"),
                    TokenType::Punctuation('>'),
                ],
            ),
            (
                "example.org\");",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('"'),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(';'),
                ],
            ),
            (
                "example.org');",
                vec![
                    TokenType::UrlNoScheme("example.org"),
                    TokenType::Punctuation('\''),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation(';'),
                ],
            ),
            (
                "http://example.org/",
                vec![TokenType::Url("http://example.org/")],
            ),
            (
                "http://example.org/a/",
                vec![TokenType::Url("http://example.org/a/")],
            ),
            (
                "http://example.org//",
                vec![TokenType::Url("http://example.org//")],
            ),
            ("example.org/", vec![TokenType::UrlNoScheme("example.org/")]),
            (
                "example.org/a/",
                vec![TokenType::UrlNoScheme("example.org/a/")],
            ),
            (
                "example.org//",
                vec![TokenType::UrlNoScheme("example.org//")],
            ),
            (
                "http://one.org/ http://two.org/",
                vec![
                    TokenType::Url("http://one.org/"),
                    TokenType::Space,
                    TokenType::Url("http://two.org/"),
                ],
            ),
            (
                "http://one.org/ : http://two.org/",
                vec![
                    TokenType::Url("http://one.org/"),
                    TokenType::Space,
                    TokenType::Punctuation(':'),
                    TokenType::Space,
                    TokenType::Url("http://two.org/"),
                ],
            ),
            (
                "(http://one.org/)(http://two.org/)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Url("http://one.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation('('),
                    TokenType::Url("http://two.org/"),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "one.org/ two.org/",
                vec![
                    TokenType::UrlNoScheme("one.org/"),
                    TokenType::Space,
                    TokenType::UrlNoScheme("two.org/"),
                ],
            ),
            (
                "one.org/ : two.org/",
                vec![
                    TokenType::UrlNoScheme("one.org/"),
                    TokenType::Space,
                    TokenType::Punctuation(':'),
                    TokenType::Space,
                    TokenType::UrlNoScheme("two.org/"),
                ],
            ),
            (
                "(one.org/)(two.org/)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("one.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("two.org/"),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "http://one.org/ two.org/",
                vec![
                    TokenType::Url("http://one.org/"),
                    TokenType::Space,
                    TokenType::UrlNoScheme("two.org/"),
                ],
            ),
            (
                "one.org/ : http://two.org/",
                vec![
                    TokenType::UrlNoScheme("one.org/"),
                    TokenType::Space,
                    TokenType::Punctuation(':'),
                    TokenType::Space,
                    TokenType::Url("http://two.org/"),
                ],
            ),
            (
                "(http://one.org/)(two.org/)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Url("http://one.org/"),
                    TokenType::Punctuation(')'),
                    TokenType::Punctuation('('),
                    TokenType::UrlNoScheme("two.org/"),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "http://üñîçøðé.com",
                vec![TokenType::Url("http://üñîçøðé.com")],
            ),
            (
                "http://üñîçøðé.com/ä",
                vec![TokenType::Url("http://üñîçøðé.com/ä")],
            ),
            (
                "http://example.org/¡",
                vec![TokenType::Url("http://example.org/¡")],
            ),
            (
                "http://example.org/¢",
                vec![TokenType::Url("http://example.org/¢")],
            ),
            (
                "http://example.org/😀",
                vec![TokenType::Url("http://example.org/😀")],
            ),
            (
                "http://example.org/¢/",
                vec![TokenType::Url("http://example.org/¢/")],
            ),
            (
                "http://xn--c1h.example.com/",
                vec![TokenType::Url("http://xn--c1h.example.com/")],
            ),
            ("üñîçøðé.com", vec![TokenType::UrlNoScheme("üñîçøðé.com")]),
            (
                "üñîçøðé.com/ä",
                vec![TokenType::UrlNoScheme("üñîçøðé.com/ä")],
            ),
            (
                "example.org/¡",
                vec![TokenType::UrlNoScheme("example.org/¡")],
            ),
            (
                "example.org/¢",
                vec![TokenType::UrlNoScheme("example.org/¢")],
            ),
            (
                "example.org/😀",
                vec![TokenType::UrlNoScheme("example.org/😀")],
            ),
            (
                "example.org/¢/",
                vec![TokenType::UrlNoScheme("example.org/¢/")],
            ),
            (
                "xn--c1h.example.com/",
                vec![TokenType::UrlNoScheme("xn--c1h.example.com/")],
            ),
            (
                "example.",
                vec![
                    TokenType::Alphabetic("example"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "example./",
                vec![
                    TokenType::Alphabetic("example"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('/'),
                ],
            ),
            (
                "foo.com.",
                vec![
                    TokenType::UrlNoScheme("foo.com"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "example.c",
                vec![
                    TokenType::Alphabetic("example"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("c"),
                ],
            ),
            ("example.co", vec![TokenType::UrlNoScheme("example.co")]),
            ("example.com", vec![TokenType::UrlNoScheme("example.com")]),
            ("e.com", vec![TokenType::UrlNoScheme("e.com")]),
            (
                "exampl.e.c",
                vec![
                    TokenType::Alphabetic("exampl"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("e"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("c"),
                ],
            ),
            ("exampl.e.co", vec![TokenType::UrlNoScheme("exampl.e.co")]),
            (
                "e.xample.c",
                vec![
                    TokenType::Alphabetic("e"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("xample"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("c"),
                ],
            ),
            ("e.xample.co", vec![TokenType::UrlNoScheme("e.xample.co")]),
            (
                "v1.1.1",
                vec![
                    TokenType::Alphanumeric("v1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("1"),
                ],
            ),
            (
                "foo.bar@example.org",
                vec![TokenType::Email("foo.bar@example.org")],
            ),
            (
                "example.com@example.com",
                vec![TokenType::Email("example.com@example.com")],
            ),
            (
                "Look, no scheme: example.org/foo email@foo.com",
                vec![
                    TokenType::Alphabetic("Look"),
                    TokenType::Punctuation(','),
                    TokenType::Space,
                    TokenType::Alphabetic("no"),
                    TokenType::Space,
                    TokenType::Alphabetic("scheme"),
                    TokenType::Punctuation(':'),
                    TokenType::Space,
                    TokenType::UrlNoScheme("example.org/foo"),
                    TokenType::Space,
                    TokenType::Email("email@foo.com"),
                ],
            ),
            (
                "Web:\nwww.foobar.co\nE-Mail:\n      bar@foobar.co (bla bla bla)",
                vec![
                    TokenType::Alphabetic("Web"),
                    TokenType::Punctuation(':'),
                    TokenType::Space,
                    TokenType::UrlNoScheme("www.foobar.co"),
                    TokenType::Space,
                    TokenType::Alphabetic("E"),
                    TokenType::Punctuation('-'),
                    TokenType::Alphabetic("Mail"),
                    TokenType::Punctuation(':'),
                    TokenType::Space,
                    TokenType::Email("bar@foobar.co"),
                    TokenType::Space,
                    TokenType::Punctuation('('),
                    TokenType::Alphabetic("bla"),
                    TokenType::Space,
                    TokenType::Alphabetic("bla"),
                    TokenType::Space,
                    TokenType::Alphabetic("bla"),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "upi://pay?pa=XXXXXXX&pn=XXXXX",
                vec![TokenType::UrlNoHost("upi://pay?pa=XXXXXXX&pn=XXXXX")],
            ),
            (
                "https://example.org?pa=XXXXXXX&pn=XXXXX",
                vec![TokenType::Url("https://example.org?pa=XXXXXXX&pn=XXXXX")],
            ),
            (
                "website https://domain.com",
                vec![
                    TokenType::Alphabetic("website"),
                    TokenType::Space,
                    TokenType::Url("https://domain.com"),
                ],
            ),
            ("a12.b-c.com", vec![TokenType::UrlNoScheme("a12.b-c.com")]),
            (
                "v1.2.3",
                vec![
                    TokenType::Alphanumeric("v1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("2"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("3"),
                ],
            ),
            (
                "https://12-7.0.0.1/",
                vec![TokenType::UrlNoHost("https://12-7.0.0.1/")],
            ),
            (
                "https://user:pass@example.com/",
                vec![TokenType::Url("https://user:pass@example.com/")],
            ),
            (
                "https://user:-.!$@example.com/",
                vec![TokenType::Url("https://user:-.!$@example.com/")],
            ),
            (
                "https://user:!$&'()*+,;=@example.com/",
                vec![TokenType::Url("https://user:!$&'()*+,;=@example.com/")],
            ),
            (
                "https://user:pass@ex@mple.com/",
                vec![
                    TokenType::UrlNoHost("https://user:pass@ex"),
                    TokenType::Punctuation('@'),
                    TokenType::UrlNoScheme("mple.com/"),
                ],
            ),
            (
                "https://localhost:8080!",
                vec![
                    TokenType::UrlNoHost("https://localhost:8080"),
                    TokenType::Punctuation('!'),
                ],
            ),
            (
                "https://localhost:8080/",
                vec![TokenType::UrlNoHost("https://localhost:8080/")],
            ),
            (
                "https://user:pass@example.com:8080/hi",
                vec![TokenType::Url("https://user:pass@example.com:8080/hi")],
            ),
            (
                "https://127.0.0.1/",
                vec![TokenType::Url("https://127.0.0.1/")],
            ),
            ("1.0.0.0", vec![TokenType::IpAddr("1.0.0.0")]),
            (
                "1.0.0.0/foo/bar",
                vec![TokenType::UrlNoScheme("1.0.0.0/foo/bar")],
            ),
            ("1.0 ", vec![TokenType::Float("1.0"), TokenType::Space]),
            (
                "1.0.0",
                vec![
                    TokenType::Integer("1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("0"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("0"),
                ],
            ),
            (
                "1.0.0.0.0",
                vec![
                    TokenType::Integer("1"),
                    TokenType::Punctuation('.'),
                    TokenType::IpAddr("0.0.0.0"),
                ],
            ),
            (
                "1.0.0.",
                vec![
                    TokenType::Integer("1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("0"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("0"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "https://example.com.:8080/test",
                vec![TokenType::Url("https://example.com.:8080/test")],
            ),
            (
                "https://example.org'",
                vec![
                    TokenType::Url("https://example.org"),
                    TokenType::Punctuation('\''),
                ],
            ),
            (
                "https://example.org'a@example.com",
                vec![TokenType::Url("https://example.org'a@example.com")],
            ),
            (
                "https://a.com'https://b.com",
                vec![
                    TokenType::UrlNoHost("https://a.com'https"),
                    TokenType::Punctuation(':'),
                    TokenType::Punctuation('/'),
                    TokenType::Punctuation('/'),
                    TokenType::UrlNoScheme("b.com"),
                ],
            ),
            (
                "https://example.com...",
                vec![
                    TokenType::Url("https://example.com"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "www.example..com",
                vec![
                    TokenType::Alphabetic("www"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("example"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("com"),
                ],
            ),
            (
                "https://.www.example.com",
                vec![TokenType::Url("https://.www.example.com")],
            ),
            (
                "-a.com",
                vec![TokenType::Punctuation('-'), TokenType::UrlNoScheme("a.com")],
            ),
            ("https://a.-b.com", vec![TokenType::Url("https://a.-b.com")]),
            (
                "a-.com",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('-'),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("com"),
                ],
            ),
            (
                "a.b-.com",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("b"),
                    TokenType::Punctuation('-'),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("com"),
                ],
            ),
            ("https://a.b-.com", vec![TokenType::Url("https://a.b-.com")]),
            (
                "https://example.com-/",
                vec![
                    TokenType::Url("https://example.com"),
                    TokenType::Punctuation('-'),
                    TokenType::Punctuation('/'),
                ],
            ),
            (
                "https://example.org-",
                vec![
                    TokenType::Url("https://example.org"),
                    TokenType::Punctuation('-'),
                ],
            ),
            (
                "example.com@about",
                vec![
                    TokenType::UrlNoScheme("example.com"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphabetic("about"),
                ],
            ),
            (
                "example.com/@about",
                vec![TokenType::UrlNoScheme("example.com/@about")],
            ),
            (
                "https://example.com/@about",
                vec![TokenType::Url("https://example.com/@about")],
            ),
            (
                "info@v1.1.1",
                vec![
                    TokenType::Alphabetic("info"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphanumeric("v1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("1"),
                    TokenType::Punctuation('.'),
                    TokenType::Integer("1"),
                ],
            ),
            ("file:///", vec![TokenType::UrlNoHost("file:///")]),
            (
                "file:///home/foo",
                vec![TokenType::UrlNoHost("file:///home/foo")],
            ),
            (
                "file://localhost/home/foo",
                vec![TokenType::UrlNoHost("file://localhost/home/foo")],
            ),
            (
                "facetime://+19995551234",
                vec![TokenType::UrlNoHost("facetime://+19995551234")],
            ),
            (
                "test://123'456!!!",
                vec![
                    TokenType::UrlNoHost("test://123'456"),
                    TokenType::Punctuation('!'),
                    TokenType::Punctuation('!'),
                    TokenType::Punctuation('!'),
                ],
            ),
            (
                "test://123'456...",
                vec![
                    TokenType::UrlNoHost("test://123'456"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "test://123'456!!!/",
                vec![
                    TokenType::UrlNoHost("test://123'456"),
                    TokenType::Punctuation('!'),
                    TokenType::Punctuation('!'),
                    TokenType::Punctuation('!'),
                    TokenType::Punctuation('/'),
                ],
            ),
            (
                "test://123'456.../",
                vec![
                    TokenType::UrlNoHost("test://123'456"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('/'),
                ],
            ),
            (
                "1abc://example.com",
                vec![TokenType::Url("1abc://example.com")],
            ),
            (
                "¡¢example.com",
                vec![TokenType::UrlNoScheme("¡¢example.com")],
            ),
            ("foo", vec![TokenType::Alphabetic("foo")]),
            ("@", vec![TokenType::Punctuation('@')]),
            (
                "a@",
                vec![TokenType::Alphabetic("a"), TokenType::Punctuation('@')],
            ),
            (
                "@a",
                vec![TokenType::Punctuation('@'), TokenType::Alphabetic("a")],
            ),
            (
                "@@@",
                vec![
                    TokenType::Punctuation('@'),
                    TokenType::Punctuation('@'),
                    TokenType::Punctuation('@'),
                ],
            ),
            ("foo@example.com", vec![TokenType::Email("foo@example.com")]),
            (
                "foo.bar@example.com",
                vec![TokenType::Email("foo.bar@example.com")],
            ),
            (
                "#!$%&'*+-/=?^_`{}|~@example.org",
                vec![TokenType::Email("#!$%&'*+-/=?^_`{}|~@example.org")],
            ),
            (
                "foo a@b.com",
                vec![
                    TokenType::Alphabetic("foo"),
                    TokenType::Space,
                    TokenType::Email("a@b.com"),
                ],
            ),
            (
                "a@b.com foo",
                vec![
                    TokenType::Email("a@b.com"),
                    TokenType::Space,
                    TokenType::Alphabetic("foo"),
                ],
            ),
            (
                "\na@b.com",
                vec![TokenType::Space, TokenType::Email("a@b.com")],
            ),
            (
                "a@b.com\n",
                vec![TokenType::Email("a@b.com"), TokenType::Space],
            ),
            (
                "(a@example.com)",
                vec![
                    TokenType::Punctuation('('),
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation(')'),
                ],
            ),
            (
                "\"a@example.com\"",
                vec![
                    TokenType::Punctuation('"'),
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation('"'),
                ],
            ),
            (
                "\"a@example.com\"",
                vec![
                    TokenType::Punctuation('"'),
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation('"'),
                ],
            ),
            (
                ",a@example.com,",
                vec![
                    TokenType::Punctuation(','),
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation(','),
                ],
            ),
            (
                ":a@example.com:",
                vec![
                    TokenType::Punctuation(':'),
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation(':'),
                ],
            ),
            (
                ";a@example.com;",
                vec![
                    TokenType::Punctuation(';'),
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation(';'),
                ],
            ),
            (
                ".@example.com",
                vec![
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('@'),
                    TokenType::UrlNoScheme("example.com"),
                ],
            ),
            (
                "foo.@example.com",
                vec![
                    TokenType::Alphabetic("foo"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('@'),
                    TokenType::UrlNoScheme("example.com"),
                ],
            ),
            (
                ".foo@example.com",
                vec![
                    TokenType::Punctuation('.'),
                    TokenType::Email("foo@example.com"),
                ],
            ),
            (
                ".foo@example.com",
                vec![
                    TokenType::Punctuation('.'),
                    TokenType::Email("foo@example.com"),
                ],
            ),
            (
                "a..b@example.com",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('.'),
                    TokenType::Punctuation('.'),
                    TokenType::Email("b@example.com"),
                ],
            ),
            (
                "a@example.com.",
                vec![
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "a@b",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphabetic("b"),
                ],
            ),
            (
                "a@b.",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphabetic("b"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "a@b.com.",
                vec![TokenType::Email("a@b.com"), TokenType::Punctuation('.')],
            ),
            (
                "a@example.com-",
                vec![
                    TokenType::Email("a@example.com"),
                    TokenType::Punctuation('-'),
                ],
            ),
            ("a@foo-bar.com", vec![TokenType::Email("a@foo-bar.com")]),
            (
                "a@-foo.com",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('@'),
                    TokenType::Punctuation('-'),
                    TokenType::UrlNoScheme("foo.com"),
                ],
            ),
            (
                "a@b-.",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphabetic("b"),
                    TokenType::Punctuation('-'),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "a@b",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphabetic("b"),
                ],
            ),
            (
                "a@b.",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphabetic("b"),
                    TokenType::Punctuation('.'),
                ],
            ),
            (
                "a@example.com b@example.com",
                vec![
                    TokenType::Email("a@example.com"),
                    TokenType::Space,
                    TokenType::Email("b@example.com"),
                ],
            ),
            (
                "a@example.com @ b@example.com",
                vec![
                    TokenType::Email("a@example.com"),
                    TokenType::Space,
                    TokenType::Punctuation('@'),
                    TokenType::Space,
                    TokenType::Email("b@example.com"),
                ],
            ),
            (
                "a@xy.com;b@xy.com,c@xy.com",
                vec![
                    TokenType::Email("a@xy.com"),
                    TokenType::Punctuation(';'),
                    TokenType::Email("b@xy.com"),
                    TokenType::Punctuation(','),
                    TokenType::Email("c@xy.com"),
                ],
            ),
            (
                "üñîçøðé@example.com",
                vec![TokenType::Email("üñîçøðé@example.com")],
            ),
            (
                "üñîçøðé@üñîçøðé.com",
                vec![TokenType::Email("üñîçøðé@üñîçøðé.com")],
            ),
            ("www@example.com", vec![TokenType::Email("www@example.com")]),
            (
                "a@a.xyϸ",
                vec![
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('@'),
                    TokenType::Alphabetic("a"),
                    TokenType::Punctuation('.'),
                    TokenType::Alphabetic("xyϸ"),
                ],
            ),
            (
                "100 -100 100.00 -100.00 $100 $100.00",
                vec![
                    TokenType::Integer("100"),
                    TokenType::Space,
                    TokenType::Integer("-100"),
                    TokenType::Space,
                    TokenType::Float("100.00"),
                    TokenType::Space,
                    TokenType::Float("-100.00"),
                    TokenType::Space,
                    TokenType::Punctuation('$'),
                    TokenType::Integer("100"),
                    TokenType::Space,
                    TokenType::Punctuation('$'),
                    TokenType::Float("100.00"),
                ],
            ),
            (
                " - 100 100 . 00",
                vec![
                    TokenType::Space,
                    TokenType::Punctuation('-'),
                    TokenType::Space,
                    TokenType::Integer("100"),
                    TokenType::Space,
                    TokenType::Integer("100"),
                    TokenType::Space,
                    TokenType::Punctuation('.'),
                    TokenType::Space,
                    TokenType::Integer("00"),
                ],
            ),
            (
                "send $100.00 to user@domain.com or visit domain.com/pay-me!",
                vec![
                    TokenType::Alphabetic("send"),
                    TokenType::Space,
                    TokenType::Punctuation('$'),
                    TokenType::Float("100.00"),
                    TokenType::Space,
                    TokenType::Alphabetic("to"),
                    TokenType::Space,
                    TokenType::Email("user@domain.com"),
                    TokenType::Space,
                    TokenType::Alphabetic("or"),
                    TokenType::Space,
                    TokenType::Alphabetic("visit"),
                    TokenType::Space,
                    TokenType::UrlNoScheme("domain.com/pay-me"),
                    TokenType::Punctuation('!'),
                ],
            ),
        ] {
            let result = TypesTokenizer::new(text, &suffixes)
                .map(|t| t.word)
                .collect::<Vec<_>>();

            assert_eq!(result, expected);

            /*print!("({text:?}, ");
            print!("vec![");
            for (pos, item) in result.into_iter().enumerate() {
                if pos > 0 {
                    print!(", ");
                }
                print!("TokenType::{:?}", item);
            }
            println!("]),");*/
        }
    }
}
