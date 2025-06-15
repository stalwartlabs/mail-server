/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use calcard::vcard::VCardVersion;

use crate::{Condition, Depth, If, RequestHeaders, ResourceState, Return, Timeout};

impl<'x> RequestHeaders<'x> {
    pub fn new(uri: &'x str) -> Self {
        RequestHeaders {
            uri,
            ..Default::default()
        }
    }

    pub fn parse(&mut self, key: &str, value: &'x str) -> bool {
        hashify::fnc_map_ignore_case!(key.as_bytes(),
            "Depth" => {
                if let Some(depth) = Depth::parse(value.as_bytes()) {
                    self.depth = depth;
                    return true;
                }
            },
            "Destination" => {
                self.destination = Some(value);
                return true;
            },
            "Lock-Token" => {
                self.lock_token = Some(try_unwrap_coded_url(value));
                return true;
            },
            "If" => {
                let num = self.if_.len();
                self.parse_if(value);
                return self.if_.len() != num;
            },
            "If-Match" => {
                let num = self.if_.len();
                self.parse_if_match(value, false);
                return self.if_.len() != num;
            },
            "If-None-Match" => {
                let num = self.if_.len();
                self.parse_if_match(value, true);
                return self.if_.len() != num;
            },
            "Timeout" => {
                let value = value.split_once(',').map(|(first, _)| first).unwrap_or(value).trim();
                if let Some(seconds) = value.strip_prefix("Second-") {
                    if let Ok(seconds) = seconds.parse() {
                        self.timeout = Timeout::Second(seconds);
                        return true;
                    }
                } else if value == "Infinite" {
                    self.timeout = Timeout::Infinite;
                    return true;
                }
            },
            "Overwrite" => {
                self.overwrite_fail = value == "F";
                return true;
            },
            "CalDAV-Timezones" => {
                self.no_timezones = value == "F";
                return true;
            },
            "Prefer" => {
                for value in value.split(&[',', ';']) {
                    match value.trim() {
                        "return=minimal" => self.ret = Return::Minimal,
                        "return=representation" => self.ret = Return::Representation,
                        "depth-noroot" => self.depth_no_root = true,
                        _ => {}
                    }
                }
            },
            "Content-Type" => {
                let value = value.trim();
                if (2..=127).contains(&value.len()) {
                    self.content_type = Some(value);
                }
                return true;
            },
            "Accept" => {
                for value in value.split(',') {
                    if value.trim().starts_with("text/vcard") {
                        if let Some(version) = value.split_once("version=")
                                               .and_then(|(_, version)| VCardVersion::try_parse(version.trim())) {
                            if let Some(max_vcard_version) = &mut self.max_vcard_version {
                                if version > *max_vcard_version {
                                    *max_vcard_version = version;
                                }
                            } else {
                                self.max_vcard_version = Some(version);
                            }
                        }
                    }
                }
                return true;
            },
            _ => {}
        );

        false
    }

    pub fn has_if(&self) -> bool {
        !self.if_.is_empty()
    }

    pub fn eval_if_resources(&self) -> impl Iterator<Item = &str> {
        self.if_.iter().filter_map(|if_| if_.resource)
    }

    pub fn eval_if<T>(&self, resources: &[ResourceState<T>]) -> bool
    where
        T: AsRef<str>,
    {
        if self.if_.is_empty() {
            return true;
        }

        'outer: for if_ in &self.if_ {
            if if_.list.is_empty() {
                continue;
            }

            let (current_token, current_etag) = resources
                .iter()
                .find_map(|r| {
                    if if_.resource == r.resource.as_ref().map(|v| v.as_ref()) {
                        Some((r.state_token.as_ref(), r.etag.as_ref()))
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            for cond in if_.list.iter() {
                match cond {
                    Condition::StateToken { is_not, token } => {
                        if !((current_token == *token) ^ is_not) {
                            continue 'outer;
                        }
                    }
                    Condition::ETag { is_not, tag } => {
                        if !((current_etag == *tag) ^ is_not) {
                            continue 'outer;
                        }
                    }
                    Condition::Exists { is_not } => {
                        if !((current_etag.is_empty()) ^ is_not) {
                            continue 'outer;
                        }
                    }
                }
            }

            return true;
        }

        false
    }

    fn parse_if(&mut self, value: &'x str) {
        let value = value.as_bytes();
        let mut iter = value.iter().enumerate();
        let mut resource = None;

        while let Some((idx, ch)) = iter.next() {
            match ch {
                b'<' if resource.is_none() => {
                    for (to_idx, ch) in iter.by_ref() {
                        if *ch == b'>' {
                            resource = Some(std::str::from_utf8(&value[idx + 1..to_idx]).unwrap());
                            break;
                        }
                    }
                }
                b'(' => {
                    let mut is_not = false;
                    let mut conditions = Vec::new();
                    while let Some((idx, ch)) = iter.next() {
                        match ch {
                            b'N' => {
                                if matches!(iter.next(), Some((_, b'o')))
                                    && matches!(iter.next(), Some((_, b't')))
                                {
                                    is_not = true;
                                } else {
                                    return;
                                }
                            }
                            b'<' | b'[' => {
                                let (stop_char, is_etag) = match ch {
                                    b'<' => (b'>', false),
                                    b'[' => (b']', true),
                                    _ => unreachable!(),
                                };

                                for (to_idx, ch) in iter.by_ref() {
                                    if *ch == stop_char {
                                        let value =
                                            std::str::from_utf8(&value[idx + 1..to_idx]).unwrap();
                                        let condition = if is_etag {
                                            Condition::ETag { is_not, tag: value }
                                        } else {
                                            Condition::StateToken {
                                                is_not,
                                                token: value,
                                            }
                                        };
                                        conditions.push(condition);
                                        is_not = false;
                                        break;
                                    }
                                }
                            }
                            b')' => {
                                self.if_.push(If {
                                    resource: resource.take(),
                                    list: conditions,
                                });
                                break;
                            }
                            _ => {
                                if !ch.is_ascii_whitespace() {
                                    return;
                                }
                            }
                        }
                    }
                }
                _ => {
                    if !ch.is_ascii_whitespace() {
                        return;
                    }
                }
            }
        }
    }

    pub fn parse_if_match(&mut self, value: &'x str, is_not: bool) {
        if value == "*" {
            self.if_.push(If {
                resource: None,
                list: vec![Condition::Exists { is_not }],
            });
        } else if !is_not {
            for etag in value.split(',') {
                self.if_.push(If {
                    resource: None,
                    list: vec![Condition::ETag {
                        is_not,
                        tag: etag.trim(),
                    }],
                });
            }
        } else {
            let mut etags = Vec::new();
            for etag in value.split(',') {
                etags.push(Condition::ETag {
                    is_not,
                    tag: etag.trim(),
                });
            }
            self.if_.push(If {
                resource: None,
                list: etags,
            });
        }
    }

    pub fn base_uri(&self) -> Option<&str> {
        dav_base_uri(self.uri)
    }
}

pub fn dav_base_uri(uri: &str) -> Option<&str> {
    // From a path ../dav/collection/account/..
    // returns ../dav/collection/account without the trailing slash

    let uri = uri.as_bytes();
    let mut found_dav = false;
    let mut last_idx = 0;
    let mut sep_count = 0;

    for (idx, ch) in uri.iter().enumerate() {
        if *ch == b'/' {
            if !found_dav {
                found_dav = uri.get(idx + 1..idx + 5).is_some_and(|s| s == b"dav/");
            } else if found_dav {
                if sep_count == 2 {
                    break;
                }
                sep_count += 1;
            }
        }
        last_idx = idx;
    }

    if sep_count == 2 {
        uri.get(..last_idx + 1)
            .map(|uri| std::str::from_utf8(uri).unwrap())
    } else {
        None
    }
}

impl Depth {
    pub fn parse(value: &[u8]) -> Option<Self> {
        hashify::tiny_map!(value,
            "0" => Depth::Zero,
            "1" => Depth::One,
            "infinity" => Depth::Infinity,
            "infinite" => Depth::Infinity,
        )
    }
}

fn try_unwrap_coded_url(url: &str) -> &str {
    url.strip_prefix("<")
        .and_then(|url| url.strip_suffix(">"))
        .unwrap_or(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_uri() {
        for (uri, expected_base) in [
            (
                "http://host/dav/collection/account/test/",
                Some("http://host/dav/collection/account"),
            ),
            (
                "http://host/dav/collection/account/test",
                Some("http://host/dav/collection/account"),
            ),
            (
                "http://host/dav/collection/account/",
                Some("http://host/dav/collection/account"),
            ),
            (
                "http://host/dav/collection/account",
                Some("http://host/dav/collection/account"),
            ),
            (
                "http://host/dev/dav/collection/account/test/",
                Some("http://host/dev/dav/collection/account"),
            ),
            (
                "http://host/dev/dav/collection/account/test",
                Some("http://host/dev/dav/collection/account"),
            ),
            (
                "http://host/dev/dav/collection/account/",
                Some("http://host/dev/dav/collection/account"),
            ),
            (
                "http://host/dev/dav/collection/account",
                Some("http://host/dev/dav/collection/account"),
            ),
            (
                "/dav/collection/account/test/",
                Some("/dav/collection/account"),
            ),
            (
                "/dav/collection/account/test",
                Some("/dav/collection/account"),
            ),
            ("/dav/collection/account/", Some("/dav/collection/account")),
            ("/dav/collection/account", Some("/dav/collection/account")),
        ] {
            assert_eq!(RequestHeaders::new(uri).base_uri(), expected_base);
        }
    }

    #[test]
    fn eval_if_header() {
        let mut headers = RequestHeaders::default();
        assert!(headers.parse(
            "If",
            r#"(<urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>
   ["I am an ETag"])
   (["I am another ETag"])"#,
        ));

        assert!(headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
            etag: "\"I am an ETag\""
        }]));
        assert!(headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "",
            etag: "\"I am another ETag\""
        }]));
        assert!(!headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "",
            etag: "\"Unknown ETag\""
        }]));
        assert!(!headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
            etag: ""
        }]));
        assert!(!headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
            etag: "\"Other ETag\""
        }]));
        assert!(!headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "",
            etag: "\"I am an ETag\""
        }]));
        assert!(!headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:blah",
            etag: "\"I am an ETag\""
        }]));

        assert!(headers.parse(
            "If",
            r#"(Not <urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>
     <urn:uuid:58f202ac-22cf-11d1-b12d-002035b29092>)"#,
        ));
        assert!(headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:uuid:58f202ac-22cf-11d1-b12d-002035b29092",
            etag: ""
        }]));
        assert!(!headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
            etag: ""
        }]));

        assert!(headers.parse(
            "If",
            r#"(<urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>)
       (Not <DAV:no-lock>)"#
        ));
        assert!(headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
            etag: ""
        }]));
        assert!(headers.eval_if(&[ResourceState {
            resource: None,
            state_token: "urn:other-token",
            etag: ""
        }]));
    }

    #[test]
    fn parse_headers() {
        let mut headers = RequestHeaders::default();
        assert!(headers.parse("Depth", "0"));
        assert_eq!(headers.depth, Depth::Zero);

        assert!(headers.parse("Destination", "/path/to/destination"));
        assert_eq!(headers.destination, Some("/path/to/destination"));

        assert!(headers.parse("Lock-Token", "<urn:uuid:1234>"));
        assert_eq!(headers.lock_token, Some("urn:uuid:1234"));

        for (input, expected) in [
            (
                "<urn:uuid:1234>(<urn:uuid:1234>)",
                vec![If {
                    resource: "urn:uuid:1234".into(),
                    list: vec![Condition::StateToken {
                        is_not: false,
                        token: "urn:uuid:1234",
                    }],
                }],
            ),
            (
                "<>(<>)",
                vec![If {
                    resource: "".into(),
                    list: vec![Condition::StateToken {
                        is_not: false,
                        token: "",
                    }],
                }],
            ),
            (
                r#"(<urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>
       ["I am an ETag"])
       (["I am another ETag"])"#,
                vec![
                    If {
                        resource: None,
                        list: vec![
                            Condition::StateToken {
                                is_not: false,
                                token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
                            },
                            Condition::ETag {
                                is_not: false,
                                tag: "\"I am an ETag\"",
                            },
                        ],
                    },
                    If {
                        resource: None,
                        list: vec![Condition::ETag {
                            is_not: false,
                            tag: "\"I am another ETag\"",
                        }],
                    },
                ],
            ),
            (
                r#"(Not <urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>
     <urn:uuid:58f202ac-22cf-11d1-b12d-002035b29092>)"#,
                vec![If {
                    resource: None,
                    list: vec![
                        Condition::StateToken {
                            is_not: true,
                            token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
                        },
                        Condition::StateToken {
                            is_not: false,
                            token: "urn:uuid:58f202ac-22cf-11d1-b12d-002035b29092",
                        },
                    ],
                }],
            ),
            (
                r#"(<urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>)
       (Not <DAV:no-lock>)"#,
                vec![
                    If {
                        resource: None,
                        list: vec![Condition::StateToken {
                            is_not: false,
                            token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
                        }],
                    },
                    If {
                        resource: None,
                        list: vec![Condition::StateToken {
                            is_not: true,
                            token: "DAV:no-lock",
                        }],
                    },
                ],
            ),
            (
                r#"</resource1>
                 (<urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>
                 [W/"A weak ETag"]) (["strong ETag"])"#,
                vec![
                    If {
                        resource: "/resource1".into(),
                        list: vec![
                            Condition::StateToken {
                                is_not: false,
                                token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
                            },
                            Condition::ETag {
                                is_not: false,
                                tag: "W/\"A weak ETag\"",
                            },
                        ],
                    },
                    If {
                        resource: None,
                        list: vec![Condition::ETag {
                            is_not: false,
                            tag: "\"strong ETag\"",
                        }],
                    },
                ],
            ),
            (
                r#"<http://www.example.com/specs/>
            (<urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2>)"#,
                vec![If {
                    resource: "http://www.example.com/specs/".into(),
                    list: vec![Condition::StateToken {
                        is_not: false,
                        token: "urn:uuid:181d4fae-7d8c-11d0-a765-00a0c91e6bf2",
                    }],
                }],
            ),
            (
                r#"</specs/rfc2518.doc> (["4217"])"#,
                vec![If {
                    resource: "/specs/rfc2518.doc".into(),
                    list: vec![Condition::ETag {
                        is_not: false,
                        tag: "\"4217\"",
                    }],
                }],
            ),
            (
                r#"</specs/rfc2518.doc> (Not ["4217"])"#,
                vec![If {
                    resource: "/specs/rfc2518.doc".into(),
                    list: vec![Condition::ETag {
                        is_not: true,
                        tag: "\"4217\"",
                    }],
                }],
            ),
            (
                r#"</test/file.txt> (["1234"]) </specs/rfc2518.doc> (Not ["4217"])"#,
                vec![
                    If {
                        resource: "/test/file.txt".into(),
                        list: vec![Condition::ETag {
                            is_not: false,
                            tag: "\"1234\"",
                        }],
                    },
                    If {
                        resource: "/specs/rfc2518.doc".into(),
                        list: vec![Condition::ETag {
                            is_not: true,
                            tag: "\"4217\"",
                        }],
                    },
                ],
            ),
        ] {
            assert!(headers.parse("If", input));
            assert_eq!(headers.if_, expected, "Failed for input: {}", input);
            headers.if_.clear();
        }

        assert!(headers.parse("If-Match", "*"));
        assert_eq!(
            headers.if_,
            vec![If {
                resource: None,
                list: vec![Condition::Exists { is_not: false }],
            }]
        );
        headers.if_.clear();

        assert!(headers.parse("If-None-Match", "etag1, etag2"));
        assert_eq!(
            headers.if_,
            vec![If {
                resource: None,
                list: vec![
                    Condition::ETag {
                        is_not: true,
                        tag: "etag1",
                    },
                    Condition::ETag {
                        is_not: true,
                        tag: "etag2",
                    }
                ],
            },]
        );

        assert!(headers.parse("Timeout", "Second-10"));
        assert_eq!(headers.timeout, Timeout::Second(10));

        assert!(headers.parse("Timeout", "Infinite, Second-4100000000"));
        assert_eq!(headers.timeout, Timeout::Infinite);

        assert!(headers.parse("Overwrite", "F"));
        assert!(headers.overwrite_fail);
    }
}
