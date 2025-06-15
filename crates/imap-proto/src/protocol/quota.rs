/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ImapResponse, capability::QuotaResourceName, quoted_string};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: String,
    pub name: String,
}

pub struct QuotaItem {
    pub name: String,
    pub resources: Vec<QuotaResource>,
}

pub struct QuotaResource {
    pub resource: QuotaResourceName,
    pub total: u64,
    pub used: u64,
}

pub struct Response {
    pub quota_root_items: Vec<String>,
    pub quota_items: Vec<QuotaItem>,
}

impl ImapResponse for Response {
    fn serialize(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        if !self.quota_root_items.is_empty() {
            buf.extend_from_slice(b"* QUOTAROOT");
            for item in &self.quota_root_items {
                buf.push(b' ');
                quoted_string(&mut buf, item);
            }
            buf.extend_from_slice(b"\r\n");
        }

        if !self.quota_items.is_empty() {
            for item in &self.quota_items {
                buf.extend_from_slice(b"* QUOTA ");
                quoted_string(&mut buf, &item.name);
                buf.extend_from_slice(b" (");
                for (pos, resource) in item.resources.iter().enumerate() {
                    if pos > 0 {
                        buf.push(b' ');
                    }

                    let mut total = resource.total;
                    let mut used = resource.used;

                    match resource.resource {
                        QuotaResourceName::Storage => {
                            total /= 1024;
                            used /= 1024;

                            buf.extend_from_slice(b"STORAGE ")
                        }
                        QuotaResourceName::Message => buf.extend_from_slice(b"MESSAGE "),
                        QuotaResourceName::Mailbox => buf.extend_from_slice(b"MAILBOX "),
                        QuotaResourceName::AnnotationStorage => {
                            buf.extend_from_slice(b"ANNOTATION-STORAGE ")
                        }
                    }

                    buf.extend_from_slice(format!("{used} {total}").as_bytes());
                }
                buf.extend_from_slice(b")\r\n");
            }
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::{ImapResponse, capability::QuotaResourceName};

    use super::{QuotaItem, QuotaResource};

    #[test]
    fn serialize_quota() {
        for (response, expected) in [
            (
                super::Response {
                    quota_root_items: vec!["INBOX".into(), "#test".into()],
                    quota_items: vec![],
                },
                "* QUOTAROOT \"INBOX\" \"#test\"\r\n",
            ),
            (
                super::Response {
                    quota_root_items: vec![],
                    quota_items: vec![QuotaItem {
                        name: "INBOX".into(),
                        resources: vec![QuotaResource {
                            resource: QuotaResourceName::Storage,
                            total: 1073741824,
                            used: 1048576,
                        }],
                    }],
                },
                concat!("* QUOTA \"INBOX\" (STORAGE 1024 1048576)\r\n"),
            ),
            (
                super::Response {
                    quota_root_items: vec!["my mailbox".into(), "".into()],
                    quota_items: vec![QuotaItem {
                        name: "INBOX".into(),
                        resources: vec![
                            QuotaResource {
                                resource: QuotaResourceName::Storage,
                                total: 1073741824,
                                used: 1048576,
                            },
                            QuotaResource {
                                resource: QuotaResourceName::Message,
                                total: 100,
                                used: 2,
                            },
                        ],
                    }],
                },
                concat!(
                    "* QUOTAROOT \"my mailbox\" \"\"\r\n",
                    "* QUOTA \"INBOX\" (STORAGE 1024 1048576 MESSAGE 2 100)\r\n"
                ),
            ),
        ] {
            assert_eq!(String::from_utf8(response.serialize()).unwrap(), expected);
        }
    }
}
