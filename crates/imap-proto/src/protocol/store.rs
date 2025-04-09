/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use compact_str::CompactString;

use super::{Flag, ImapResponse, Sequence, fetch::FetchItem};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: CompactString,
    pub sequence_set: Sequence,
    pub operation: Operation,
    pub is_silent: bool,
    pub keywords: Vec<Flag>,
    pub unchanged_since: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Set,
    Add,
    Clear,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response<'x> {
    pub items: Vec<FetchItem<'x>>,
}

impl ImapResponse for Response<'_> {
    fn serialize(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        for item in &self.items {
            item.serialize(&mut buf);
        }
        buf
    }
}
