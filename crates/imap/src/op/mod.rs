/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ::store::query::log::Query;
use imap_proto::StatusResponse;

pub mod acl;
pub mod append;
pub mod authenticate;
pub mod capability;
pub mod close;
pub mod copy_move;
pub mod create;
pub mod delete;
pub mod enable;
pub mod expunge;
pub mod fetch;
pub mod idle;
pub mod list;
pub mod login;
pub mod logout;
pub mod namespace;
pub mod noop;
pub mod rename;
pub mod search;
pub mod select;
pub mod status;
pub mod store;
pub mod subscribe;
pub mod thread;

trait FromModSeq {
    fn from_modseq(modseq: u64) -> Self;
}

trait ToModSeq {
    fn to_modseq(&self) -> u64;
}

impl FromModSeq for Query {
    fn from_modseq(modseq: u64) -> Self {
        if modseq > 0 {
            Query::Since(modseq - 1)
        } else {
            Query::All
        }
    }
}

impl ToModSeq for Option<u64> {
    fn to_modseq(&self) -> u64 {
        self.map(|modseq| modseq + 1).unwrap_or(0)
    }
}

pub type Result<T> = std::result::Result<T, StatusResponse>;
