/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod imap;
pub mod internal;
pub mod ldap;
pub mod memory;
pub mod oidc;
pub mod smtp;
pub mod sql;

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub enum RcptType {
    Mailbox,
    List(Vec<String>),
    #[default]
    Invalid,
}

impl From<bool> for RcptType {
    fn from(value: bool) -> Self {
        if value {
            RcptType::Mailbox
        } else {
            RcptType::Invalid
        }
    }
}
