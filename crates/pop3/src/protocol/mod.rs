/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod request;
pub mod response;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Command<T, M> {
    // Authorization state
    User {
        name: T,
    },
    Pass {
        string: T,
    },
    Apop {
        name: T,
        digest: T,
    },
    Quit,

    // Transaction state
    Stat,
    List {
        msg: Option<u32>,
    },
    Retr {
        msg: u32,
    },
    Dele {
        msg: u32,
    },
    DeleMany {
        msgs: Vec<u32>,
    },
    #[default]
    Noop,
    Rset,
    Top {
        msg: u32,
        n: u32,
    },
    Uidl {
        msg: Option<u32>,
    },

    // Extensions
    Capa,
    Stls,
    Utf8,
    Auth {
        mechanism: M,
        params: Vec<T>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    Plain,
    CramMd5,
    DigestMd5,
    ScramSha1,
    ScramSha256,
    Apop,
    Ntlm,
    Gssapi,
    Anonymous,
    External,
    OAuthBearer,
    XOauth2,
}
