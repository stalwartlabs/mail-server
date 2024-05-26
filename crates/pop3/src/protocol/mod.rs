/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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
