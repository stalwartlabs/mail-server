/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart IMAP Server.
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arguments {
    pub tag: String,
    pub mechanism: Mechanism,
    pub params: Vec<String>,
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

impl Mechanism {
    pub fn serialize(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(match self {
            Mechanism::Plain => b"PLAIN",
            Mechanism::CramMd5 => b"CRAM-MD5",
            Mechanism::DigestMd5 => b"DIGEST-MD5",
            Mechanism::ScramSha1 => b"SCRAM-SHA-1",
            Mechanism::ScramSha256 => b"SCRAM-SHA-256",
            Mechanism::Apop => b"APOP",
            Mechanism::Ntlm => b"NTLM",
            Mechanism::Gssapi => b"GSSAPI",
            Mechanism::Anonymous => b"ANONYMOUS",
            Mechanism::External => b"EXTERNAL",
            Mechanism::OAuthBearer => b"OAUTHBEARER",
            Mechanism::XOauth2 => b"XOAUTH2",
        });
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(10);
        self.serialize(&mut buf);
        buf
    }
}
