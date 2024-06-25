/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
