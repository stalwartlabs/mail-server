/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod index;

use compact_str::CompactString;
use store::{SERIALIZE_IDENTITY_V1, SerializedVersion};

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct Identity {
    pub name: CompactString,
    pub email: CompactString,
    pub reply_to: Option<Vec<EmailAddress>>,
    pub bcc: Option<Vec<EmailAddress>>,
    pub text_signature: CompactString,
    pub html_signature: CompactString,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct EmailAddress {
    pub name: Option<CompactString>,
    pub email: CompactString,
}

impl SerializedVersion for Identity {
    fn serialize_version() -> u8 {
        SERIALIZE_IDENTITY_V1
    }
}
