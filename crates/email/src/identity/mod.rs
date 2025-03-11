/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use store::SerializedVersion;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
pub struct Identity {
    pub name: String,
    pub email: String,
    pub reply_to: Option<Vec<EmailAddress>>,
    pub bcc: Option<Vec<EmailAddress>>,
    pub text_signature: String,
    pub html_signature: String,
}

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Clone, PartialEq, Eq)]
pub struct EmailAddress {
    pub name: Option<String>,
    pub email: String,
}

impl SerializedVersion for Identity {
    fn serialize_version() -> u8 {
        0
    }
}
