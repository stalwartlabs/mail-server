/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use serde::Serialize;
use store::write::{DeserializeFrom, SerializeInto};
use utils::map::bitmap::BitmapItem;

use crate::parser::{json::Parser, JsonObjectParser};

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy, Serialize)]
#[repr(u8)]
pub enum DataType {
    #[serde(rename = "Email")]
    Email = 0,
    #[serde(rename = "EmailDelivery")]
    EmailDelivery = 1,
    #[serde(rename = "EmailSubmission")]
    EmailSubmission = 2,
    #[serde(rename = "Mailbox")]
    Mailbox = 3,
    #[serde(rename = "Thread")]
    Thread = 4,
    #[serde(rename = "Identity")]
    Identity = 5,
    #[serde(rename = "Core")]
    Core = 6,
    #[serde(rename = "PushSubscription")]
    PushSubscription = 7,
    #[serde(rename = "SearchSnippet")]
    SearchSnippet = 8,
    #[serde(rename = "VacationResponse")]
    VacationResponse = 9,
    #[serde(rename = "MDN")]
    Mdn = 10,
    #[serde(rename = "Quota")]
    Quota = 11,
    #[serde(rename = "SieveScript")]
    SieveScript = 12,
    None = 13,
}

impl BitmapItem for DataType {
    fn max() -> u64 {
        DataType::None as u64
    }

    fn is_valid(&self) -> bool {
        !matches!(self, DataType::None)
    }
}

impl From<u64> for DataType {
    fn from(value: u64) -> Self {
        match value {
            0 => DataType::Email,
            1 => DataType::EmailDelivery,
            2 => DataType::EmailSubmission,
            3 => DataType::Mailbox,
            4 => DataType::Thread,
            5 => DataType::Identity,
            6 => DataType::Core,
            7 => DataType::PushSubscription,
            8 => DataType::SearchSnippet,
            9 => DataType::VacationResponse,
            10 => DataType::Mdn,
            11 => DataType::Quota,
            12 => DataType::SieveScript,
            _ => {
                debug_assert!(false, "Invalid type_state value: {}", value);
                DataType::None
            }
        }
    }
}

impl From<DataType> for u64 {
    fn from(type_state: DataType) -> u64 {
        type_state as u64
    }
}

impl JsonObjectParser for DataType {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut hash = 0;
        let mut shift = 0;

        while let Some(ch) = parser.next_unescaped()? {
            if shift < 128 {
                hash |= (ch as u128) << shift;
                shift += 8;
            } else {
                return Err(parser.error_value());
            }
        }

        match hash {
            0x006c_6961_6d45 => Ok(DataType::Email),
            0x0079_7265_7669_6c65_446c_6961_6d45 => Ok(DataType::EmailDelivery),
            0x006e_6f69_7373_696d_6275_536c_6961_6d45 => Ok(DataType::EmailSubmission),
            0x0078_6f62_6c69_614d => Ok(DataType::Mailbox),
            0x6461_6572_6854 => Ok(DataType::Thread),
            0x7974_6974_6e65_6449 => Ok(DataType::Identity),
            0x6572_6f43 => Ok(DataType::Core),
            0x6e6f_6974_7069_7263_7362_7553_6873_7550 => Ok(DataType::PushSubscription),
            0x0074_6570_7069_6e53_6863_7261_6553 => Ok(DataType::SearchSnippet),
            0x6573_6e6f_7073_6552_6e6f_6974_6163_6156 => Ok(DataType::VacationResponse),
            0x004e_444d => Ok(DataType::Mdn),
            0x0061_746f_7551 => Ok(DataType::Quota),
            0x0074_7069_7263_5365_7665_6953 => Ok(DataType::SieveScript),
            _ => Err(parser.error_value()),
        }
    }
}

impl TryFrom<&str> for DataType {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut hash = 0;
        let mut shift = 0;

        for &ch in value.as_bytes() {
            if shift < 128 {
                hash |= (ch as u128) << shift;
                shift += 8;
            } else {
                return Err(());
            }
        }

        match hash {
            0x006c_6961_6d45 => Ok(DataType::Email),
            0x0079_7265_7669_6c65_446c_6961_6d45 => Ok(DataType::EmailDelivery),
            0x006e_6f69_7373_696d_6275_536c_6961_6d45 => Ok(DataType::EmailSubmission),
            0x0078_6f62_6c69_614d => Ok(DataType::Mailbox),
            0x6461_6572_6854 => Ok(DataType::Thread),
            0x7974_6974_6e65_6449 => Ok(DataType::Identity),
            0x6572_6f43 => Ok(DataType::Core),
            0x6e6f_6974_7069_7263_7362_7553_6873_7550 => Ok(DataType::PushSubscription),
            0x0074_6570_7069_6e53_6863_7261_6553 => Ok(DataType::SearchSnippet),
            0x6573_6e6f_7073_6552_6e6f_6974_6163_6156 => Ok(DataType::VacationResponse),
            0x004e_444d => Ok(DataType::Mdn),
            0x0061_746f_7551 => Ok(DataType::Quota),
            0x0074_7069_7263_5365_7665_6953 => Ok(DataType::SieveScript),
            _ => Err(()),
        }
    }
}

impl DataType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DataType::Email => "Email",
            DataType::EmailDelivery => "EmailDelivery",
            DataType::EmailSubmission => "EmailSubmission",
            DataType::Mailbox => "Mailbox",
            DataType::Thread => "Thread",
            DataType::Identity => "Identity",
            DataType::Core => "Core",
            DataType::PushSubscription => "PushSubscription",
            DataType::SearchSnippet => "SearchSnippet",
            DataType::VacationResponse => "VacationResponse",
            DataType::Mdn => "MDN",
            DataType::Quota => "Quota",
            DataType::SieveScript => "SieveScript",
            DataType::None => "",
        }
    }
}

impl Display for DataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl SerializeInto for DataType {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.push(*self as u8);
    }
}

impl DeserializeFrom for DataType {
    fn deserialize_from(bytes: &mut std::slice::Iter<'_, u8>) -> Option<Self> {
        match *bytes.next()? {
            0 => Some(DataType::Email),
            1 => Some(DataType::EmailDelivery),
            2 => Some(DataType::EmailSubmission),
            3 => Some(DataType::Mailbox),
            4 => Some(DataType::Thread),
            5 => Some(DataType::Identity),
            6 => Some(DataType::Core),
            7 => Some(DataType::PushSubscription),
            8 => Some(DataType::SearchSnippet),
            9 => Some(DataType::VacationResponse),
            10 => Some(DataType::Mdn),
            11 => Some(DataType::Quota),
            12 => Some(DataType::SieveScript),
            _ => None,
        }
    }
}

impl<'de> serde::Deserialize<'de> for DataType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DataType::try_from(<&str>::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid JMAP data type"))
    }
}
