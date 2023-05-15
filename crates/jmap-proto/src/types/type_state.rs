use std::fmt::Display;

use serde::Serialize;
use store::write::{DeserializeFrom, SerializeInto};
use utils::map::bitmap::BitmapItem;

use crate::parser::{json::Parser, JsonObjectParser};

#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy, Serialize)]
#[repr(u8)]
pub enum TypeState {
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
    None = 6,
}

impl BitmapItem for TypeState {
    fn max() -> u64 {
        TypeState::None as u64
    }

    fn is_valid(&self) -> bool {
        !matches!(self, TypeState::None)
    }
}

impl From<u64> for TypeState {
    fn from(value: u64) -> Self {
        match value {
            0 => TypeState::Email,
            1 => TypeState::EmailDelivery,
            2 => TypeState::EmailSubmission,
            3 => TypeState::Mailbox,
            4 => TypeState::Thread,
            5 => TypeState::Identity,
            _ => {
                debug_assert!(false, "Invalid type_state value: {}", value);
                TypeState::None
            }
        }
    }
}

impl From<TypeState> for u64 {
    fn from(type_state: TypeState) -> u64 {
        type_state as u64
    }
}

impl JsonObjectParser for TypeState {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
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
            0x006c_6961_6d45 => Ok(TypeState::Email),
            0x0079_7265_7669_6c65_446c_6961_6d45 => Ok(TypeState::EmailDelivery),
            0x006e_6f69_7373_696d_6275_536c_6961_6d45 => Ok(TypeState::EmailSubmission),
            0x0078_6f62_6c69_614d => Ok(TypeState::Mailbox),
            0x6461_6572_6854 => Ok(TypeState::Thread),
            0x7974_6974_6e65_6449 => Ok(TypeState::Identity),
            _ => Err(parser.error_value()),
        }
    }
}

impl TryFrom<&str> for TypeState {
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
            0x006c_6961_6d45 => Ok(TypeState::Email),
            0x0079_7265_7669_6c65_446c_6961_6d45 => Ok(TypeState::EmailDelivery),
            0x006e_6f69_7373_696d_6275_536c_6961_6d45 => Ok(TypeState::EmailSubmission),
            0x0078_6f62_6c69_614d => Ok(TypeState::Mailbox),
            0x6461_6572_6854 => Ok(TypeState::Thread),
            0x7974_6974_6e65_6449 => Ok(TypeState::Identity),
            _ => Err(()),
        }
    }
}

impl TypeState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TypeState::Email => "Email",
            TypeState::EmailDelivery => "EmailDelivery",
            TypeState::EmailSubmission => "EmailSubmission",
            TypeState::Mailbox => "Mailbox",
            TypeState::Thread => "Thread",
            TypeState::Identity => "Identity",
            TypeState::None => "",
        }
    }
}

impl Display for TypeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl SerializeInto for TypeState {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.push(*self as u8);
    }
}

impl DeserializeFrom for TypeState {
    fn deserialize_from(bytes: &mut std::slice::Iter<'_, u8>) -> Option<Self> {
        match *bytes.next()? {
            0 => Some(TypeState::Email),
            1 => Some(TypeState::EmailDelivery),
            2 => Some(TypeState::EmailSubmission),
            3 => Some(TypeState::Mailbox),
            4 => Some(TypeState::Thread),
            5 => Some(TypeState::Identity),
            _ => None,
        }
    }
}

impl<'de> serde::Deserialize<'de> for TypeState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        TypeState::try_from(<&str>::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid JMAP type state"))
    }
}
