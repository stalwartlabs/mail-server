use std::fmt::Display;

use serde::Serialize;
use store::write::{DeserializeFrom, SerializeInto};

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
            0x6c69_616d_45 => Ok(TypeState::Email),
            0x7972_6576_696c_6544_6c69_616d_45 => Ok(TypeState::EmailDelivery),
            0x6e6f_6973_7369_6d62_7553_6c69_616d_45 => Ok(TypeState::EmailSubmission),
            0x786f_626c_6961_4d => Ok(TypeState::Mailbox),
            0x6461_6572_6854 => Ok(TypeState::Thread),
            0x7974_6974_6e65_6449 => Ok(TypeState::Identity),
            _ => Err(parser.error_value()),
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
