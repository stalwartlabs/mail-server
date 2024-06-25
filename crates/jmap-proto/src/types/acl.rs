/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::{self, Display};

use utils::map::bitmap::BitmapItem;

use crate::parser::{json::Parser, JsonObjectParser};

#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Clone, Copy)]
#[repr(u8)]
pub enum Acl {
    Read = 0,
    Modify = 1,
    Delete = 2,
    ReadItems = 3,
    AddItems = 4,
    ModifyItems = 5,
    RemoveItems = 6,
    CreateChild = 7,
    Administer = 8,
    Submit = 9,
    None = 10,
}

impl JsonObjectParser for Acl {
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
            0x6461_6572 => Ok(Acl::Read),
            0x7966_6964_6f6d => Ok(Acl::Modify),
            0x6574_656c_6564 => Ok(Acl::Delete),
            0x0073_6d65_7449_6461_6572 => Ok(Acl::ReadItems),
            0x736d_6574_4964_6461 => Ok(Acl::AddItems),
            0x0073_6d65_7449_7966_6964_6f6d => Ok(Acl::ModifyItems),
            0x0073_6d65_7449_6576_6f6d_6572 => Ok(Acl::RemoveItems),
            0x0064_6c69_6843_6574_6165_7263 => Ok(Acl::CreateChild),
            0x7265_7473_696e_696d_6461 => Ok(Acl::Administer),
            0x7469_6d62_7573 => Ok(Acl::Submit),
            _ => Err(parser.error_value()),
        }
    }
}

impl Acl {
    fn as_str(&self) -> &'static str {
        match self {
            Acl::Read => "read",
            Acl::Modify => "modify",
            Acl::Delete => "delete",
            Acl::ReadItems => "readItems",
            Acl::AddItems => "addItems",
            Acl::ModifyItems => "modifyItems",
            Acl::RemoveItems => "removeItems",
            Acl::CreateChild => "createChild",
            Acl::Administer => "administer",
            Acl::Submit => "submit",
            Acl::None => "",
        }
    }
}

impl Display for Acl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl serde::Serialize for Acl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl BitmapItem for Acl {
    fn max() -> u64 {
        Acl::None as u64
    }

    fn is_valid(&self) -> bool {
        !matches!(self, Acl::None)
    }
}

impl From<Acl> for u64 {
    fn from(value: Acl) -> Self {
        value as u64
    }
}

impl From<u64> for Acl {
    fn from(value: u64) -> Self {
        match value {
            0 => Acl::Read,
            1 => Acl::Modify,
            2 => Acl::Delete,
            3 => Acl::ReadItems,
            4 => Acl::AddItems,
            5 => Acl::ModifyItems,
            6 => Acl::RemoveItems,
            7 => Acl::CreateChild,
            8 => Acl::Administer,
            9 => Acl::Submit,
            _ => Acl::None,
        }
    }
}

/*impl SerializeInto for Acl {
    fn serialize_into(&self, buf: &mut Vec<u8>) {
        buf.push(*self as u8);
    }
}

impl DeserializeFrom for Acl {
    fn deserialize_from(bytes: &mut std::slice::Iter<'_, u8>) -> Option<Self> {
        match *bytes.next()? {
            0 => Some(Acl::Read),
            1 => Some(Acl::Modify),
            2 => Some(Acl::Delete),
            3 => Some(Acl::ReadItems),
            4 => Some(Acl::AddItems),
            5 => Some(Acl::ModifyItems),
            6 => Some(Acl::RemoveItems),
            7 => Some(Acl::CreateChild),
            8 => Some(Acl::Administer),
            9 => Some(Acl::Submit),
            _ => None,
        }
    }
}*/
