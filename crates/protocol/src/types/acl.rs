use std::fmt::{self, Display};

use crate::parser::{json::Parser, JsonObjectParser};

#[derive(Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum Acl {
    Read,
    Modify,
    Delete,
    ReadItems,
    AddItems,
    ModifyItems,
    RemoveItems,
    CreateChild,
    Administer,
    Submit,
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
            0x736d_6574_4964_6165_72 => Ok(Acl::ReadItems),
            0x736d_6574_4964_6461 => Ok(Acl::AddItems),
            0x736d_6574_4979_6669_646f_6d => Ok(Acl::ModifyItems),
            0x736d_6574_4965_766f_6d65_72 => Ok(Acl::RemoveItems),
            0x646c_6968_4365_7461_6572_63 => Ok(Acl::CreateChild),
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
