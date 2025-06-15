/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use store::{Serialize, write::TagValue};

use crate::parser::{JsonObjectParser, json::Parser};

pub const SEEN: usize = 0;
pub const DRAFT: usize = 1;
pub const FLAGGED: usize = 2;
pub const ANSWERED: usize = 3;
pub const RECENT: usize = 4;
pub const IMPORTANT: usize = 5;
pub const PHISHING: usize = 6;
pub const JUNK: usize = 7;
pub const NOTJUNK: usize = 8;
pub const DELETED: usize = 9;
pub const FORWARDED: usize = 10;
pub const MDN_SENT: usize = 11;
pub const OTHER: usize = 12;

#[derive(
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Default,
    serde::Serialize,
)]
#[serde(untagged)]
#[rkyv(derive(PartialEq), compare(PartialEq))]
pub enum Keyword {
    #[serde(rename(serialize = "$seen"))]
    Seen,
    #[serde(rename(serialize = "$draft"))]
    Draft,
    #[serde(rename(serialize = "$flagged"))]
    Flagged,
    #[serde(rename(serialize = "$answered"))]
    Answered,
    #[default]
    #[serde(rename(serialize = "$recent"))]
    Recent,
    #[serde(rename(serialize = "$important"))]
    Important,
    #[serde(rename(serialize = "$phishing"))]
    Phishing,
    #[serde(rename(serialize = "$junk"))]
    Junk,
    #[serde(rename(serialize = "$notjunk"))]
    NotJunk,
    #[serde(rename(serialize = "$deleted"))]
    Deleted,
    #[serde(rename(serialize = "$forwarded"))]
    Forwarded,
    #[serde(rename(serialize = "$mdnsent"))]
    MdnSent,
    Other(String),
}

impl JsonObjectParser for Keyword {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let pos = parser.pos;
        if parser
            .next_unescaped()?
            .ok_or_else(|| parser.error_value())?
            == b'$'
        {
            let mut hash = 0;
            let mut shift = 0;

            while let Some(ch) = parser.next_unescaped()? {
                if shift < 128 {
                    hash |= (ch as u128) << shift;
                    shift += 8;
                } else {
                    break;
                }
            }

            match hash {
                0x6e65_6573 => return Ok(Keyword::Seen),
                0x0074_6661_7264 => return Ok(Keyword::Draft),
                0x0064_6567_6761_6c66 => return Ok(Keyword::Flagged),
                0x6465_7265_7773_6e61 => return Ok(Keyword::Answered),
                0x746e_6563_6572 => return Ok(Keyword::Recent),
                0x0074_6e61_7472_6f70_6d69 => return Ok(Keyword::Important),
                0x676e_6968_7369_6870 => return Ok(Keyword::Phishing),
                0x6b6e_756a => return Ok(Keyword::Junk),
                0x006b_6e75_6a74_6f6e => return Ok(Keyword::NotJunk),
                0x0064_6574_656c_6564 => return Ok(Keyword::Deleted),
                0x0064_6564_7261_7772_6f66 => return Ok(Keyword::Forwarded),
                0x0074_6e65_736e_646d => return Ok(Keyword::MdnSent),
                _ => (),
            }
        }

        if parser.is_eof || parser.skip_string() {
            Ok(Keyword::Other(
                String::from_utf8_lossy(parser.bytes[pos..parser.pos - 1].as_ref()).into_owned(),
            ))
        } else {
            Err(parser.error_unterminated())
        }
    }
}

impl<T: AsRef<str>> From<T> for Keyword {
    fn from(value: T) -> Self {
        let value = value.as_ref();
        if value
            .as_bytes()
            .first()
            .is_some_and(|&ch| [b'$', b'\\'].contains(&ch))
        {
            let mut hash = 0;
            let mut shift = 0;

            for &ch in value.as_bytes().iter().skip(1) {
                if shift < 128 {
                    hash |= (ch.to_ascii_lowercase() as u128) << shift;
                    shift += 8;
                } else {
                    break;
                }
            }

            match hash {
                0x6e65_6573 => return Keyword::Seen,
                0x0074_6661_7264 => return Keyword::Draft,
                0x0064_6567_6761_6c66 => return Keyword::Flagged,
                0x6465_7265_7773_6e61 => return Keyword::Answered,
                0x746e_6563_6572 => return Keyword::Recent,
                0x0074_6e61_7472_6f70_6d69 => return Keyword::Important,
                0x676e_6968_7369_6870 => return Keyword::Phishing,
                0x6b6e_756a => return Keyword::Junk,
                0x006b_6e75_6a74_6f6e => return Keyword::NotJunk,
                0x0064_6574_656c_6564 => return Keyword::Deleted,
                0x0064_6564_7261_7772_6f66 => return Keyword::Forwarded,
                0x0074_6e65_736e_646d => return Keyword::MdnSent,
                _ => (),
            }
        }

        Keyword::Other(String::from(value))
    }
}

impl Display for Keyword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Keyword::Seen => write!(f, "$seen"),
            Keyword::Draft => write!(f, "$draft"),
            Keyword::Flagged => write!(f, "$flagged"),
            Keyword::Answered => write!(f, "$answered"),
            Keyword::Recent => write!(f, "$recent"),
            Keyword::Important => write!(f, "$important"),
            Keyword::Phishing => write!(f, "$phishing"),
            Keyword::Junk => write!(f, "$junk"),
            Keyword::NotJunk => write!(f, "$notjunk"),
            Keyword::Deleted => write!(f, "$deleted"),
            Keyword::Forwarded => write!(f, "$forwarded"),
            Keyword::MdnSent => write!(f, "$mdnsent"),
            Keyword::Other(s) => write!(f, "{}", s),
        }
    }
}

impl Display for ArchivedKeyword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchivedKeyword::Seen => write!(f, "$seen"),
            ArchivedKeyword::Draft => write!(f, "$draft"),
            ArchivedKeyword::Flagged => write!(f, "$flagged"),
            ArchivedKeyword::Answered => write!(f, "$answered"),
            ArchivedKeyword::Recent => write!(f, "$recent"),
            ArchivedKeyword::Important => write!(f, "$important"),
            ArchivedKeyword::Phishing => write!(f, "$phishing"),
            ArchivedKeyword::Junk => write!(f, "$junk"),
            ArchivedKeyword::NotJunk => write!(f, "$notjunk"),
            ArchivedKeyword::Deleted => write!(f, "$deleted"),
            ArchivedKeyword::Forwarded => write!(f, "$forwarded"),
            ArchivedKeyword::MdnSent => write!(f, "$mdnsent"),
            ArchivedKeyword::Other(s) => write!(f, "{}", s),
        }
    }
}

impl Serialize for Keyword {
    fn serialize(&self) -> trc::Result<Vec<u8>> {
        Ok(match self {
            Keyword::Seen => vec![SEEN as u8],
            Keyword::Draft => vec![DRAFT as u8],
            Keyword::Flagged => vec![FLAGGED as u8],
            Keyword::Answered => vec![ANSWERED as u8],
            Keyword::Recent => vec![RECENT as u8],
            Keyword::Important => vec![IMPORTANT as u8],
            Keyword::Phishing => vec![PHISHING as u8],
            Keyword::Junk => vec![JUNK as u8],
            Keyword::NotJunk => vec![NOTJUNK as u8],
            Keyword::Deleted => vec![DELETED as u8],
            Keyword::Forwarded => vec![FORWARDED as u8],
            Keyword::MdnSent => vec![MDN_SENT as u8],
            Keyword::Other(string) => string.as_bytes().to_vec(),
        })
    }
}

impl Keyword {
    pub fn id(&self) -> Result<u32, &str> {
        match self {
            Keyword::Seen => Ok(SEEN as u32),
            Keyword::Draft => Ok(DRAFT as u32),
            Keyword::Flagged => Ok(FLAGGED as u32),
            Keyword::Answered => Ok(ANSWERED as u32),
            Keyword::Recent => Ok(RECENT as u32),
            Keyword::Important => Ok(IMPORTANT as u32),
            Keyword::Phishing => Ok(PHISHING as u32),
            Keyword::Junk => Ok(JUNK as u32),
            Keyword::NotJunk => Ok(NOTJUNK as u32),
            Keyword::Deleted => Ok(DELETED as u32),
            Keyword::Forwarded => Ok(FORWARDED as u32),
            Keyword::MdnSent => Ok(MDN_SENT as u32),
            Keyword::Other(string) => Err(string.as_str()),
        }
    }

    pub fn into_id(self) -> Result<u32, String> {
        match self {
            Keyword::Seen => Ok(SEEN as u32),
            Keyword::Draft => Ok(DRAFT as u32),
            Keyword::Flagged => Ok(FLAGGED as u32),
            Keyword::Answered => Ok(ANSWERED as u32),
            Keyword::Recent => Ok(RECENT as u32),
            Keyword::Important => Ok(IMPORTANT as u32),
            Keyword::Phishing => Ok(PHISHING as u32),
            Keyword::Junk => Ok(JUNK as u32),
            Keyword::NotJunk => Ok(NOTJUNK as u32),
            Keyword::Deleted => Ok(DELETED as u32),
            Keyword::Forwarded => Ok(FORWARDED as u32),
            Keyword::MdnSent => Ok(MDN_SENT as u32),
            Keyword::Other(string) => Err(string),
        }
    }

    pub fn try_from_id(id: usize) -> Result<Self, usize> {
        match id {
            SEEN => Ok(Keyword::Seen),
            DRAFT => Ok(Keyword::Draft),
            FLAGGED => Ok(Keyword::Flagged),
            ANSWERED => Ok(Keyword::Answered),
            RECENT => Ok(Keyword::Recent),
            IMPORTANT => Ok(Keyword::Important),
            PHISHING => Ok(Keyword::Phishing),
            JUNK => Ok(Keyword::Junk),
            NOTJUNK => Ok(Keyword::NotJunk),
            DELETED => Ok(Keyword::Deleted),
            FORWARDED => Ok(Keyword::Forwarded),
            MDN_SENT => Ok(Keyword::MdnSent),
            _ => Err(id),
        }
    }
}

impl ArchivedKeyword {
    pub fn id(&self) -> Result<u32, &str> {
        match self {
            ArchivedKeyword::Seen => Ok(SEEN as u32),
            ArchivedKeyword::Draft => Ok(DRAFT as u32),
            ArchivedKeyword::Flagged => Ok(FLAGGED as u32),
            ArchivedKeyword::Answered => Ok(ANSWERED as u32),
            ArchivedKeyword::Recent => Ok(RECENT as u32),
            ArchivedKeyword::Important => Ok(IMPORTANT as u32),
            ArchivedKeyword::Phishing => Ok(PHISHING as u32),
            ArchivedKeyword::Junk => Ok(JUNK as u32),
            ArchivedKeyword::NotJunk => Ok(NOTJUNK as u32),
            ArchivedKeyword::Deleted => Ok(DELETED as u32),
            ArchivedKeyword::Forwarded => Ok(FORWARDED as u32),
            ArchivedKeyword::MdnSent => Ok(MDN_SENT as u32),
            ArchivedKeyword::Other(string) => Err(string.as_str()),
        }
    }
}

impl From<Keyword> for TagValue {
    fn from(value: Keyword) -> Self {
        match value.into_id() {
            Ok(id) => TagValue::Id(id),
            Err(string) => TagValue::Text(string.as_bytes().to_vec()),
        }
    }
}

impl From<&Keyword> for TagValue {
    fn from(value: &Keyword) -> Self {
        match value.id() {
            Ok(id) => TagValue::Id(id),
            Err(string) => TagValue::Text(string.as_bytes().to_vec()),
        }
    }
}

impl From<&ArchivedKeyword> for TagValue {
    fn from(value: &ArchivedKeyword) -> Self {
        match value.id() {
            Ok(id) => TagValue::Id(id),
            Err(string) => TagValue::Text(string.as_bytes().to_vec()),
        }
    }
}

impl From<&ArchivedKeyword> for Keyword {
    fn from(value: &ArchivedKeyword) -> Self {
        match value {
            ArchivedKeyword::Seen => Keyword::Seen,
            ArchivedKeyword::Draft => Keyword::Draft,
            ArchivedKeyword::Flagged => Keyword::Flagged,
            ArchivedKeyword::Answered => Keyword::Answered,
            ArchivedKeyword::Recent => Keyword::Recent,
            ArchivedKeyword::Important => Keyword::Important,
            ArchivedKeyword::Phishing => Keyword::Phishing,
            ArchivedKeyword::Junk => Keyword::Junk,
            ArchivedKeyword::NotJunk => Keyword::NotJunk,
            ArchivedKeyword::Deleted => Keyword::Deleted,
            ArchivedKeyword::Forwarded => Keyword::Forwarded,
            ArchivedKeyword::MdnSent => Keyword::MdnSent,
            ArchivedKeyword::Other(string) => Keyword::Other(string.as_str().into()),
        }
    }
}
