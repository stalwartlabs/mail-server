use std::fmt::Display;

use crate::parser::{json::Parser, JsonObjectParser};

pub const SEEN: u8 = 0;
pub const DRAFT: u8 = 1;
pub const FLAGGED: u8 = 2;
pub const ANSWERED: u8 = 3;
pub const RECENT: u8 = 4;
pub const IMPORTANT: u8 = 5;
pub const PHISHING: u8 = 6;
pub const JUNK: u8 = 7;
pub const NOTJUNK: u8 = 8;
pub const DELETED: u8 = 9;
pub const FORWARDED: u8 = 10;
pub const MDN_SENT: u8 = 11;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(untagged)]
pub enum Keyword {
    #[serde(rename(serialize = "$seen"))]
    Seen,
    #[serde(rename(serialize = "$draft"))]
    Draft,
    #[serde(rename(serialize = "$flagged"))]
    Flagged,
    #[serde(rename(serialize = "$answered"))]
    Answered,
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
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
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
                0x6465_6767_616c_66 => return Ok(Keyword::Flagged),
                0x6465_7265_7773_6e61 => return Ok(Keyword::Answered),
                0x746e_6563_6572 => return Ok(Keyword::Recent),
                0x746e_6174_726f_706d_69 => return Ok(Keyword::Important),
                0x676e_6968_7369_6870 => return Ok(Keyword::Phishing),
                0x6b6e_756a => return Ok(Keyword::Junk),
                0x6b6e_756a_746f_6e => return Ok(Keyword::NotJunk),
                0x0064_6574_656c_6564 => return Ok(Keyword::Deleted),
                0x6465_6472_6177_726f_66 => return Ok(Keyword::Forwarded),
                0x746e_6573_6e64_6d => return Ok(Keyword::MdnSent),
                _ => (),
            }
        }

        if parser.is_eof || parser.skip_string() {
            Ok(Keyword::Other(
                String::from_utf8_lossy(parser.bytes[parser.pos_marker..parser.pos - 1].as_ref())
                    .into_owned(),
            ))
        } else {
            Err(parser.error_unterminated())
        }
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
