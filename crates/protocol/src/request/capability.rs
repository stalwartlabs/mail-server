use crate::{
    error::request::RequestError,
    parser::{json::Parser, Error, JsonObjectParser},
};

#[derive(Debug, Clone, Copy, serde::Serialize, Hash, PartialEq, Eq)]
pub enum Capability {
    #[serde(rename(serialize = "urn:ietf:params:jmap:core"))]
    Core = 1 << 0,
    #[serde(rename(serialize = "urn:ietf:params:jmap:mail"))]
    Mail = 1 << 1,
    #[serde(rename(serialize = "urn:ietf:params:jmap:submission"))]
    Submission = 1 << 2,
    #[serde(rename(serialize = "urn:ietf:params:jmap:vacationresponse"))]
    VacationResponse = 1 << 3,
    #[serde(rename(serialize = "urn:ietf:params:jmap:contacts"))]
    Contacts = 1 << 4,
    #[serde(rename(serialize = "urn:ietf:params:jmap:calendars"))]
    Calendars = 1 << 5,
    #[serde(rename(serialize = "urn:ietf:params:jmap:websocket"))]
    WebSocket = 1 << 6,
    #[serde(rename(serialize = "urn:ietf:params:jmap:sieve"))]
    Sieve = 1 << 7,
}

impl JsonObjectParser for Capability {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        for ch in b"urn:ietf:params:jmap:" {
            if parser
                .next_unescaped()?
                .ok_or_else(|| parser.error_capability())?
                != *ch
            {
                return Err(parser.error_capability());
            }
        }

        match u128::parse(parser) {
            Ok(key) => match key {
                0x6572_6f63 => Ok(Capability::Core),
                0x6c69_616d => Ok(Capability::Mail),
                0x6e6f_6973_7369_6d62_7573 => Ok(Capability::Submission),
                0x6573_6e6f_7073_6572_6e6f_6974_6163_6176 => Ok(Capability::VacationResponse),
                0x7374_6361_746e_6f63 => Ok(Capability::Contacts),
                0x7372_6164_6e65_6c61_63 => Ok(Capability::Calendars),
                0x7465_6b63_6f73_6265_77 => Ok(Capability::WebSocket),
                0x6576_6569_73 => Ok(Capability::Sieve),
                _ => Err(parser.error_capability()),
            },
            Err(Error::Method(_)) => Err(parser.error_capability()),
            Err(err @ Error::Request(_)) => Err(err),
        }
    }
}

impl<'x> Parser<'x> {
    fn error_capability(&mut self) -> Error {
        if self.is_eof || self.skip_string() {
            Error::Request(RequestError::unknown_capability(&String::from_utf8_lossy(
                self.bytes[self.pos_marker..self.pos - 1].as_ref(),
            )))
        } else {
            self.error_unterminated()
        }
    }
}
