use std::borrow::Cow;

use mail_parser::{parsers::MessageStream, Header};

use crate::{Recipient, SpamFilterInput, SpamFilterOutput, SpamFilterResult};

pub mod date;
pub mod dmarc;
pub mod ehlo;
pub mod from;
pub mod headers;
pub mod init;
pub mod iprev;
pub mod messageid;
pub mod recipient;
pub mod replyto;

impl SpamFilterInput<'_> {
    pub fn header_as_address(&self, header: &Header<'_>) -> Option<Cow<'_, str>> {
        self.message
            .raw_message()
            .get(header.offset_start..header.offset_end)
            .map(|bytes| MessageStream::new(bytes).parse_address())
            .and_then(|addr| addr.into_address())
            .and_then(|addr| addr.into_list().into_iter().next())
            .and_then(|addr| addr.address)
    }
}

impl SpamFilterOutput {
    pub fn all_recipients(&self) -> impl Iterator<Item = &Recipient> {
        self.recipients_to
            .iter()
            .chain(self.recipients_cc.iter())
            .chain(self.recipients_bcc.iter())
    }
}

impl SpamFilterResult {
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.insert(tag.into());
    }
}
