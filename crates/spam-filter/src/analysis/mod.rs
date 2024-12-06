use crate::SpamFilterContext;

pub mod date;
pub mod dmarc;
pub mod ehlo;
pub mod headers;
pub mod init;
pub mod iprev;
pub mod messageid;

impl SpamFilterContext<'_> {
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.output.tags.insert(tag.into());
    }
}
