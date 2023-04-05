use std::borrow::Cow;

use mail_parser::{
    decoders::html::html_to_text,
    parsers::{fields::thread::thread_name, preview::preview_text},
    Addr, GetHeader, Group, HeaderName, HeaderValue, Message, MessagePart, PartType, RfcHeader,
};
use protocol::{
    object::Object,
    types::{
        date::UTCDate,
        keyword::Keyword,
        property::{HeaderForm, Property},
        value::Value,
    },
};
use store::{
    fts::{builder::FtsIndexBuilder, Language},
    write::{BatchBuilder, F_INDEX, F_TOKENIZE, F_VALUE},
};

use crate::email::headers::IntoForm;

pub const MAX_MESSAGE_PARTS: usize = 1000;
pub const MAX_ID_LENGTH: usize = 100;
pub const MAX_SORT_FIELD_LENGTH: usize = 255;
pub const MAX_STORED_FIELD_LENGTH: usize = 512;
pub const PREVIEW_LENGTH: usize = 256;

trait IndexMessage {
    fn index_message(
        &mut self,
        message: Message,
        keywords: Vec<Keyword>,
        mailbox_ids: Vec<u32>,
        received_at: u64,
        default_language: Language,
    ) -> store::Result<()>;
}

/*

  o  id
  o  blobId
  o  threadId
  o  mailboxIds
  o  keywords
  o  receivedAt

*/

impl IndexMessage for BatchBuilder {
    fn index_message(
        &mut self,
        message: Message,
        keywords: Vec<Keyword>,
        mailbox_ids: Vec<u32>,
        received_at: u64,
        default_language: Language,
    ) -> store::Result<()> {
        let mut object = Object::with_capacity(10);

        // Index keywords
        self.value(
            Property::Keywords,
            Value::from(keywords),
            F_VALUE | F_TOKENIZE,
        );

        // Index mailboxIds
        self.value(
            Property::MailboxIds,
            Value::from(mailbox_ids),
            F_VALUE | F_TOKENIZE,
        );

        // Index size
        object.append(Property::Size, message.raw_message.len());
        self.value(Property::Size, message.raw_message.len() as u32, F_INDEX);

        // Index receivedAt
        object.append(
            Property::ReceivedAt,
            Value::Date(UTCDate::from_timestamp(received_at as i64)),
        );
        self.value(Property::ReceivedAt, received_at, F_INDEX);

        let mut fts = FtsIndexBuilder::with_default_language(default_language);
        let mut seen_headers = [false; 40];
        let mut language = Language::Unknown;
        let mut has_attachments = false;
        let preview_part_id = message
            .text_body
            .first()
            .or_else(|| message.html_body.first())
            .copied()
            .unwrap_or(usize::MAX);

        for (part_id, part) in message
            .parts
            .into_iter()
            .take(MAX_MESSAGE_PARTS)
            .enumerate()
        {
            let part_language = part.language().unwrap_or(language);
            if part_id == 0 {
                language = part_language;
                for header in part.headers.into_iter().rev() {
                    if let HeaderName::Rfc(rfc_header) = header.name {
                        match rfc_header {
                            RfcHeader::MessageId
                            | RfcHeader::InReplyTo
                            | RfcHeader::References
                            | RfcHeader::ResentMessageId => {
                                match &header.value {
                                    HeaderValue::Text(id) if id.len() < MAX_ID_LENGTH => {
                                        self.value(Property::MessageId, id.as_ref(), F_INDEX);
                                    }
                                    HeaderValue::TextList(ids) => {
                                        for id in ids {
                                            if id.len() < MAX_ID_LENGTH {
                                                self.value(
                                                    Property::MessageId,
                                                    id.as_ref(),
                                                    F_INDEX,
                                                );
                                            }
                                        }
                                    }
                                    _ => (),
                                }

                                if matches!(rfc_header, RfcHeader::MessageId | RfcHeader::InReplyTo)
                                    && !seen_headers[rfc_header as usize]
                                {
                                    object.append(
                                        rfc_header.into(),
                                        header
                                            .value
                                            .trim_text(MAX_STORED_FIELD_LENGTH)
                                            .into_form(&HeaderForm::MessageIds),
                                    );
                                    seen_headers[rfc_header as usize] = true;
                                }
                            }
                            RfcHeader::From
                            | RfcHeader::To
                            | RfcHeader::Cc
                            | RfcHeader::Bcc
                            | RfcHeader::ReplyTo
                            | RfcHeader::Sender => {
                                let seen_header = seen_headers[rfc_header as usize];
                                if matches!(
                                    rfc_header,
                                    RfcHeader::From
                                        | RfcHeader::To
                                        | RfcHeader::Cc
                                        | RfcHeader::Bcc
                                ) {
                                    let mut sort_text =
                                        String::with_capacity(MAX_SORT_FIELD_LENGTH);
                                    let mut found_addr = seen_header;
                                    let mut last_is_space = true;

                                    header.value.visit_addresses(|value, is_addr| {
                                        if !found_addr {
                                            if !sort_text.is_empty() {
                                                sort_text.push(' ');
                                                last_is_space = true;
                                            }
                                            found_addr = is_addr;
                                            'outer: for ch in value.chars() {
                                                for ch in ch.to_lowercase() {
                                                    if sort_text.len() < MAX_SORT_FIELD_LENGTH {
                                                        let is_space = ch.is_whitespace();
                                                        if !is_space || !last_is_space {
                                                            sort_text.push(ch);
                                                            last_is_space = is_space;
                                                        }
                                                    } else {
                                                        found_addr = true;
                                                        break 'outer;
                                                    }
                                                }
                                            }
                                        }

                                        // Index an address name or email without stemming
                                        fts.index_raw(rfc_header, value);
                                    });

                                    if !seen_header {
                                        // Add address to inverted index
                                        self.value(
                                            rfc_header,
                                            if !sort_text.is_empty() {
                                                &sort_text
                                            } else {
                                                "!"
                                            },
                                            F_INDEX,
                                        );
                                    }
                                }

                                if !seen_header {
                                    // Add address to object
                                    object.append(
                                        rfc_header.into(),
                                        header
                                            .value
                                            .trim_text(MAX_STORED_FIELD_LENGTH)
                                            .into_form(&HeaderForm::Addresses),
                                    );
                                    seen_headers[rfc_header as usize] = true;
                                }
                            }
                            RfcHeader::Date => {
                                if !seen_headers[rfc_header as usize] {
                                    if let HeaderValue::DateTime(datetime) = &header.value {
                                        self.value(
                                            Property::SentAt,
                                            datetime.to_timestamp() as u64,
                                            F_INDEX,
                                        );
                                    }
                                    object.append(
                                        Property::SentAt,
                                        header.value.into_form(&HeaderForm::Date),
                                    );
                                    seen_headers[rfc_header as usize] = true;
                                }
                            }
                            RfcHeader::Subject => {
                                // Index subject
                                let subject = match &header.value {
                                    HeaderValue::Text(text) => text.clone(),
                                    HeaderValue::TextList(list) if !list.is_empty() => {
                                        list.first().unwrap().clone()
                                    }
                                    _ => "".into(),
                                };

                                if !seen_headers[rfc_header as usize] {
                                    // Add to object
                                    object.append(
                                        Property::Subject,
                                        header
                                            .value
                                            .trim_text(MAX_STORED_FIELD_LENGTH)
                                            .into_form(&HeaderForm::Text),
                                    );

                                    // Index thread name
                                    let thread_name = thread_name(&subject);
                                    self.value(
                                        Property::Subject,
                                        if !thread_name.is_empty() {
                                            thread_name.trim_text(MAX_SORT_FIELD_LENGTH)
                                        } else {
                                            "!"
                                        },
                                        F_INDEX,
                                    );

                                    seen_headers[rfc_header as usize] = true;
                                }

                                // Index subject for FTS
                                fts.index(Property::Subject, subject, language);
                            }
                            _ => (),
                        }
                    }
                }
            }

            match part.body {
                PartType::Text(text) => {
                    if part_id == preview_part_id {
                        object.append(
                            Property::Preview,
                            preview_text(text.clone(), PREVIEW_LENGTH),
                        );
                    }

                    if message.text_body.contains(&part_id) || message.html_body.contains(&part_id)
                    {
                        fts.index(Property::TextBody, text, part_language);
                    } else {
                        fts.index(Property::Attachments, text, part_language);
                        has_attachments = true;
                    }
                }
                PartType::Html(html) => {
                    let text = html_to_text(&html);
                    if part_id == preview_part_id {
                        object.append(
                            Property::Preview,
                            preview_text(text.clone().into(), PREVIEW_LENGTH),
                        );
                    }

                    if message.text_body.contains(&part_id) || message.html_body.contains(&part_id)
                    {
                        fts.index(Property::TextBody, text, part_language);
                    } else {
                        fts.index(Property::Attachments, text, part_language);
                        has_attachments = true;
                    }
                }
                PartType::Binary(_) if !has_attachments => {
                    has_attachments = true;
                }
                PartType::Message(mut nested_message) => {
                    let nested_message_language = nested_message
                        .root_part()
                        .language()
                        .unwrap_or(Language::Unknown);
                    if let Some(HeaderValue::Text(subject)) =
                        nested_message.remove_header_rfc(RfcHeader::Subject)
                    {
                        fts.index(
                            Property::Attachments,
                            subject.into_owned(),
                            nested_message_language,
                        );
                    }

                    for sub_part in nested_message.parts.into_iter().take(MAX_MESSAGE_PARTS) {
                        let language = sub_part.language().unwrap_or(nested_message_language);
                        match sub_part.body {
                            PartType::Text(text) => {
                                fts.index(Property::Attachments, text, language);
                            }
                            PartType::Html(html) => {
                                fts.index(Property::Attachments, html_to_text(&html), language);
                            }
                            _ => (),
                        }
                    }

                    if !has_attachments {
                        has_attachments = true;
                    }
                }
                _ => {}
            }
        }

        // Store and index hasAttachment property
        object.append(Property::HasAttachment, has_attachments);
        if has_attachments {
            self.bitmap(Property::HasAttachment, (), 0);
        }

        // Store properties
        self.value(Property::BodyStructure, Value::from(object), F_VALUE);

        // Store full text index
        self.custom(fts)?;

        Ok(())
    }
}

trait GetContentLanguage {
    fn language(&self) -> Option<Language>;
}

impl GetContentLanguage for MessagePart<'_> {
    fn language(&self) -> Option<Language> {
        self.headers.rfc(&RfcHeader::ContentLanguage).and_then(|v| {
            Language::from_iso_639(match v {
                HeaderValue::Text(v) => v.as_ref(),
                HeaderValue::TextList(v) => v.first()?,
                _ => {
                    return None;
                }
            })
            .unwrap_or(Language::Unknown)
            .into()
        })
    }
}

trait VisitAddresses {
    fn visit_addresses(&self, visitor: impl FnMut(&str, bool));
}

impl VisitAddresses for HeaderValue<'_> {
    fn visit_addresses(&self, mut visitor: impl FnMut(&str, bool)) {
        match self {
            HeaderValue::Address(addr) => {
                if let Some(name) = &addr.name {
                    visitor(name.as_ref(), false);
                }
                if let Some(addr) = &addr.address {
                    visitor(addr.as_ref(), true);
                }
            }
            HeaderValue::AddressList(addr_list) => {
                for addr in addr_list {
                    if let Some(name) = &addr.name {
                        visitor(name.as_ref(), false);
                    }
                    if let Some(addr) = &addr.address {
                        visitor(addr.as_ref(), true);
                    }
                }
            }
            HeaderValue::Group(group) => {
                if let Some(name) = &group.name {
                    visitor(name.as_ref(), false);
                }
                for addr in &group.addresses {
                    if let Some(name) = &addr.name {
                        visitor(name.as_ref(), false);
                    }
                    if let Some(addr) = &addr.address {
                        visitor(addr.as_ref(), true);
                    }
                }
            }
            HeaderValue::GroupList(groups) => {
                for group in groups {
                    if let Some(name) = &group.name {
                        visitor(name.as_ref(), false);
                    }
                    for addr in &group.addresses {
                        if let Some(name) = &addr.name {
                            visitor(name.as_ref(), false);
                        }
                        if let Some(addr) = &addr.address {
                            visitor(addr.as_ref(), true);
                        }
                    }
                }
            }
            _ => (),
        }
    }
}

trait TrimTextValue {
    fn trim_text(self, length: usize) -> Self;
}

impl TrimTextValue for HeaderValue<'_> {
    fn trim_text(self, length: usize) -> Self {
        match self {
            HeaderValue::Address(v) => HeaderValue::Address(v.trim_text(length)),
            HeaderValue::AddressList(v) => HeaderValue::AddressList(v.trim_text(length)),
            HeaderValue::Group(v) => HeaderValue::Group(v.trim_text(length)),
            HeaderValue::GroupList(v) => HeaderValue::GroupList(v.trim_text(length)),
            HeaderValue::Text(v) => HeaderValue::Text(v.trim_text(length)),
            HeaderValue::TextList(v) => HeaderValue::TextList(v.trim_text(length)),
            v => v,
        }
    }
}

impl TrimTextValue for Addr<'_> {
    fn trim_text(self, length: usize) -> Self {
        Self {
            name: self.name.map(|v| v.trim_text(length)),
            address: self.address.map(|v| v.trim_text(length)),
        }
    }
}

impl TrimTextValue for Group<'_> {
    fn trim_text(self, length: usize) -> Self {
        Self {
            name: self.name.map(|v| v.trim_text(length)),
            addresses: self.addresses.trim_text(length),
        }
    }
}

impl TrimTextValue for Cow<'_, str> {
    fn trim_text(self, length: usize) -> Self {
        if self.len() < length {
            self
        } else {
            match self {
                Cow::Borrowed(v) => v.trim_text(length).into(),
                Cow::Owned(v) => v.trim_text(length).into(),
            }
        }
    }
}

impl TrimTextValue for &str {
    fn trim_text(self, length: usize) -> Self {
        if self.len() < length {
            self
        } else {
            let mut index = 0;

            for (i, _) in self.char_indices() {
                if i > length {
                    break;
                }
                index = i;
            }

            &self[..index]
        }
    }
}

impl TrimTextValue for String {
    fn trim_text(self, length: usize) -> Self {
        if self.len() < length {
            self
        } else {
            let mut result = String::with_capacity(length);
            for (i, c) in self.char_indices() {
                if i > length {
                    break;
                }
                result.push(c);
            }
            result
        }
    }
}

impl<T: TrimTextValue> TrimTextValue for Vec<T> {
    fn trim_text(self, length: usize) -> Self {
        self.into_iter().map(|v| v.trim_text(length)).collect()
    }
}
