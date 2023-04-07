use mail_builder::mime::MimePart;
use mail_parser::{MessagePart, PartType};
use protocol::{
    object::Object,
    types::{
        blob::{BlobId, BlobSection},
        property::Property,
        value::Value,
    },
};
use store::BlobHash;

pub trait ToBodyPart {
    fn to_body_part(
        &self,
        part_id: usize,
        properties: &[Property],
        message_raw: &[u8],
        blob_id: &BlobId,
    ) -> Value;
}

impl ToBodyPart for MessagePart<'_> {
    fn to_body_part(
        &self,
        part_id: usize,
        properties: &[Property],
        message_raw: &[u8],
        blob_id: &BlobId,
    ) -> Value {
        let mut values = Object::with_capacity(properties.len());
        let has_body = !matches!(self.body, PartType::Multipart(_));

        for property in properties {
            let value = match property {
                Property::PartId => part_id.to_string().into(),
                Property::BlobId if has_body => {
                    let base_offset = blob_id.start_offset();
                    BlobId::new_section(
                        blob_id.hash,
                        self.offset_body + base_offset,
                        self.offset_end + base_offset,
                        self.encoding as u8,
                    )
                    .into()
                }
                Property::Size if has_body => match &self.body {
                    PartType::Text(text) | PartType::Html(text) => text.len(),
                    PartType::Binary(bin) | PartType::InlineBinary(bin) => bin.len(),
                    PartType::Message(message) => message.root_part().raw_len(),
                    PartType::Multipart(_) => 0,
                }
                .into(),
                _ => Value::Null,
            };
            values.append(property.clone(), value);
        }

        values.into()
    }
}
