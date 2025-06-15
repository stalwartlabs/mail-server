/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fs;

use email::message::metadata::MessageMetadata;
use imap::op::fetch::AsImapDataItem;
use imap_proto::{
    ResponseCode, StatusResponse,
    protocol::fetch::{BodyContents, DataItem, Section},
};
use mail_parser::MessageParser;
use store::{
    Deserialize, Serialize,
    write::{Archive, Archiver},
};

use super::resources_dir;

#[test]
fn imap_test_body_structure() {
    println!("Running BODYSTRUCTURE...");

    for file_name in fs::read_dir(resources_dir()).unwrap() {
        let mut file_name = file_name.as_ref().unwrap().path();
        if file_name.extension().is_none_or(|e| e != "txt") {
            continue;
        }

        let mut buf = Vec::new();
        let raw_message = fs::read(&file_name).unwrap();
        let message_ = MessageParser::new().parse(&raw_message).unwrap();
        let metadata = MessageMetadata {
            preview: Default::default(),
            size: message_.raw_message.len() as u32,
            raw_headers: message_
                .raw_message
                .as_ref()
                .get(
                    message_.root_part().offset_header as usize
                        ..message_.root_part().offset_body as usize,
                )
                .unwrap_or_default()
                .to_vec(),
            contents: vec![],
            received_at: 0,
            has_attachments: false,
            blob_hash: Default::default(),
        }
        .with_contents(message_);
        //let c = println!("metadata {:#?}", metadata);
        let metadata_ =
            Archive::deserialize_owned(Archiver::new(metadata).serialize().unwrap()).unwrap();
        let metadata = metadata_.unarchive::<MessageMetadata>().unwrap();
        let decoded = metadata.decode_contents(&raw_message);

        //let c = println!("parts {:#?}", decoded);

        // Serialize body and bodystructure
        for is_extended in [false, true] {
            let mut buf_ = Vec::new();
            metadata
                .body_structure(&decoded, is_extended)
                .serialize(&mut buf_, is_extended);
            if is_extended {
                buf.extend_from_slice(b"BODYSTRUCTURE ");
            } else {
                buf.extend_from_slice(b"BODY ");
            }

            // Poor man's indentation
            let mut indent_count = 0;
            let mut in_quote = false;
            for ch in buf_ {
                if ch == b'(' && !in_quote {
                    buf.extend_from_slice(b"(\n");
                    indent_count += 1;
                    for _ in 0..indent_count {
                        buf.extend_from_slice(b"   ");
                    }
                } else if ch == b')' && !in_quote {
                    buf.push(b'\n');
                    indent_count -= 1;
                    for _ in 0..indent_count {
                        buf.extend_from_slice(b"   ");
                    }
                    buf.push(b')');
                } else {
                    if ch == b'"' {
                        in_quote = !in_quote;
                    }
                    buf.push(ch);
                }
            }
            buf.extend_from_slice(b"\n\n");
        }

        // Serialize body parts
        let mut iter = 1..9;
        let mut stack = Vec::new();
        let mut sections = Vec::new();
        loop {
            'inner: while let Some(part_id) = iter.next() {
                if part_id == 1 {
                    for section in [
                        None,
                        Some(Section::Header),
                        Some(Section::Text),
                        Some(Section::Mime),
                    ] {
                        let mut body_sections = sections
                            .iter()
                            .map(|id| Section::Part { num: *id })
                            .collect::<Vec<_>>();
                        let is_first = if let Some(section) = section {
                            body_sections.push(section);
                            false
                        } else {
                            true
                        };

                        if let Some(contents) =
                            metadata.body_section(&decoded, &body_sections, None)
                        {
                            DataItem::BodySection {
                                sections: body_sections,
                                origin_octet: None,
                                contents,
                            }
                            .serialize(&mut buf);

                            if is_first {
                                match metadata.binary(&decoded, &sections, None) {
                                    Ok(Some(contents)) => {
                                        buf.push(b'\n');
                                        DataItem::Binary {
                                            sections: sections.clone(),
                                            offset: None,
                                            contents: match contents {
                                                BodyContents::Bytes(_) => {
                                                    BodyContents::Text("[binary content]".into())
                                                }
                                                text => text,
                                            },
                                        }
                                        .serialize(&mut buf);
                                    }
                                    Ok(None) => (),
                                    Err(_) => {
                                        buf.push(b'\n');
                                        buf.extend_from_slice(
                                            &StatusResponse::no(format!(
                                                "Failed to decode part {} of message {}.",
                                                sections
                                                    .iter()
                                                    .map(|s| s.to_string())
                                                    .collect::<Vec<_>>()
                                                    .join("."),
                                                0
                                            ))
                                            .with_code(ResponseCode::UnknownCte)
                                            .serialize(Vec::new()),
                                        );
                                    }
                                }

                                if let Some(size) = metadata.binary_size(&decoded, &sections) {
                                    buf.push(b'\n');
                                    DataItem::BinarySize {
                                        sections: sections.clone(),
                                        size,
                                    }
                                    .serialize(&mut buf);
                                }
                            }

                            buf.extend_from_slice(b"\n----------------------------------\n");
                        } else {
                            break 'inner;
                        }
                    }
                }
                sections.push(part_id);
                stack.push(iter);
                iter = 1..9;
            }
            if let Some(prev_iter) = stack.pop() {
                sections.pop();
                iter = prev_iter;
            } else {
                break;
            }
        }

        // Check header fields and partial sections
        for sections in [
            vec![Section::HeaderFields {
                not: false,
                fields: vec!["From".into(), "To".into()],
            }],
            vec![Section::HeaderFields {
                not: true,
                fields: vec!["Subject".into(), "Cc".into()],
            }],
        ] {
            DataItem::BodySection {
                contents: metadata.body_section(&decoded, &sections, None).unwrap(),
                sections: sections.clone(),
                origin_octet: None,
            }
            .serialize(&mut buf);
            buf.extend_from_slice(b"\n----------------------------------\n");
            DataItem::BodySection {
                contents: metadata
                    .body_section(&decoded, &sections, (10, 25).into())
                    .unwrap(),
                sections,
                origin_octet: 10.into(),
            }
            .serialize(&mut buf);
            buf.extend_from_slice(b"\n----------------------------------\n");
        }

        file_name.set_extension("imap");

        let expected_result = fs::read(&file_name).unwrap();

        if buf != expected_result {
            file_name.set_extension("imap_failed");
            fs::write(&file_name, buf).unwrap();
            panic!("Failed test, written output to {}", file_name.display());
        }
    }
}
