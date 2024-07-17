/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, sync::Arc};

use crate::{
    core::{SelectedMailbox, Session, SessionData},
    spawn_op,
};
use ahash::AHashMap;
use common::listener::SessionStream;
use imap_proto::{
    parser::PushUnique,
    protocol::{
        expunge::Vanished,
        fetch::{
            self, Arguments, Attribute, BodyContents, BodyPart, BodyPartExtension, BodyPartFields,
            DataItem, Envelope, FetchItem, Section,
        },
        Flag,
    },
    receiver::Request,
    Command, ResponseCode, ResponseType, StatusResponse,
};
use jmap::email::metadata::MessageMetadata;
use jmap_proto::types::{
    acl::Acl, collection::Collection, id::Id, keyword::Keyword, property::Property,
    state::StateChange, type_state::DataType,
};
use mail_parser::{Address, GetHeader, HeaderName, Message, PartType};
use store::{
    query::log::{Change, Query},
    write::{assert::HashedValue, BatchBuilder, Bincode, F_BITMAP, F_VALUE},
};

use super::{FromModSeq, ImapContext};

impl<T: SessionStream> Session<T> {
    pub async fn handle_fetch(
        &mut self,
        request: Request<Command>,
        is_uid: bool,
    ) -> trc::Result<()> {
        let arguments = request.parse_fetch()?;

        let (data, mailbox) = self.state.select_data();
        let is_qresync = self.is_qresync;
        let is_rev2 = self.version.is_rev2();

        let enabled_condstore = if !self.is_condstore && arguments.changed_since.is_some()
            || arguments.attributes.contains(&Attribute::ModSeq)
        {
            self.is_condstore = true;
            true
        } else {
            false
        };

        spawn_op!(data, {
            let response = data
                .fetch(
                    arguments,
                    mailbox,
                    is_uid,
                    is_qresync,
                    is_rev2,
                    enabled_condstore,
                )
                .await?;
            data.write_bytes(response.into_bytes()).await
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub async fn fetch(
        &self,
        mut arguments: Arguments,
        mailbox: Arc<SelectedMailbox>,
        is_uid: bool,
        is_qresync: bool,
        _is_rev2: bool,
        enabled_condstore: bool,
    ) -> trc::Result<StatusResponse> {
        // Validate VANISHED parameter
        if arguments.include_vanished {
            if !is_qresync {
                return Err(trc::Cause::Imap
                    .into_err()
                    .details("Enable QRESYNC first to use the VANISHED parameter.")
                    .ctx(trc::Key::Type, ResponseType::Bad)
                    .id(arguments.tag));
            } else if !is_uid {
                return Err(trc::Cause::Imap
                    .into_err()
                    .details("VANISHED parameter is only available for UID FETCH.")
                    .ctx(trc::Key::Type, ResponseType::Bad)
                    .id(arguments.tag));
            }
        }

        // Resync messages if needed
        let account_id = mailbox.id.account_id;
        let mut modseq = self
            .synchronize_messages(&mailbox)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Convert IMAP ids to JMAP ids.
        let mut ids = mailbox
            .sequence_to_ids(&arguments.sequence_set, is_uid)
            .await
            .imap_ctx(&arguments.tag, trc::location!())?;

        // Convert state to modseq
        if let Some(changed_since) = arguments.changed_since {
            // Obtain changes since the modseq.
            let changelog = self
                .jmap
                .changes_(
                    account_id,
                    Collection::Email,
                    Query::from_modseq(changed_since),
                )
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;

            // Process changes
            let mut changed_ids = AHashMap::new();
            let mut has_vanished = false;

            for change in changelog.changes {
                match change {
                    Change::Insert(id) | Change::Update(id) | Change::ChildUpdate(id) => {
                        let id = (id & u32::MAX as u64) as u32;
                        if let Some(uid) = ids.get(&id) {
                            changed_ids.insert(id, *uid);
                        }
                        if !has_vanished {
                            has_vanished = matches!(change, Change::Update(_));
                        }
                    }
                    Change::Delete(_) => {
                        has_vanished = true;
                    }
                }
            }

            // Send vanished UIDs
            if arguments.include_vanished && has_vanished {
                // Add to vanished all known destroyed Ids
                let vanished = mailbox
                    .sequence_expand_missing(&arguments.sequence_set, true)
                    .await;

                if !vanished.is_empty() {
                    let mut buf = Vec::with_capacity(vanished.len() * 3);
                    Vanished {
                        earlier: true,
                        ids: vanished,
                    }
                    .serialize(&mut buf);
                    self.write_bytes(buf).await;
                }
            }

            // Filter out ids without changes
            if changed_ids.is_empty() {
                // Condstore was just enabled, return highest modseq.
                if enabled_condstore {
                    self.write_bytes(
                        StatusResponse::ok("Highest Modseq")
                            .with_code(ResponseCode::highest_modseq(modseq))
                            .into_bytes(),
                    )
                    .await;
                }
                return Ok(
                    StatusResponse::completed(Command::Fetch(is_uid)).with_tag(arguments.tag)
                );
            }
            ids = changed_ids;
            arguments.attributes.push_unique(Attribute::ModSeq);
        }

        // Build properties list
        let mut set_seen_flags = false;
        let mut needs_thread_id = false;
        let mut needs_blobs = false;

        for attribute in &arguments.attributes {
            match attribute {
                Attribute::BodySection { sections, .. }
                    if sections.first().map_or(false, |s| {
                        matches!(s, Section::Header | Section::HeaderFields { .. })
                    }) => {}
                Attribute::Body | Attribute::BodyStructure | Attribute::BinarySize { .. } => {
                    /*
                        Note that this did not result in \Seen being set, because
                        RFC822.HEADER response data occurs as a result of a FETCH
                        of RFC822.HEADER.  BODY[HEADER] response data occurs as a
                        result of a FETCH of BODY[HEADER] (which sets \Seen) or
                        BODY.PEEK[HEADER] (which does not set \Seen).
                    */
                    needs_blobs = true;
                }
                Attribute::BodySection { peek, .. } | Attribute::Binary { peek, .. } => {
                    if mailbox.is_select && !*peek {
                        set_seen_flags = true;
                    }
                    needs_blobs = true;
                }
                Attribute::Rfc822Text | Attribute::Rfc822 => {
                    if mailbox.is_select {
                        set_seen_flags = true;
                    }
                    needs_blobs = true;
                }
                Attribute::ThreadId => {
                    needs_thread_id = true;
                }
                _ => (),
            }
        }

        if set_seen_flags
            && !self
                .check_mailbox_acl(
                    mailbox.id.account_id,
                    mailbox.id.mailbox_id,
                    Acl::ModifyItems,
                )
                .await
                .imap_ctx(&arguments.tag, trc::location!())?
        {
            set_seen_flags = false;
        }

        if is_uid {
            if arguments.attributes.is_empty() {
                arguments.attributes.push(Attribute::Flags);
            } else if !arguments.attributes.contains(&Attribute::Uid) {
                arguments.attributes.insert(0, Attribute::Uid);
            }
        }

        let mut set_seen_ids = Vec::new();

        // Process each message
        let mut ids = ids
            .into_iter()
            .map(|(id, imap_id)| (imap_id.seqnum, imap_id.uid, id))
            .collect::<Vec<_>>();
        ids.sort_unstable_by_key(|(seqnum, _, _)| *seqnum);
        for (seqnum, uid, id) in ids {
            // Obtain attributes and keywords
            let (email, keywords) = if let (Some(email), Some(keywords)) = (
                self.jmap
                    .get_property::<Bincode<MessageMetadata>>(
                        account_id,
                        Collection::Email,
                        id,
                        &Property::BodyStructure,
                    )
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?,
                self.jmap
                    .get_property::<HashedValue<Vec<Keyword>>>(
                        account_id,
                        Collection::Email,
                        id,
                        &Property::Keywords,
                    )
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?,
            ) {
                (email.inner, keywords)
            } else {
                tracing::debug!(
                    event = "not-found",
                    account_id = account_id,
                    collection = ?Collection::Email,
                    document_id = id,
                    "Message metadata not found");
                continue;
            };

            // Fetch and parse blob
            let raw_message = if needs_blobs {
                // Retrieve raw message if needed
                match self
                    .jmap
                    .get_blob(&email.blob_hash, 0..usize::MAX)
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?
                {
                    Some(raw_message) => raw_message,
                    None => {
                        tracing::warn!(event = "not-found",
                        account_id = account_id,
                        collection = ?Collection::Email,
                        document_id = id,
                        blob_id = ?email.blob_hash,
                        "Blob not found");
                        continue;
                    }
                }
            } else {
                email.raw_headers
            };
            let message = email.contents.into_message(&raw_message);

            // Build response
            let mut items = Vec::with_capacity(arguments.attributes.len());
            let set_seen_flag =
                set_seen_flags && !keywords.inner.iter().any(|k| k == &Keyword::Seen);
            let thread_id = if needs_thread_id || set_seen_flag {
                if let Some(thread_id) = self
                    .jmap
                    .get_property::<u32>(account_id, Collection::Email, id, Property::ThreadId)
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?
                {
                    thread_id
                } else {
                    continue;
                }
            } else {
                0
            };
            for attribute in &arguments.attributes {
                match attribute {
                    Attribute::Envelope => {
                        items.push(DataItem::Envelope {
                            envelope: message.envelope(),
                        });
                    }
                    Attribute::Flags => {
                        let mut flags = keywords
                            .inner
                            .iter()
                            .map(|k| Flag::from(k.clone()))
                            .collect::<Vec<_>>();
                        if set_seen_flag {
                            flags.push(Flag::Seen);
                        }
                        items.push(DataItem::Flags { flags });
                    }
                    Attribute::InternalDate => {
                        items.push(DataItem::InternalDate {
                            date: email.received_at as i64,
                        });
                    }
                    Attribute::Preview { .. } => {
                        items.push(DataItem::Preview {
                            contents: if !email.preview.is_empty() {
                                Some(email.preview.as_bytes().into())
                            } else {
                                None
                            },
                        });
                    }
                    Attribute::Rfc822Size => {
                        items.push(DataItem::Rfc822Size { size: email.size });
                    }
                    Attribute::Uid => {
                        items.push(DataItem::Uid { uid });
                    }
                    Attribute::Rfc822 => {
                        items.push(DataItem::Rfc822 {
                            contents: raw_message.as_slice().into(),
                        });
                    }
                    Attribute::Rfc822Header => {
                        let message = message.root_part();
                        if let Some(header) =
                            raw_message.get(message.offset_header..message.offset_body)
                        {
                            items.push(DataItem::Rfc822Header {
                                contents: header.into(),
                            });
                        }
                    }
                    Attribute::Rfc822Text => {
                        items.push(DataItem::Rfc822Text {
                            contents: raw_message.as_slice().into(),
                        });
                    }
                    Attribute::Body => {
                        items.push(DataItem::Body {
                            part: message.body_structure(false),
                        });
                    }
                    Attribute::BodyStructure => {
                        items.push(DataItem::BodyStructure {
                            part: message.body_structure(true),
                        });
                    }
                    Attribute::BodySection {
                        sections, partial, ..
                    } => {
                        if let Some(contents) = message.body_section(sections, *partial) {
                            items.push(DataItem::BodySection {
                                sections: sections.to_vec(),
                                origin_octet: partial.map(|(start, _)| start),
                                contents,
                            });
                        }
                    }

                    Attribute::Binary {
                        sections, partial, ..
                    } => match message.binary(sections, *partial) {
                        Ok(Some(contents)) => {
                            items.push(DataItem::Binary {
                                sections: sections.to_vec(),
                                offset: partial.map(|(start, _)| start),
                                contents,
                            });
                        }
                        Err(_) => {
                            self.write_error(
                                trc::Cause::Imap
                                    .into_err()
                                    .details(format!(
                                        "Failed to decode part {} of message {}.",
                                        sections
                                            .iter()
                                            .map(|s| s.to_string())
                                            .collect::<Vec<_>>()
                                            .join("."),
                                        if is_uid { uid } else { seqnum }
                                    ))
                                    .code(ResponseCode::UnknownCte),
                            )
                            .await?;
                            continue;
                        }
                        _ => (),
                    },
                    Attribute::BinarySize { sections } => {
                        if let Some(size) = message.binary_size(sections) {
                            items.push(DataItem::BinarySize {
                                sections: sections.to_vec(),
                                size,
                            });
                        }
                    }
                    Attribute::ModSeq => {
                        if let Ok(Some(modseq)) = self
                            .jmap
                            .get_property::<u64>(account_id, Collection::Email, id, Property::Cid)
                            .await
                        {
                            items.push(DataItem::ModSeq { modseq: modseq + 1 });
                        }
                    }
                    Attribute::EmailId => {
                        items.push(DataItem::EmailId {
                            email_id: Id::from_parts(account_id, id).to_string(),
                        });
                    }
                    Attribute::ThreadId => {
                        items.push(DataItem::ThreadId {
                            thread_id: Id::from_parts(account_id, thread_id).to_string(),
                        });
                    }
                }
            }

            // Add flags to the response if the message was unseen
            if set_seen_flag && !arguments.attributes.contains(&Attribute::Flags) {
                let mut flags = keywords
                    .inner
                    .iter()
                    .map(|k| Flag::from(k.clone()))
                    .collect::<Vec<_>>();
                flags.push(Flag::Seen);
                items.push(DataItem::Flags { flags });
            }

            // Serialize fetch item
            let mut buf = Vec::with_capacity(128);
            FetchItem { id: seqnum, items }.serialize(&mut buf);
            self.write_bytes(buf).await?;

            // Add to set flags
            if set_seen_flag {
                set_seen_ids.push((Id::from_parts(thread_id, id), keywords));
            }
        }

        // Set Seen ids
        if !set_seen_ids.is_empty() {
            let mut changelog = self
                .jmap
                .begin_changes(account_id)
                .await
                .imap_ctx(&arguments.tag, trc::location!())?;
            for (id, mut keywords) in set_seen_ids {
                keywords.inner.push(Keyword::Seen);
                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::Email)
                    .update_document(id.document_id())
                    .assert_value(Property::Keywords, &keywords)
                    .value(Property::Keywords, keywords.inner, F_VALUE)
                    .value(Property::Keywords, Keyword::Seen, F_BITMAP)
                    .value(Property::Cid, changelog.change_id, F_VALUE);
                match self.jmap.write_batch(batch).await {
                    Ok(_) => {
                        changelog.log_update(Collection::Email, id);
                    }
                    Err(err) => {
                        if !err.is_assertion_failure() {
                            return Err(err.id(arguments.tag));
                        }
                    }
                }
            }
            if !changelog.is_empty() {
                // Write changes
                let change_id = self
                    .jmap
                    .commit_changes(account_id, changelog)
                    .await
                    .imap_ctx(&arguments.tag, trc::location!())?;
                modseq = change_id.into();
                self.jmap
                    .broadcast_state_change(
                        StateChange::new(account_id).with_change(DataType::Email, change_id),
                    )
                    .await;
            }
        }

        // Condstore was enabled with this command
        if enabled_condstore {
            self.write_bytes(
                StatusResponse::ok("Highest Modseq")
                    .with_code(ResponseCode::highest_modseq(modseq))
                    .into_bytes(),
            )
            .await;
        }

        Ok(StatusResponse::completed(Command::Fetch(is_uid)).with_tag(arguments.tag))
    }
}

#[allow(clippy::result_unit_err)]
pub trait AsImapDataItem<'x> {
    fn body_structure(&self, is_extended: bool) -> BodyPart;
    fn body_section<'z: 'x>(
        &'z self,
        sections: &[Section],
        partial: Option<(u32, u32)>,
    ) -> Option<Cow<'x, [u8]>>;
    fn binary(
        &self,
        sections: &[u32],
        partial: Option<(u32, u32)>,
    ) -> Result<Option<BodyContents>, ()>;
    fn binary_size(&self, sections: &[u32]) -> Option<usize>;
    fn as_body_part(&self, part_id: usize, is_extended: bool) -> BodyPart;
    fn envelope(&self) -> Envelope;
}

impl<'x> AsImapDataItem<'x> for Message<'x> {
    fn body_structure(&self, is_extended: bool) -> BodyPart {
        let mut stack = Vec::new();
        let mut parts = [0].iter();
        let mut message = self;
        let mut root_part = None;

        loop {
            while let Some(part_id) = parts.next() {
                let mut part = message.as_body_part(*part_id, is_extended);

                match &message.parts[*part_id].body {
                    PartType::Message(nested_message) => {
                        part.set_envelope(nested_message.envelope());
                        if let Some(root_part) = root_part {
                            stack.push((root_part, parts, message.into()));
                        }
                        root_part = part.into();
                        parts = [0].iter();
                        message = nested_message;
                        continue;
                    }
                    PartType::Multipart(subparts) => {
                        if let Some(root_part) = root_part {
                            stack.push((root_part, parts, None));
                        }
                        root_part = part.into();
                        parts = subparts.iter();
                        continue;
                    }
                    _ => (),
                }
                if let Some(root_part) = &mut root_part {
                    root_part.add_part(part);
                } else {
                    return part;
                }
            }
            if let Some((mut prev_root_part, prev_parts, prev_message)) = stack.pop() {
                if let Some(prev_message) = prev_message {
                    message = prev_message;
                }

                prev_root_part.add_part(root_part.unwrap());
                parts = prev_parts;
                root_part = prev_root_part.into();
            } else {
                break;
            }
        }

        root_part.unwrap()
    }

    fn as_body_part(&self, part_id: usize, is_extended: bool) -> BodyPart {
        let part = &self.parts[part_id];
        let body = self.raw_message.get(part.offset_body..part.offset_end);
        let (is_multipart, is_text) = match &part.body {
            PartType::Text(_) | PartType::Html(_) => (false, true),
            PartType::Multipart(_) => (true, false),
            _ => (false, false),
        };
        let content_type = part
            .headers
            .header_value(&HeaderName::ContentType)
            .and_then(|ct| ct.as_content_type());

        let mut body_md5 = None;
        let mut extension = BodyPartExtension::default();
        let mut fields = BodyPartFields::default();

        if !is_multipart || is_extended {
            fields.body_parameters = content_type.as_ref().and_then(|ct| {
                ct.attributes.as_ref().map(|at| {
                    at.iter()
                        .map(|(h, v)| (h.as_ref().into(), v.as_ref().into()))
                        .collect::<Vec<_>>()
                })
            })
        }

        if !is_multipart {
            fields.body_subtype = content_type
                .as_ref()
                .and_then(|ct| ct.c_subtype.as_ref().map(|cs| cs.as_ref().into()));

            fields.body_id = part
                .headers
                .header_value(&HeaderName::ContentId)
                .and_then(|id| id.as_text().map(|id| format!("<{}>", id).into()));

            fields.body_description = part
                .headers
                .header_value(&HeaderName::ContentDescription)
                .and_then(|ct| ct.as_text().map(|ct| ct.into()));

            fields.body_encoding = part
                .headers
                .header_value(&HeaderName::ContentTransferEncoding)
                .and_then(|ct| ct.as_text().map(|ct| ct.into()));

            fields.body_size_octets = body.as_ref().map(|b| b.len()).unwrap_or(0);

            if is_text {
                if fields.body_subtype.is_none() {
                    fields.body_subtype = Some("plain".into());
                }
                if fields.body_encoding.is_none() {
                    fields.body_encoding = Some("7bit".into());
                }
                if fields.body_parameters.is_none() {
                    fields.body_parameters = Some(vec![("charset".into(), "us-ascii".into())]);
                }
            }
        }

        if is_extended {
            if !is_multipart {
                body_md5 = body
                    .as_ref()
                    .map(|b| format!("{:x}", md5::compute(b)).into());
            }

            extension.body_disposition = part
                .headers
                .header_value(&HeaderName::ContentDisposition)
                .and_then(|cd| cd.as_content_type())
                .map(|cd| {
                    (
                        cd.c_type.as_ref().into(),
                        cd.attributes
                            .as_ref()
                            .map(|at| {
                                at.iter()
                                    .map(|(h, v)| (h.as_ref().into(), v.as_ref().into()))
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default(),
                    )
                });

            extension.body_language = part
                .headers
                .header_value(&HeaderName::ContentLanguage)
                .and_then(|hv| {
                    hv.as_text_list()
                        .map(|list| list.into_iter().map(|item| item.into()).collect())
                });

            extension.body_location = part
                .headers
                .header_value(&HeaderName::ContentLocation)
                .and_then(|ct| ct.as_text().map(|ct| ct.into()));
        }

        match &part.body {
            PartType::Multipart(parts) => BodyPart::Multipart {
                body_parts: Vec::with_capacity(parts.len()),
                body_subtype: content_type
                    .as_ref()
                    .and_then(|ct| ct.c_subtype.as_ref().map(|cs| cs.as_ref().into()))
                    .unwrap_or_else(|| "".into()),
                body_parameters: fields.body_parameters,
                extension,
            },
            PartType::Message(_) => BodyPart::Message {
                fields,
                envelope: None,
                body: None,
                body_size_lines: 0,
                body_md5,
                extension,
            },
            _ => {
                if is_text {
                    BodyPart::Text {
                        fields,
                        body_size_lines: body
                            .as_ref()
                            .map(|b| b.iter().filter(|&&ch| ch == b'\n').count())
                            .unwrap_or(0),
                        body_md5,
                        extension,
                    }
                } else {
                    BodyPart::Basic {
                        body_type: content_type
                            .as_ref()
                            .map(|ct| Cow::from(ct.c_type.as_ref())),
                        fields,
                        body_md5,
                        extension,
                    }
                }
            }
        }
    }

    fn body_section<'z: 'x>(
        &'z self,
        sections: &[Section],
        partial: Option<(u32, u32)>,
    ) -> Option<Cow<'x, [u8]>> {
        let mut part = self.root_part();
        if sections.is_empty() {
            return Some(
                get_partial_bytes(
                    self.raw_message.get(part.offset_header..part.offset_end)?,
                    partial,
                )
                .into(),
            );
        }

        let mut message = self;
        let mut sections_iter = sections.iter().enumerate().peekable();

        while let Some((section_num, section)) = sections_iter.next() {
            match section {
                Section::Part { num } => {
                    part = if let Some(sub_part_ids) = part.sub_parts() {
                        sub_part_ids
                            .get((*num).saturating_sub(1) as usize)
                            .and_then(|pos| message.parts.get(*pos))
                    } else if *num == 1 && (section_num == sections.len() - 1 || part.is_message())
                    {
                        Some(part)
                    } else {
                        None
                    }?;

                    if let (
                        PartType::Message(nested_message),
                        Some((
                            _,
                            Section::Part { .. }
                            | Section::Header
                            | Section::HeaderFields { .. }
                            | Section::Text,
                        )),
                    ) = (&part.body, sections_iter.peek())
                    {
                        message = nested_message;
                        part = message.root_part();
                    }
                }
                Section::Header => {
                    return Some(
                        get_partial_bytes(
                            message
                                .raw_message
                                .get(part.offset_header..part.offset_body)?,
                            partial,
                        )
                        .into(),
                    );
                }
                Section::HeaderFields { not, fields } => {
                    let mut headers =
                        Vec::with_capacity(part.offset_body.saturating_sub(part.offset_header));
                    for header in &part.headers {
                        let header_name = header.name.as_str();
                        if fields.iter().any(|f| header_name.eq_ignore_ascii_case(f)) != *not {
                            headers.extend_from_slice(header_name.as_bytes());
                            headers.push(b':');
                            headers.extend_from_slice(
                                message
                                    .raw_message
                                    .get(header.offset_start..header.offset_end)
                                    .unwrap_or(b""),
                            );
                        }
                    }

                    headers.extend_from_slice(b"\r\n");

                    return Some(if partial.is_none() {
                        headers.into()
                    } else {
                        get_partial_bytes(&headers, partial).to_vec().into()
                    });
                }
                Section::Text => {
                    return Some(
                        get_partial_bytes(
                            message.raw_message.get(part.offset_body..part.offset_end)?,
                            partial,
                        )
                        .into(),
                    );
                }
                Section::Mime => {
                    let mut headers =
                        Vec::with_capacity(part.offset_body.saturating_sub(part.offset_header));
                    for header in &part.headers {
                        if header.name.is_mime_header()
                            || header.name.as_str().starts_with("Content-")
                        {
                            headers.extend_from_slice(header.name.as_str().as_bytes());
                            headers.extend_from_slice(b":");
                            headers.extend_from_slice(
                                message
                                    .raw_message
                                    .get(header.offset_start..header.offset_end)
                                    .unwrap_or(b""),
                            );
                        }
                    }
                    headers.extend_from_slice(b"\r\n");
                    return Some(if partial.is_none() {
                        headers.into()
                    } else {
                        get_partial_bytes(&headers, partial).to_vec().into()
                    });
                }
            }
        }

        // BODY[x] should return both headers and body, but most clients
        // expect BODY[x] to return only the body, just like BOXY[x.TEXT] does.

        Some(
            get_partial_bytes(
                message.raw_message.get(part.offset_body..part.offset_end)?,
                partial,
            )
            .into(),
        )
    }

    fn binary(
        &self,
        sections: &[u32],
        partial: Option<(u32, u32)>,
    ) -> Result<Option<BodyContents>, ()> {
        let mut message = self;
        let mut part = self.root_part();
        let mut sections_iter = sections.iter().enumerate().peekable();

        while let Some((section_num, num)) = sections_iter.next() {
            part = if let Some(sub_part_ids) = part.sub_parts() {
                if let Some(part) = sub_part_ids
                    .get((*num).saturating_sub(1) as usize)
                    .and_then(|pos| message.parts.get(*pos))
                {
                    part
                } else {
                    return Ok(None);
                }
            } else if *num == 1 && (section_num == sections.len() - 1 || part.is_message()) {
                part
            } else {
                return Ok(None);
            };

            if let (PartType::Message(nested_message), Some(_)) = (&part.body, sections_iter.peek())
            {
                message = nested_message;
                part = message.root_part();
            }
        }

        if !part.is_encoding_problem {
            Ok(match &part.body {
                PartType::Text(text) | PartType::Html(text) => BodyContents::Text(
                    String::from_utf8_lossy(get_partial_bytes(text.as_bytes(), partial)),
                )
                .into(),
                PartType::Binary(bytes) | PartType::InlineBinary(bytes) => {
                    BodyContents::Bytes(get_partial_bytes(bytes.as_ref(), partial).into()).into()
                }
                PartType::Message(message) => BodyContents::Bytes(
                    get_partial_bytes(
                        message
                            .raw_message
                            .get(
                                message.root_part().raw_header_offset()
                                    ..message.root_part().raw_end_offset(),
                            )
                            .unwrap_or_default(),
                        partial,
                    )
                    .into(),
                )
                .into(),
                PartType::Multipart(_) => BodyContents::Bytes(
                    get_partial_bytes(
                        message
                            .raw_message
                            .get(part.raw_header_offset()..part.raw_end_offset())
                            .unwrap_or_default(),
                        partial,
                    )
                    .into(),
                )
                .into(),
            })
        } else {
            Err(())
        }
    }

    fn binary_size(&self, sections: &[u32]) -> Option<usize> {
        let mut message = self;
        let mut part = self.root_part();
        let mut sections_iter = sections.iter().enumerate().peekable();

        while let Some((section_num, num)) = sections_iter.next() {
            part = if let Some(sub_part_ids) = part.sub_parts() {
                sub_part_ids
                    .get((*num).saturating_sub(1) as usize)
                    .and_then(|pos| message.parts.get(*pos))
            } else if *num == 1 && (section_num == sections.len() - 1 || part.is_message()) {
                Some(part)
            } else {
                None
            }?;

            if let (PartType::Message(nested_message), Some(_)) = (&part.body, sections_iter.peek())
            {
                message = nested_message;
                part = message.root_part();
            }
        }

        match &part.body {
            PartType::Text(text) | PartType::Html(text) => text.len(),
            PartType::Binary(bytes) | PartType::InlineBinary(bytes) => bytes.len(),
            PartType::Message(message) => message.root_part().raw_len(),
            PartType::Multipart(_) => part.raw_len(),
        }
        .into()
    }

    fn envelope(&self) -> Envelope {
        Envelope {
            date: self.date().cloned(),
            subject: self.subject().map(|s| s.into()),
            from: self
                .header_values(HeaderName::From)
                .flat_map(|a| a.as_imap_address())
                .collect(),
            sender: self
                .header_values(HeaderName::Sender)
                .flat_map(|a| a.as_imap_address())
                .collect(),
            reply_to: self
                .header_values(HeaderName::ReplyTo)
                .flat_map(|a| a.as_imap_address())
                .collect(),
            to: self
                .header_values(HeaderName::To)
                .flat_map(|a| a.as_imap_address())
                .collect(),
            cc: self
                .header_values(HeaderName::Cc)
                .flat_map(|a| a.as_imap_address())
                .collect(),
            bcc: self
                .header_values(HeaderName::Bcc)
                .flat_map(|a| a.as_imap_address())
                .collect(),
            in_reply_to: self.in_reply_to().as_text_list().map(|list| {
                let mut irt = String::with_capacity(list.len() * 10);
                for (pos, l) in list.iter().enumerate() {
                    if pos > 0 {
                        irt.push(' ');
                    }
                    irt.push('<');
                    irt.push_str(l.as_ref());
                    irt.push('>');
                }
                irt.into()
            }),
            message_id: self.message_id().map(|id| format!("<{}>", id).into()),
        }
    }
}

#[inline(always)]
fn get_partial_bytes(bytes: &[u8], partial: Option<(u32, u32)>) -> &[u8] {
    if let Some((start, end)) = partial {
        bytes
            .get(start as usize..std::cmp::min((start + end) as usize, bytes.len()))
            .unwrap_or_default()
    } else {
        bytes
    }
}

trait AsImapAddress {
    fn as_imap_address(&self) -> Vec<fetch::Address>;
}

impl AsImapAddress for mail_parser::HeaderValue<'_> {
    fn as_imap_address(&self) -> Vec<fetch::Address> {
        let mut addresses = Vec::new();

        match self {
            mail_parser::HeaderValue::Address(Address::List(list)) => {
                for addr in list {
                    if let Some(email) = &addr.address {
                        addresses.push(fetch::Address::Single(fetch::EmailAddress {
                            name: addr.name.as_ref().map(|n| n.as_ref().into()),
                            address: email.as_ref().into(),
                        }));
                    }
                }
            }
            mail_parser::HeaderValue::Address(Address::Group(list)) => {
                for group in list {
                    addresses.push(fetch::Address::Group(fetch::AddressGroup {
                        name: group.name.as_ref().map(|n| n.as_ref().into()),
                        addresses: group
                            .addresses
                            .iter()
                            .filter_map(|addr| {
                                fetch::EmailAddress {
                                    name: addr.name.as_ref().map(|n| n.as_ref().into()),
                                    address: addr.address.as_ref()?.as_ref().into(),
                                }
                                .into()
                            })
                            .collect(),
                    }));
                }
            }
            _ => (),
        }

        addresses
    }
}
