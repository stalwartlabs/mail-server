/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use mail_parser::decoders::base64::base64_decode;
use utils::map::vec_map::VecMap;

use crate::{
    error::set::SetError,
    parser::{json::Parser, Ignore, JsonObjectParser, Token},
    request::{reference::MaybeReference, RequestProperty},
    response::Response,
    types::{blob::BlobId, id::Id},
};

use super::ahash_is_empty;

#[derive(Debug, Clone)]
pub struct BlobUploadRequest {
    pub account_id: Id,
    pub create: VecMap<String, UploadObject>,
}

#[derive(Debug, Clone)]
pub struct UploadObject {
    pub type_: Option<String>,
    pub data: Vec<DataSourceObject>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataSourceObject {
    Id {
        id: MaybeReference<BlobId, String>,
        length: Option<usize>,
        offset: Option<usize>,
    },
    Value(Vec<u8>),
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BlobUploadResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "created")]
    #[serde(skip_serializing_if = "ahash_is_empty")]
    pub created: AHashMap<String, BlobUploadResponseObject>,

    #[serde(rename = "notCreated")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_created: VecMap<String, SetError>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BlobUploadResponseObject {
    pub id: BlobId,
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_: Option<String>,
    pub size: usize,
}

impl JsonObjectParser for BlobUploadRequest {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut request = BlobUploadRequest {
            account_id: Id::default(),
            create: VecMap::new(),
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match &key.hash[0] {
                0x0064_4974_6e75_6f63_6361 if !key.is_ref => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                0x6574_6165_7263 if !key.is_ref => {
                    request.create = <VecMap<String, UploadObject>>::parse(parser)?;
                }
                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }
        }

        Ok(request)
    }
}

impl JsonObjectParser for UploadObject {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut request = UploadObject {
            type_: None,
            data: Vec::new(),
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match &key.hash[0] {
                0x6570_7974 if !key.is_ref => {
                    request.type_ = parser
                        .next_token::<String>()?
                        .unwrap_string_or_null("type")?;
                }
                0x6174_6164 if !key.is_ref => {
                    parser.next_token::<Ignore>()?.assert(Token::ArrayStart)?;
                    loop {
                        match parser.next_token::<Ignore>()? {
                            Token::Comma => (),
                            Token::ArrayEnd => break,
                            Token::DictStart => {
                                request.data.push(DataSourceObject::parse(parser)?);
                            }
                            token => return Err(token.error("", "DataSourceObject")),
                        }
                    }
                }
                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }
        }

        Ok(request)
    }
}

impl JsonObjectParser for DataSourceObject {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut data: Option<Vec<u8>> = None;
        let mut blob_id: Option<MaybeReference<BlobId, String>> = None;
        let mut offset: Option<usize> = None;
        let mut length: Option<usize> = None;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match &key.hash[0] {
                0x0074_7865_5473_613a_6174_6164 if !key.is_ref => {
                    data = parser
                        .next_token::<String>()?
                        .unwrap_string("data:asText")?
                        .into_bytes()
                        .into();
                }
                0x0034_3665_7361_4273_613a_6174_6164 if !key.is_ref => {
                    data = base64_decode(
                        parser
                            .next_token::<String>()?
                            .unwrap_string("data:asBase64")?
                            .as_bytes(),
                    )
                    .ok_or_else(|| parser.error("Failed to decode data:asBase64"))?
                    .into();
                }
                0x6449_626f_6c62 if !key.is_ref => {
                    blob_id = parser
                        .next_token::<MaybeReference<BlobId, String>>()?
                        .unwrap_string("blobId")?
                        .into();
                }
                0x6874_676e_656c if !key.is_ref => {
                    length = parser
                        .next_token::<Ignore>()?
                        .unwrap_usize_or_null("length")?;
                }
                0x7465_7366_666f if !key.is_ref => {
                    offset = parser
                        .next_token::<Ignore>()?
                        .unwrap_usize_or_null("offset")?;
                }
                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }
        }

        if let Some(data) = data {
            Ok(DataSourceObject::Value(data))
        } else if let Some(blob_id) = blob_id {
            Ok(DataSourceObject::Id {
                id: blob_id,
                length,
                offset,
            })
        } else {
            Err(parser.error("Missing data or blobId in DataSourceObject"))
        }
    }
}

impl BlobUploadResponse {
    pub fn update_created_ids(&self, response: &mut Response) {
        for (user_id, obj) in &self.created {
            response
                .created_ids
                .insert(user_id.clone(), obj.id.clone().into());
        }
    }
}
