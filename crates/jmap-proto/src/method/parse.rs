/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::map::vec_map::VecMap;

use crate::{
    object::Object,
    parser::{json::Parser, Ignore, JsonObjectParser, Token},
    request::RequestProperty,
    types::{blob::BlobId, id::Id, property::Property, value::Value},
};

#[derive(Debug, Clone)]
pub struct ParseEmailRequest {
    pub account_id: Id,
    pub blob_ids: Vec<BlobId>,
    pub properties: Option<Vec<Property>>,
    pub body_properties: Option<Vec<Property>>,
    pub fetch_text_body_values: Option<bool>,
    pub fetch_html_body_values: Option<bool>,
    pub fetch_all_body_values: Option<bool>,
    pub max_body_value_bytes: Option<usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ParseEmailResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "parsed")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub parsed: VecMap<BlobId, Object<Value>>,

    #[serde(rename = "notParsable")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_parsable: Vec<BlobId>,

    #[serde(rename = "notFound")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_found: Vec<BlobId>,
}

impl JsonObjectParser for ParseEmailRequest {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut request = ParseEmailRequest {
            account_id: Id::default(),
            properties: None,
            blob_ids: vec![],
            body_properties: None,
            fetch_text_body_values: None,
            fetch_html_body_values: None,
            fetch_all_body_values: None,
            max_body_value_bytes: None,
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match (&key.hash[0], &key.hash[1]) {
                (0x0064_4974_6e75_6f63_6361, _) if !key.is_ref => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                (0x0073_6449_626f_6c62, _) => {
                    request.blob_ids = <Vec<BlobId>>::parse(parser)?;
                }
                (0x7365_6974_7265_706f_7270, _) => {
                    request.properties = <Option<Vec<Property>>>::parse(parser)?;
                }
                (0x7365_6974_7265_706f_7250_7964_6f62, _) => {
                    request.body_properties = <Option<Vec<Property>>>::parse(parser)?;
                }
                (0x6c61_5679_646f_4274_7865_5468_6374_6566, 0x0073_6575) => {
                    request.fetch_text_body_values = parser
                        .next_token::<Ignore>()?
                        .unwrap_bool_or_null("fetchTextBodyValues")?;
                }
                (0x6c61_5679_646f_424c_4d54_4868_6374_6566, 0x0073_6575) => {
                    request.fetch_html_body_values = parser
                        .next_token::<Ignore>()?
                        .unwrap_bool_or_null("fetchHTMLBodyValues")?;
                }
                (0x756c_6156_7964_6f42_6c6c_4168_6374_6566, 0x7365) => {
                    request.fetch_all_body_values = parser
                        .next_token::<Ignore>()?
                        .unwrap_bool_or_null("fetchAllBodyValues")?;
                }
                (0x6574_7942_6575_6c61_5679_646f_4278_616d, 0x73) => {
                    request.max_body_value_bytes = parser
                        .next_token::<Ignore>()?
                        .unwrap_usize_or_null("maxBodyValueBytes")?;
                }
                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }
        }

        Ok(request)
    }
}
