/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::map::vec_map::VecMap;

use crate::{
    parser::{json::Parser, JsonObjectParser, Token},
    request::RequestProperty,
    types::{blob::BlobId, id::Id, type_state::DataType, MaybeUnparsable},
};

#[derive(Debug, Clone)]
pub struct BlobLookupRequest {
    pub account_id: Id,
    pub type_names: Vec<MaybeUnparsable<DataType>>,
    pub ids: Vec<MaybeUnparsable<BlobId>>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BlobLookupResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "list")]
    pub list: Vec<BlobInfo>,

    #[serde(rename = "notFound")]
    pub not_found: Vec<MaybeUnparsable<BlobId>>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BlobInfo {
    pub id: BlobId,
    #[serde(rename = "matchedIds")]
    pub matched_ids: VecMap<DataType, Vec<Id>>,
}

impl JsonObjectParser for BlobLookupRequest {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut request = BlobLookupRequest {
            account_id: Id::default(),
            type_names: Vec::new(),
            ids: Vec::new(),
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match &key.hash[0] {
                0x0064_4974_6e75_6f63_6361 if !key.is_ref => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                0x0073_656d_614e_6570_7974 if !key.is_ref => {
                    request.type_names = <Vec<MaybeUnparsable<DataType>>>::parse(parser)?;
                }
                0x0073_6469 if !key.is_ref => {
                    request.ids = <Vec<MaybeUnparsable<BlobId>>>::parse(parser)?;
                }
                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }
        }

        Ok(request)
    }
}
