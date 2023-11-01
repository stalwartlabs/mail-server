/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
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
