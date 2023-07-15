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

use serde::Serialize;

use crate::{
    error::set::SetError,
    parser::{json::Parser, JsonObjectParser, Token},
    request::RequestProperty,
    types::{blob::BlobId, id::Id},
};

#[derive(Debug, Clone)]
pub struct ValidateSieveScriptRequest {
    pub account_id: Id,
    pub blob_id: BlobId,
}

#[derive(Debug, Serialize)]
pub struct ValidateSieveScriptResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,
    pub error: Option<SetError>,
}

impl JsonObjectParser for ValidateSieveScriptRequest {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut request = ValidateSieveScriptRequest {
            account_id: Id::default(),
            blob_id: BlobId::default(),
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match &key.hash[0] {
                0x0064_4974_6e75_6f63_6361 if !key.is_ref => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                0x6449_626f_6c62 if !key.is_ref => {
                    request.blob_id = parser.next_token::<BlobId>()?.unwrap_string("blobId")?;
                }
                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }
        }

        Ok(request)
    }
}
