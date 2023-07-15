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

use crate::{
    parser::{json::Parser, Ignore, JsonObjectParser, Token},
    request::{
        reference::{MaybeReference, ResultReference},
        RequestProperty,
    },
    types::id::Id,
};

use super::query::{parse_filter, Filter};

#[derive(Debug, Clone)]
pub struct GetSearchSnippetRequest {
    pub account_id: Id,
    pub filter: Vec<Filter>,
    pub email_ids: MaybeReference<Vec<Id>, ResultReference>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GetSearchSnippetResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "list")]
    pub list: Vec<SearchSnippet>,

    #[serde(rename = "notFound")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_found: Vec<Id>,
}

#[derive(serde::Serialize, Clone, Debug)]
pub struct SearchSnippet {
    #[serde(rename = "emailId")]
    pub email_id: Id,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
}

impl JsonObjectParser for GetSearchSnippetRequest {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut request = GetSearchSnippetRequest {
            account_id: Id::default(),
            filter: vec![],
            email_ids: MaybeReference::Value(vec![]),
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match &key.hash[0] {
                0x0064_4974_6e75_6f63_6361 if !key.is_ref => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                0x7265_746c_6966 if !key.is_ref => match parser.next_token::<Ignore>()? {
                    Token::DictStart => {
                        request.filter = parse_filter(parser)?;
                    }
                    Token::Null => (),
                    token => {
                        return Err(token.error("filter", "object or null"));
                    }
                },
                0x7364_496c_6961_6d65 => {
                    request.email_ids = if !key.is_ref {
                        MaybeReference::Value(<Vec<Id>>::parse(parser)?)
                    } else {
                        MaybeReference::Reference(ResultReference::parse(parser)?)
                    };
                }
                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }
        }

        Ok(request)
    }
}
