/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
