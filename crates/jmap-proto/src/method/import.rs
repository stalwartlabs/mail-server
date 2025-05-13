/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use utils::map::vec_map::VecMap;

use crate::{
    error::set::SetError,
    object::Object,
    parser::{json::Parser, JsonObjectParser, Token},
    request::{
        reference::{MaybeReference, ResultReference},
        RequestProperty,
    },
    response::Response,
    types::{
        blob::BlobId,
        date::UTCDate,
        id::Id,
        keyword::Keyword,
        property::Property,
        state::{State, StateChange},
        value::{SetValueMap, Value},
    },
};

#[derive(Debug, Clone)]
pub struct ImportEmailRequest {
    pub account_id: Id,
    pub if_in_state: Option<State>,
    pub emails: VecMap<String, ImportEmail>,
}

#[derive(Debug, Clone)]
pub struct ImportEmail {
    pub blob_id: BlobId,
    pub mailbox_ids: MaybeReference<Vec<MaybeReference<Id, String>>, ResultReference>,
    pub keywords: Vec<Keyword>,
    pub received_at: Option<UTCDate>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ImportEmailResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "oldState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_state: Option<State>,

    #[serde(rename = "newState")]
    pub new_state: State,

    #[serde(rename = "created")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub created: VecMap<String, Object<Value>>,

    #[serde(rename = "notCreated")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_created: VecMap<String, SetError>,

    #[serde(skip)]
    pub state_change: Option<StateChange>,
}

impl JsonObjectParser for ImportEmailRequest {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut request = ImportEmailRequest {
            account_id: Id::default(),
            if_in_state: None,
            emails: VecMap::new(),
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match &key.hash[0] {
                0x0064_4974_6e75_6f63_6361 if !key.is_ref => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                0x0065_7461_7453_6e49_6669 if !key.is_ref => {
                    request.if_in_state = parser
                        .next_token::<State>()?
                        .unwrap_string_or_null("ifInState")?;
                }
                0x736c_6961_6d65 if !key.is_ref => {
                    request.emails = <VecMap<String, ImportEmail>>::parse(parser)?;
                }
                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }
        }

        Ok(request)
    }
}

impl JsonObjectParser for ImportEmail {
    fn parse(parser: &mut Parser<'_>) -> trc::Result<Self>
    where
        Self: Sized,
    {
        let mut request = ImportEmail {
            blob_id: BlobId::default(),
            mailbox_ids: MaybeReference::Value(vec![]),
            keywords: vec![],
            received_at: None,
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match &key.hash[0] {
                0x6449_626f_6c62 if !key.is_ref => {
                    request.blob_id = parser.next_token::<BlobId>()?.unwrap_string("blobId")?;
                }
                0x7364_4978_6f62_6c69_616d => {
                    request.mailbox_ids = if !key.is_ref {
                        MaybeReference::Value(
                            <SetValueMap<MaybeReference<Id, String>>>::parse(parser)?.values,
                        )
                    } else {
                        MaybeReference::Reference(ResultReference::parse(parser)?)
                    };
                }
                0x7364_726f_7779_656b if !key.is_ref => {
                    request.keywords = <SetValueMap<Keyword>>::parse(parser)?.values;
                }
                0x7441_6465_7669_6563_6572 if !key.is_ref => {
                    request.received_at = parser
                        .next_token::<UTCDate>()?
                        .unwrap_string_or_null("receivedAt")?;
                }
                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }
        }

        Ok(request)
    }
}

impl ImportEmailResponse {
    pub fn update_created_ids(&self, response: &mut Response) {
        for (user_id, obj) in &self.created {
            if let Some(id) = obj.get(&Property::Id).as_id() {
                response.created_ids.insert(user_id.clone(), (*id).into());
            }
        }
    }
}
