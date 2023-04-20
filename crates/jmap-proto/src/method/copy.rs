use serde::Serialize;
use utils::map::vec_map::VecMap;

use crate::{
    error::{method::MethodError, set::SetError},
    object::Object,
    parser::{json::Parser, Error, JsonObjectParser, Token},
    request::{method::MethodObject, reference::MaybeReference, RequestProperty},
    types::{
        blob::BlobId,
        id::Id,
        state::State,
        value::{SetValue, Value},
    },
};

#[derive(Debug, Clone)]
pub struct CopyRequest {
    pub from_account_id: Id,
    pub if_from_in_state: Option<State>,
    pub account_id: Id,
    pub if_in_state: Option<State>,
    pub create: VecMap<MaybeReference<Id, String>, Object<SetValue>>,
    pub on_success_destroy_original: Option<bool>,
    pub destroy_from_if_in_state: Option<State>,
    pub arguments: RequestArguments,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CopyResponse {
    #[serde(rename = "fromAccountId")]
    pub from_account_id: Id,

    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "oldState")]
    pub old_state: State,

    #[serde(rename = "newState")]
    pub new_state: State,

    #[serde(rename = "created")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub created: VecMap<Id, Object<Value>>,

    #[serde(rename = "notCreated")]
    #[serde(skip_serializing_if = "VecMap::is_empty")]
    pub not_created: VecMap<Id, SetError>,
}

#[derive(Debug, Clone)]
pub struct CopyBlobRequest {
    pub from_account_id: Id,
    pub account_id: Id,
    pub blob_ids: Vec<BlobId>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CopyBlobResponse {
    #[serde(rename = "fromAccountId")]
    pub from_account_id: Id,

    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "copied")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copied: Option<VecMap<BlobId, BlobId>>,

    #[serde(rename = "notCopied")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_copied: Option<VecMap<BlobId, SetError>>,
}

#[derive(Debug, Clone)]
pub enum RequestArguments {
    Email,
}

impl JsonObjectParser for CopyRequest {
    fn parse(parser: &mut Parser) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut request = CopyRequest {
            arguments: match &parser.ctx {
                MethodObject::Email => RequestArguments::Email,
                _ => {
                    return Err(Error::Method(MethodError::UnknownMethod(format!(
                        "{}/copy",
                        parser.ctx
                    ))))
                }
            },
            account_id: Id::default(),
            if_in_state: None,
            from_account_id: Id::default(),
            if_from_in_state: None,
            create: VecMap::default(),
            on_success_destroy_original: None,
            destroy_from_if_in_state: None,
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match &key.hash[0] {
                0x6449_746e_756f_6363_61 => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                0x6574_6165_7263 => {
                    request.create =
                        <VecMap<MaybeReference<Id, String>, Object<SetValue>>>::parse(parser)?;
                }
                0x6449_746e_756f_6363_416d_6f72_66 => {
                    request.from_account_id =
                        parser.next_token::<Id>()?.unwrap_string("fromAccountId")?;
                }
                0x6574_6174_536e_496d_6f72_4666_69 => {
                    request.if_from_in_state = parser
                        .next_token::<State>()?
                        .unwrap_string_or_null("ifFromInState")?;
                }
                0x796f_7274_7365_4473_7365_6363_7553_6e6f => {
                    request.on_success_destroy_original = parser
                        .next_token::<String>()?
                        .unwrap_bool_or_null("onSuccessDestroyOriginal")?;
                }
                0x536e_4966_496d_6f72_4679_6f72_7473_6564 => {
                    request.destroy_from_if_in_state = parser
                        .next_token::<State>()?
                        .unwrap_string_or_null("destroyFromIfInState")?;
                }
                0x6574_6174_536e_4966_69 => {
                    request.if_in_state = parser
                        .next_token::<State>()?
                        .unwrap_string_or_null("ifInState")?;
                }
                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }
        }

        Ok(request)
    }
}

impl JsonObjectParser for CopyBlobRequest {
    fn parse(parser: &mut Parser) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut request = CopyBlobRequest {
            account_id: Id::default(),
            from_account_id: Id::default(),
            blob_ids: Vec::new(),
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match &key.hash[0] {
                0x6449_746e_756f_6363_61 => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                0x6449_746e_756f_6363_416d_6f72_66 => {
                    request.from_account_id =
                        parser.next_token::<Id>()?.unwrap_string("fromAccountId")?;
                }
                0x7364_4962_6f6c_62 => {
                    request.blob_ids = parser
                        .next_token::<Vec<BlobId>>()?
                        .unwrap_string("blobIds")?;
                }
                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }
        }

        Ok(request)
    }
}
