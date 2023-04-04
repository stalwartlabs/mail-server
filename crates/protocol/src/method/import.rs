use utils::map::vec_map::VecMap;

use crate::{
    error::set::SetError,
    object::Object,
    parser::{json::Parser, JsonObjectParser, Token},
    request::{
        reference::{MaybeReference, ResultReference},
        RequestProperty,
    },
    types::{
        blob::BlobId,
        date::UTCDate,
        id::Id,
        keyword::Keyword,
        state::State,
        value::{SetValueMap, Value},
    },
};

#[derive(Debug, Clone)]
pub struct ImportEmailRequest {
    pub account_id: Id,
    pub if_in_state: Option<State>,
    pub emails: VecMap<String, EmailImport>,
}

#[derive(Debug, Clone)]
pub struct EmailImport {
    pub blob_id: BlobId,
    pub mailbox_ids: Option<MaybeReference<Vec<MaybeReference<Id, String>>, ResultReference>>,
    pub keywords: Vec<Keyword>,
    pub received_at: Option<UTCDate>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EmailImportResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "oldState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_state: Option<State>,

    #[serde(rename = "newState")]
    pub new_state: State,

    #[serde(rename = "created")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<VecMap<String, Object<Value>>>,

    #[serde(rename = "notCreated")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_created: Option<VecMap<String, SetError>>,
}

impl JsonObjectParser for ImportEmailRequest {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
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

        while {
            let property = parser.next_dict_key::<RequestProperty>()?;
            match &property.hash[0] {
                0x6449_746e_756f_6363_61 if !property.is_ref => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                0x6574_6174_536e_4966_69 if !property.is_ref => {
                    request.if_in_state = parser
                        .next_token::<State>()?
                        .unwrap_string_or_null("ifInState")?;
                }
                0x736c_6961_6d65 if !property.is_ref => {
                    request.emails = <VecMap<String, EmailImport>>::parse(parser)?;
                }
                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }

            !parser.is_dict_end()?
        } {}

        Ok(request)
    }
}

impl JsonObjectParser for EmailImport {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut request = EmailImport {
            blob_id: BlobId::default(),
            mailbox_ids: None,
            keywords: vec![],
            received_at: None,
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while {
            let property = parser.next_dict_key::<RequestProperty>()?;
            match &property.hash[0] {
                0x6449_626f_6c62 if !property.is_ref => {
                    request.blob_id = parser.next_token::<BlobId>()?.unwrap_string("blobId")?;
                }
                0x7364_4978_6f62_6c69_616d => {
                    request.mailbox_ids = if !property.is_ref {
                        Some(MaybeReference::Value(
                            <SetValueMap<MaybeReference<Id, String>>>::parse(parser)?.values,
                        ))
                    } else {
                        Some(MaybeReference::Reference(ResultReference::parse(parser)?))
                    };
                }
                0x7364_726f_7779_656b if !property.is_ref => {
                    request.keywords = <SetValueMap<Keyword>>::parse(parser)?.values;
                }
                0x7441_6465_7669_6563_6572 if !property.is_ref => {
                    request.received_at = parser
                        .next_token::<UTCDate>()?
                        .unwrap_string_or_null("receivedAt")?;
                }
                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }

            !parser.is_dict_end()?
        } {}

        Ok(request)
    }
}
