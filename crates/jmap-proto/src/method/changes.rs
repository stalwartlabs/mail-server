use crate::{
    error::method::MethodError,
    parser::{json::Parser, Error, Ignore, JsonObjectParser, Token},
    request::{method::MethodObject, RequestProperty},
    types::{id::Id, property::Property, state::State},
};

#[derive(Debug, Clone)]
pub struct ChangesRequest {
    pub account_id: Id,
    pub since_state: State,
    pub max_changes: Option<usize>,
    pub arguments: RequestArguments,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChangesResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "oldState")]
    pub old_state: State,

    #[serde(rename = "newState")]
    pub new_state: State,

    #[serde(rename = "hasMoreChanges")]
    pub has_more_changes: bool,

    pub created: Vec<Id>,

    pub updated: Vec<Id>,

    pub destroyed: Vec<Id>,

    #[serde(rename = "updatedProperties")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_properties: Option<Vec<Property>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum RequestArguments {
    Email,
    Mailbox,
    Thread,
    Identity,
    EmailSubmission,
}

impl JsonObjectParser for ChangesRequest {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut request = ChangesRequest {
            arguments: match &parser.ctx {
                MethodObject::Email => RequestArguments::Email,
                MethodObject::Mailbox => RequestArguments::Mailbox,
                MethodObject::Thread => RequestArguments::Thread,
                MethodObject::Identity => RequestArguments::Identity,
                MethodObject::EmailSubmission => RequestArguments::EmailSubmission,
                _ => {
                    return Err(Error::Method(MethodError::UnknownMethod(format!(
                        "{}/changes",
                        parser.ctx
                    ))))
                }
            },
            account_id: Id::default(),
            since_state: State::Initial,
            max_changes: None,
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match &key.hash[0] {
                0x6449_746e_756f_6363_61 => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                0x6574_6174_5365_636e_6973 => {
                    request.since_state = parser
                        .next_token::<State>()?
                        .unwrap_string("sinceQueryState")?;
                }
                0x7365_676e_6168_4378_616d => {
                    request.max_changes = parser
                        .next_token::<Ignore>()?
                        .unwrap_usize_or_null("maxChanges")?;
                }

                _ => {
                    parser.skip_token(parser.depth_array, parser.depth_dict)?;
                }
            }
        }

        Ok(request)
    }
}
