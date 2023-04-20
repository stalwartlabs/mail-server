use crate::{
    error::method::MethodError,
    parser::{json::Parser, Error, Ignore, JsonObjectParser, Token},
    request::{method::MethodObject, RequestProperty, RequestPropertyParser},
    types::{id::Id, state::State},
};

use super::query::{parse_filter, Comparator, Filter, RequestArguments};

#[derive(Debug, Clone)]
pub struct QueryChangesRequest {
    pub account_id: Id,
    pub filter: Vec<Filter>,
    pub sort: Option<Vec<Comparator>>,
    pub since_query_state: State,
    pub max_changes: Option<usize>,
    pub up_to_id: Option<Id>,
    pub calculate_total: Option<bool>,
    pub arguments: RequestArguments,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct QueryChangesResponse {
    #[serde(rename = "accountId")]
    pub account_id: Id,

    #[serde(rename = "oldQueryState")]
    pub old_query_state: State,

    #[serde(rename = "newQueryState")]
    pub new_query_state: State,

    #[serde(rename = "total")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<usize>,

    #[serde(rename = "removed")]
    pub removed: Vec<Id>,

    #[serde(rename = "added")]
    pub added: Vec<AddedItem>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AddedItem {
    pub id: Id,
    pub index: usize,
}

impl AddedItem {
    pub fn new(id: Id, index: usize) -> Self {
        Self { id, index }
    }
}

impl JsonObjectParser for QueryChangesRequest {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut request = QueryChangesRequest {
            arguments: match &parser.ctx {
                MethodObject::Email => RequestArguments::Email(Default::default()),
                MethodObject::Mailbox => RequestArguments::Mailbox(Default::default()),
                MethodObject::EmailSubmission => RequestArguments::EmailSubmission,
                _ => {
                    return Err(Error::Method(MethodError::UnknownMethod(format!(
                        "{}/queryChanges",
                        parser.ctx
                    ))))
                }
            },
            filter: vec![],
            sort: None,
            calculate_total: None,
            account_id: Id::default(),
            since_query_state: State::Initial,
            max_changes: None,
            up_to_id: None,
        };

        parser
            .next_token::<String>()?
            .assert_jmap(Token::DictStart)?;

        while let Some(key) = parser.next_dict_key::<RequestProperty>()? {
            match &key.hash[0] {
                0x6449_746e_756f_6363_61 => {
                    request.account_id = parser.next_token::<Id>()?.unwrap_string("accountId")?;
                }
                0x7265_746c_6966 => match parser.next_token::<Ignore>()? {
                    Token::DictStart => {
                        request.filter = parse_filter(parser)?;
                    }
                    Token::Null => (),
                    token => {
                        return Err(token.error("filter", "object or null"));
                    }
                },
                0x7472_6f73 => {
                    request.sort = <Option<Vec<Comparator>>>::parse(parser)?;
                }
                0x6574_6174_5379_7265_7551_6563_6e69_73 => {
                    request.since_query_state = parser
                        .next_token::<State>()?
                        .unwrap_string("sinceQueryState")?;
                }
                0x7365_676e_6168_4378_616d => {
                    request.max_changes = parser
                        .next_token::<Ignore>()?
                        .unwrap_usize_or_null("maxChanges")?;
                }
                0x6449_6f54_7075 => {
                    request.up_to_id =
                        parser.next_token::<Id>()?.unwrap_string_or_null("upToId")?;
                }
                0x6c61_746f_5465_7461_6c75_636c_6163 => {
                    request.calculate_total = parser
                        .next_token::<Ignore>()?
                        .unwrap_bool_or_null("calculateTotal")?;
                }

                _ => {
                    if !request.arguments.parse(parser, key)? {
                        parser.skip_token(parser.depth_array, parser.depth_dict)?;
                    }
                }
            }
        }

        Ok(request)
    }
}
