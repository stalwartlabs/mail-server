pub mod capability;
pub mod echo;
pub mod method;
pub mod parser;
pub mod reference;

use std::{
    collections::HashMap,
    fmt::{Debug, Display},
};

use crate::{
    error::method::MethodError,
    method::{
        changes::ChangesRequest,
        copy::{CopyBlobRequest, CopyRequest},
        get::{self, GetRequest},
        import::ImportEmailRequest,
        parse::ParseEmailRequest,
        query::{self, QueryRequest},
        query_changes::QueryChangesRequest,
        search_snippet::GetSearchSnippetRequest,
        set::SetRequest,
        validate::ValidateSieveScriptRequest,
    },
    parser::{json::Parser, JsonObjectParser},
    types::id::Id,
};

use self::echo::Echo;

#[derive(Debug)]
pub struct Request {
    pub using: u32,
    pub method_calls: Vec<Call<RequestMethod>>,
    pub created_ids: Option<HashMap<String, Id>>,
}

#[derive(Debug, serde::Serialize)]
pub struct Call<T> {
    pub id: String,
    pub method: T,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RequestProperty {
    pub hash: [u128; 2],
    pub is_ref: bool,
}

#[derive(Debug)]
pub enum RequestMethod {
    Get(GetRequest<get::RequestArguments>),
    Set(SetRequest),
    Changes(ChangesRequest),
    Copy(CopyRequest),
    CopyBlob(CopyBlobRequest),
    ImportEmail(ImportEmailRequest),
    ParseEmail(ParseEmailRequest),
    QueryChanges(QueryChangesRequest),
    Query(QueryRequest<query::RequestArguments>),
    SearchSnippet(GetSearchSnippetRequest),
    ValidateScript(ValidateSieveScriptRequest),
    Echo(Echo),
    Error(MethodError),
}

impl JsonObjectParser for RequestProperty {
    fn parse(parser: &mut Parser<'_>) -> crate::parser::Result<Self>
    where
        Self: Sized,
    {
        let mut hash = [0; 2];
        let mut shift = 0;
        let mut is_ref = false;

        'outer: for hash in hash.iter_mut() {
            while let Some(ch) = parser.next_unescaped()? {
                if shift < 128 {
                    if ch != b'#' || parser.pos > parser.pos_marker + 1 {
                        *hash |= (ch as u128) << shift;
                        shift += 8;
                    } else {
                        is_ref = true;
                    }
                } else {
                    shift = 0;
                    continue 'outer;
                }
            }
            break;
        }

        Ok(RequestProperty { hash, is_ref })
    }
}

impl Display for RequestProperty {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Ok(())
    }
}

pub trait RequestPropertyParser {
    fn parse(
        &mut self,
        parser: &mut Parser,
        property: RequestProperty,
    ) -> crate::parser::Result<bool>;
}
