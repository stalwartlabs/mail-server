pub mod references;

use ahash::AHashMap;
use serde::Serialize;

use crate::{
    error::method::MethodError,
    method::{
        ahash_is_empty,
        changes::ChangesResponse,
        copy::{CopyBlobResponse, CopyResponse},
        get::GetResponse,
        import::ImportEmailResponse,
        parse::ParseEmailResponse,
        query::QueryResponse,
        query_changes::QueryChangesResponse,
        search_snippet::GetSearchSnippetResponse,
        set::SetResponse,
        validate::ValidateSieveScriptResponse,
    },
    request::{echo::Echo, Call},
    types::id::Id,
};

#[derive(Debug, serde::Serialize)]
pub enum ResponseMethod {
    Get(GetResponse),
    Set(SetResponse),
    Changes(ChangesResponse),
    Copy(CopyResponse),
    CopyBlob(CopyBlobResponse),
    ImportEmail(ImportEmailResponse),
    ParseEmail(ParseEmailResponse),
    QueryChanges(QueryChangesResponse),
    Query(QueryResponse),
    SearchSnippet(GetSearchSnippetResponse),
    ValidateScript(ValidateSieveScriptResponse),
    Echo(Echo),
    Error(MethodError),
}

#[derive(Debug, serde::Serialize)]
pub struct Response {
    #[serde(rename = "methodResponses")]
    pub method_responses: Vec<Call<ResponseMethod>>,

    #[serde(rename = "sessionState")]
    #[serde(serialize_with = "serialize_hex")]
    pub session_state: u32,

    #[serde(rename(deserialize = "createdIds"))]
    #[serde(skip_serializing_if = "ahash_is_empty")]
    pub created_ids: AHashMap<String, Id>,
}

impl Response {
    pub fn new(session_state: u32, created_ids: AHashMap<String, Id>, capacity: usize) -> Self {
        Response {
            session_state,
            created_ids,
            method_responses: Vec::with_capacity(capacity),
        }
    }

    pub fn push_response(&mut self, id: String, method: impl Into<ResponseMethod>) {
        self.method_responses.push(Call {
            id,
            method: method.into(),
        });
    }

    pub fn push_created_id(&mut self, create_id: String, id: Id) {
        self.created_ids.insert(create_id, id);
    }
}

pub fn serialize_hex<S>(value: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    format!("{:x}", value).serialize(serializer)
}

impl From<MethodError> for ResponseMethod {
    fn from(error: MethodError) -> Self {
        ResponseMethod::Error(error)
    }
}

impl From<Echo> for ResponseMethod {
    fn from(echo: Echo) -> Self {
        ResponseMethod::Echo(echo)
    }
}

impl From<GetResponse> for ResponseMethod {
    fn from(get: GetResponse) -> Self {
        ResponseMethod::Get(get)
    }
}

impl From<SetResponse> for ResponseMethod {
    fn from(set: SetResponse) -> Self {
        ResponseMethod::Set(set)
    }
}

impl From<ChangesResponse> for ResponseMethod {
    fn from(changes: ChangesResponse) -> Self {
        ResponseMethod::Changes(changes)
    }
}

impl From<CopyResponse> for ResponseMethod {
    fn from(copy: CopyResponse) -> Self {
        ResponseMethod::Copy(copy)
    }
}

impl From<CopyBlobResponse> for ResponseMethod {
    fn from(copy_blob: CopyBlobResponse) -> Self {
        ResponseMethod::CopyBlob(copy_blob)
    }
}

impl From<ImportEmailResponse> for ResponseMethod {
    fn from(import_email: ImportEmailResponse) -> Self {
        ResponseMethod::ImportEmail(import_email)
    }
}

impl From<ParseEmailResponse> for ResponseMethod {
    fn from(parse_email: ParseEmailResponse) -> Self {
        ResponseMethod::ParseEmail(parse_email)
    }
}

impl From<QueryChangesResponse> for ResponseMethod {
    fn from(query_changes: QueryChangesResponse) -> Self {
        ResponseMethod::QueryChanges(query_changes)
    }
}

impl From<QueryResponse> for ResponseMethod {
    fn from(query: QueryResponse) -> Self {
        ResponseMethod::Query(query)
    }
}

impl From<GetSearchSnippetResponse> for ResponseMethod {
    fn from(search_snippet: GetSearchSnippetResponse) -> Self {
        ResponseMethod::SearchSnippet(search_snippet)
    }
}

impl From<ValidateSieveScriptResponse> for ResponseMethod {
    fn from(validate_script: ValidateSieveScriptResponse) -> Self {
        ResponseMethod::ValidateScript(validate_script)
    }
}
