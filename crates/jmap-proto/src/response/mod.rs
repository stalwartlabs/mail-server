/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod references;
pub mod serialize;

use std::collections::HashMap;

use crate::{
    error::method::MethodErrorWrapper,
    method::{
        changes::ChangesResponse,
        copy::{CopyBlobResponse, CopyResponse},
        get::GetResponse,
        import::ImportEmailResponse,
        lookup::BlobLookupResponse,
        parse::ParseEmailResponse,
        query::QueryResponse,
        query_changes::QueryChangesResponse,
        search_snippet::GetSearchSnippetResponse,
        set::SetResponse,
        upload::BlobUploadResponse,
        validate::ValidateSieveScriptResponse,
    },
    request::{echo::Echo, method::MethodName, Call},
    types::any_id::AnyId,
};

use self::serialize::serialize_hex;

#[derive(Debug, serde::Serialize)]
#[serde(untagged)]
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
    LookupBlob(BlobLookupResponse),
    UploadBlob(BlobUploadResponse),
    Echo(Echo),
    Error(MethodErrorWrapper),
}

#[derive(Debug, serde::Serialize)]
pub struct Response {
    #[serde(rename = "methodResponses")]
    pub method_responses: Vec<Call<ResponseMethod>>,

    #[serde(rename = "sessionState")]
    #[serde(serialize_with = "serialize_hex")]
    pub session_state: u32,

    #[serde(rename = "createdIds")]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub created_ids: HashMap<String, AnyId>,
}

impl Response {
    pub fn new(session_state: u32, created_ids: HashMap<String, AnyId>, capacity: usize) -> Self {
        Response {
            session_state,
            created_ids,
            method_responses: Vec::with_capacity(capacity),
        }
    }

    pub fn push_response(
        &mut self,
        id: String,
        name: MethodName,
        method: impl Into<ResponseMethod>,
    ) {
        self.method_responses.push(Call {
            id,
            method: method.into(),
            name,
        });
    }

    pub fn push_error(&mut self, id: String, err: impl Into<MethodErrorWrapper>) {
        self.method_responses.push(Call {
            id,
            method: ResponseMethod::Error(err.into()),
            name: MethodName::error(),
        });
    }

    pub fn push_created_id(&mut self, create_id: String, id: impl Into<AnyId>) {
        self.created_ids.insert(create_id, id.into());
    }
}

impl From<trc::Error> for ResponseMethod {
    fn from(error: trc::Error) -> Self {
        ResponseMethod::Error(error.into())
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

impl From<BlobUploadResponse> for ResponseMethod {
    fn from(upload_blob: BlobUploadResponse) -> Self {
        ResponseMethod::UploadBlob(upload_blob)
    }
}

impl From<BlobLookupResponse> for ResponseMethod {
    fn from(lookup_blob: BlobLookupResponse) -> Self {
        ResponseMethod::LookupBlob(lookup_blob)
    }
}

impl<T: Into<ResponseMethod>> From<trc::Result<T>> for ResponseMethod {
    fn from(result: trc::Result<T>) -> Self {
        match result {
            Ok(value) => value.into(),
            Err(error) => error.into(),
        }
    }
}
