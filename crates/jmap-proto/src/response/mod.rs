/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart JMAP Server.
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

pub mod references;
pub mod serialize;

use std::collections::HashMap;

use crate::{
    error::method::MethodError,
    method::{
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
    request::{echo::Echo, method::MethodName, Call},
    types::id::Id,
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

    #[serde(rename = "createdIds")]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub created_ids: HashMap<String, Id>,
}

impl Response {
    pub fn new(session_state: u32, created_ids: HashMap<String, Id>, capacity: usize) -> Self {
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

    pub fn push_error(&mut self, id: String, err: MethodError) {
        self.method_responses.push(Call {
            id,
            method: ResponseMethod::Error(err),
            name: MethodName::error(),
        });
    }

    pub fn push_created_id(&mut self, create_id: String, id: Id) {
        self.created_ids.insert(create_id, id);
    }
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

impl<T: Into<ResponseMethod>> From<Result<T, MethodError>> for ResponseMethod {
    fn from(result: Result<T, MethodError>) -> Self {
        match result {
            Ok(value) => value.into(),
            Err(error) => error.into(),
        }
    }
}
