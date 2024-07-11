/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod capability;
pub mod echo;
pub mod method;
pub mod parser;
pub mod reference;
pub mod websocket;

use std::{
    collections::HashMap,
    fmt::{Debug, Display},
};

use crate::{
    method::{
        changes::ChangesRequest,
        copy::{self, CopyBlobRequest, CopyRequest},
        get::{self, GetRequest},
        import::ImportEmailRequest,
        lookup::BlobLookupRequest,
        parse::ParseEmailRequest,
        query::{self, QueryRequest},
        query_changes::QueryChangesRequest,
        search_snippet::GetSearchSnippetRequest,
        set::{self, SetRequest},
        upload::BlobUploadRequest,
        validate::ValidateSieveScriptRequest,
    },
    parser::{json::Parser, JsonObjectParser},
    types::any_id::AnyId,
};

use self::{echo::Echo, method::MethodName};

#[derive(Debug, Default)]
pub struct Request {
    pub using: u32,
    pub method_calls: Vec<Call<RequestMethod>>,
    pub created_ids: Option<HashMap<String, AnyId>>,
}

#[derive(Debug)]
pub struct Call<T> {
    pub id: String,
    pub name: MethodName,
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
    Set(SetRequest<set::RequestArguments>),
    Changes(ChangesRequest),
    Copy(CopyRequest<copy::RequestArguments>),
    CopyBlob(CopyBlobRequest),
    ImportEmail(ImportEmailRequest),
    ParseEmail(ParseEmailRequest),
    QueryChanges(QueryChangesRequest),
    Query(QueryRequest<query::RequestArguments>),
    SearchSnippet(GetSearchSnippetRequest),
    ValidateScript(ValidateSieveScriptRequest),
    LookupBlob(BlobLookupRequest),
    UploadBlob(BlobUploadRequest),
    Echo(Echo),
    Error(trc::Error),
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
                if ch != b'#' || parser.pos > parser.pos_marker + 1 {
                    *hash |= (ch as u128) << shift;
                    shift += 8;
                    if shift == 128 {
                        shift = 0;
                        continue 'outer;
                    }
                } else {
                    is_ref = true;
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
