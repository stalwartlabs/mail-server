/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
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
    error::method::MethodError,
    method::{
        changes::ChangesRequest,
        copy::{self, CopyBlobRequest, CopyRequest},
        get::{self, GetRequest},
        import::ImportEmailRequest,
        parse::ParseEmailRequest,
        query::{self, QueryRequest},
        query_changes::QueryChangesRequest,
        search_snippet::GetSearchSnippetRequest,
        set::{self, SetRequest},
        validate::ValidateSieveScriptRequest,
    },
    parser::{json::Parser, JsonObjectParser},
    types::id::Id,
};

use self::{echo::Echo, method::MethodName};

#[derive(Debug, Default)]
pub struct Request {
    pub using: u32,
    pub method_calls: Vec<Call<RequestMethod>>,
    pub created_ids: Option<HashMap<String, Id>>,
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
