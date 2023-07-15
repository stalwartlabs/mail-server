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

use std::fmt::Display;

use serde::ser::SerializeMap;
use serde::Serialize;

#[derive(Debug)]
pub enum MethodError {
    InvalidArguments(String),
    RequestTooLarge,
    StateMismatch,
    AnchorNotFound,
    UnsupportedFilter(String),
    UnsupportedSort(String),
    ServerFail(String),
    UnknownMethod(String),
    ServerUnavailable,
    ServerPartialFail,
    InvalidResultReference(String),
    Forbidden(String),
    AccountNotFound,
    AccountNotSupportedByMethod,
    AccountReadOnly,
    NotFound,
}

impl Display for MethodError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MethodError::InvalidArguments(err) => write!(f, "Invalid arguments: {}", err),
            MethodError::RequestTooLarge => write!(f, "Request too large"),
            MethodError::StateMismatch => write!(f, "State mismatch"),
            MethodError::AnchorNotFound => write!(f, "Anchor not found"),
            MethodError::UnsupportedFilter(err) => write!(f, "Unsupported filter: {}", err),
            MethodError::UnsupportedSort(err) => write!(f, "Unsupported sort: {}", err),
            MethodError::ServerFail(err) => write!(f, "Server error: {}", err),
            MethodError::UnknownMethod(err) => write!(f, "Unknown method: {}", err),
            MethodError::ServerUnavailable => write!(f, "Server unavailable"),
            MethodError::ServerPartialFail => write!(f, "Server partial fail"),
            MethodError::InvalidResultReference(err) => {
                write!(f, "Invalid result reference: {}", err)
            }
            MethodError::Forbidden(err) => write!(f, "Forbidden: {}", err),
            MethodError::AccountNotFound => write!(f, "Account not found"),
            MethodError::AccountNotSupportedByMethod => {
                write!(f, "Account not supported by method")
            }
            MethodError::AccountReadOnly => write!(f, "Account read only"),
            MethodError::NotFound => write!(f, "Not found"),
        }
    }
}

impl Serialize for MethodError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(2.into())?;

        let (error_type, description) = match self {
            MethodError::InvalidArguments(description) => {
                ("invalidArguments", description.as_str())
            }
            MethodError::RequestTooLarge => (
                "requestTooLarge",
                concat!(
                    "The number of ids requested by the client exceeds the maximum number ",
                    "the server is willing to process in a single method call."
                ),
            ),
            MethodError::StateMismatch => (
                "stateMismatch",
                concat!(
                    "An \"ifInState\" argument was supplied, but ",
                    "it does not match the current state."
                ),
            ),
            MethodError::AnchorNotFound => (
                "anchorNotFound",
                concat!(
                    "An anchor argument was supplied, but it ",
                    "cannot be found in the results of the query."
                ),
            ),
            MethodError::UnsupportedFilter(description) => {
                ("unsupportedFilter", description.as_str())
            }
            MethodError::UnsupportedSort(description) => ("unsupportedSort", description.as_str()),
            MethodError::ServerFail(_) => ("serverFail", {
                concat!(
                    "An unexpected error occurred while processing ",
                    "this call, please contact the system administrator."
                )
            }),
            MethodError::NotFound => ("serverPartialFail", {
                concat!(
                    "One or more items are no longer available on the ",
                    "server, please try again."
                )
            }),
            MethodError::UnknownMethod(description) => ("unknownMethod", description.as_str()),
            MethodError::ServerUnavailable => (
                "serverUnavailable",
                concat!(
                    "This server is temporarily unavailable. ",
                    "Attempting this same operation later may succeed."
                ),
            ),
            MethodError::ServerPartialFail => (
                "serverPartialFail",
                concat!(
                    "Some, but not all, expected changes described by the method ",
                    "occurred. Please resynchronize to determine server state."
                ),
            ),
            MethodError::InvalidResultReference(description) => {
                ("invalidResultReference", description.as_str())
            }
            MethodError::Forbidden(description) => ("forbidden", description.as_str()),
            MethodError::AccountNotFound => (
                "accountNotFound",
                "The accountId does not correspond to a valid account",
            ),
            MethodError::AccountNotSupportedByMethod => (
                "accountNotSupportedByMethod",
                concat!(
                    "The accountId given corresponds to a valid account, ",
                    "but the account does not support this method or data type."
                ),
            ),
            MethodError::AccountReadOnly => (
                "accountReadOnly",
                "This method modifies state, but the account is read-only.",
            ),
        };

        map.serialize_entry("type", error_type)?;
        if !description.is_empty() {
            map.serialize_entry("description", description)?;
        }
        map.end()
    }
}
