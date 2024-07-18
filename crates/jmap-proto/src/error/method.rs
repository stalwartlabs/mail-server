/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
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
    CannotCalculateChanges,
    UnknownDataType,
}

#[derive(Debug)]
pub struct MethodErrorWrapper(trc::Error);

impl From<trc::Error> for MethodErrorWrapper {
    fn from(value: trc::Error) -> Self {
        MethodErrorWrapper(value)
    }
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
            MethodError::UnknownDataType => write!(f, "Unknown data type"),
            MethodError::CannotCalculateChanges => write!(f, "Cannot calculate changes"),
        }
    }
}

impl Serialize for MethodErrorWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(2.into())?;

        let description = self.0.value(trc::Key::Details).and_then(|v| v.as_str());

        let (error_type, description) = match self.0.as_ref() {
            trc::Cause::Jmap(cause) => match cause {
                trc::JmapCause::InvalidArguments => {
                    ("invalidArguments", description.unwrap_or_default())
                }
                trc::JmapCause::RequestTooLarge => (
                    "requestTooLarge",
                    concat!(
                        "The number of ids requested by the client exceeds the maximum number ",
                        "the server is willing to process in a single method call."
                    ),
                ),
                trc::JmapCause::StateMismatch => (
                    "stateMismatch",
                    concat!(
                        "An \"ifInState\" argument was supplied, but ",
                        "it does not match the current state."
                    ),
                ),
                trc::JmapCause::AnchorNotFound => (
                    "anchorNotFound",
                    concat!(
                        "An anchor argument was supplied, but it ",
                        "cannot be found in the results of the query."
                    ),
                ),
                trc::JmapCause::UnsupportedFilter => {
                    ("unsupportedFilter", description.unwrap_or_default())
                }
                trc::JmapCause::UnsupportedSort => {
                    ("unsupportedSort", description.unwrap_or_default())
                }
                trc::JmapCause::NotFound => ("serverPartialFail", {
                    concat!(
                        "One or more items are no longer available on the ",
                        "server, please try again."
                    )
                }),
                trc::JmapCause::UnknownMethod => ("unknownMethod", description.unwrap_or_default()),
                trc::JmapCause::InvalidResultReference => {
                    ("invalidResultReference", description.unwrap_or_default())
                }
                trc::JmapCause::Forbidden => ("forbidden", description.unwrap_or_default()),
                trc::JmapCause::AccountNotFound => (
                    "accountNotFound",
                    "The accountId does not correspond to a valid account",
                ),
                trc::JmapCause::AccountNotSupportedByMethod => (
                    "accountNotSupportedByMethod",
                    concat!(
                        "The accountId given corresponds to a valid account, ",
                        "but the account does not support this method or data type."
                    ),
                ),
                trc::JmapCause::AccountReadOnly => (
                    "accountReadOnly",
                    "This method modifies state, but the account is read-only.",
                ),
                trc::JmapCause::UnknownDataType => (
                    "unknownDataType",
                    concat!(
                        "The server does not recognise this data type, ",
                        "or the capability to enable it is not present ",
                        "in the current Request Object."
                    ),
                ),
                trc::JmapCause::CannotCalculateChanges => (
                    "cannotCalculateChanges",
                    concat!(
                        "The server cannot calculate the changes ",
                        "between the old and new states."
                    ),
                ),
                trc::JmapCause::UnknownCapability
                | trc::JmapCause::NotJSON
                | trc::JmapCause::NotRequest => (
                    "serverUnavailable",
                    concat!(
                        "This server is temporarily unavailable. ",
                        "Attempting this same operation later may succeed."
                    ),
                ),
            },
            _ => (
                "serverUnavailable",
                concat!(
                    "This server is temporarily unavailable. ",
                    "Attempting this same operation later may succeed."
                ),
            ),
        };

        map.serialize_entry("type", error_type)?;
        if !description.is_empty() {
            map.serialize_entry("description", description)?;
        }
        map.end()
    }
}
