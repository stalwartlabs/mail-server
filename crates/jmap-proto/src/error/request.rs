/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{borrow::Cow, fmt::Display};

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum RequestLimitError {
    #[serde(rename = "maxSizeRequest")]
    SizeRequest,
    #[serde(rename = "maxSizeUpload")]
    SizeUpload,
    #[serde(rename = "maxCallsInRequest")]
    CallsIn,
    #[serde(rename = "maxConcurrentRequests")]
    ConcurrentRequest,
    #[serde(rename = "maxConcurrentUpload")]
    ConcurrentUpload,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum RequestErrorType {
    #[serde(rename = "urn:ietf:params:jmap:error:unknownCapability")]
    UnknownCapability,
    #[serde(rename = "urn:ietf:params:jmap:error:notJSON")]
    NotJSON,
    #[serde(rename = "urn:ietf:params:jmap:error:notRequest")]
    NotRequest,
    #[serde(rename = "urn:ietf:params:jmap:error:limit")]
    Limit,
    #[serde(rename = "about:blank")]
    Other,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RequestError<'x> {
    #[serde(rename = "type")]
    pub p_type: RequestErrorType,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<Cow<'x, str>>,
    pub detail: Cow<'x, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<RequestLimitError>,
}

impl<'x> RequestError<'x> {
    pub fn blank(
        status: u16,
        title: impl Into<Cow<'x, str>>,
        detail: impl Into<Cow<'x, str>>,
    ) -> Self {
        RequestError {
            p_type: RequestErrorType::Other,
            status,
            title: Some(title.into()),
            detail: detail.into(),
            limit: None,
        }
    }

    pub fn internal_server_error() -> Self {
        RequestError::blank(
            500,
            "Internal Server Error",
            concat!(
                "There was a problem while processing your request. ",
                "Please contact the system administrator if this problem persists."
            ),
        )
    }

    pub fn unavailable() -> Self {
        RequestError::blank(
            503,
            "Temporarily Unavailable",
            concat!(
                "There was a temporary problem while processing your request. ",
                "Please try again in a few moments."
            ),
        )
    }

    pub fn invalid_parameters() -> Self {
        RequestError::blank(
            400,
            "Invalid Parameters",
            "One or multiple parameters could not be parsed.",
        )
    }

    pub fn forbidden() -> Self {
        RequestError::blank(
            403,
            "Forbidden",
            "You do not have enough permissions to access this resource.",
        )
    }

    pub fn over_blob_quota(max_files: usize, max_bytes: usize) -> Self {
        RequestError::blank(
            403,
            "Quota exceeded",
            format!(
                "You have exceeded the blob upload quota of {} files or {} bytes.",
                max_files, max_bytes
            ),
        )
    }

    pub fn over_quota() -> Self {
        RequestError::blank(
            403,
            "Quota exceeded",
            "You have exceeded your account quota.",
        )
    }

    pub fn too_many_requests() -> Self {
        RequestError::blank(
            429,
            "Too Many Requests",
            "Your request has been rate limited. Please try again in a few seconds.",
        )
    }

    pub fn too_many_auth_attempts() -> Self {
        RequestError::blank(
            429,
            "Too Many Authentication Attempts",
            "Your request has been rate limited. Please try again in a few minutes.",
        )
    }

    pub fn limit(limit_type: RequestLimitError) -> Self {
        RequestError {
            p_type: RequestErrorType::Limit,
            status: 400,
            title: None,
            detail: match limit_type {
                RequestLimitError::SizeRequest => concat!(
                    "The request is larger than the server ",
                    "is willing to process."
                ),
                RequestLimitError::SizeUpload => concat!(
                    "The uploaded file is larger than the server ",
                    "is willing to process."
                ),
                RequestLimitError::CallsIn => concat!(
                    "The request exceeds the maximum number ",
                    "of calls in a single request."
                ),
                RequestLimitError::ConcurrentRequest => concat!(
                    "The request exceeds the maximum number ",
                    "of concurrent requests."
                ),
                RequestLimitError::ConcurrentUpload => concat!(
                    "The request exceeds the maximum number ",
                    "of concurrent uploads."
                ),
            }
            .into(),
            limit: Some(limit_type),
        }
    }

    pub fn not_found() -> Self {
        RequestError::blank(
            404,
            "Not Found",
            "The requested resource does not exist on this server.",
        )
    }

    pub fn unauthorized() -> Self {
        RequestError::blank(401, "Unauthorized", "You have to authenticate first.")
    }

    pub fn unknown_capability(capability: &str) -> RequestError {
        RequestError {
            p_type: RequestErrorType::UnknownCapability,
            limit: None,
            title: None,
            status: 400,
            detail: format!(
                concat!(
                    "The Request object used capability ",
                    "'{}', which is not supported",
                    "by this server."
                ),
                capability
            )
            .into(),
        }
    }

    pub fn not_json(detail: &str) -> RequestError {
        RequestError {
            p_type: RequestErrorType::NotJSON,
            limit: None,
            title: None,
            status: 400,
            detail: format!("Failed to parse JSON: {detail}").into(),
        }
    }

    pub fn not_request(detail: impl Into<Cow<'x, str>>) -> RequestError<'x> {
        RequestError {
            p_type: RequestErrorType::NotRequest,
            limit: None,
            title: None,
            status: 400,
            detail: detail.into(),
        }
    }
}

impl Display for RequestError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}
