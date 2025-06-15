/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use http_proto::{HttpResponse, JsonResponse, ToHttpResponse};
use hyper::StatusCode;
use jmap_proto::{
    error::request::{RequestError, RequestLimitError},
    request::capability::Session,
    response::Response,
};

use crate::blob::UploadResponse;

pub mod event_source;
pub mod request;
pub mod session;

impl ToHttpResponse for UploadResponse {
    fn into_http_response(self) -> HttpResponse {
        JsonResponse::new(self).into_http_response()
    }
}

pub trait ToJmapHttpResponse {
    fn into_http_response(self) -> HttpResponse;
}

impl ToJmapHttpResponse for Response {
    fn into_http_response(self) -> HttpResponse {
        JsonResponse::new(self).into_http_response()
    }
}

impl ToJmapHttpResponse for Session {
    fn into_http_response(self) -> HttpResponse {
        JsonResponse::new(self).into_http_response()
    }
}

impl ToJmapHttpResponse for RequestError<'_> {
    fn into_http_response(self) -> HttpResponse {
        HttpResponse::new(StatusCode::from_u16(self.status).unwrap_or(StatusCode::BAD_REQUEST))
            .with_content_type("application/problem+json")
            .with_text_body(serde_json::to_string(&self).unwrap_or_default())
    }
}

pub trait ToRequestError {
    fn to_request_error(&self) -> RequestError<'_>;
}

impl ToRequestError for trc::Error {
    fn to_request_error(&self) -> RequestError<'_> {
        let details_or_reason = self
            .value(trc::Key::Details)
            .or_else(|| self.value(trc::Key::Reason))
            .and_then(|v| v.as_str());
        let details = details_or_reason.unwrap_or_else(|| self.as_ref().message());

        match self.as_ref() {
            trc::EventType::Jmap(cause) => match cause {
                trc::JmapEvent::UnknownCapability => RequestError::unknown_capability(details),
                trc::JmapEvent::NotJson => RequestError::not_json(details),
                trc::JmapEvent::NotRequest => RequestError::not_request(details),
                _ => RequestError::invalid_parameters(),
            },
            trc::EventType::Limit(cause) => match cause {
                trc::LimitEvent::SizeRequest => RequestError::limit(RequestLimitError::SizeRequest),
                trc::LimitEvent::SizeUpload => RequestError::limit(RequestLimitError::SizeUpload),
                trc::LimitEvent::CallsIn => RequestError::limit(RequestLimitError::CallsIn),
                trc::LimitEvent::ConcurrentRequest | trc::LimitEvent::ConcurrentConnection => {
                    RequestError::limit(RequestLimitError::ConcurrentRequest)
                }
                trc::LimitEvent::ConcurrentUpload => {
                    RequestError::limit(RequestLimitError::ConcurrentUpload)
                }
                trc::LimitEvent::Quota => RequestError::over_quota(),
                trc::LimitEvent::TenantQuota => RequestError::tenant_over_quota(),
                trc::LimitEvent::BlobQuota => RequestError::over_blob_quota(
                    self.value(trc::Key::Total)
                        .and_then(|v| v.to_uint())
                        .unwrap_or_default() as usize,
                    self.value(trc::Key::Size)
                        .and_then(|v| v.to_uint())
                        .unwrap_or_default() as usize,
                ),
                trc::LimitEvent::TooManyRequests => RequestError::too_many_requests(),
            },
            trc::EventType::Auth(cause) => match cause {
                trc::AuthEvent::MissingTotp => {
                    RequestError::blank(402, "TOTP code required", cause.message())
                }
                trc::AuthEvent::TooManyAttempts => RequestError::too_many_auth_attempts(),
                _ => RequestError::unauthorized(),
            },
            trc::EventType::Security(cause) => match cause {
                trc::SecurityEvent::AuthenticationBan
                | trc::SecurityEvent::ScanBan
                | trc::SecurityEvent::AbuseBan
                | trc::SecurityEvent::LoiterBan
                | trc::SecurityEvent::IpBlocked => RequestError::too_many_auth_attempts(),
                trc::SecurityEvent::Unauthorized => RequestError::forbidden(),
            },
            trc::EventType::Resource(cause) => match cause {
                trc::ResourceEvent::NotFound => RequestError::not_found(),
                trc::ResourceEvent::BadParameters => RequestError::blank(
                    StatusCode::BAD_REQUEST.as_u16(),
                    "Invalid parameters",
                    details_or_reason.unwrap_or("One or multiple parameters could not be parsed."),
                ),
                trc::ResourceEvent::Error => RequestError::internal_server_error(),
                _ => RequestError::internal_server_error(),
            },
            _ => RequestError::internal_server_error(),
        }
    }
}
