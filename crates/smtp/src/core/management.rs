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

use std::{borrow::Cow, collections::HashMap, net::IpAddr, str::FromStr, sync::Arc};

use directory::{AuthResult, Type};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::{self, Bytes},
    header::{self, HeaderValue, AUTHORIZATION},
    server::conn::http1,
    service::service_fn,
    Method, StatusCode, Uri,
};
use hyper_util::rt::TokioIo;
use mail_auth::{
    dmarc::URI,
    mta_sts::ReportUri,
    report::{
        self,
        tlsrpt::{FailureDetails, Policy, TlsReport},
        Feedback,
    },
};
use mail_parser::{decoders::base64::base64_decode, DateTime};
use mail_send::Credentials;
use serde::{Deserializer, Serializer};
use serde_json::json;
use store::{
    write::{
        key::DeserializeBigEndian, now, BatchBuilder, Bincode, QueueClass, ReportClass,
        ReportEvent, ValueClass,
    },
    Deserialize, IterateParams, ValueKey, U64_LEN,
};

use utils::listener::{limiter::InFlight, SessionData, SessionManager, SessionStream};

use crate::{
    queue::{self, ErrorDetails, HostResponse, QueueId, Status},
    reporting::analysis::IncomingReport,
};

use super::{SmtpAdminSessionManager, SMTP};

#[derive(Debug, serde::Serialize)]
pub struct Response<T> {
    data: T,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Message {
    pub id: QueueId,
    pub return_path: String,
    pub domains: Vec<Domain>,
    #[serde(deserialize_with = "deserialize_datetime")]
    #[serde(serialize_with = "serialize_datetime")]
    pub created: DateTime,
    pub size: usize,
    #[serde(skip_serializing_if = "is_zero")]
    #[serde(default)]
    pub priority: i16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_id: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Domain {
    pub name: String,
    pub status: Status<String, String>,
    pub recipients: Vec<Recipient>,

    pub retry_num: u32,
    #[serde(deserialize_with = "deserialize_maybe_datetime")]
    #[serde(serialize_with = "serialize_maybe_datetime")]
    pub next_retry: Option<DateTime>,
    #[serde(deserialize_with = "deserialize_maybe_datetime")]
    #[serde(serialize_with = "serialize_maybe_datetime")]
    pub next_notify: Option<DateTime>,
    #[serde(deserialize_with = "deserialize_datetime")]
    #[serde(serialize_with = "serialize_datetime")]
    pub expires: DateTime,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Recipient {
    pub address: String,
    pub status: Status<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orcpt: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum Report {
    Tls {
        id: String,
        domain: String,
        #[serde(deserialize_with = "deserialize_datetime")]
        #[serde(serialize_with = "serialize_datetime")]
        range_from: DateTime,
        #[serde(deserialize_with = "deserialize_datetime")]
        #[serde(serialize_with = "serialize_datetime")]
        range_to: DateTime,
        report: TlsReport,
        rua: Vec<ReportUri>,
    },
    Dmarc {
        id: String,
        domain: String,
        #[serde(deserialize_with = "deserialize_datetime")]
        #[serde(serialize_with = "serialize_datetime")]
        range_from: DateTime,
        #[serde(deserialize_with = "deserialize_datetime")]
        #[serde(serialize_with = "serialize_datetime")]
        range_to: DateTime,
        report: report::Report,
        rua: Vec<URI>,
    },
}

impl SessionManager for SmtpAdminSessionManager {
    fn handle<T: SessionStream>(
        self,
        session: SessionData<T>,
    ) -> impl std::future::Future<Output = ()> + Send {
        handle_request(
            session.stream,
            self.inner,
            session.remote_ip,
            session.in_flight,
        )
    }

    #[allow(clippy::manual_async_fn)]
    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }

    fn is_ip_blocked(&self, addr: &IpAddr) -> bool {
        self.inner
            .shared
            .default_directory
            .blocked_ips
            .is_blocked(addr)
    }
}

async fn handle_request(
    stream: impl SessionStream,
    core: Arc<SMTP>,
    remote_addr: IpAddr,
    _in_flight: InFlight,
) {
    if let Err(http_err) = http1::Builder::new()
        .keep_alive(true)
        .serve_connection(
            TokioIo::new(stream),
            service_fn(|req: hyper::Request<body::Incoming>| {
                let core = core.clone();

                async move {
                    let mut response = core.parse_request(&req, remote_addr).await;

                    // Add CORS headers
                    if let Ok(response) = &mut response {
                        let headers = response.headers_mut();
                        headers.insert(
                            header::ACCESS_CONTROL_ALLOW_ORIGIN,
                            HeaderValue::from_static("*"),
                        );
                        headers.insert(
                            header::ACCESS_CONTROL_ALLOW_METHODS,
                            HeaderValue::from_static(
                                "POST, GET, PATCH, PUT, DELETE, HEAD, OPTIONS",
                            ),
                        );
                        headers.insert(
                            header::ACCESS_CONTROL_ALLOW_HEADERS,
                            HeaderValue::from_static(
                                "Authorization, Content-Type, Accept, X-Requested-With",
                            ),
                        );
                    }

                    tracing::debug!(
                        context = "management",
                        event = "request",
                        remote.ip = remote_addr.to_string(),
                        uri = req.uri().to_string(),
                        status = match &response {
                            Ok(response) => response.status().to_string(),
                            Err(error) => error.to_string(),
                        }
                    );

                    response
                }
            }),
        )
        .await
    {
        tracing::debug!(
            context = "management",
            event = "http-error",
            remote.ip = remote_addr.to_string(),
            reason = %http_err,
        );
    }
}

impl SMTP {
    async fn parse_request(
        &self,
        req: &hyper::Request<hyper::body::Incoming>,
        remote_addr: IpAddr,
    ) -> Result<hyper::Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        if req.method() == Method::OPTIONS {
            return Ok(hyper::Response::builder()
                .status(StatusCode::OK)
                .body(
                    Empty::<Bytes>::new()
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap());
        }

        // Authenticate request
        let mut is_authenticated = false;
        if let Some((mechanism, payload)) = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.trim().split_once(' '))
        {
            if mechanism.eq_ignore_ascii_case("basic") {
                // Decode the base64 encoded credentials
                if let Some((username, secret)) = base64_decode(payload.as_bytes())
                    .and_then(|token| String::from_utf8(token).ok())
                    .and_then(|token| {
                        token.split_once(':').map(|(login, secret)| {
                            (login.trim().to_lowercase(), secret.to_string())
                        })
                    })
                {
                    match self
                        .shared
                        .default_directory
                        .authenticate(&Credentials::Plain { username, secret }, remote_addr, false)
                        .await
                    {
                        Ok(AuthResult::Success(principal)) if principal.typ == Type::Superuser => {
                            is_authenticated = true;
                        }
                        Ok(AuthResult::Success(_)) => {
                            tracing::debug!(
                                context = "management",
                                event = "auth-error",
                                "Insufficient privileges."
                            );
                        }
                        Ok(AuthResult::Failure | AuthResult::Banned) => {
                            tracing::debug!(
                                context = "management",
                                event = "auth-error",
                                "Invalid username or password."
                            );
                        }
                        _ => {
                            tracing::debug!(
                                context = "management",
                                event = "auth-error",
                                "Temporary authentication failure."
                            );
                        }
                    }
                } else {
                    tracing::debug!(
                        context = "management",
                        event = "auth-error",
                        "Failed to decode base64 Authorization header."
                    );
                }
            } else {
                tracing::debug!(
                    context = "management",
                    event = "auth-error",
                    mechanism = mechanism,
                    "Unsupported authentication mechanism."
                );
            }
        }
        if !is_authenticated {
            return Ok(hyper::Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(header::WWW_AUTHENTICATE, "Basic realm=\"Stalwart SMTP\"")
                .body(
                    Empty::<Bytes>::new()
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap());
        }

        let mut path = req.uri().path().split('/');
        path.next();
        path.next(); // Skip the leading /api
        Ok(self
            .handle_manage_request(
                req.uri(),
                req.method(),
                path.next().unwrap_or_default(),
                path.next().unwrap_or_default(),
                path.next(),
            )
            .await)
    }

    pub async fn handle_manage_request(
        &self,
        uri: &Uri,
        method: &Method,
        path_1: &str,
        path_2: &str,
        path_3: Option<&str>,
    ) -> hyper::Response<BoxBody<Bytes, hyper::Error>> {
        let params = UrlParams::new(uri);

        let (status, response) = match (method, path_1, path_2, path_3) {
            (&Method::GET, "queue", "messages", None) => {
                let text = params.get("text");
                let from = params.get("from");
                let to = params.get("to");
                let before = params.parse::<Timestamp>("before").map(|t| t.into_inner());
                let after = params.parse::<Timestamp>("after").map(|t| t.into_inner());
                let page: usize = params.parse::<usize>("page").unwrap_or_default();
                let limit: usize = params.parse::<usize>("limit").unwrap_or_default();
                let values = params.has_key("values");

                let mut result_ids = Vec::new();
                let mut result_values = Vec::new();
                let from_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(0)));
                let to_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(u64::MAX)));
                let has_filters = text.is_some()
                    || from.is_some()
                    || to.is_some()
                    || before.is_some()
                    || after.is_some();
                let mut offset = page.saturating_sub(1) * limit;
                let mut total = 0;
                let mut total_returned = 0;
                let _ = self
                    .shared
                    .default_data_store
                    .iterate(
                        IterateParams::new(from_key, to_key).ascending(),
                        |key, value| {
                            let message = Bincode::<queue::Message>::deserialize(value)?.inner;
                            let matches = !has_filters
                                || (text
                                    .as_ref()
                                    .map(|text| {
                                        message.return_path.contains(text)
                                            || message
                                                .recipients
                                                .iter()
                                                .any(|r| r.address_lcase.contains(text))
                                    })
                                    .unwrap_or_else(|| {
                                        from.as_ref()
                                            .map_or(true, |from| message.return_path.contains(from))
                                            && to.as_ref().map_or(true, |to| {
                                                message
                                                    .recipients
                                                    .iter()
                                                    .any(|r| r.address_lcase.contains(to))
                                            })
                                    })
                                    && before.as_ref().map_or(true, |before| {
                                        message.next_delivery_event() < *before
                                    })
                                    && after.as_ref().map_or(true, |after| {
                                        message.next_delivery_event() > *after
                                    }));

                            if matches {
                                if offset == 0 {
                                    if limit == 0 || total_returned < limit {
                                        if values {
                                            result_values.push(Message::from(&message));
                                        } else {
                                            result_ids.push(key.deserialize_be_u64(1)?);
                                        }
                                        total_returned += 1;
                                    }
                                } else {
                                    offset -= 1;
                                }

                                total += 1;
                            }

                            Ok(true)
                        },
                    )
                    .await;

                (
                    StatusCode::OK,
                    if values {
                        serde_json::to_string(&json!({
                                "data": {
                                    "items": result_values,
                                    "total": total,
                                },
                        }))
                    } else {
                        serde_json::to_string(&json!({
                                "data": {
                                    "items": result_ids,
                                    "total": total,
                                },
                        }))
                    }
                    .unwrap_or_default(),
                )
            }
            (&Method::GET, "queue", "messages", Some(queue_id)) => {
                if let Some(message) = self
                    .read_message(queue_id.parse().unwrap_or_default())
                    .await
                {
                    (
                        StatusCode::OK,
                        serde_json::to_string(&Response {
                            data: Message::from(&message),
                        })
                        .unwrap_or_default(),
                    )
                } else {
                    not_found()
                }
            }
            (&Method::PATCH, "queue", "messages", Some(queue_id)) => {
                let time = params
                    .parse::<Timestamp>("at")
                    .map(|t| t.into_inner())
                    .unwrap_or_else(now);
                let item = params.get("filter");

                if let Some(mut message) = self
                    .read_message(queue_id.parse().unwrap_or_default())
                    .await
                {
                    let prev_event = message.next_event().unwrap_or_default();
                    let mut found = false;

                    for domain in &mut message.domains {
                        if matches!(
                            domain.status,
                            Status::Scheduled | Status::TemporaryFailure(_)
                        ) && item
                            .as_ref()
                            .map_or(true, |item| domain.domain.contains(item))
                        {
                            domain.retry.due = time;
                            if domain.expires > time {
                                domain.expires = time + 10;
                            }
                            found = true;
                        }
                    }

                    if found {
                        let next_event = message.next_event().unwrap_or_default();
                        message
                            .save_changes(self, prev_event.into(), next_event.into())
                            .await;
                        let _ = self.queue.tx.send(queue::Event::Reload).await;
                    }

                    (
                        StatusCode::OK,
                        serde_json::to_string(&Response { data: found }).unwrap_or_default(),
                    )
                } else {
                    not_found()
                }
            }
            (&Method::DELETE, "queue", "messages", Some(queue_id)) => {
                if let Some(mut message) = self
                    .read_message(queue_id.parse().unwrap_or_default())
                    .await
                {
                    let mut found = false;
                    let prev_event = message.next_event().unwrap_or_default();

                    if let Some(item) = params.get("filter") {
                        // Cancel delivery for all recipients that match
                        for rcpt in &mut message.recipients {
                            if rcpt.address_lcase.contains(item) {
                                rcpt.status = Status::PermanentFailure(HostResponse {
                                    hostname: ErrorDetails::default(),
                                    response: smtp_proto::Response {
                                        code: 0,
                                        esc: [0, 0, 0],
                                        message: "Delivery canceled.".to_string(),
                                    },
                                });
                                found = true;
                            }
                        }
                        if found {
                            // Mark as completed domains without any pending deliveries
                            for (domain_idx, domain) in message.domains.iter_mut().enumerate() {
                                if matches!(
                                    domain.status,
                                    Status::TemporaryFailure(_) | Status::Scheduled
                                ) {
                                    let mut total_rcpt = 0;
                                    let mut total_completed = 0;

                                    for rcpt in &message.recipients {
                                        if rcpt.domain_idx == domain_idx {
                                            total_rcpt += 1;
                                            if matches!(
                                                rcpt.status,
                                                Status::PermanentFailure(_) | Status::Completed(_)
                                            ) {
                                                total_completed += 1;
                                            }
                                        }
                                    }

                                    if total_rcpt == total_completed {
                                        domain.status = Status::Completed(());
                                    }
                                }
                            }

                            // Delete message if there are no pending deliveries
                            if message.domains.iter().any(|domain| {
                                matches!(
                                    domain.status,
                                    Status::TemporaryFailure(_) | Status::Scheduled
                                )
                            }) {
                                let next_event = message.next_event().unwrap_or_default();
                                message
                                    .save_changes(self, next_event.into(), prev_event.into())
                                    .await;
                            } else {
                                message.remove(self, prev_event).await;
                            }
                        }
                    } else {
                        message.remove(self, prev_event).await;
                        found = true;
                    }

                    (
                        StatusCode::OK,
                        serde_json::to_string(&Response { data: found }).unwrap_or_default(),
                    )
                } else {
                    not_found()
                }
            }
            (&Method::GET, "queue", "reports", None) => {
                let domain = params.get("domain").map(|d| d.to_lowercase());
                let type_ = params.get("type").and_then(|t| match t {
                    "dmarc" => 0u8.into(),
                    "tls" => 1u8.into(),
                    _ => None,
                });
                let page: usize = params.parse("page").unwrap_or_default();
                let limit: usize = params.parse("limit").unwrap_or_default();

                let mut result = Vec::new();
                let from_key = ValueKey::from(ValueClass::Queue(QueueClass::DmarcReportHeader(
                    ReportEvent {
                        due: 0,
                        policy_hash: 0,
                        seq_id: 0,
                        domain: String::new(),
                    },
                )));
                let to_key = ValueKey::from(ValueClass::Queue(QueueClass::TlsReportHeader(
                    ReportEvent {
                        due: u64::MAX,
                        policy_hash: 0,
                        seq_id: 0,
                        domain: String::new(),
                    },
                )));
                let mut offset = page.saturating_sub(1) * limit;
                let mut total = 0;
                let mut total_returned = 0;
                let _ = self
                    .shared
                    .default_data_store
                    .iterate(
                        IterateParams::new(from_key, to_key).ascending().no_values(),
                        |key, _| {
                            if type_.map_or(true, |t| t == *key.last().unwrap()) {
                                let event = ReportEvent::deserialize(key)?;
                                if event.seq_id != 0
                                    && domain.as_ref().map_or(true, |d| event.domain.contains(d))
                                {
                                    if offset == 0 {
                                        if limit == 0 || total_returned < limit {
                                            result.push(
                                                if *key.last().unwrap() == 0 {
                                                    QueueClass::DmarcReportHeader(event)
                                                } else {
                                                    QueueClass::TlsReportHeader(event)
                                                }
                                                .queue_id(),
                                            );
                                            total_returned += 1;
                                        }
                                    } else {
                                        offset -= 1;
                                    }

                                    total += 1;
                                }
                            }

                            Ok(true)
                        },
                    )
                    .await;

                (
                    StatusCode::OK,
                    serde_json::to_string(&json!({
                            "data": {
                                "items": result,
                                "total": total,
                            },
                    }))
                    .unwrap_or_default(),
                )
            }
            (&Method::GET, "queue", "reports", Some(report_id)) => {
                let mut result = None;
                if let Some(report_id) = parse_queued_report_id(report_id) {
                    match report_id {
                        QueueClass::DmarcReportHeader(event) => {
                            let mut rua = Vec::new();
                            if let Ok(Some(report)) = self
                                .generate_dmarc_aggregate_report(&event, &mut rua, None)
                                .await
                            {
                                result = Report::dmarc(event, report, rua).into();
                            }
                        }
                        QueueClass::TlsReportHeader(event) => {
                            let mut rua = Vec::new();
                            if let Ok(Some(report)) = self
                                .generate_tls_aggregate_report(&[event.clone()], &mut rua, None)
                                .await
                            {
                                result = Report::tls(event, report, rua).into();
                            }
                        }
                        _ => (),
                    }
                }

                if let Some(result) = result {
                    (
                        StatusCode::OK,
                        serde_json::to_string(&Response { data: result }).unwrap_or_default(),
                    )
                } else {
                    not_found()
                }
            }
            (&Method::DELETE, "queue", "reports", Some(report_id)) => {
                if let Some(report_id) = parse_queued_report_id(report_id) {
                    match report_id {
                        QueueClass::DmarcReportHeader(event) => {
                            self.delete_dmarc_report(event).await;
                        }
                        QueueClass::TlsReportHeader(event) => {
                            self.delete_tls_report(vec![event]).await;
                        }
                        _ => (),
                    }

                    (
                        StatusCode::OK,
                        serde_json::to_string(&Response { data: true }).unwrap_or_default(),
                    )
                } else {
                    not_found()
                }
            }
            (&Method::GET, "reports", class @ ("dmarc" | "tls" | "arf"), None) => {
                let filter = params.get("text");
                let page: usize = params.parse::<usize>("page").unwrap_or_default();
                let limit: usize = params.parse::<usize>("limit").unwrap_or_default();

                let (from_key, to_key, typ) = match class {
                    "dmarc" => (
                        ValueKey::from(ValueClass::Report(ReportClass::Dmarc {
                            id: 0,
                            expires: 0,
                        })),
                        ValueKey::from(ValueClass::Report(ReportClass::Dmarc {
                            id: u64::MAX,
                            expires: u64::MAX,
                        })),
                        ReportType::Dmarc,
                    ),
                    "tls" => (
                        ValueKey::from(ValueClass::Report(ReportClass::Tls { id: 0, expires: 0 })),
                        ValueKey::from(ValueClass::Report(ReportClass::Tls {
                            id: u64::MAX,
                            expires: u64::MAX,
                        })),
                        ReportType::Tls,
                    ),
                    "arf" => (
                        ValueKey::from(ValueClass::Report(ReportClass::Arf { id: 0, expires: 0 })),
                        ValueKey::from(ValueClass::Report(ReportClass::Arf {
                            id: u64::MAX,
                            expires: u64::MAX,
                        })),
                        ReportType::Arf,
                    ),
                    _ => unreachable!(),
                };

                let mut results = Vec::new();
                let mut offset = page.saturating_sub(1) * limit;
                let mut total = 0;
                let mut last_id = 0;
                let result = self
                    .shared
                    .default_data_store
                    .iterate(
                        IterateParams::new(from_key, to_key)
                            .set_values(filter.is_some())
                            .descending(),
                        |key, value| {
                            // Skip chunked records
                            let id = key.deserialize_be_u64(U64_LEN + 1)?;
                            if id == last_id {
                                return Ok(true);
                            }
                            last_id = id;

                            // TODO: Support filtering chunked records (over 10MB) on FDB
                            let matches = filter.map_or(true, |filter| match typ {
                                ReportType::Dmarc => Bincode::<
                                    IncomingReport<mail_auth::report::Report>,
                                >::deserialize(
                                    value
                                )
                                .map_or(false, |v| v.inner.contains(filter)),
                                ReportType::Tls => {
                                    Bincode::<IncomingReport<TlsReport>>::deserialize(value)
                                        .map_or(false, |v| v.inner.contains(filter))
                                }
                                ReportType::Arf => {
                                    Bincode::<IncomingReport<Feedback>>::deserialize(value)
                                        .map_or(false, |v| v.inner.contains(filter))
                                }
                            });
                            if matches {
                                if offset == 0 {
                                    if limit == 0 || results.len() < limit {
                                        results.push(format!(
                                            "{}_{}",
                                            id,
                                            key.deserialize_be_u64(1)?
                                        ));
                                    }
                                } else {
                                    offset -= 1;
                                }

                                total += 1;
                            }

                            Ok(true)
                        },
                    )
                    .await;
                match result {
                    Ok(_) => (
                        StatusCode::OK,
                        serde_json::to_string(&json!({
                            "data": {
                                "items": results,
                                "total": total,
                            },
                        }))
                        .unwrap_or_default(),
                    ),
                    Err(err) => err.into_bad_request(),
                }
            }
            (&Method::GET, "reports", class @ ("dmarc" | "tls" | "arf"), Some(report_id)) => {
                if let Some(report_id) = parse_incoming_report_id(class, report_id) {
                    match &report_id {
                        ReportClass::Tls { .. } => match self
                            .shared
                            .default_data_store
                            .get_value::<Bincode<IncomingReport<TlsReport>>>(ValueKey::from(
                                ValueClass::Report(report_id),
                            ))
                            .await
                        {
                            Ok(Some(report)) => (
                                StatusCode::OK,
                                serde_json::to_string(&json!({
                                    "data": report.inner,
                                }))
                                .unwrap_or_default(),
                            ),
                            Ok(None) => not_found(),
                            Err(err) => err.into_bad_request(),
                        },
                        ReportClass::Dmarc { .. } => match self
                            .shared
                            .default_data_store
                            .get_value::<Bincode<IncomingReport<mail_auth::report::Report>>>(
                                ValueKey::from(ValueClass::Report(report_id)),
                            )
                            .await
                        {
                            Ok(Some(report)) => (
                                StatusCode::OK,
                                serde_json::to_string(&json!({
                                    "data": report.inner,
                                }))
                                .unwrap_or_default(),
                            ),
                            Ok(None) => not_found(),
                            Err(err) => err.into_bad_request(),
                        },
                        ReportClass::Arf { .. } => match self
                            .shared
                            .default_data_store
                            .get_value::<Bincode<IncomingReport<Feedback>>>(ValueKey::from(
                                ValueClass::Report(report_id),
                            ))
                            .await
                        {
                            Ok(Some(report)) => (
                                StatusCode::OK,
                                serde_json::to_string(&json!({
                                    "data": report.inner,
                                }))
                                .unwrap_or_default(),
                            ),
                            Ok(None) => not_found(),
                            Err(err) => err.into_bad_request(),
                        },
                    }
                } else {
                    not_found()
                }
            }
            (&Method::DELETE, "reports", class @ ("dmarc" | "tls" | "arf"), Some(report_id)) => {
                if let Some(report_id) = parse_incoming_report_id(class, report_id) {
                    let mut batch = BatchBuilder::new();
                    batch.clear(ValueClass::Report(report_id));
                    let result = self
                        .shared
                        .default_data_store
                        .write(batch.build())
                        .await
                        .is_ok();
                    (
                        StatusCode::OK,
                        serde_json::to_string(&Response { data: result }).unwrap_or_default(),
                    )
                } else {
                    not_found()
                }
            }
            _ => not_found(),
        };

        hyper::Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                Full::new(Bytes::from(response))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }
}

fn not_found() -> (StatusCode, String) {
    (
        StatusCode::NOT_FOUND,
        "{\"error\": \"not-found\", \"details\": \"URL does not exist.\"}".to_string(),
    )
}

#[derive(Default)]
struct UrlParams<'x> {
    params: HashMap<Cow<'x, str>, Cow<'x, str>>,
}

impl<'x> UrlParams<'x> {
    pub fn new(uri: &'x Uri) -> Self {
        if let Some(query) = uri.query() {
            Self {
                params: form_urlencoded::parse(query.as_bytes())
                    .filter(|(_, value)| !value.is_empty())
                    .collect(),
            }
        } else {
            Self::default()
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(|v| v.as_ref())
    }

    pub fn has_key(&self, key: &str) -> bool {
        self.params.contains_key(key)
    }

    pub fn parse<T>(&self, key: &str) -> Option<T>
    where
        T: std::str::FromStr,
    {
        self.get(key).and_then(|v| v.parse().ok())
    }
}

enum ReportType {
    Dmarc,
    Tls,
    Arf,
}

impl From<&str> for ReportType {
    fn from(s: &str) -> Self {
        match s {
            "dmarc" => Self::Dmarc,
            "tls" => Self::Tls,
            "arf" => Self::Arf,
            _ => unreachable!(),
        }
    }
}

trait Contains {
    fn contains(&self, text: &str) -> bool;
}

impl Contains for mail_auth::report::Report {
    fn contains(&self, text: &str) -> bool {
        self.domain().contains(text)
            || self.org_name().to_lowercase().contains(text)
            || self.report_id().contains(text)
            || self
                .extra_contact_info()
                .map_or(false, |c| c.to_lowercase().contains(text))
            || self.records().iter().any(|record| record.contains(text))
    }
}

impl Contains for mail_auth::report::Record {
    fn contains(&self, filter: &str) -> bool {
        self.envelope_from().contains(filter)
            || self.header_from().contains(filter)
            || self.envelope_to().map_or(false, |to| to.contains(filter))
            || self.dkim_auth_result().iter().any(|dkim| {
                dkim.domain().contains(filter)
                    || dkim.selector().contains(filter)
                    || dkim
                        .human_result()
                        .as_ref()
                        .map_or(false, |r| r.contains(filter))
            })
            || self.spf_auth_result().iter().any(|spf| {
                spf.domain().contains(filter)
                    || spf.human_result().map_or(false, |r| r.contains(filter))
            })
            || self
                .source_ip()
                .map_or(false, |ip| ip.to_string().contains(filter))
    }
}

impl Contains for TlsReport {
    fn contains(&self, text: &str) -> bool {
        self.organization_name
            .as_ref()
            .map_or(false, |o| o.to_lowercase().contains(text))
            || self
                .contact_info
                .as_ref()
                .map_or(false, |c| c.to_lowercase().contains(text))
            || self.report_id.contains(text)
            || self.policies.iter().any(|p| p.contains(text))
    }
}

impl Contains for Policy {
    fn contains(&self, filter: &str) -> bool {
        self.policy.policy_domain.contains(filter)
            || self
                .policy
                .policy_string
                .iter()
                .any(|s| s.to_lowercase().contains(filter))
            || self
                .policy
                .mx_host
                .iter()
                .any(|s| s.to_lowercase().contains(filter))
            || self.failure_details.iter().any(|f| f.contains(filter))
    }
}

impl Contains for FailureDetails {
    fn contains(&self, filter: &str) -> bool {
        self.sending_mta_ip
            .map_or(false, |s| s.to_string().contains(filter))
            || self
                .receiving_ip
                .map_or(false, |s| s.to_string().contains(filter))
            || self
                .receiving_mx_hostname
                .as_ref()
                .map_or(false, |s| s.contains(filter))
            || self
                .receiving_mx_helo
                .as_ref()
                .map_or(false, |s| s.contains(filter))
            || self
                .additional_information
                .as_ref()
                .map_or(false, |s| s.contains(filter))
            || self
                .failure_reason_code
                .as_ref()
                .map_or(false, |s| s.contains(filter))
    }
}

impl<'x> Contains for Feedback<'x> {
    fn contains(&self, text: &str) -> bool {
        // Check if any of the string fields contain the filter
        self.authentication_results()
            .iter()
            .any(|s| s.contains(text))
            || self
                .original_envelope_id()
                .map_or(false, |s| s.contains(text))
            || self
                .original_mail_from()
                .map_or(false, |s| s.contains(text))
            || self.original_rcpt_to().map_or(false, |s| s.contains(text))
            || self.reported_domain().iter().any(|s| s.contains(text))
            || self.reported_uri().iter().any(|s| s.contains(text))
            || self.reporting_mta().map_or(false, |s| s.contains(text))
            || self.user_agent().map_or(false, |s| s.contains(text))
            || self.dkim_adsp_dns().map_or(false, |s| s.contains(text))
            || self
                .dkim_canonicalized_body()
                .map_or(false, |s| s.contains(text))
            || self
                .dkim_canonicalized_header()
                .map_or(false, |s| s.contains(text))
            || self.dkim_domain().map_or(false, |s| s.contains(text))
            || self.dkim_identity().map_or(false, |s| s.contains(text))
            || self.dkim_selector().map_or(false, |s| s.contains(text))
            || self.dkim_selector_dns().map_or(false, |s| s.contains(text))
            || self.spf_dns().map_or(false, |s| s.contains(text))
            || self.message().map_or(false, |s| s.contains(text))
            || self.headers().map_or(false, |s| s.contains(text))
    }
}

impl<T: Contains> Contains for IncomingReport<T> {
    fn contains(&self, text: &str) -> bool {
        self.from.to_lowercase().contains(text)
            || self.to.iter().any(|to| to.to_lowercase().contains(text))
            || self.subject.to_lowercase().contains(text)
            || self.report.contains(text)
    }
}

impl From<&queue::Message> for Message {
    fn from(message: &queue::Message) -> Self {
        let now = now();

        Message {
            id: message.id,
            return_path: message.return_path.clone(),
            created: DateTime::from_timestamp(message.created as i64),
            size: message.size,
            priority: message.priority,
            env_id: message.env_id.clone(),
            domains: message
                .domains
                .iter()
                .enumerate()
                .map(|(idx, domain)| Domain {
                    name: domain.domain.clone(),
                    status: match &domain.status {
                        Status::Scheduled => Status::Scheduled,
                        Status::Completed(_) => Status::Completed(String::new()),
                        Status::TemporaryFailure(status) => {
                            Status::TemporaryFailure(status.to_string())
                        }
                        Status::PermanentFailure(status) => {
                            Status::PermanentFailure(status.to_string())
                        }
                    },
                    retry_num: domain.retry.inner,
                    next_retry: Some(DateTime::from_timestamp(domain.retry.due as i64)),
                    next_notify: if domain.notify.due > now {
                        DateTime::from_timestamp(domain.notify.due as i64).into()
                    } else {
                        None
                    },
                    recipients: message
                        .recipients
                        .iter()
                        .filter(|rcpt| rcpt.domain_idx == idx)
                        .map(|rcpt| Recipient {
                            address: rcpt.address.clone(),
                            status: match &rcpt.status {
                                Status::Scheduled => Status::Scheduled,
                                Status::Completed(status) => {
                                    Status::Completed(status.response.to_string())
                                }
                                Status::TemporaryFailure(status) => {
                                    Status::TemporaryFailure(status.response.to_string())
                                }
                                Status::PermanentFailure(status) => {
                                    Status::PermanentFailure(status.response.to_string())
                                }
                            },
                            orcpt: rcpt.orcpt.clone(),
                        })
                        .collect(),
                    expires: DateTime::from_timestamp(domain.expires as i64),
                })
                .collect(),
        }
    }
}

impl Report {
    fn dmarc(event: ReportEvent, report: report::Report, rua: Vec<URI>) -> Self {
        Self::Dmarc {
            domain: event.domain.clone(),
            range_from: DateTime::from_timestamp(event.seq_id as i64),
            range_to: DateTime::from_timestamp(event.due as i64),
            id: QueueClass::DmarcReportHeader(event).queue_id(),
            report,
            rua,
        }
    }

    fn tls(event: ReportEvent, report: TlsReport, rua: Vec<ReportUri>) -> Self {
        Self::Tls {
            domain: event.domain.clone(),
            range_from: DateTime::from_timestamp(event.seq_id as i64),
            range_to: DateTime::from_timestamp(event.due as i64),
            id: QueueClass::TlsReportHeader(event).queue_id(),
            report,
            rua,
        }
    }
}

trait GenerateQueueId {
    fn queue_id(&self) -> String;
}

impl GenerateQueueId for QueueClass {
    fn queue_id(&self) -> String {
        match self {
            QueueClass::DmarcReportHeader(h) => {
                format!("d!{}!{}!{}!{}", h.domain, h.policy_hash, h.seq_id, h.due)
            }
            QueueClass::TlsReportHeader(h) => {
                format!("t!{}!{}!{}!{}", h.domain, h.policy_hash, h.seq_id, h.due)
            }
            _ => unreachable!(),
        }
    }
}

fn parse_queued_report_id(id: &str) -> Option<QueueClass> {
    let mut parts = id.split('!');
    let type_ = parts.next()?;
    let event = ReportEvent {
        domain: parts.next()?.to_string(),
        policy_hash: parts.next().and_then(|p| p.parse::<u64>().ok())?,
        seq_id: parts.next().and_then(|p| p.parse::<u64>().ok())?,
        due: parts.next().and_then(|p| p.parse::<u64>().ok())?,
    };
    match type_ {
        "d" => Some(QueueClass::DmarcReportHeader(event)),
        "t" => Some(QueueClass::TlsReportHeader(event)),
        _ => None,
    }
}

fn parse_incoming_report_id(class: &str, id: &str) -> Option<ReportClass> {
    let mut parts = id.split('_');
    let id = parts.next()?.parse().ok()?;
    let expires = parts.next()?.parse().ok()?;
    match class {
        "dmarc" => Some(ReportClass::Dmarc { id, expires }),
        "tls" => Some(ReportClass::Tls { id, expires }),
        "arf" => Some(ReportClass::Arf { id, expires }),
        _ => None,
    }
}

struct Timestamp(u64);

impl FromStr for Timestamp {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(dt) = DateTime::parse_rfc3339(s) {
            let instant = dt.to_timestamp() as u64;
            if instant >= now() {
                return Ok(Timestamp(instant));
            }
        }

        Err(())
    }
}

impl Timestamp {
    pub fn into_inner(self) -> u64 {
        self.0
    }
}

trait BadRequest {
    fn into_bad_request(self) -> (StatusCode, String);
}

impl BadRequest for String {
    fn into_bad_request(self) -> (StatusCode, String) {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "{{\"error\": \"bad-parameters\", \"details\": {}}}",
                serde_json::to_string(&self).unwrap()
            ),
        )
    }
}

impl BadRequest for store::Error {
    fn into_bad_request(self) -> (StatusCode, String) {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::to_string(&json!({
                "error": "internal-error",
                "details": self.to_string(),
            }))
            .unwrap_or_default(),
        )
    }
}

fn is_zero(num: &i16) -> bool {
    *num == 0
}

fn serialize_maybe_datetime<S>(value: &Option<DateTime>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(value) => serializer.serialize_some(&value.to_rfc3339()),
        None => serializer.serialize_none(),
    }
}

fn deserialize_maybe_datetime<'de, D>(deserializer: D) -> Result<Option<DateTime>, D::Error>
where
    D: Deserializer<'de>,
{
    if let Some(value) = <Option<&str> as serde::Deserialize>::deserialize(deserializer)? {
        if let Some(value) = DateTime::parse_rfc3339(value) {
            Ok(Some(value))
        } else {
            Err(serde::de::Error::custom(
                "Failed to parse RFC3339 timestamp",
            ))
        }
    } else {
        Ok(None)
    }
}

fn serialize_datetime<S>(value: &DateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_rfc3339())
}

fn deserialize_datetime<'de, D>(deserializer: D) -> Result<DateTime, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::Deserialize;

    if let Some(value) = DateTime::parse_rfc3339(<&str>::deserialize(deserializer)?) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "Failed to parse RFC3339 timestamp",
        ))
    }
}
