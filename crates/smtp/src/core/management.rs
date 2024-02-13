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

use std::{borrow::Cow, net::IpAddr, sync::Arc};

use directory::{AuthResult, Type};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::{self, Bytes},
    header::{self, AUTHORIZATION},
    server::conn::http1,
    service::service_fn,
    Method, StatusCode, Uri,
};
use hyper_util::rt::TokioIo;
use mail_parser::{decoders::base64::base64_decode, DateTime};
use mail_send::Credentials;
use serde::{Deserializer, Serializer};
use store::{
    write::{key::DeserializeBigEndian, now, Bincode, QueueClass, ReportEvent, ValueClass},
    Deserialize, IterateParams, ValueKey,
};

use utils::listener::{limiter::InFlight, SessionData, SessionManager, SessionStream};

use crate::queue::{self, HostResponse, QueueId, Status};

use super::{SmtpAdminSessionManager, SMTP};

#[derive(Debug, serde::Serialize)]
pub struct Response<T> {
    data: T,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Message {
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
pub struct Report {
    pub domain: String,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(deserialize_with = "deserialize_datetime")]
    #[serde(serialize_with = "serialize_datetime")]
    pub range_from: DateTime,
    #[serde(deserialize_with = "deserialize_datetime")]
    #[serde(serialize_with = "serialize_datetime")]
    pub range_to: DateTime,
    pub size: usize,
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
                    let response = core.parse_request(&req, remote_addr).await;

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
        path.next(); // Skip the leading /admin
        Ok(self
            .handle_manage_request(
                req.uri(),
                req.method(),
                path.next().unwrap_or_default(),
                path.next().unwrap_or_default(),
            )
            .await)
    }

    pub async fn handle_manage_request(
        &self,
        uri: &Uri,
        method: &Method,
        path_1: &str,
        path_2: &str,
    ) -> hyper::Response<BoxBody<Bytes, hyper::Error>> {
        let (status, response) = match (method, path_1, path_2) {
            (&Method::GET, "queue", "list") => {
                let mut from = None;
                let mut to = None;
                let mut before = None;
                let mut after = None;
                let mut error = None;

                if let Some(query) = uri.query() {
                    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                        match key.as_ref() {
                            "from" => {
                                from = value.into_owned().into();
                            }
                            "to" => {
                                to = value.into_owned().into();
                            }
                            "after" => match value.parse_timestamp() {
                                Ok(dt) => {
                                    after = dt.into();
                                }
                                Err(reason) => {
                                    error = reason.into();
                                    break;
                                }
                            },
                            "before" => match value.parse_timestamp() {
                                Ok(dt) => {
                                    before = dt.into();
                                }
                                Err(reason) => {
                                    error = reason.into();
                                    break;
                                }
                            },
                            _ => {
                                error = format!("Invalid parameter {key:?}.").into();
                                break;
                            }
                        }
                    }
                }

                match error {
                    None => {
                        let mut result = Vec::new();
                        let from_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(0)));
                        let to_key =
                            ValueKey::from(ValueClass::Queue(QueueClass::Message(u64::MAX)));
                        let has_filters =
                            from.is_some() || to.is_some() || before.is_some() || after.is_some();
                        let _ =
                            self.shared
                                .default_data_store
                                .iterate(
                                    IterateParams::new(from_key, to_key).ascending(),
                                    |key, value| {
                                        if has_filters {
                                            let message =
                                                Bincode::<queue::Message>::deserialize(value)?
                                                    .inner;
                                            if from.as_ref().map_or(true, |from| {
                                                message.return_path.contains(from)
                                            }) && to.as_ref().map_or(true, |to| {
                                                message
                                                    .recipients
                                                    .iter()
                                                    .any(|r| r.address_lcase.contains(to))
                                            }) && before.as_ref().map_or(true, |before| {
                                                message.next_delivery_event() < *before
                                            }) && after.as_ref().map_or(true, |after| {
                                                message.next_delivery_event() > *after
                                            }) {
                                                result.push(key.deserialize_be_u64(1)?);
                                            }
                                        } else {
                                            result.push(key.deserialize_be_u64(1)?);
                                        }
                                        Ok(true)
                                    },
                                )
                                .await;

                        (
                            StatusCode::OK,
                            serde_json::to_string(&Response { data: result }).unwrap_or_default(),
                        )
                    }
                    Some(error) => error.into_bad_request(),
                }
            }
            (&Method::GET, "queue", "status") => {
                let mut queue_ids = Vec::new();
                let mut error = None;

                if let Some(query) = uri.query() {
                    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                        match key.as_ref() {
                            "id" | "ids" => match value.parse_queue_ids() {
                                Ok(ids) => {
                                    queue_ids = ids;
                                }
                                Err(reason) => {
                                    error = reason.into();
                                    break;
                                }
                            },
                            _ => {
                                error = format!("Invalid parameter {key:?}.").into();
                                break;
                            }
                        }
                    }
                }

                match error {
                    None => {
                        let mut result = Vec::with_capacity(queue_ids.len());
                        for queue_id in queue_ids {
                            if let Some(message) = self.read_message(queue_id).await {
                                result.push(Message::from(&message).into());
                            } else {
                                result.push(None);
                            }
                        }

                        (
                            StatusCode::OK,
                            serde_json::to_string(&Response { data: result }).unwrap_or_default(),
                        )
                    }
                    Some(error) => error.into_bad_request(),
                }
            }
            (&Method::GET, "queue", "retry") => {
                let mut queue_ids = Vec::new();
                let mut time = now();
                let mut item = None;
                let mut error = None;

                if let Some(query) = uri.query() {
                    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                        match key.as_ref() {
                            "id" | "ids" => match value.parse_queue_ids() {
                                Ok(ids) => {
                                    queue_ids = ids;
                                }
                                Err(reason) => {
                                    error = reason.into();
                                    break;
                                }
                            },
                            "at" => match value.parse_timestamp() {
                                Ok(dt) => {
                                    time = dt;
                                }
                                Err(reason) => {
                                    error = reason.into();
                                    break;
                                }
                            },
                            "filter" => {
                                item = value.into_owned().into();
                            }
                            _ => {
                                error = format!("Invalid parameter {key:?}.").into();
                                break;
                            }
                        }
                    }
                }

                match error {
                    None => {
                        let mut result = Vec::with_capacity(queue_ids.len());

                        for queue_id in queue_ids {
                            let mut found = false;

                            if let Some(mut message) = self.read_message(queue_id).await {
                                let prev_event = message.next_event().unwrap_or_default();

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
                                }
                            }

                            result.push(found);
                        }

                        if result.iter().any(|r| *r) {
                            let _ = self.queue.tx.send(queue::Event::Reload).await;
                        }

                        (
                            StatusCode::OK,
                            serde_json::to_string(&Response { data: result }).unwrap_or_default(),
                        )
                    }
                    Some(error) => error.into_bad_request(),
                }
            }
            (&Method::GET, "queue", "cancel") => {
                let mut queue_ids = Vec::new();
                let mut item = None;
                let mut error = None;

                if let Some(query) = uri.query() {
                    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                        match key.as_ref() {
                            "id" | "ids" => match value.parse_queue_ids() {
                                Ok(ids) => {
                                    queue_ids = ids;
                                }
                                Err(reason) => {
                                    error = reason.into();
                                    break;
                                }
                            },
                            "filter" => {
                                item = value.into_owned().into();
                            }
                            _ => {
                                error = format!("Invalid parameter {key:?}.").into();
                                break;
                            }
                        }
                    }
                }

                match error {
                    None => {
                        let mut result = Vec::with_capacity(queue_ids.len());

                        for queue_id in queue_ids {
                            let mut found = false;

                            if let Some(mut message) = self.read_message(queue_id).await {
                                let prev_event = message.next_event().unwrap_or_default();

                                if let Some(item) = &item {
                                    // Cancel delivery for all recipients that match
                                    for rcpt in &mut message.recipients {
                                        if rcpt.address_lcase.contains(item) {
                                            rcpt.status = Status::Completed(HostResponse {
                                                hostname: String::new(),
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
                                        for (domain_idx, domain) in
                                            message.domains.iter_mut().enumerate()
                                        {
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
                                                            Status::PermanentFailure(_)
                                                                | Status::Completed(_)
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
                                            let next_event =
                                                message.next_event().unwrap_or_default();
                                            message
                                                .save_changes(
                                                    self,
                                                    next_event.into(),
                                                    prev_event.into(),
                                                )
                                                .await;
                                        } else {
                                            message.remove(self, prev_event).await;
                                        }
                                    }
                                } else {
                                    message.remove(self, prev_event).await;
                                    found = true;
                                }
                            }

                            result.push(found);
                        }

                        (
                            StatusCode::OK,
                            serde_json::to_string(&Response { data: result }).unwrap_or_default(),
                        )
                    }
                    Some(error) => error.into_bad_request(),
                }
            }
            (&Method::GET, "report", "list") => {
                let mut domain = None;
                let mut type_ = None;
                let mut error = None;

                if let Some(query) = uri.query() {
                    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                        match key.as_ref() {
                            "type" => match value.as_ref() {
                                "dmarc" => {
                                    type_ = 0u8.into();
                                }
                                "tls" => {
                                    type_ = 1u8.into();
                                }
                                _ => {
                                    error = format!("Invalid report type {value:?}.").into();
                                    break;
                                }
                            },
                            "domain" => {
                                domain = value.into_owned().into();
                            }
                            _ => {
                                error = format!("Invalid parameter {key:?}.").into();
                                break;
                            }
                        }
                    }
                }

                match error {
                    None => {
                        let mut result = Vec::new();
                        let from_key = ValueKey::from(ValueClass::Queue(
                            QueueClass::DmarcReportHeader(ReportEvent {
                                due: 0,
                                policy_hash: 0,
                                seq_id: 0,
                                domain: String::new(),
                            }),
                        ));
                        let to_key = ValueKey::from(ValueClass::Queue(
                            QueueClass::TlsReportHeader(ReportEvent {
                                due: u64::MAX,
                                policy_hash: 0,
                                seq_id: 0,
                                domain: String::new(),
                            }),
                        ));
                        let _ = self
                            .shared
                            .default_data_store
                            .iterate(
                                IterateParams::new(from_key, to_key).ascending().no_values(),
                                |key, _| {
                                    if type_.map_or(true, |t| t == *key.last().unwrap()) {
                                        let event = ReportEvent::deserialize(key)?;
                                        if event.seq_id != 0
                                            && domain.as_ref().map_or(true, |d| {
                                                d.eq_ignore_ascii_case(&event.domain)
                                            })
                                        {
                                            result.push(
                                                if *key.last().unwrap() == 0 {
                                                    QueueClass::DmarcReportHeader(event)
                                                } else {
                                                    QueueClass::TlsReportHeader(event)
                                                }
                                                .queue_id(),
                                            );
                                        }
                                    }

                                    Ok(true)
                                },
                            )
                            .await;

                        (
                            StatusCode::OK,
                            serde_json::to_string(&Response { data: result }).unwrap_or_default(),
                        )
                    }
                    Some(error) => error.into_bad_request(),
                }
            }
            (&Method::GET, "report", "status") => {
                let mut report_ids = Vec::new();
                let mut error = None;

                if let Some(query) = uri.query() {
                    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                        match key.as_ref() {
                            "id" | "ids" => match value.parse_report_ids() {
                                Ok(ids) => {
                                    report_ids = ids;
                                }
                                Err(reason) => {
                                    error = reason.into();
                                    break;
                                }
                            },
                            _ => {
                                error = format!("Invalid parameter {key:?}.").into();
                                break;
                            }
                        }
                    }
                }

                let mut result = Vec::with_capacity(report_ids.len());
                for report_id in report_ids {
                    if let Ok(Some(_)) = self
                        .shared
                        .default_data_store
                        .get_value::<()>(ValueKey::from(ValueClass::Queue(report_id.clone())))
                        .await
                    {
                        result.push(Report::from(report_id).into());
                    } else {
                        result.push(None);
                    }
                }

                match error {
                    None => (
                        StatusCode::OK,
                        serde_json::to_string(&Response { data: result }).unwrap_or_default(),
                    ),
                    Some(error) => error.into_bad_request(),
                }
            }
            (&Method::GET, "report", "cancel") => {
                let mut report_ids = Vec::new();
                let mut error = None;

                if let Some(query) = uri.query() {
                    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                        match key.as_ref() {
                            "id" | "ids" => match value.parse_report_ids() {
                                Ok(ids) => {
                                    report_ids = ids;
                                }
                                Err(reason) => {
                                    error = reason.into();
                                    break;
                                }
                            },
                            _ => {
                                error = format!("Invalid parameter {key:?}.").into();
                                break;
                            }
                        }
                    }
                }

                match error {
                    None => {
                        let mut result = Vec::with_capacity(report_ids.len());

                        for report_id in report_ids {
                            match report_id {
                                QueueClass::DmarcReportHeader(event) => {
                                    self.delete_dmarc_report(event).await;
                                }
                                QueueClass::TlsReportHeader(event) => {
                                    self.delete_tls_report(vec![event]).await;
                                }
                                _ => (),
                            }

                            result.push(true);
                        }

                        (
                            StatusCode::OK,
                            serde_json::to_string(&Response { data: result }).unwrap_or_default(),
                        )
                    }
                    Some(error) => error.into_bad_request(),
                }
            }
            _ => (
                StatusCode::NOT_FOUND,
                format!(
                    "{{\"error\": \"not-found\", \"details\": \"URL {} does not exist.\"}}",
                    uri.path()
                ),
            ),
        };

        hyper::Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
            .body(
                Full::new(Bytes::from(response))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap()
    }
}

impl From<&queue::Message> for Message {
    fn from(message: &queue::Message) -> Self {
        let now = now();

        Message {
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
                    next_retry: if domain.retry.due > now {
                        DateTime::from_timestamp(domain.retry.due as i64).into()
                    } else {
                        None
                    },
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

impl From<QueueClass> for Report {
    fn from(value: QueueClass) -> Self {
        match value {
            QueueClass::DmarcReportHeader(event) => Report {
                domain: event.domain,
                type_: "dmarc".to_string(),
                range_from: DateTime::from_timestamp(event.seq_id as i64),
                range_to: DateTime::from_timestamp(event.due as i64),
                size: 0,
            },
            QueueClass::TlsReportHeader(event) => Report {
                domain: event.domain,
                type_: "tls".to_string(),
                range_from: DateTime::from_timestamp(event.seq_id as i64),
                range_to: DateTime::from_timestamp(event.due as i64),
                size: 0,
            },
            _ => unreachable!(),
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

trait ParseValues {
    fn parse_timestamp(&self) -> Result<u64, String>;
    fn parse_queue_ids(&self) -> Result<Vec<QueueId>, String>;
    fn parse_report_ids(&self) -> Result<Vec<QueueClass>, String>;
}

impl ParseValues for Cow<'_, str> {
    fn parse_timestamp(&self) -> Result<u64, String> {
        if let Some(dt) = DateTime::parse_rfc3339(self.as_ref()) {
            let instant = dt.to_timestamp() as u64;
            if instant >= now() {
                return Ok(instant);
            }
        }

        Err(format!("Invalid timestamp {self:?}."))
    }

    fn parse_queue_ids(&self) -> Result<Vec<QueueId>, String> {
        let mut ids = Vec::new();
        for id in self.split(',') {
            if !id.is_empty() {
                match id.parse() {
                    Ok(id) => {
                        ids.push(id);
                    }
                    Err(_) => {
                        return Err(format!("Failed to parse id {id:?}."));
                    }
                }
            }
        }
        Ok(ids)
    }

    fn parse_report_ids(&self) -> Result<Vec<QueueClass>, String> {
        let mut ids = Vec::new();
        for id in self.split(',') {
            if !id.is_empty() {
                let mut parts = id.split('!');
                match (
                    parts.next(),
                    parts.next(),
                    parts.next().and_then(|p| p.parse::<u64>().ok()),
                    parts.next().and_then(|p| p.parse::<u64>().ok()),
                    parts.next().and_then(|p| p.parse::<u64>().ok()),
                ) {
                    (Some("d"), Some(domain), Some(policy), Some(seq_id), Some(due))
                        if !domain.is_empty() =>
                    {
                        ids.push(QueueClass::DmarcReportHeader(ReportEvent {
                            due,
                            policy_hash: policy,
                            seq_id,
                            domain: domain.to_string(),
                        }));
                    }
                    (Some("t"), Some(domain), Some(policy), Some(seq_id), Some(due))
                        if !domain.is_empty() =>
                    {
                        ids.push(QueueClass::TlsReportHeader(ReportEvent {
                            due,
                            policy_hash: policy,
                            seq_id,
                            domain: domain.to_string(),
                        }));
                    }
                    _ => {
                        return Err(format!("Failed to parse id {id:?}."));
                    }
                }
            }
        }
        Ok(ids)
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
