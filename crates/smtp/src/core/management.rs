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

use std::{borrow::Cow, fmt::Display, net::IpAddr, sync::Arc, time::Instant};

use directory::Type;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::{self, Bytes},
    header::{self, AUTHORIZATION},
    server::conn::http1,
    service::service_fn,
    Method, StatusCode, Uri,
};
use mail_parser::{decoders::base64::base64_decode, DateTime};
use mail_send::Credentials;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::oneshot,
};

use utils::listener::{limiter::InFlight, SessionManager};

use crate::{
    queue::{self, instant_to_timestamp, InstantFromTimestamp, QueueId, Status},
    reporting::{
        self,
        scheduler::{ReportKey, ReportPolicy, ReportType, ReportValue},
    },
};

use super::{SmtpAdminSessionManager, SMTP};

#[derive(Debug)]
pub enum QueueRequest {
    List {
        from: Option<String>,
        to: Option<String>,
        before: Option<Instant>,
        after: Option<Instant>,
        result_tx: oneshot::Sender<Vec<u64>>,
    },
    Status {
        queue_ids: Vec<QueueId>,
        result_tx: oneshot::Sender<Vec<Option<Message>>>,
    },
    Cancel {
        queue_ids: Vec<QueueId>,
        item: Option<String>,
        result_tx: oneshot::Sender<Vec<bool>>,
    },
    Retry {
        queue_ids: Vec<QueueId>,
        item: Option<String>,
        time: Instant,
        result_tx: oneshot::Sender<Vec<bool>>,
    },
}

#[derive(Debug)]
pub enum ReportRequest {
    List {
        type_: Option<ReportType<(), ()>>,
        domain: Option<String>,
        result_tx: oneshot::Sender<Vec<String>>,
    },
    Status {
        report_ids: Vec<ReportKey>,
        result_tx: oneshot::Sender<Vec<Option<Report>>>,
    },
    Cancel {
        report_ids: Vec<ReportKey>,
        result_tx: oneshot::Sender<Vec<bool>>,
    },
}

#[derive(Debug, Serialize)]
pub struct Response<T> {
    data: T,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Recipient {
    pub address: String,
    pub status: Status<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orcpt: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
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
    fn spawn(&self, session: utils::listener::SessionData<tokio::net::TcpStream>) {
        let core = self.inner.clone();
        tokio::spawn(async move {
            if let Some(tls_acceptor) = &session.instance.tls_acceptor {
                match tls_acceptor.accept(session.stream).await {
                    Ok(stream) => {
                        handle_request(stream, core, session.remote_ip, session.in_flight).await;
                    }
                    Err(err) => {
                        tracing::debug!(
                            context = "tls",
                            event = "error",
                            remote.ip = session.remote_ip.to_string(),
                            "Failed to accept TLS management connection: {}",
                            err
                        );
                    }
                }
            } else {
                handle_request(session.stream, core, session.remote_ip, session.in_flight).await;
            }
        });
    }

    fn shutdown(&self) {
        // No-op
    }
}

async fn handle_request(
    stream: impl AsyncRead + AsyncWrite + Unpin + 'static,
    core: Arc<SMTP>,
    remote_addr: IpAddr,
    _in_flight: InFlight,
) {
    if let Err(http_err) = http1::Builder::new()
        .keep_alive(true)
        .serve_connection(
            stream,
            service_fn(|req: hyper::Request<body::Incoming>| {
                let core = core.clone();

                async move {
                    let response = core.parse_request(&req).await;

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
                        .queue
                        .config
                        .management_lookup
                        .authenticate(&Credentials::Plain { username, secret })
                        .await
                    {
                        Ok(Some(principal)) if principal.typ == Type::Superuser => {
                            is_authenticated = true;
                        }
                        Ok(Some(_)) => {
                            tracing::debug!(
                                context = "management",
                                event = "auth-error",
                                "Insufficient privileges."
                            );
                        }
                        Ok(None) => {
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
                        let (result_tx, result_rx) = oneshot::channel();
                        self.send_queue_event(
                            QueueRequest::List {
                                from,
                                to,
                                before,
                                after,
                                result_tx,
                            },
                            result_rx,
                        )
                        .await
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
                        let (result_tx, result_rx) = oneshot::channel();
                        self.send_queue_event(
                            QueueRequest::Status {
                                queue_ids,
                                result_tx,
                            },
                            result_rx,
                        )
                        .await
                    }
                    Some(error) => error.into_bad_request(),
                }
            }
            (&Method::GET, "queue", "retry") => {
                let mut queue_ids = Vec::new();
                let mut time = Instant::now();
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
                        let (result_tx, result_rx) = oneshot::channel();
                        self.send_queue_event(
                            QueueRequest::Retry {
                                queue_ids,
                                item,
                                time,
                                result_tx,
                            },
                            result_rx,
                        )
                        .await
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
                        let (result_tx, result_rx) = oneshot::channel();
                        self.send_queue_event(
                            QueueRequest::Cancel {
                                queue_ids,
                                item,
                                result_tx,
                            },
                            result_rx,
                        )
                        .await
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
                                    type_ = ReportType::Dmarc(()).into();
                                }
                                "tls" => {
                                    type_ = ReportType::Tls(()).into();
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
                        let (result_tx, result_rx) = oneshot::channel();
                        self.send_report_event(
                            ReportRequest::List {
                                type_,
                                domain,
                                result_tx,
                            },
                            result_rx,
                        )
                        .await
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

                match error {
                    None => {
                        let (result_tx, result_rx) = oneshot::channel();
                        self.send_report_event(
                            ReportRequest::Status {
                                report_ids,
                                result_tx,
                            },
                            result_rx,
                        )
                        .await
                    }
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
                        let (result_tx, result_rx) = oneshot::channel();
                        self.send_report_event(
                            ReportRequest::Cancel {
                                report_ids,
                                result_tx,
                            },
                            result_rx,
                        )
                        .await
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

    async fn send_queue_event<T: Serialize>(
        &self,
        request: QueueRequest,
        rx: oneshot::Receiver<T>,
    ) -> (StatusCode, String) {
        match self.queue.tx.send(queue::Event::Manage(request)).await {
            Ok(_) => match rx.await {
                Ok(result) => {
                    return (
                        StatusCode::OK,
                        serde_json::to_string(&Response { data: result }).unwrap_or_default(),
                    )
                }
                Err(_) => {
                    tracing::debug!(
                        context = "queue",
                        event = "recv-error",
                        reason = "Failed to receive manage request response."
                    );
                }
            },
            Err(_) => {
                tracing::debug!(
                    context = "queue",
                    event = "send-error",
                    reason = "Failed to send manage request event."
                );
            }
        }

        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "{\"error\": \"internal-error\", \"details\": \"Resource unavailable, try again later.\"}"
                .to_string(),
        )
    }

    async fn send_report_event<T: Serialize>(
        &self,
        request: ReportRequest,
        rx: oneshot::Receiver<T>,
    ) -> (StatusCode, String) {
        match self.report.tx.send(reporting::Event::Manage(request)).await {
            Ok(_) => match rx.await {
                Ok(result) => {
                    return (
                        StatusCode::OK,
                        serde_json::to_string(&Response { data: result }).unwrap_or_default(),
                    )
                }
                Err(_) => {
                    tracing::debug!(
                        context = "queue",
                        event = "recv-error",
                        reason = "Failed to receive manage request response."
                    );
                }
            },
            Err(_) => {
                tracing::debug!(
                    context = "queue",
                    event = "send-error",
                    reason = "Failed to send manage request event."
                );
            }
        }

        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "{\"error\": \"internal-error\", \"details\": \"Resource unavailable, try again later.\"}"
                .to_string(),
        )
    }
}

impl From<&queue::Message> for Message {
    fn from(message: &queue::Message) -> Self {
        let now = Instant::now();

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
                        DateTime::from_timestamp(instant_to_timestamp(now, domain.retry.due) as i64)
                            .into()
                    } else {
                        None
                    },
                    next_notify: if domain.notify.due > now {
                        DateTime::from_timestamp(
                            instant_to_timestamp(
                                now,
                                domain.notify.due,
                            )
                                as i64,
                        )
                        .into()
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
                    expires: DateTime::from_timestamp(
                        instant_to_timestamp(now, domain.expires) as i64
                    ),
                })
                .collect(),
        }
    }
}

impl From<(&ReportKey, &ReportValue)> for Report {
    fn from((key, value): (&ReportKey, &ReportValue)) -> Self {
        match (key, value) {
            (ReportType::Dmarc(domain), ReportType::Dmarc(value)) => Report {
                domain: domain.inner.clone(),
                range_from: DateTime::from_timestamp(value.created as i64),
                range_to: DateTime::from_timestamp(
                    (value.created + value.deliver_at.as_secs()) as i64,
                ),
                size: value.size,
                type_: "dmarc".to_string(),
            },
            (ReportType::Tls(domain), ReportType::Tls(value)) => Report {
                domain: domain.clone(),
                range_from: DateTime::from_timestamp(value.created as i64),
                range_to: DateTime::from_timestamp(
                    (value.created + value.deliver_at.as_secs()) as i64,
                ),
                size: value.size,
                type_: "tls".to_string(),
            },
            _ => unreachable!(),
        }
    }
}

impl Display for ReportKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportType::Dmarc(policy) => write!(f, "d!{}!{}", policy.inner, policy.policy),
            ReportType::Tls(domain) => write!(f, "t!{domain}"),
        }
    }
}

trait ParseValues {
    fn parse_timestamp(&self) -> Result<Instant, String>;
    fn parse_queue_ids(&self) -> Result<Vec<QueueId>, String>;
    fn parse_report_ids(&self) -> Result<Vec<ReportKey>, String>;
}

impl ParseValues for Cow<'_, str> {
    fn parse_timestamp(&self) -> Result<Instant, String> {
        if let Some(dt) = DateTime::parse_rfc3339(self.as_ref()) {
            let instant = (dt.to_timestamp() as u64).to_instant();
            if instant >= Instant::now() {
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

    fn parse_report_ids(&self) -> Result<Vec<ReportKey>, String> {
        let mut ids = Vec::new();
        for id in self.split(',') {
            if !id.is_empty() {
                let mut parts = id.split('!');
                match (parts.next(), parts.next()) {
                    (Some("d"), Some(domain)) if !domain.is_empty() => {
                        if let Some(policy) = parts.next().and_then(|policy| policy.parse().ok()) {
                            ids.push(ReportType::Dmarc(ReportPolicy {
                                inner: domain.to_string(),
                                policy,
                            }));
                            continue;
                        }
                    }
                    (Some("t"), Some(domain)) if !domain.is_empty() => {
                        ids.push(ReportType::Tls(domain.to_string()));
                        continue;
                    }
                    _ => (),
                }

                return Err(format!("Failed to parse id {id:?}."));
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
    if let Some(value) = Option::<&str>::deserialize(deserializer)? {
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
    if let Some(value) = DateTime::parse_rfc3339(<&str>::deserialize(deserializer)?) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "Failed to parse RFC3339 timestamp",
        ))
    }
}
