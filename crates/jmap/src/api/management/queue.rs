/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hyper::Method;
use mail_auth::{
    dmarc::URI,
    mta_sts::ReportUri,
    report::{self, tlsrpt::TlsReport},
};
use mail_parser::DateTime;
use serde::{Deserializer, Serializer};
use serde_json::json;
use smtp::queue::{self, ErrorDetails, HostResponse, QueueId, Status};
use store::{
    write::{key::DeserializeBigEndian, now, Bincode, QueueClass, ReportEvent, ValueClass},
    Deserialize, IterateParams, ValueKey,
};
use utils::url_params::UrlParams;

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
    JMAP,
};

use super::{decode_path_element, Timestamp};

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
    pub blob_hash: String,
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

impl JMAP {
    pub async fn handle_manage_queue(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
    ) -> trc::Result<HttpResponse> {
        let params = UrlParams::new(req.uri().query());

        match (
            path.get(1).copied().unwrap_or_default(),
            path.get(2).copied().map(decode_path_element),
            req.method(),
        ) {
            ("messages", None, &Method::GET) => {
                let text = params.get("text");
                let from = params.get("from");
                let to = params.get("to");
                let before = params.parse::<Timestamp>("before").map(|t| t.into_inner());
                let after = params.parse::<Timestamp>("after").map(|t| t.into_inner());
                let page = params.parse::<usize>("page").unwrap_or_default();
                let limit = params.parse::<usize>("limit").unwrap_or_default();
                let values = params.has_key("values");

                let range_start = params.parse::<u64>("range-start").unwrap_or_default();
                let range_end = params.parse::<u64>("range-end").unwrap_or(u64::MAX);
                let max_total = params.parse::<usize>("max-total").unwrap_or_default();

                let mut result_ids = Vec::new();
                let mut result_values = Vec::new();
                let from_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(range_start)));
                let to_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(range_end)));
                let has_filters = text.is_some()
                    || from.is_some()
                    || to.is_some()
                    || before.is_some()
                    || after.is_some();
                let mut offset = page.saturating_sub(1) * limit;
                let mut total = 0;
                let mut total_returned = 0;
                self.core
                    .storage
                    .data
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
                                            result_ids.push(key.deserialize_be_u64(0)?);
                                        }
                                        total_returned += 1;
                                    }
                                } else {
                                    offset -= 1;
                                }

                                total += 1;
                            }

                            Ok(max_total == 0 || total < max_total)
                        },
                    )
                    .await?;

                Ok(if values {
                    JsonResponse::new(json!({
                            "data":{
                                "items": result_values,
                                "total": total,
                            },
                    }))
                } else {
                    JsonResponse::new(json!({
                            "data": {
                                "items": result_ids,
                                "total": total,
                            },
                    }))
                }
                .into_http_response())
            }
            ("messages", Some(queue_id), &Method::GET) => {
                if let Some(message) = self
                    .smtp
                    .read_message(queue_id.parse().unwrap_or_default())
                    .await
                {
                    Ok(JsonResponse::new(json!({
                            "data": Message::from(&message),
                    }))
                    .into_http_response())
                } else {
                    Err(trc::ResourceEvent::NotFound.into_err())
                }
            }
            ("messages", Some(queue_id), &Method::PATCH) => {
                let time = params
                    .parse::<Timestamp>("at")
                    .map(|t| t.into_inner())
                    .unwrap_or_else(now);
                let item = params.get("filter");

                if let Some(mut message) = self
                    .smtp
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
                            .save_changes(&self.smtp, prev_event.into(), next_event.into())
                            .await;
                        let _ = self.smtp.inner.queue_tx.send(queue::Event::Reload).await;
                    }

                    Ok(JsonResponse::new(json!({
                            "data": found,
                    }))
                    .into_http_response())
                } else {
                    Err(trc::ResourceEvent::NotFound.into_err())
                }
            }
            ("messages", Some(queue_id), &Method::DELETE) => {
                if let Some(mut message) = self
                    .smtp
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
                                    .save_changes(&self.smtp, next_event.into(), prev_event.into())
                                    .await;
                            } else {
                                message.remove(&self.smtp, prev_event).await;
                            }
                        }
                    } else {
                        message.remove(&self.smtp, prev_event).await;
                        found = true;
                    }

                    Ok(JsonResponse::new(json!({
                            "data": found,
                    }))
                    .into_http_response())
                } else {
                    Err(trc::ResourceEvent::NotFound.into_err())
                }
            }
            ("reports", None, &Method::GET) => {
                let domain = params.get("domain").map(|d| d.to_lowercase());
                let type_ = params.get("type").and_then(|t| match t {
                    "dmarc" => 0u8.into(),
                    "tls" => 1u8.into(),
                    _ => None,
                });
                let page: usize = params.parse("page").unwrap_or_default();
                let limit: usize = params.parse("limit").unwrap_or_default();

                let range_start = params.parse::<u64>("range-start").unwrap_or_default();
                let range_end = params.parse::<u64>("range-end").unwrap_or(u64::MAX);
                let max_total = params.parse::<usize>("max-total").unwrap_or_default();

                let mut result = Vec::new();
                let from_key = ValueKey::from(ValueClass::Queue(QueueClass::DmarcReportHeader(
                    ReportEvent {
                        due: range_start,
                        policy_hash: 0,
                        seq_id: 0,
                        domain: String::new(),
                    },
                )));
                let to_key = ValueKey::from(ValueClass::Queue(QueueClass::TlsReportHeader(
                    ReportEvent {
                        due: range_end,
                        policy_hash: 0,
                        seq_id: 0,
                        domain: String::new(),
                    },
                )));
                let mut offset = page.saturating_sub(1) * limit;
                let mut total = 0;
                let mut total_returned = 0;
                self.core
                    .storage
                    .data
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

                            Ok(max_total == 0 || total < max_total)
                        },
                    )
                    .await?;

                Ok(JsonResponse::new(json!({
                        "data": {
                            "items": result,
                            "total": total,
                        },
                }))
                .into_http_response())
            }
            ("reports", Some(report_id), &Method::GET) => {
                let mut result = None;
                if let Some(report_id) = parse_queued_report_id(report_id.as_ref()) {
                    match report_id {
                        QueueClass::DmarcReportHeader(event) => {
                            let mut rua = Vec::new();
                            if let Some(report) = self
                                .smtp
                                .generate_dmarc_aggregate_report(&event, &mut rua, None, 0)
                                .await?
                            {
                                result = Report::dmarc(event, report, rua).into();
                            }
                        }
                        QueueClass::TlsReportHeader(event) => {
                            let mut rua = Vec::new();
                            if let Some(report) = self
                                .smtp
                                .generate_tls_aggregate_report(&[event.clone()], &mut rua, None, 0)
                                .await?
                            {
                                result = Report::tls(event, report, rua).into();
                            }
                        }
                        _ => (),
                    }
                }

                if let Some(result) = result {
                    Ok(JsonResponse::new(json!({
                            "data": result,
                    }))
                    .into_http_response())
                } else {
                    Err(trc::ResourceEvent::NotFound.into_err())
                }
            }
            ("reports", Some(report_id), &Method::DELETE) => {
                if let Some(report_id) = parse_queued_report_id(report_id.as_ref()) {
                    match report_id {
                        QueueClass::DmarcReportHeader(event) => {
                            self.smtp.delete_dmarc_report(event).await;
                        }
                        QueueClass::TlsReportHeader(event) => {
                            self.smtp.delete_tls_report(vec![event]).await;
                        }
                        _ => (),
                    }

                    Ok(JsonResponse::new(json!({
                            "data": true,
                    }))
                    .into_http_response())
                } else {
                    Err(trc::ResourceEvent::NotFound.into_err())
                }
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}

impl From<&queue::Message> for Message {
    fn from(message: &queue::Message) -> Self {
        let now = now();

        Message {
            id: message.queue_id,
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
            blob_hash: URL_SAFE_NO_PAD.encode::<&[u8]>(message.blob_hash.as_ref()),
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

fn is_zero(num: &i16) -> bool {
    *num == 0
}
