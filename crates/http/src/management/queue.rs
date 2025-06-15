/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{future::Future, sync::atomic::Ordering};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Server, auth::AccessToken, ipc::QueueEvent};

use directory::{Permission, Type, backend::internal::manage::ManageDirectory};
use hyper::Method;
use mail_auth::{
    dmarc::URI,
    mta_sts::ReportUri,
    report::{self, tlsrpt::TlsReport},
};
use mail_parser::DateTime;
use serde::{Deserializer, Serializer};
use serde_json::json;
use smtp::{
    queue::{
        self, ArchivedMessage, ArchivedStatus, DisplayArchivedResponse, ErrorDetails, HostResponse,
        QueueId, Status, spool::SmtpSpool,
    },
    reporting::{dmarc::DmarcReporting, tls::TlsReporting},
};
use store::{
    Deserialize, IterateParams, ValueKey,
    write::{
        AlignedBytes, Archive, QueueClass, ReportEvent, ValueClass, key::DeserializeBigEndian, now,
    },
};
use trc::AddContext;
use utils::url_params::UrlParams;

use super::FutureTimestamp;
use http_proto::{request::decode_path_element, *};

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Message {
    pub id: QueueId,
    pub return_path: String,
    pub domains: Vec<Domain>,
    #[serde(deserialize_with = "deserialize_datetime")]
    #[serde(serialize_with = "serialize_datetime")]
    pub created: DateTime,
    pub size: u64,
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
#[serde(rename_all = "camelCase")]
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

pub trait QueueManagement: Sync + Send {
    fn handle_manage_queue(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl QueueManagement for Server {
    async fn handle_manage_queue(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
        let params = UrlParams::new(req.uri().query());

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL

        // Limit to tenant domains
        let mut tenant_domains: Option<Vec<String>> = None;
        #[cfg(feature = "enterprise")]
        if self.core.is_enterprise_edition() {
            if let Some(tenant) = access_token.tenant {
                tenant_domains = self
                    .core
                    .storage
                    .data
                    .list_principals(None, tenant.id.into(), &[Type::Domain], false, 0, 0)
                    .await
                    .map(|principals| {
                        principals
                            .items
                            .into_iter()
                            .map(|p| p.name)
                            .collect::<Vec<_>>()
                    })
                    .caused_by(trc::location!())?
                    .into();
            }
        }

        // SPDX-SnippetEnd

        match (
            path.get(1).copied().unwrap_or_default(),
            path.get(2).copied().map(decode_path_element),
            req.method(),
        ) {
            ("messages", None, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::MessageQueueList)?;

                let result = fetch_queued_messages(self, &params, &tenant_domains).await?;

                let queue_status = self.inner.data.queue_status.load(Ordering::Relaxed);

                Ok(if !result.values.is_empty() {
                    JsonResponse::new(json!({
                            "data":{
                                "items": result.values,
                                "total": result.total,
                                "status": queue_status,
                            },
                    }))
                } else {
                    JsonResponse::new(json!({
                            "data": {
                                "items": result.ids,
                                "total":  result.total,
                                "status": queue_status,
                            },
                    }))
                }
                .into_http_response())
            }
            ("messages", Some(queue_id), &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::MessageQueueGet)?;

                if let Some(message_) = self
                    .read_message_archive(queue_id.parse().unwrap_or_default())
                    .await?
                {
                    let message = message_.unarchive::<queue::Message>()?;
                    if message.is_tenant_domain(&tenant_domains) {
                        return Ok(JsonResponse::new(json!({
                                "data": Message::from(message),
                        }))
                        .into_http_response());
                    }
                }
                Err(trc::ResourceEvent::NotFound.into_err())
            }
            ("messages", None, &Method::PATCH) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::MessageQueueUpdate)?;

                let time = params
                    .parse::<FutureTimestamp>("at")
                    .map(|t| t.into_inner())
                    .unwrap_or_else(now);
                let result = fetch_queued_messages(self, &params, &tenant_domains).await?;

                let found = !result.ids.is_empty();
                if found {
                    let server = self.clone();
                    tokio::spawn(async move {
                        for id in result.ids {
                            if let Some(mut message) = server.read_message(id).await {
                                let prev_event = message.next_event().unwrap_or_default();
                                let mut has_changes = false;

                                for domain in &mut message.domains {
                                    if matches!(
                                        domain.status,
                                        Status::Scheduled | Status::TemporaryFailure(_)
                                    ) {
                                        domain.retry.due = time;
                                        if domain.expires > time {
                                            domain.expires = time + 10;
                                        }
                                        has_changes = true;
                                    }
                                }

                                if has_changes {
                                    let next_event = message.next_event().unwrap_or_default();
                                    message
                                        .save_changes(&server, prev_event.into(), next_event.into())
                                        .await;
                                }
                            }
                        }

                        let _ = server.inner.ipc.queue_tx.send(QueueEvent::Refresh).await;
                    });
                }

                Ok(JsonResponse::new(json!({
                        "data": found,
                }))
                .into_http_response())
            }
            ("messages", Some(queue_id), &Method::PATCH) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::MessageQueueUpdate)?;

                let time = params
                    .parse::<FutureTimestamp>("at")
                    .map(|t| t.into_inner())
                    .unwrap_or_else(now);
                let item = params.get("filter");

                if let Some(mut message) = self
                    .read_message(queue_id.parse().unwrap_or_default())
                    .await
                    .filter(|message| {
                        tenant_domains
                            .as_ref()
                            .is_none_or(|domains| message.has_domain(domains))
                    })
                {
                    let prev_event = message.next_event().unwrap_or_default();
                    let mut found = false;

                    for domain in &mut message.domains {
                        if matches!(
                            domain.status,
                            Status::Scheduled | Status::TemporaryFailure(_)
                        ) && item
                            .as_ref()
                            .is_none_or(|item| domain.domain.contains(item))
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
                        let _ = self.inner.ipc.queue_tx.send(QueueEvent::Refresh).await;
                    }

                    Ok(JsonResponse::new(json!({
                            "data": found,
                    }))
                    .into_http_response())
                } else {
                    Err(trc::ResourceEvent::NotFound.into_err())
                }
            }
            ("messages", None, &Method::DELETE) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::MessageQueueDelete)?;

                let result = fetch_queued_messages(self, &params, &tenant_domains).await?;

                let found = !result.ids.is_empty();
                if found {
                    let server = self.clone();
                    tokio::spawn(async move {
                        let is_active = server.inner.data.queue_status.load(Ordering::Relaxed);

                        if is_active {
                            let _ = server
                                .inner
                                .ipc
                                .queue_tx
                                .send(QueueEvent::Paused(true))
                                .await;
                        }

                        for id in result.ids {
                            if let Some(message) = server.read_message(id).await {
                                let prev_event = message.next_event().unwrap_or_default();
                                message.remove(&server, prev_event).await;
                            }
                        }

                        if is_active {
                            let _ = server
                                .inner
                                .ipc
                                .queue_tx
                                .send(QueueEvent::Paused(false))
                                .await;
                        }
                    });
                }

                Ok(JsonResponse::new(json!({
                        "data": found,
                }))
                .into_http_response())
            }
            ("messages", Some(queue_id), &Method::DELETE) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::MessageQueueDelete)?;

                if let Some(mut message) = self
                    .read_message(queue_id.parse().unwrap_or_default())
                    .await
                    .filter(|message| {
                        tenant_domains
                            .as_ref()
                            .is_none_or(|domains| message.has_domain(domains))
                    })
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
                                        if rcpt.domain_idx == domain_idx as u32 {
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

                    Ok(JsonResponse::new(json!({
                            "data": found,
                    }))
                    .into_http_response())
                } else {
                    Err(trc::ResourceEvent::NotFound.into_err())
                }
            }
            ("reports", None, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::OutgoingReportList)?;

                let result = fetch_queued_reports(self, &params, &tenant_domains).await?;

                Ok(JsonResponse::new(json!({
                        "data": {
                            "items": result.ids.into_iter().map(|id| id.queue_id()).collect::<Vec<_>>(),
                            "total": result.total,
                        },
                }))
                .into_http_response())
            }
            ("reports", Some(report_id), &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::OutgoingReportGet)?;

                let mut result = None;
                if let Some(report_id) = parse_queued_report_id(report_id.as_ref()) {
                    match report_id {
                        QueueClass::DmarcReportHeader(event)
                            if tenant_domains.as_ref().is_none_or(|domains| {
                                domains.iter().any(|dd| dd == &event.domain)
                            }) =>
                        {
                            let mut rua = Vec::new();
                            if let Some(report) = self
                                .generate_dmarc_aggregate_report(&event, &mut rua, None, 0)
                                .await?
                            {
                                result = Report::dmarc(event, report, rua).into();
                            }
                        }
                        QueueClass::TlsReportHeader(event)
                            if tenant_domains.as_ref().is_none_or(|domains| {
                                domains.iter().any(|dd| dd == &event.domain)
                            }) =>
                        {
                            let mut rua = Vec::new();
                            if let Some(report) = self
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
            ("reports", None, &Method::DELETE) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::OutgoingReportDelete)?;

                let result = fetch_queued_reports(self, &params, &tenant_domains).await?;
                let found = !result.ids.is_empty();
                if found {
                    let server = self.clone();
                    tokio::spawn(async move {
                        for id in result.ids {
                            match id {
                                QueueClass::DmarcReportHeader(event) => {
                                    server.delete_dmarc_report(event).await;
                                }
                                QueueClass::TlsReportHeader(event) => {
                                    server.delete_tls_report(vec![event]).await;
                                }
                                _ => (),
                            }
                        }
                    });
                }

                Ok(JsonResponse::new(json!({
                        "data": found,
                }))
                .into_http_response())
            }
            ("reports", Some(report_id), &Method::DELETE) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::OutgoingReportDelete)?;

                if let Some(report_id) = parse_queued_report_id(report_id.as_ref()) {
                    let result = match report_id {
                        QueueClass::DmarcReportHeader(event)
                            if tenant_domains.as_ref().is_none_or(|domains| {
                                domains.iter().any(|dd| dd == &event.domain)
                            }) =>
                        {
                            self.delete_dmarc_report(event).await;
                            true
                        }
                        QueueClass::TlsReportHeader(event)
                            if tenant_domains.as_ref().is_none_or(|domains| {
                                domains.iter().any(|dd| dd == &event.domain)
                            }) =>
                        {
                            self.delete_tls_report(vec![event]).await;
                            true
                        }
                        _ => false,
                    };

                    Ok(JsonResponse::new(json!({
                            "data": result,
                    }))
                    .into_http_response())
                } else {
                    Err(trc::ResourceEvent::NotFound.into_err())
                }
            }
            ("status", None, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::MessageQueueGet)?;

                Ok(JsonResponse::new(json!({
                        "data": self.inner.data.queue_status.load(Ordering::Relaxed),
                }))
                .into_http_response())
            }
            ("status", Some(action), &Method::PATCH) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::MessageQueueUpdate)?;

                let prev_status = self.inner.data.queue_status.load(Ordering::Relaxed);

                let _ = self
                    .inner
                    .ipc
                    .queue_tx
                    .send(QueueEvent::Paused(action == "stop"))
                    .await;

                Ok(JsonResponse::new(json!({
                        "data": prev_status,
                }))
                .into_http_response())
            }
            _ => Err(trc::ResourceEvent::NotFound.into_err()),
        }
    }
}

impl From<&ArchivedMessage> for Message {
    fn from(message: &ArchivedMessage) -> Self {
        let now = now();

        Message {
            id: message.queue_id.into(),
            return_path: message.return_path.to_string(),
            created: DateTime::from_timestamp(u64::from(message.created) as i64),
            size: message.size.into(),
            priority: message.priority.into(),
            env_id: message.env_id.as_ref().map(|id| id.to_string()),
            domains: message
                .domains
                .iter()
                .enumerate()
                .map(|(idx, domain)| Domain {
                    name: domain.domain.to_string(),
                    status: match &domain.status {
                        ArchivedStatus::Scheduled => Status::Scheduled,
                        ArchivedStatus::Completed(_) => Status::Completed(String::new()),
                        ArchivedStatus::TemporaryFailure(status) => {
                            Status::TemporaryFailure(status.to_string())
                        }
                        ArchivedStatus::PermanentFailure(status) => {
                            Status::PermanentFailure(status.to_string())
                        }
                    },
                    retry_num: domain.retry.inner.into(),
                    next_retry: Some(DateTime::from_timestamp(u64::from(domain.retry.due) as i64)),
                    next_notify: if domain.notify.due > now {
                        DateTime::from_timestamp(u64::from(domain.notify.due) as i64).into()
                    } else {
                        None
                    },
                    recipients: message
                        .recipients
                        .iter()
                        .filter(|rcpt| u32::from(rcpt.domain_idx) == idx as u32)
                        .map(|rcpt| Recipient {
                            address: rcpt.address.to_string(),
                            status: match &rcpt.status {
                                ArchivedStatus::Scheduled => Status::Scheduled,
                                ArchivedStatus::Completed(status) => {
                                    Status::Completed(status.response.to_string())
                                }
                                ArchivedStatus::TemporaryFailure(status) => {
                                    Status::TemporaryFailure(status.response.to_string())
                                }
                                ArchivedStatus::PermanentFailure(status) => {
                                    Status::PermanentFailure(status.response.to_string())
                                }
                            },
                            orcpt: rcpt.orcpt.as_ref().map(|orcpt| orcpt.to_string()),
                        })
                        .collect(),
                    expires: DateTime::from_timestamp(u64::from(domain.expires) as i64),
                })
                .collect(),
            blob_hash: URL_SAFE_NO_PAD.encode::<&[u8]>(message.blob_hash.0.as_slice()),
        }
    }
}

struct QueuedMessages {
    ids: Vec<u64>,
    values: Vec<Message>,
    total: usize,
}

async fn fetch_queued_messages(
    server: &Server,
    params: &UrlParams<'_>,
    tenant_domains: &Option<Vec<String>>,
) -> trc::Result<QueuedMessages> {
    let text = params.get("text");
    let from = params.get("from");
    let to = params.get("to");
    let before = params
        .parse::<FutureTimestamp>("before")
        .map(|t| t.into_inner());
    let after = params
        .parse::<FutureTimestamp>("after")
        .map(|t| t.into_inner());
    let page = params.parse::<usize>("page").unwrap_or_default();
    let limit = params.parse::<usize>("limit").unwrap_or_default();
    let values = params.has_key("values");

    let range_start = params.parse::<u64>("range-start").unwrap_or_default();
    let range_end = params.parse::<u64>("range-end").unwrap_or(u64::MAX);
    let max_total = params.parse::<usize>("max-total").unwrap_or_default();

    let mut result = QueuedMessages {
        ids: Vec::new(),
        values: Vec::new(),
        total: 0,
    };
    let from_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(range_start)));
    let to_key = ValueKey::from(ValueClass::Queue(QueueClass::Message(range_end)));
    let has_filters =
        text.is_some() || from.is_some() || to.is_some() || before.is_some() || after.is_some();
    let mut offset = page.saturating_sub(1) * limit;
    let mut total_returned = 0;

    server
        .core
        .storage
        .data
        .iterate(
            IterateParams::new(from_key, to_key).ascending(),
            |key, value| {
                let message_ = <Archive<AlignedBytes> as Deserialize>::deserialize(value)
                    .add_context(|ctx| ctx.ctx(trc::Key::Key, key))?;
                let message = message_
                    .unarchive::<queue::Message>()
                    .add_context(|ctx| ctx.ctx(trc::Key::Key, key))?;
                let matches = tenant_domains
                    .as_ref()
                    .is_none_or(|domains| message.has_domain(domains))
                    && (!has_filters
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
                                    .is_none_or(|from| message.return_path.contains(from))
                                    && to.as_ref().is_none_or(|to| {
                                        message
                                            .recipients
                                            .iter()
                                            .any(|r| r.address_lcase.contains(to))
                                    })
                            })
                            && before
                                .as_ref()
                                .is_none_or(|before| message.next_delivery_event() < *before)
                            && after
                                .as_ref()
                                .is_none_or(|after| message.next_delivery_event() > *after)));

                if matches {
                    if offset == 0 {
                        if limit == 0 || total_returned < limit {
                            if values {
                                result.values.push(Message::from(message));
                            } else {
                                result.ids.push(key.deserialize_be_u64(0)?);
                            }
                            total_returned += 1;
                        }
                    } else {
                        offset -= 1;
                    }

                    result.total += 1;
                }

                Ok(max_total == 0 || result.total < max_total)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| result)
}

struct QueuedReports {
    ids: Vec<QueueClass>,
    total: usize,
}

async fn fetch_queued_reports(
    server: &Server,
    params: &UrlParams<'_>,
    tenant_domains: &Option<Vec<String>>,
) -> trc::Result<QueuedReports> {
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

    let mut result = QueuedReports {
        ids: Vec::new(),
        total: 0,
    };
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
    let mut total_returned = 0;

    server
        .core
        .storage
        .data
        .iterate(
            IterateParams::new(from_key, to_key).ascending().no_values(),
            |key, _| {
                if type_.is_none_or(|t| t == *key.last().unwrap()) {
                    let event = ReportEvent::deserialize(key)?;
                    if tenant_domains
                        .as_ref()
                        .is_none_or(|domains| domains.iter().any(|dd| dd == &event.domain))
                        && event.seq_id != 0
                        && domain.as_ref().is_none_or(|d| event.domain.contains(d))
                    {
                        if offset == 0 {
                            if limit == 0 || total_returned < limit {
                                result.ids.push(if *key.last().unwrap() == 0 {
                                    QueueClass::DmarcReportHeader(event)
                                } else {
                                    QueueClass::TlsReportHeader(event)
                                });
                                total_returned += 1;
                            }
                        } else {
                            offset -= 1;
                        }

                        result.total += 1;
                    }
                }

                Ok(max_total == 0 || result.total < max_total)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| result)
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

trait IsTenantDomain {
    fn is_tenant_domain(&self, tenant_domains: &Option<Vec<String>>) -> bool;
}
impl IsTenantDomain for ArchivedMessage {
    fn is_tenant_domain(&self, tenant_domains: &Option<Vec<String>>) -> bool {
        tenant_domains
            .as_ref()
            .is_none_or(|domains| self.has_domain(domains))
    }
}
