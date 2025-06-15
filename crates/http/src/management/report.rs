/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use directory::{Permission, Type, backend::internal::manage::ManageDirectory};
use http_proto::{request::decode_path_element, *};
use hyper::Method;
use mail_auth::report::{
    Feedback,
    tlsrpt::{FailureDetails, Policy, TlsReport},
};
use serde_json::json;
use smtp::reporting::analysis::IncomingReport;
use std::future::Future;
use store::{
    Deserialize, IterateParams, Key, U64_LEN, ValueKey,
    write::{
        AlignedBytes, Archive, BatchBuilder, ReportClass, ValueClass, key::DeserializeBigEndian,
    },
};
use trc::AddContext;
use utils::url_params::UrlParams;

enum ReportType {
    Dmarc,
    Tls,
    Arf,
}

pub trait ManageReports: Sync + Send {
    fn handle_manage_reports(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl ManageReports for Server {
    async fn handle_manage_reports(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
        access_token: &AccessToken,
    ) -> trc::Result<HttpResponse> {
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
            (class @ ("dmarc" | "tls" | "arf"), None, &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::IncomingReportList)?;

                let params = UrlParams::new(req.uri().query());

                let IncomingReports { ids, total } =
                    fetch_incoming_reports(self, class, &params, &tenant_domains).await?;

                Ok(JsonResponse::new(json!({
                        "data": {
                            "items": ids.into_iter().map(|(id, expires)| {
                                format!("{id}_{expires}")
                            }).collect::<Vec<_>>(),
                            "total": total,
                        },
                }))
                .into_http_response())
            }
            (class @ ("dmarc" | "tls" | "arf"), Some(report_id), &Method::GET) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::IncomingReportGet)?;

                if let Some(report_id) = parse_incoming_report_id(class, report_id.as_ref()) {
                    match &report_id {
                        ReportClass::Tls { .. } => match fetch_report::<IncomingReport<TlsReport>>(
                            self,
                            ValueKey::from(ValueClass::Report(report_id)),
                        )
                        .await?
                        {
                            Some(report)
                                if tenant_domains
                                    .as_ref()
                                    .is_none_or(|domains| report.has_domain(domains)) =>
                            {
                                Ok(JsonResponse::new(json!({
                                        "data": report,
                                }))
                                .into_http_response())
                            }
                            _ => Err(trc::ResourceEvent::NotFound.into_err()),
                        },
                        ReportClass::Dmarc { .. } => {
                            match fetch_report::<IncomingReport<mail_auth::report::Report>>(
                                self,
                                ValueKey::from(ValueClass::Report(report_id)),
                            )
                            .await?
                            {
                                Some(report)
                                    if tenant_domains
                                        .as_ref()
                                        .is_none_or(|domains| report.has_domain(domains)) =>
                                {
                                    Ok(JsonResponse::new(json!({
                                            "data": report,
                                    }))
                                    .into_http_response())
                                }
                                _ => Err(trc::ResourceEvent::NotFound.into_err()),
                            }
                        }
                        ReportClass::Arf { .. } => match fetch_report::<IncomingReport<Feedback>>(
                            self,
                            ValueKey::from(ValueClass::Report(report_id)),
                        )
                        .await?
                        {
                            Some(report)
                                if tenant_domains
                                    .as_ref()
                                    .is_none_or(|domains| report.has_domain(domains)) =>
                            {
                                Ok(JsonResponse::new(json!({
                                        "data": report,
                                }))
                                .into_http_response())
                            }
                            _ => Err(trc::ResourceEvent::NotFound.into_err()),
                        },
                    }
                } else {
                    Err(trc::ResourceEvent::NotFound.into_err())
                }
            }
            (class @ ("dmarc" | "tls" | "arf"), None, &Method::DELETE) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::IncomingReportDelete)?;

                let params = UrlParams::new(req.uri().query());

                let IncomingReports { ids, .. } =
                    fetch_incoming_reports(self, class, &params, &tenant_domains).await?;

                let found = !ids.is_empty();
                if found {
                    let class = match class {
                        "dmarc" => ReportClass::Dmarc { id: 0, expires: 0 },
                        "tls" => ReportClass::Tls { id: 0, expires: 0 },
                        "arf" => ReportClass::Arf { id: 0, expires: 0 },
                        _ => unreachable!(),
                    };
                    let server = self.clone();
                    tokio::spawn(async move {
                        let mut batch = BatchBuilder::new();

                        for (id, expires) in ids {
                            let report_id = match &class {
                                ReportClass::Dmarc { .. } => ReportClass::Dmarc { id, expires },
                                ReportClass::Tls { .. } => ReportClass::Tls { id, expires },
                                ReportClass::Arf { .. } => ReportClass::Arf { id, expires },
                            };

                            batch.clear(ValueClass::Report(report_id));

                            if batch.is_large_batch() {
                                if let Err(err) =
                                    server.core.storage.data.write(batch.build_all()).await
                                {
                                    trc::error!(err.caused_by(trc::location!()));
                                }
                                batch = BatchBuilder::new();
                            }
                        }

                        if !batch.is_empty() {
                            if let Err(err) =
                                server.core.storage.data.write(batch.build_all()).await
                            {
                                trc::error!(err.caused_by(trc::location!()));
                            }
                        }
                    });
                }

                Ok(JsonResponse::new(json!({
                        "data": found,
                }))
                .into_http_response())
            }
            (class @ ("dmarc" | "tls" | "arf"), Some(report_id), &Method::DELETE) => {
                // Validate the access token
                access_token.assert_has_permission(Permission::IncomingReportDelete)?;

                if let Some(report_id) = parse_incoming_report_id(class, report_id.as_ref()) {
                    if let Some(domains) = &tenant_domains {
                        let is_tenant_report = match &report_id {
                            ReportClass::Tls { .. } => fetch_report::<IncomingReport<TlsReport>>(
                                self,
                                ValueKey::from(ValueClass::Report(report_id.clone())),
                            )
                            .await?
                            .is_none_or(|report| report.has_domain(domains)),
                            ReportClass::Dmarc { .. } => {
                                fetch_report::<IncomingReport<mail_auth::report::Report>>(
                                    self,
                                    ValueKey::from(ValueClass::Report(report_id.clone())),
                                )
                                .await?
                                .is_none_or(|report| report.has_domain(domains))
                            }

                            ReportClass::Arf { .. } => fetch_report::<IncomingReport<Feedback>>(
                                self,
                                ValueKey::from(ValueClass::Report(report_id.clone())),
                            )
                            .await?
                            .is_none_or(|report| report.has_domain(domains)),
                        };

                        if !is_tenant_report {
                            return Err(trc::ResourceEvent::NotFound.into_err());
                        }
                    }

                    let mut batch = BatchBuilder::new();
                    batch.clear(ValueClass::Report(report_id));
                    self.core.storage.data.write(batch.build_all()).await?;

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

async fn fetch_report<T>(server: &Server, key: impl Key) -> trc::Result<Option<T>>
where
    T: rkyv::Archive
        + for<'a> rkyv::Serialize<
            rkyv::api::high::HighSerializer<
                rkyv::util::AlignedVec,
                rkyv::ser::allocator::ArenaHandle<'a>,
                rkyv::rancor::Error,
            >,
        >,
    T::Archived: for<'a> rkyv::bytecheck::CheckBytes<rkyv::api::high::HighValidator<'a, rkyv::rancor::Error>>
        + rkyv::Deserialize<T, rkyv::api::high::HighDeserializer<rkyv::rancor::Error>>,
{
    if let Some(tls) = server
        .store()
        .get_value::<Archive<AlignedBytes>>(key)
        .await?
    {
        tls.deserialize::<T>().map(Some)
    } else {
        Ok(None)
    }
}

struct IncomingReports {
    ids: Vec<(u64, u64)>,
    total: usize,
}

async fn fetch_incoming_reports(
    server: &Server,
    class: &str,
    params: &UrlParams<'_>,
    tenant_domains: &Option<Vec<String>>,
) -> trc::Result<IncomingReports> {
    let filter = params.get("text");
    let page: usize = params.parse::<usize>("page").unwrap_or_default();
    let limit: usize = params.parse::<usize>("limit").unwrap_or_default();

    let range_start = params.parse::<u64>("range-start").unwrap_or_default();
    let range_end = params.parse::<u64>("range-end").unwrap_or(u64::MAX);
    let max_total = params.parse::<usize>("max-total").unwrap_or_default();

    let (from_key, to_key, typ) = match class {
        "dmarc" => (
            ValueKey::from(ValueClass::Report(ReportClass::Dmarc {
                id: range_start,
                expires: 0,
            })),
            ValueKey::from(ValueClass::Report(ReportClass::Dmarc {
                id: range_end,
                expires: u64::MAX,
            })),
            ReportType::Dmarc,
        ),
        "tls" => (
            ValueKey::from(ValueClass::Report(ReportClass::Tls {
                id: range_start,
                expires: 0,
            })),
            ValueKey::from(ValueClass::Report(ReportClass::Tls {
                id: range_end,
                expires: u64::MAX,
            })),
            ReportType::Tls,
        ),
        "arf" => (
            ValueKey::from(ValueClass::Report(ReportClass::Arf {
                id: range_start,
                expires: 0,
            })),
            ValueKey::from(ValueClass::Report(ReportClass::Arf {
                id: range_end,
                expires: u64::MAX,
            })),
            ReportType::Arf,
        ),
        _ => unreachable!(),
    };

    let mut results = IncomingReports {
        ids: Vec::new(),
        total: 0,
    };
    let mut offset = page.saturating_sub(1) * limit;
    let mut last_id = 0;
    let has_filters = filter.is_some() || tenant_domains.is_some();

    server
        .core
        .storage
        .data
        .iterate(
            IterateParams::new(from_key, to_key)
                .set_values(has_filters)
                .descending(),
            |key, value| {
                // Skip chunked records
                let id = key.deserialize_be_u64(U64_LEN + 1)?;
                if id == last_id {
                    return Ok(true);
                }
                last_id = id;

                // TODO: Support filtering chunked records (over 10MB) on FDB
                let matches = if has_filters {
                    let archive = <Archive<AlignedBytes> as Deserialize>::deserialize(value)?;
                    match typ {
                        ReportType::Dmarc => {
                            let report = archive
                                .deserialize::<IncomingReport<mail_auth::report::Report>>()
                                .caused_by(trc::location!())?;

                            filter.is_none_or(|f| report.contains(f))
                                && tenant_domains
                                    .as_ref()
                                    .is_none_or(|domains| report.has_domain(domains))
                        }
                        ReportType::Tls => {
                            let report = archive
                                .deserialize::<IncomingReport<TlsReport>>()
                                .caused_by(trc::location!())?;

                            filter.is_none_or(|f| report.contains(f))
                                && tenant_domains
                                    .as_ref()
                                    .is_none_or(|domains| report.has_domain(domains))
                        }
                        ReportType::Arf => {
                            let report = archive
                                .deserialize::<IncomingReport<Feedback>>()
                                .caused_by(trc::location!())?;

                            filter.is_none_or(|f| report.contains(f))
                                && tenant_domains
                                    .as_ref()
                                    .is_none_or(|domains| report.has_domain(domains))
                        }
                    }
                } else {
                    true
                };

                if matches {
                    if offset == 0 {
                        if limit == 0 || results.ids.len() < limit {
                            results.ids.push((id, key.deserialize_be_u64(1)?));
                        }
                    } else {
                        offset -= 1;
                    }

                    results.total += 1;
                }

                Ok(max_total == 0 || results.total < max_total)
            },
        )
        .await
        .caused_by(trc::location!())
        .map(|_| results)
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
                .is_some_and(|c| c.to_lowercase().contains(text))
            || self.records().iter().any(|record| record.contains(text))
    }
}

impl Contains for mail_auth::report::Record {
    fn contains(&self, filter: &str) -> bool {
        self.envelope_from().contains(filter)
            || self.header_from().contains(filter)
            || self.envelope_to().is_some_and(|to| to.contains(filter))
            || self.dkim_auth_result().iter().any(|dkim| {
                dkim.domain().contains(filter)
                    || dkim.selector().contains(filter)
                    || dkim
                        .human_result()
                        .as_ref()
                        .is_some_and(|r| r.contains(filter))
            })
            || self.spf_auth_result().iter().any(|spf| {
                spf.domain().contains(filter)
                    || spf.human_result().is_some_and(|r| r.contains(filter))
            })
            || self
                .source_ip()
                .is_some_and(|ip| ip.to_string().contains(filter))
    }
}

impl Contains for TlsReport {
    fn contains(&self, text: &str) -> bool {
        self.organization_name
            .as_ref()
            .is_some_and(|o| o.to_lowercase().contains(text))
            || self
                .contact_info
                .as_ref()
                .is_some_and(|c| c.to_lowercase().contains(text))
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
            .is_some_and(|s| s.to_string().contains(filter))
            || self
                .receiving_ip
                .is_some_and(|s| s.to_string().contains(filter))
            || self
                .receiving_mx_hostname
                .as_ref()
                .is_some_and(|s| s.contains(filter))
            || self
                .receiving_mx_helo
                .as_ref()
                .is_some_and(|s| s.contains(filter))
            || self
                .additional_information
                .as_ref()
                .is_some_and(|s| s.contains(filter))
            || self
                .failure_reason_code
                .as_ref()
                .is_some_and(|s| s.contains(filter))
    }
}

impl Contains for Feedback<'_> {
    fn contains(&self, text: &str) -> bool {
        // Check if any of the string fields contain the filter
        self.authentication_results()
            .iter()
            .any(|s| s.contains(text))
            || self
                .original_envelope_id()
                .is_some_and(|s| s.contains(text))
            || self.original_mail_from().is_some_and(|s| s.contains(text))
            || self.original_rcpt_to().is_some_and(|s| s.contains(text))
            || self.reported_domain().iter().any(|s| s.contains(text))
            || self.reported_uri().iter().any(|s| s.contains(text))
            || self.reporting_mta().is_some_and(|s| s.contains(text))
            || self.user_agent().is_some_and(|s| s.contains(text))
            || self.dkim_adsp_dns().is_some_and(|s| s.contains(text))
            || self
                .dkim_canonicalized_body()
                .is_some_and(|s| s.contains(text))
            || self
                .dkim_canonicalized_header()
                .is_some_and(|s| s.contains(text))
            || self.dkim_domain().is_some_and(|s| s.contains(text))
            || self.dkim_identity().is_some_and(|s| s.contains(text))
            || self.dkim_selector().is_some_and(|s| s.contains(text))
            || self.dkim_selector_dns().is_some_and(|s| s.contains(text))
            || self.spf_dns().is_some_and(|s| s.contains(text))
            || self.message().is_some_and(|s| s.contains(text))
            || self.headers().is_some_and(|s| s.contains(text))
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
