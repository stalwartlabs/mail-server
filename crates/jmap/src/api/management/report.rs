/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use hyper::Method;
use mail_auth::report::{
    tlsrpt::{FailureDetails, Policy, TlsReport},
    Feedback,
};
use serde_json::json;
use smtp::reporting::analysis::IncomingReport;
use store::{
    write::{key::DeserializeBigEndian, BatchBuilder, Bincode, ReportClass, ValueClass},
    Deserialize, IterateParams, ValueKey, U64_LEN,
};
use utils::url_params::UrlParams;

use crate::{
    api::{http::ToHttpResponse, HttpRequest, HttpResponse, JsonResponse},
    JMAP,
};

use super::decode_path_element;

enum ReportType {
    Dmarc,
    Tls,
    Arf,
}

impl JMAP {
    pub async fn handle_manage_reports(
        &self,
        req: &HttpRequest,
        path: Vec<&str>,
    ) -> trc::Result<HttpResponse> {
        match (
            path.get(1).copied().unwrap_or_default(),
            path.get(2).copied().map(decode_path_element),
            req.method(),
        ) {
            (class @ ("dmarc" | "tls" | "arf"), None, &Method::GET) => {
                let params = UrlParams::new(req.uri().query());
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

                let mut results = Vec::new();
                let mut offset = page.saturating_sub(1) * limit;
                let mut total = 0;
                let mut last_id = 0;
                self.core
                    .storage
                    .data
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

                            Ok(max_total == 0 || total < max_total)
                        },
                    )
                    .await?;

                Ok(JsonResponse::new(json!({
                        "data": {
                            "items": results,
                            "total": total,
                        },
                }))
                .into_http_response())
            }
            (class @ ("dmarc" | "tls" | "arf"), Some(report_id), &Method::GET) => {
                if let Some(report_id) = parse_incoming_report_id(class, report_id.as_ref()) {
                    match &report_id {
                        ReportClass::Tls { .. } => match self
                            .core
                            .storage
                            .data
                            .get_value::<Bincode<IncomingReport<TlsReport>>>(ValueKey::from(
                                ValueClass::Report(report_id),
                            ))
                            .await?
                        {
                            Some(report) => Ok(JsonResponse::new(json!({
                                    "data": report.inner,
                            }))
                            .into_http_response()),
                            None => Err(trc::ResourceCause::NotFound.into_err()),
                        },
                        ReportClass::Dmarc { .. } => match self
                            .core
                            .storage
                            .data
                            .get_value::<Bincode<IncomingReport<mail_auth::report::Report>>>(
                                ValueKey::from(ValueClass::Report(report_id)),
                            )
                            .await?
                        {
                            Some(report) => Ok(JsonResponse::new(json!({
                                    "data": report.inner,
                            }))
                            .into_http_response()),
                            None => Err(trc::ResourceCause::NotFound.into_err()),
                        },
                        ReportClass::Arf { .. } => match self
                            .core
                            .storage
                            .data
                            .get_value::<Bincode<IncomingReport<Feedback>>>(ValueKey::from(
                                ValueClass::Report(report_id),
                            ))
                            .await?
                        {
                            Some(report) => Ok(JsonResponse::new(json!({
                                    "data": report.inner,
                            }))
                            .into_http_response()),
                            None => Err(trc::ResourceCause::NotFound.into_err()),
                        },
                    }
                } else {
                    Err(trc::ResourceCause::NotFound.into_err())
                }
            }
            (class @ ("dmarc" | "tls" | "arf"), Some(report_id), &Method::DELETE) => {
                if let Some(report_id) = parse_incoming_report_id(class, report_id.as_ref()) {
                    let mut batch = BatchBuilder::new();
                    batch.clear(ValueClass::Report(report_id));
                    self.core.storage.data.write(batch.build()).await?;

                    Ok(JsonResponse::new(json!({
                            "data": true,
                    }))
                    .into_http_response())
                } else {
                    Err(trc::ResourceCause::NotFound.into_err())
                }
            }
            _ => Err(trc::ResourceCause::NotFound.into_err()),
        }
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
