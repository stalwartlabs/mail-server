/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::cli::{Client, ReportCommands, ReportFormat};
use crate::modules::{queue::deserialize_datetime, List};
use console::Term;
use human_size::{Byte, SpecificSize};
use mail_auth::{
    dmarc::URI,
    mta_sts::ReportUri,
    report::{self, tlsrpt::TlsReport},
};
use mail_parser::DateTime;
use prettytable::{format, Attr, Cell, Row, Table};
use reqwest::Method;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Report {
    Tls {
        id: String,
        domain: String,
        #[serde(deserialize_with = "deserialize_datetime")]
        range_from: DateTime,
        #[serde(deserialize_with = "deserialize_datetime")]
        range_to: DateTime,
        report: TlsReport,
        rua: Vec<ReportUri>,
    },
    Dmarc {
        id: String,
        domain: String,
        #[serde(deserialize_with = "deserialize_datetime")]
        range_from: DateTime,
        #[serde(deserialize_with = "deserialize_datetime")]
        range_to: DateTime,
        report: report::Report,
        rua: Vec<URI>,
    },
}

impl Report {
    pub fn domain(&self) -> &str {
        match self {
            Report::Tls { domain, .. } => domain,
            Report::Dmarc { domain, .. } => domain,
        }
    }

    pub fn type_(&self) -> &str {
        match self {
            Report::Tls { .. } => "TLS",
            Report::Dmarc { .. } => "DMARC",
        }
    }

    pub fn range_from(&self) -> &DateTime {
        match self {
            Report::Tls { range_from, .. } => range_from,
            Report::Dmarc { range_from, .. } => range_from,
        }
    }

    pub fn range_to(&self) -> &DateTime {
        match self {
            Report::Tls { range_to, .. } => range_to,
            Report::Dmarc { range_to, .. } => range_to,
        }
    }

    pub fn num_records(&self) -> usize {
        match self {
            Report::Tls { report, .. } => report
                .policies
                .iter()
                .map(|p| p.failure_details.len())
                .sum(),
            Report::Dmarc { report, .. } => report.records().len(),
        }
    }
}

impl ReportCommands {
    pub async fn exec(self, client: Client) {
        match self {
            ReportCommands::List {
                domain,
                format,
                page_size,
            } => {
                let stdout = Term::buffered_stdout();
                let mut query = form_urlencoded::Serializer::new("/api/queue/reports".to_string());

                if let Some(domain) = &domain {
                    query.append_pair("domain", domain);
                }
                if let Some(format) = &format {
                    query.append_pair("type", format.id());
                }

                let ids = client
                    .http_request::<List<String>, String>(Method::GET, &query.finish(), None)
                    .await
                    .items;
                let ids_len = ids.len();
                let page_size = page_size.map(|p| std::cmp::max(p, 1)).unwrap_or(20);
                let pages_total = (ids_len as f64 / page_size as f64).ceil() as usize;
                for (page_num, chunk) in ids.chunks(page_size).enumerate() {
                    // Build table
                    let mut table = Table::new();
                    table.add_row(Row::new(
                        ["ID", "Domain", "Type", "From Date", "To Date", "Records"]
                            .iter()
                            .map(|p| Cell::new(p).with_style(Attr::Bold))
                            .collect(),
                    ));
                    for id in chunk {
                        let report = client
                            .try_http_request::<Report, String>(
                                Method::GET,
                                &format!("/api/queue/reports/{id}"),
                                None,
                            )
                            .await;

                        if let Some(report) = report {
                            table.add_row(Row::new(vec![
                                Cell::new(id),
                                Cell::new(report.domain()),
                                Cell::new(report.type_()),
                                Cell::new(&report.range_from().to_rfc822()),
                                Cell::new(&report.range_to().to_rfc822()),
                                Cell::new(
                                    &SpecificSize::new(report.num_records() as u32, Byte)
                                        .unwrap()
                                        .to_string(),
                                ),
                            ]));
                        }
                    }

                    eprintln!();
                    table.printstd();
                    eprintln!();
                    if page_num + 1 != pages_total {
                        eprintln!("\n--- Press any key to continue or 'q' to exit ---");
                        if let Ok('q' | 'Q') = stdout.read_char() {
                            break;
                        }
                    }
                }
                eprintln!("\n{ids_len} queued message(s) found.")
            }
            ReportCommands::Status { ids } => {
                for id in ids {
                    let report = client
                        .try_http_request::<Report, String>(
                            Method::GET,
                            &format!("/api/queue/reports/{id}"),
                            None,
                        )
                        .await;

                    let mut table = Table::new();
                    table.add_row(Row::new(vec![
                        Cell::new("ID").with_style(Attr::Bold),
                        Cell::new(&id),
                    ]));
                    if let Some(report) = report {
                        table.add_row(Row::new(vec![
                            Cell::new("Domain Name").with_style(Attr::Bold),
                            Cell::new(report.domain()),
                        ]));
                        table.add_row(Row::new(vec![
                            Cell::new("Type").with_style(Attr::Bold),
                            Cell::new(report.type_()),
                        ]));
                        table.add_row(Row::new(vec![
                            Cell::new("From Date").with_style(Attr::Bold),
                            Cell::new(&report.range_from().to_rfc822()),
                        ]));
                        table.add_row(Row::new(vec![
                            Cell::new("To Date").with_style(Attr::Bold),
                            Cell::new(&report.range_to().to_rfc822()),
                        ]));
                        table.add_row(Row::new(vec![
                            Cell::new("Records").with_style(Attr::Bold),
                            Cell::new(
                                &SpecificSize::new(report.num_records() as u32, Byte)
                                    .unwrap()
                                    .to_string(),
                            ),
                        ]));
                    } else {
                        table.add_row(Row::new(vec![Cell::new_align(
                            "-- Not found --",
                            format::Alignment::CENTER,
                        )
                        .with_hspan(2)]));
                    }

                    eprintln!();
                    table.printstd();
                    eprintln!();
                }
            }
            ReportCommands::Cancel { ids } => {
                let mut success_count = 0;
                let mut failed_list = vec![];
                for id in ids {
                    let success = client
                        .try_http_request::<bool, String>(
                            Method::DELETE,
                            &format!("/api/queue/reports/{id}"),
                            None,
                        )
                        .await;

                    if success.unwrap_or_default() {
                        success_count += 1;
                    } else {
                        failed_list.push(id);
                    }
                }
                eprint!("\nRemoved {success_count} report(s).");
                if !failed_list.is_empty() {
                    eprint!(
                        " Unable to remove report id(s): {}.",
                        failed_list.join(", ")
                    );
                }
                eprintln!();
            }
        }
    }
}

impl ReportFormat {
    fn id(&self) -> &'static str {
        match self {
            ReportFormat::Dmarc => "dmarc",
            ReportFormat::Tls => "tls",
        }
    }
}
