/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
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

use super::cli::{Client, ReportCommands, ReportFormat};
use crate::modules::queue::deserialize_datetime;
use console::Term;
use human_size::{Byte, SpecificSize};
use mail_parser::DateTime;
use prettytable::{format::Alignment, Attr, Cell, Row, Table};
use reqwest::Method;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Report {
    pub domain: String,
    #[serde(rename = "type")]
    pub type_: ReportFormat,
    #[serde(deserialize_with = "deserialize_datetime")]
    pub range_from: DateTime,
    #[serde(deserialize_with = "deserialize_datetime")]
    pub range_to: DateTime,
    pub size: usize,
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
                let mut query = form_urlencoded::Serializer::new("/admin/report/list?".to_string());

                if let Some(domain) = &domain {
                    query.append_pair("domain", domain);
                }
                if let Some(format) = &format {
                    query.append_pair("type", format.id());
                }

                let ids = client
                    .http_request::<Vec<String>, String>(Method::GET, &query.finish(), None)
                    .await;
                let ids_len = ids.len();
                let page_size = page_size.map(|p| std::cmp::max(p, 1)).unwrap_or(20);
                let pages_total = (ids_len as f64 / page_size as f64).ceil() as usize;
                for (page_num, chunk) in ids.chunks(page_size).enumerate() {
                    // Build table
                    let mut table = Table::new();
                    table.add_row(Row::new(
                        ["ID", "Domain", "Type", "From Date", "To Date", "Size"]
                            .iter()
                            .map(|p| Cell::new(p).with_style(Attr::Bold))
                            .collect(),
                    ));
                    for (report, id) in client
                        .http_request::<Vec<Option<Report>>, String>(
                            Method::GET,
                            &format!("/admin/report/status?ids={}", chunk.join(",")),
                            None,
                        )
                        .await
                        .into_iter()
                        .zip(chunk)
                    {
                        if let Some(report) = report {
                            table.add_row(Row::new(vec![
                                Cell::new(id),
                                Cell::new(&report.domain),
                                Cell::new(report.type_.name()),
                                Cell::new(&report.range_from.to_rfc822()),
                                Cell::new(&report.range_to.to_rfc822()),
                                Cell::new(
                                    &SpecificSize::new(report.size as u32, Byte)
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
                for (report, id) in client
                    .http_request::<Vec<Option<Report>>, String>(
                        Method::GET,
                        &format!("/admin/report/status?ids={}", ids.join(",")),
                        None,
                    )
                    .await
                    .into_iter()
                    .zip(&ids)
                {
                    let mut table = Table::new();
                    table.add_row(Row::new(vec![
                        Cell::new("ID").with_style(Attr::Bold),
                        Cell::new(id),
                    ]));
                    if let Some(report) = report {
                        table.add_row(Row::new(vec![
                            Cell::new("Domain Name").with_style(Attr::Bold),
                            Cell::new(&report.domain),
                        ]));
                        table.add_row(Row::new(vec![
                            Cell::new("Type").with_style(Attr::Bold),
                            Cell::new(report.type_.name()),
                        ]));
                        table.add_row(Row::new(vec![
                            Cell::new("From Date").with_style(Attr::Bold),
                            Cell::new(&report.range_from.to_rfc822()),
                        ]));
                        table.add_row(Row::new(vec![
                            Cell::new("To Date").with_style(Attr::Bold),
                            Cell::new(&report.range_to.to_rfc822()),
                        ]));
                        table.add_row(Row::new(vec![
                            Cell::new("Size").with_style(Attr::Bold),
                            Cell::new(
                                &SpecificSize::new(report.size as u32, Byte)
                                    .unwrap()
                                    .to_string(),
                            ),
                        ]));
                    } else {
                        table.add_row(Row::new(vec![Cell::new_align(
                            "-- Not found --",
                            Alignment::CENTER,
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
                for (success, id) in client
                    .http_request::<Vec<bool>, String>(
                        Method::GET,
                        &format!("/admin/report/cancel?ids={}", ids.join(",")),
                        None,
                    )
                    .await
                    .into_iter()
                    .zip(ids)
                {
                    if success {
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

    fn name(&self) -> &'static str {
        match self {
            ReportFormat::Dmarc => "DMARC",
            ReportFormat::Tls => "TLS",
        }
    }
}
