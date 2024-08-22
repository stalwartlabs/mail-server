/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use prettytable::{Attr, Cell, Row, Table, format};
use reqwest::Method;
use serde_json::Value;

use crate::modules::List;

use super::cli::{Client, DomainCommands};

use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize, Clone)]
struct DnsRecord {
    #[serde(rename = "type")]
    typ: String,
    name: String,
    content: String,
}

impl DomainCommands {
    pub async fn exec(self, client: Client) {
        match self {
            DomainCommands::Create { name } => {
                client
                    .http_request::<Value, String>(
                        Method::POST,
                        &format!("/api/domain/{name}"),
                        None,
                    )
                    .await;
                eprintln!("Successfully created domain {name:?}");
            }
            DomainCommands::Delete { name } => {
                client
                    .http_request::<Value, String>(
                        Method::DELETE,
                        &format!("/api/domain/{name}"),
                        None,
                    )
                    .await;
                eprintln!("Successfully deleted domain {name:?}");
            }
            DomainCommands::DNSRecords { name } => {
                let records = client
                    .http_request::<Vec<DnsRecord>, String>(
                        Method::GET,
                        &format!("/api/domain/{name}"),
                        None,
                    )
                    .await;

                if !records.is_empty() {
                    let mut table = Table::new();
                    // no borderline separator separator, as long values will mess it up
                    table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);

                    table.add_row(Row::new(vec![
                        Cell::new("Type").with_style(Attr::Bold),
                        Cell::new("Name").with_style(Attr::Bold),
                        Cell::new("Contents").with_style(Attr::Bold),
                    ]));

                    for record in &records {
                        table.add_row(Row::new(vec![
                            Cell::new(&record.typ),
                            Cell::new(&record.name),
                            Cell::new(&record.content),
                        ]));
                    }

                    eprintln!();
                    table.printstd();
                    eprintln!();
                }
            }
            DomainCommands::List { from, limit } => {
                let query = if from.is_none() && limit.is_none() {
                    Cow::Borrowed("/api/domain")
                } else {
                    let mut query = "/api/domain?".to_string();
                    if let Some(from) = &from {
                        query.push_str(&format!("from={from}"));
                    }
                    if let Some(limit) = limit {
                        query.push_str(&format!(
                            "{}limit={limit}",
                            if from.is_some() { "&" } else { "" }
                        ));
                    }
                    Cow::Owned(query)
                };

                let domains = client
                    .http_request::<List<String>, String>(Method::GET, query.as_ref(), None)
                    .await;
                if !domains.items.is_empty() {
                    let mut table = Table::new();
                    table.add_row(Row::new(vec![
                        Cell::new("Domain Name").with_style(Attr::Bold)
                    ]));

                    for domain in &domains.items {
                        table.add_row(Row::new(vec![Cell::new(domain)]));
                    }

                    eprintln!();
                    table.printstd();
                    eprintln!();
                }

                eprintln!(
                    "\n\n{} domain{} found.\n",
                    domains.total,
                    if domains.total == 1 { "" } else { "s" }
                );
            }
        }
    }
}
