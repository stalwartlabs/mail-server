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

use std::borrow::Cow;

use prettytable::{Attr, Cell, Row, Table};
use reqwest::Method;
use serde_json::Value;

use crate::modules::List;

use super::cli::{Client, DomainCommands};

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
