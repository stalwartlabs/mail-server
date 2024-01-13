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

use prettytable::{Attr, Cell, Row, Table};
use reqwest::Method;
use serde_json::Value;

use super::cli::{Client, ServerCommands};

impl ServerCommands {
    pub async fn exec(self, client: Client) {
        match self {
            ServerCommands::DatabaseMaintenance {} => {
                client
                    .http_request::<Value, String>(Method::GET, "/admin/store/maintenance", None)
                    .await;
                eprintln!("Success.");
            }
            ServerCommands::ReloadCertificates {} => {
                client
                    .http_request::<Value, String>(Method::GET, "/admin/reload/certificates", None)
                    .await;
                eprintln!("Success.");
            }
            ServerCommands::ReloadConfig {} => {
                client
                    .http_request::<Value, String>(Method::GET, "/admin/reload/config", None)
                    .await;
                eprintln!("Success.");
            }
            ServerCommands::AddConfig { key, value } => {
                client
                    .http_request::<Value, _>(
                        Method::POST,
                        "/admin/config",
                        Some(vec![(key.clone(), value.unwrap_or_default())]),
                    )
                    .await;
                eprintln!("Successfully added key {key}.");
            }
            ServerCommands::DeleteConfig { key } => {
                client
                    .http_request::<Value, String>(
                        Method::DELETE,
                        &format!("/admin/config/{key}"),
                        None,
                    )
                    .await;
                eprintln!("Successfully deleted key {key}.");
            }
            ServerCommands::ListConfig { prefix } => {
                let results = client
                    .http_request::<Vec<(String, String)>, String>(
                        Method::GET,
                        &format!("/admin/config/{}", prefix.unwrap_or_default()),
                        None,
                    )
                    .await;

                if !results.is_empty() {
                    let mut table = Table::new();
                    table.add_row(Row::new(vec![
                        Cell::new("Key").with_style(Attr::Bold),
                        Cell::new("Value").with_style(Attr::Bold),
                    ]));

                    for (key, value) in &results {
                        table.add_row(Row::new(vec![Cell::new(key), Cell::new(value)]));
                    }

                    eprintln!();
                    table.printstd();
                    eprintln!();
                }

                eprintln!(
                    "\n\n{} key{} found.\n",
                    results.len(),
                    if results.len() == 1 { "" } else { "s" }
                );
            }
        }
    }
}
