/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashMap;

use prettytable::{Attr, Cell, Row, Table};
use reqwest::Method;
use serde_json::Value;

use crate::modules::Response;

use super::cli::{Client, ServerCommands};

impl ServerCommands {
    pub async fn exec(self, client: Client) {
        match self {
            ServerCommands::DatabaseMaintenance {} => {
                client
                    .http_request::<Value, String>(Method::GET, "/api/store/maintenance", None)
                    .await;
                eprintln!("Success.");
            }
            ServerCommands::ReloadCertificates {} => {
                client
                    .http_request::<Value, String>(Method::GET, "/api/reload/certificate", None)
                    .await;
                eprintln!("Success.");
            }
            ServerCommands::ReloadConfig {} => {
                client
                    .http_request::<Value, String>(Method::GET, "/api/reload", None)
                    .await;
                eprintln!("Success.");
            }
            ServerCommands::AddConfig { key, value } => {
                client
                    .http_request::<Value, _>(
                        Method::POST,
                        "/api/settings",
                        Some(vec![(key.clone(), value.unwrap_or_default())]),
                    )
                    .await;
                eprintln!("Successfully added key {key}.");
            }
            ServerCommands::DeleteConfig { key } => {
                client
                    .http_request::<Value, String>(
                        Method::DELETE,
                        &format!("/api/settings/{key}"),
                        None,
                    )
                    .await;
                eprintln!("Successfully deleted key {key}.");
            }
            ServerCommands::ListConfig { prefix } => {
                let results = client
                    .http_request::<Response<HashMap<String, String>>, String>(
                        Method::GET,
                        &format!("/api/settings/list/{}", prefix.unwrap_or_default()),
                        None,
                    )
                    .await
                    .items;

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
