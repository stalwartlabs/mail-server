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

use super::cli::{Client, QueueCommands};
use console::Term;
use human_size::{Byte, SpecificSize};
use mail_parser::DateTime;
use prettytable::{format::Alignment, Attr, Cell, Row, Table};
use reqwest::Method;
use serde::{Deserialize, Deserializer};

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Message {
    pub return_path: String,
    pub domains: Vec<Domain>,
    #[serde(deserialize_with = "deserialize_datetime")]
    pub created: DateTime,
    pub size: usize,
    #[serde(default)]
    pub priority: i16,
    pub env_id: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Domain {
    pub name: String,
    pub status: Status,
    pub recipients: Vec<Recipient>,

    pub retry_num: u32,
    #[serde(deserialize_with = "deserialize_maybe_datetime")]
    pub next_retry: Option<DateTime>,
    #[serde(deserialize_with = "deserialize_maybe_datetime")]
    pub next_notify: Option<DateTime>,
    #[serde(deserialize_with = "deserialize_datetime")]
    pub expires: DateTime,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Recipient {
    pub address: String,
    pub status: Status,
    pub orcpt: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub enum Status {
    #[serde(rename = "scheduled")]
    Scheduled,
    #[serde(rename = "completed")]
    Completed(String),
    #[serde(rename = "temp_fail")]
    TemporaryFailure(String),
    #[serde(rename = "perm_fail")]
    PermanentFailure(String),
}

impl QueueCommands {
    pub async fn exec(self, client: Client) {
        match self {
            QueueCommands::List {
                sender,
                rcpt,
                before,
                after,
                page_size,
            } => {
                let stdout = Term::buffered_stdout();
                let ids = client.query_messages(&sender, &rcpt, &before, &after).await;
                let ids_len = ids.len();
                let page_size = page_size.map(|p| std::cmp::max(p, 1)).unwrap_or(20);
                let pages_total = (ids_len as f64 / page_size as f64).ceil() as usize;
                for (page_num, chunk) in ids.chunks(page_size).enumerate() {
                    // Build table
                    let mut table = Table::new();
                    table.add_row(Row::new(
                        ["ID", "Delivery Due", "Sender", "Recipients", "Size"]
                            .iter()
                            .map(|p| Cell::new(p).with_style(Attr::Bold))
                            .collect(),
                    ));
                    for (message, id) in client
                        .http_request::<Vec<Option<Message>>, String>(
                            Method::GET,
                            &build_query("/admin/queue/status?ids=", chunk),
                            None,
                        )
                        .await
                        .into_iter()
                        .zip(chunk)
                    {
                        if let Some(message) = message {
                            let mut rcpts = String::new();
                            let mut deliver_at = i64::MAX;
                            let mut deliver_pos = 0;
                            for (pos, domain) in message.domains.iter().enumerate() {
                                if let Some(next_retry) = &domain.next_retry {
                                    let ts = next_retry.to_timestamp();
                                    if ts < deliver_at {
                                        deliver_at = ts;
                                        deliver_pos = pos;
                                    }
                                }
                                for rcpt in &domain.recipients {
                                    if !rcpts.is_empty() {
                                        rcpts.push('\n');
                                    }
                                    rcpts.push_str(&rcpt.address);
                                    rcpts.push_str(" (");
                                    rcpts.push_str(rcpt.status.status_short());
                                    rcpts.push(')');
                                }
                            }

                            let mut cells = Vec::new();
                            cells.push(Cell::new(&format!("{id:X}")));
                            cells.push(if deliver_at != i64::MAX {
                                Cell::new(
                                    &message.domains[deliver_pos]
                                        .next_retry
                                        .as_ref()
                                        .unwrap()
                                        .to_rfc822(),
                                )
                            } else {
                                Cell::new("None")
                            });
                            cells.push(Cell::new(if !message.return_path.is_empty() {
                                &message.return_path
                            } else {
                                "<>"
                            }));
                            cells.push(Cell::new(&rcpts));
                            cells.push(Cell::new(
                                &SpecificSize::new(message.size as u32, Byte)
                                    .unwrap()
                                    .to_string(),
                            ));
                            table.add_row(Row::new(cells));
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
            QueueCommands::Status { ids } => {
                for (message, id) in client
                    .http_request::<Vec<Option<Message>>, String>(
                        Method::GET,
                        &build_query("/admin/queue/status?ids=", &parse_ids(&ids)),
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
                    if let Some(message) = message {
                        table.add_row(Row::new(vec![
                            Cell::new("Sender").with_style(Attr::Bold),
                            Cell::new(if !message.return_path.is_empty() {
                                &message.return_path
                            } else {
                                "<>"
                            }),
                        ]));
                        table.add_row(Row::new(vec![
                            Cell::new("Created").with_style(Attr::Bold),
                            Cell::new(&message.created.to_rfc822()),
                        ]));
                        table.add_row(Row::new(vec![
                            Cell::new("Size").with_style(Attr::Bold),
                            Cell::new(
                                &SpecificSize::new(message.size as u32, Byte)
                                    .unwrap()
                                    .to_string(),
                            ),
                        ]));
                        if let Some(env_id) = &message.env_id {
                            table.add_row(Row::new(vec![
                                Cell::new("Env-Id").with_style(Attr::Bold),
                                Cell::new(env_id),
                            ]));
                        }
                        if message.priority != 0 {
                            table.add_row(Row::new(vec![
                                Cell::new("Priority").with_style(Attr::Bold),
                                Cell::new(&message.priority.to_string()),
                            ]));
                        }
                        for domain in &message.domains {
                            table.add_row(Row::new(vec![Cell::new_align(
                                &domain.name,
                                Alignment::RIGHT,
                            )
                            .with_style(Attr::Bold)
                            .with_style(Attr::Italic(true))
                            .with_hspan(2)]));
                            table.add_row(Row::new(vec![
                                Cell::new("Status").with_style(Attr::Bold),
                                Cell::new(domain.status.status()),
                            ]));
                            table.add_row(Row::new(vec![
                                Cell::new("Details").with_style(Attr::Bold),
                                Cell::new(domain.status.details()),
                            ]));
                            table.add_row(Row::new(vec![
                                Cell::new("Retry #").with_style(Attr::Bold),
                                Cell::new(&domain.retry_num.to_string()),
                            ]));
                            if let Some(dt) = &domain.next_retry {
                                table.add_row(Row::new(vec![
                                    Cell::new("Delivery Due").with_style(Attr::Bold),
                                    Cell::new(&dt.to_rfc822()),
                                ]));
                            }
                            if let Some(dt) = &domain.next_notify {
                                table.add_row(Row::new(vec![
                                    Cell::new("Notify at").with_style(Attr::Bold),
                                    Cell::new(&dt.to_rfc822()),
                                ]));
                            }
                            table.add_row(Row::new(vec![
                                Cell::new("Expires").with_style(Attr::Bold),
                                Cell::new(&domain.expires.to_rfc822()),
                            ]));

                            let mut rcpts = Table::new();
                            rcpts.add_row(Row::new(vec![
                                Cell::new("Address").with_style(Attr::Bold),
                                Cell::new("Status").with_style(Attr::Bold),
                                Cell::new("Details").with_style(Attr::Bold),
                            ]));
                            for rcpt in &domain.recipients {
                                rcpts.add_row(Row::new(vec![
                                    Cell::new(&rcpt.address),
                                    Cell::new(rcpt.status.status()),
                                    Cell::new(rcpt.status.details()),
                                ]));
                            }
                            table.add_row(Row::new(vec![
                                Cell::new("Recipients").with_style(Attr::Bold),
                                Cell::from(&rcpts),
                            ]));
                        }
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
            QueueCommands::Retry {
                sender,
                domain,
                before,
                after,
                time,
                ids,
            } => {
                let (parsed_ids, ids) = if ids.is_empty() {
                    if sender.is_some() || domain.is_some() || before.is_some() || after.is_some() {
                        let parsed_ids = client
                            .query_messages(&sender, &domain, &before, &after)
                            .await;
                        let ids = parsed_ids.iter().map(|id| format!("{id:X}")).collect();
                        (parsed_ids, ids)
                    } else {
                        (vec![], vec![])
                    }
                } else {
                    (parse_ids(&ids), ids)
                };

                if ids.is_empty() {
                    eprintln!("No messages were found.");
                    std::process::exit(1);
                }

                let mut query = form_urlencoded::Serializer::new("/admin/queue/retry?".to_string());

                if let Some(filter) = &domain {
                    query.append_pair("filter", filter);
                }
                if let Some(at) = time {
                    query.append_pair("at", &at.to_rfc3339());
                }
                query.append_pair("ids", &append_ids(String::new(), &parsed_ids));

                let mut success_count = 0;
                let mut failed_list = vec![];
                for (success, id) in client
                    .http_request::<Vec<bool>, String>(Method::GET, &query.finish(), None)
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
                eprint!("\nSuccessfully rescheduled {success_count} message(s).");
                if !failed_list.is_empty() {
                    eprint!(" Unable to reschedule id(s): {}.", failed_list.join(", "));
                }
                eprintln!();
            }
            QueueCommands::Cancel {
                sender,
                rcpt,
                before,
                after,
                ids,
            } => {
                let (parsed_ids, ids) = if ids.is_empty() {
                    if sender.is_some() || rcpt.is_some() || before.is_some() || after.is_some() {
                        let parsed_ids =
                            client.query_messages(&sender, &rcpt, &before, &after).await;
                        let ids = parsed_ids.iter().map(|id| format!("{id:X}")).collect();
                        (parsed_ids, ids)
                    } else {
                        (vec![], vec![])
                    }
                } else {
                    (parse_ids(&ids), ids)
                };

                if ids.is_empty() {
                    eprintln!("No messages were found.");
                    std::process::exit(1);
                }

                let mut query =
                    form_urlencoded::Serializer::new("/admin/queue/cancel?".to_string());

                if let Some(filter) = &rcpt {
                    query.append_pair("filter", filter);
                }
                query.append_pair("ids", &append_ids(String::new(), &parsed_ids));

                let mut success_count = 0;
                let mut failed_list = vec![];
                for (success, id) in client
                    .http_request::<Vec<bool>, String>(Method::GET, &query.finish(), None)
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
                eprint!("\nCancelled delivery of {success_count} message(s).");
                if !failed_list.is_empty() {
                    eprint!(
                        " Unable to cancel delivery for id(s): {}.",
                        failed_list.join(", ")
                    );
                }
                eprintln!();
            }
        }
    }
}

impl Client {
    async fn query_messages(
        &self,
        from: &Option<String>,
        rcpt: &Option<String>,
        before: &Option<DateTime>,
        after: &Option<DateTime>,
    ) -> Vec<u64> {
        let mut query = form_urlencoded::Serializer::new("/admin/queue/list?".to_string());

        if let Some(sender) = from {
            query.append_pair("from", sender);
        }
        if let Some(rcpt) = rcpt {
            query.append_pair("to", rcpt);
        }
        if let Some(before) = before {
            query.append_pair("before", &before.to_rfc3339());
        }
        if let Some(after) = after {
            query.append_pair("after", &after.to_rfc3339());
        }

        self.http_request::<Vec<u64>, String>(Method::GET, &query.finish(), None)
            .await
    }
}

fn deserialize_maybe_datetime<'de, D>(deserializer: D) -> Result<Option<DateTime>, D::Error>
where
    D: Deserializer<'de>,
{
    if let Some(value) = Option::<&str>::deserialize(deserializer)? {
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

pub fn deserialize_datetime<'de, D>(deserializer: D) -> Result<DateTime, D::Error>
where
    D: Deserializer<'de>,
{
    if let Some(value) = DateTime::parse_rfc3339(<&str>::deserialize(deserializer)?) {
        Ok(value)
    } else {
        Err(serde::de::Error::custom(
            "Failed to parse RFC3339 timestamp",
        ))
    }
}

fn parse_ids(ids: &[String]) -> Vec<u64> {
    let mut result = Vec::with_capacity(ids.len());
    for id in ids {
        match u64::from_str_radix(id, 16) {
            Ok(id) => {
                result.push(id);
            }
            Err(_) => {
                eprintln!("Failed to parse id {id:?}.");
                std::process::exit(1);
            }
        }
    }
    result
}

fn build_query(path: &str, ids: &[u64]) -> String {
    let mut query = String::with_capacity(path.len() + (ids.len() * 10));
    query.push_str(path);
    append_ids(query, ids)
}

fn append_ids(mut query: String, ids: &[u64]) -> String {
    for (pos, id) in ids.iter().enumerate() {
        if pos != 0 {
            query.push(',');
        }
        query.push_str(&id.to_string());
    }
    query
}

impl Status {
    fn status_short(&self) -> &str {
        match self {
            Status::Scheduled => "scheduled",
            Status::Completed(_) => "delivered",
            Status::TemporaryFailure(_) => "tempfail",
            Status::PermanentFailure(_) => "permfail",
        }
    }

    fn status(&self) -> &str {
        match self {
            Status::Scheduled => "Scheduled",
            Status::Completed(_) => "Delivered",
            Status::TemporaryFailure(_) => "Temporary Failure",
            Status::PermanentFailure(_) => "Permanent Failure",
        }
    }

    fn details(&self) -> &str {
        match self {
            Status::Scheduled => "",
            Status::Completed(status) => status,
            Status::TemporaryFailure(status) => status,
            Status::PermanentFailure(status) => status,
        }
    }
}
