/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

use prettytable::{Attr, Cell, Row, Table};
use pwhash::sha512_crypt;
use reqwest::Method;
use serde_json::Value;

use super::{
    cli::{AccountCommands, Client},
    Principal, PrincipalField, PrincipalUpdate, PrincipalValue, Type,
};

impl AccountCommands {
    pub async fn exec(self, client: Client) {
        match self {
            AccountCommands::Create {
                name,
                password,
                description,
                quota,
                is_admin,
                addresses,
                member_of,
            } => {
                let principal = Principal {
                    typ: if is_admin.unwrap_or_default() {
                        Type::Superuser
                    } else {
                        Type::Individual
                    }
                    .into(),
                    quota,
                    name: name.clone().into(),
                    secrets: vec![sha512_crypt::hash(password).unwrap()],
                    emails: addresses.unwrap_or_default(),
                    member_of: member_of.unwrap_or_default(),
                    description,
                    ..Default::default()
                };
                let account_id = client
                    .http_request::<u32, _>(Method::POST, "/api/principal", Some(principal))
                    .await;
                eprintln!("Successfully created account {name:?} with id {account_id}.");
            }
            AccountCommands::Update {
                name,
                new_name,
                password,
                description,
                quota,
                is_admin,
                addresses,
                member_of,
            } => {
                let mut changes = Vec::new();
                if let Some(new_name) = new_name {
                    changes.push(PrincipalUpdate::set(
                        PrincipalField::Name,
                        PrincipalValue::String(new_name),
                    ));
                }
                if let Some(password) = password {
                    changes.push(PrincipalUpdate::add_item(
                        PrincipalField::Secrets,
                        PrincipalValue::String(sha512_crypt::hash(password).unwrap()),
                    ));
                }
                if let Some(description) = description {
                    changes.push(PrincipalUpdate::set(
                        PrincipalField::Description,
                        PrincipalValue::String(description),
                    ));
                }
                if let Some(quota) = quota {
                    changes.push(PrincipalUpdate::set(
                        PrincipalField::Quota,
                        PrincipalValue::Integer(quota),
                    ));
                }
                if let Some(is_admin) = is_admin {
                    changes.push(PrincipalUpdate::set(
                        PrincipalField::Type,
                        PrincipalValue::String(
                            if is_admin {
                                Type::Superuser
                            } else {
                                Type::Individual
                            }
                            .to_string()
                            .to_ascii_lowercase(),
                        ),
                    ));
                }
                if let Some(addresses) = addresses {
                    changes.push(PrincipalUpdate::set(
                        PrincipalField::Emails,
                        PrincipalValue::StringList(addresses),
                    ));
                }
                if let Some(member_of) = member_of {
                    changes.push(PrincipalUpdate::set(
                        PrincipalField::MemberOf,
                        PrincipalValue::StringList(member_of),
                    ));
                }

                if !changes.is_empty() {
                    client
                        .http_request::<Value, _>(
                            Method::PATCH,
                            &format!("/api/principal/{name}"),
                            Some(changes),
                        )
                        .await;
                    eprintln!("Successfully updated account {name:?}.");
                } else {
                    eprintln!("No changes to apply.");
                }
            }
            AccountCommands::AddEmail { name, addresses } => {
                client
                    .http_request::<Value, _>(
                        Method::PATCH,
                        &format!("/api/principal/{name}"),
                        Some(
                            addresses
                                .into_iter()
                                .map(|address| {
                                    PrincipalUpdate::add_item(
                                        PrincipalField::Emails,
                                        PrincipalValue::String(address),
                                    )
                                })
                                .collect::<Vec<_>>(),
                        ),
                    )
                    .await;
                eprintln!("Successfully updated account {name:?}.");
            }
            AccountCommands::RemoveEmail { name, addresses } => {
                client
                    .http_request::<Value, _>(
                        Method::PATCH,
                        &format!("/api/principal/{name}"),
                        Some(
                            addresses
                                .into_iter()
                                .map(|address| {
                                    PrincipalUpdate::remove_item(
                                        PrincipalField::Emails,
                                        PrincipalValue::String(address),
                                    )
                                })
                                .collect::<Vec<_>>(),
                        ),
                    )
                    .await;
                eprintln!("Successfully updated account {name:?}.");
            }
            AccountCommands::AddToGroup { name, member_of } => {
                client
                    .http_request::<Value, _>(
                        Method::PATCH,
                        &format!("/api/principal/{name}"),
                        Some(
                            member_of
                                .into_iter()
                                .map(|group| {
                                    PrincipalUpdate::add_item(
                                        PrincipalField::MemberOf,
                                        PrincipalValue::String(group),
                                    )
                                })
                                .collect::<Vec<_>>(),
                        ),
                    )
                    .await;
                eprintln!("Successfully updated account {name:?}.");
            }
            AccountCommands::RemoveFromGroup { name, member_of } => {
                client
                    .http_request::<Value, _>(
                        Method::PATCH,
                        &format!("/api/principal/{name}"),
                        Some(
                            member_of
                                .into_iter()
                                .map(|group| {
                                    PrincipalUpdate::remove_item(
                                        PrincipalField::MemberOf,
                                        PrincipalValue::String(group),
                                    )
                                })
                                .collect::<Vec<_>>(),
                        ),
                    )
                    .await;
                eprintln!("Successfully updated account {name:?}.");
            }
            AccountCommands::Delete { name } => {
                client
                    .http_request::<Value, String>(
                        Method::DELETE,
                        &format!("/api/principal/{name}"),
                        None,
                    )
                    .await;
                eprintln!("Successfully deleted account {name:?}.");
            }
            AccountCommands::Display { name } => {
                client.display_principal(&name).await;
            }
            AccountCommands::List {
                filter,
                limit,
                page,
            } => {
                client
                    .list_principals("individual", "Account", filter, page, limit)
                    .await;
            }
        }
    }
}

impl Client {
    pub async fn display_principal(&self, name: &str) {
        let principal = self
            .http_request::<Principal, String>(Method::GET, &format!("/api/principal/{name}"), None)
            .await;
        let mut table = Table::new();
        if let Some(name) = principal.name {
            table.add_row(Row::new(vec![
                Cell::new("Name").with_style(Attr::Bold),
                Cell::new(&name),
            ]));
        }
        if let Some(typ) = principal.typ {
            table.add_row(Row::new(vec![
                Cell::new("Type").with_style(Attr::Bold),
                Cell::new(&typ.to_string()),
            ]));
        }
        if let Some(description) = principal.description {
            table.add_row(Row::new(vec![
                Cell::new("Description").with_style(Attr::Bold),
                Cell::new(&description),
            ]));
        }
        if matches!(
            principal.typ,
            Some(Type::Individual | Type::Superuser | Type::Group)
        ) {
            if let Some(quota) = principal.quota {
                table.add_row(Row::new(vec![
                    Cell::new("Quota").with_style(Attr::Bold),
                    if quota != 0 {
                        Cell::new(&quota.to_string())
                    } else {
                        Cell::new("Unlimited")
                    },
                ]));
            }
            if let Some(used_quota) = principal.used_quota {
                table.add_row(Row::new(vec![
                    Cell::new("Used Quota").with_style(Attr::Bold),
                    Cell::new(&used_quota.to_string()),
                ]));
            }
        }
        if !principal.members.is_empty() {
            table.add_row(Row::new(vec![
                Cell::new("Members").with_style(Attr::Bold),
                Cell::new(&principal.members.join(", ")),
            ]));
        }
        if !principal.member_of.is_empty() {
            table.add_row(Row::new(vec![
                Cell::new("Member of").with_style(Attr::Bold),
                Cell::new(&principal.member_of.join(", ")),
            ]));
        }
        if !principal.emails.is_empty() {
            table.add_row(Row::new(vec![
                Cell::new("E-mail address(es)").with_style(Attr::Bold),
                Cell::new(&principal.emails.join(", ")),
            ]));
        }
        eprintln!();
        table.printstd();
        eprintln!();
    }

    pub async fn list_principals(
        &self,
        record_type: &str,
        record_name: &str,
        filter: Option<String>,
        page: Option<usize>,
        limit: Option<usize>,
    ) {
        let mut query = form_urlencoded::Serializer::new("/api/principal?".to_string());

        query.append_pair("type", record_type);

        if let Some(filter) = &filter {
            query.append_pair("filter", filter);
        }
        if let Some(limit) = limit {
            query.append_pair("limit", &limit.to_string());
        }
        if let Some(page) = page {
            query.append_pair("page", &page.to_string());
        }

        let results = self
            .http_request::<ListResponse, String>(Method::GET, &query.finish(), None)
            .await;
        if !results.items.is_empty() {
            let mut table = Table::new();
            table.add_row(Row::new(vec![
                Cell::new(&format!("{record_name} Name")).with_style(Attr::Bold)
            ]));

            for item in &results.items {
                table.add_row(Row::new(vec![Cell::new(item)]));
            }

            eprintln!();
            table.printstd();
            eprintln!();
        }

        eprintln!(
            "\n\n{} {}{} found.\n",
            results.total,
            record_name.to_ascii_lowercase(),
            if results.total == 1 { "" } else { "s" }
        );
    }
}

#[derive(Debug, serde::Deserialize)]
struct ListResponse {
    pub total: usize,
    pub items: Vec<String>,
}

impl Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Type::Superuser => write!(f, "Superuser"),
            Type::Individual => write!(f, "Individual"),
            Type::Group => write!(f, "Group"),
            Type::List => write!(f, "List"),
            Type::Resource => write!(f, "Resource"),
            Type::Location => write!(f, "Location"),
            Type::Other => write!(f, "Other"),
        }
    }
}
