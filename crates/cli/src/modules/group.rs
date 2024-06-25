/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::vec;

use reqwest::Method;
use serde_json::Value;

use crate::modules::{Principal, Type};

use super::{
    cli::{Client, GroupCommands},
    PrincipalField, PrincipalUpdate, PrincipalValue,
};

impl GroupCommands {
    pub async fn exec(self, client: Client) {
        match self {
            GroupCommands::Create {
                name,
                email,
                description,
                members,
            } => {
                let principal = Principal {
                    typ: Some(Type::Group),
                    name: name.clone().into(),
                    emails: email.map(|e| vec![e]).unwrap_or_default(),
                    description,
                    ..Default::default()
                };
                let account_id = client
                    .http_request::<u32, _>(Method::POST, "/api/principal", Some(principal))
                    .await;
                if let Some(members) = members {
                    client
                        .http_request::<Value, _>(
                            Method::PATCH,
                            &format!("/api/principal/{name}"),
                            Some(vec![PrincipalUpdate::set(
                                PrincipalField::Members,
                                PrincipalValue::StringList(members),
                            )]),
                        )
                        .await;
                }
                eprintln!("Successfully created group {name:?} with id {account_id}.");
            }
            GroupCommands::Update {
                name,
                new_name,
                email,
                description,
                members,
            } => {
                let mut changes = Vec::new();
                if let Some(new_name) = new_name {
                    changes.push(PrincipalUpdate::set(
                        PrincipalField::Name,
                        PrincipalValue::String(new_name),
                    ));
                }
                if let Some(email) = email {
                    changes.push(PrincipalUpdate::set(
                        PrincipalField::Emails,
                        PrincipalValue::StringList(vec![email]),
                    ));
                }
                if let Some(members) = members {
                    changes.push(PrincipalUpdate::set(
                        PrincipalField::Members,
                        PrincipalValue::StringList(members),
                    ));
                }
                if let Some(description) = description {
                    changes.push(PrincipalUpdate::set(
                        PrincipalField::Description,
                        PrincipalValue::String(description),
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
                    eprintln!("Successfully updated group {name:?}.");
                } else {
                    eprintln!("No changes to apply.");
                }
            }
            GroupCommands::AddMembers { name, members } => {
                client
                    .http_request::<Value, _>(
                        Method::PATCH,
                        &format!("/api/principal/{name}"),
                        Some(
                            members
                                .into_iter()
                                .map(|group| {
                                    PrincipalUpdate::add_item(
                                        PrincipalField::Members,
                                        PrincipalValue::String(group),
                                    )
                                })
                                .collect::<Vec<_>>(),
                        ),
                    )
                    .await;
                eprintln!("Successfully updated group {name:?}.");
            }
            GroupCommands::RemoveMembers { name, members } => {
                client
                    .http_request::<Value, _>(
                        Method::PATCH,
                        &format!("/api/principal/{name}"),
                        Some(
                            members
                                .into_iter()
                                .map(|group| {
                                    PrincipalUpdate::remove_item(
                                        PrincipalField::Members,
                                        PrincipalValue::String(group),
                                    )
                                })
                                .collect::<Vec<_>>(),
                        ),
                    )
                    .await;
                eprintln!("Successfully updated group {name:?}.");
            }
            GroupCommands::Display { name } => {
                client.display_principal(&name).await;
            }
            GroupCommands::List {
                filter,
                limit,
                page,
            } => {
                client
                    .list_principals("group", "Group", filter, page, limit)
                    .await;
            }
        }
    }
}
