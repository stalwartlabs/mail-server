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
                member_of,
            } => {
                let principal = Principal {
                    id: None,
                    typ: Some(Type::Group),
                    quota: None,
                    used_quota: None,
                    name: name.clone().into(),
                    secrets: vec![],
                    emails: email.map(|e| vec![e]).unwrap_or_default(),
                    member_of: member_of.unwrap_or_default(),
                    description,
                };
                let account_id = client
                    .http_request::<u32, _>(Method::POST, "/admin/principal", Some(principal))
                    .await;
                eprintln!("Successfully created group {name:?} with id {account_id}.");
            }
            GroupCommands::Update {
                name,
                new_name,
                email,
                description,
                member_of,
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
                if let Some(member_of) = member_of {
                    changes.push(PrincipalUpdate::set(
                        PrincipalField::MemberOf,
                        PrincipalValue::StringList(member_of),
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
                            &format!("/admin/principal/{name}"),
                            Some(changes),
                        )
                        .await;
                    eprintln!("Successfully updated group {name:?}.");
                } else {
                    eprintln!("No changes to apply.");
                }
            }
            GroupCommands::AddToGroup { name, member_of } => {
                client
                    .http_request::<Value, _>(
                        Method::PATCH,
                        &format!("/admin/principal/{name}"),
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
                eprintln!("Successfully updated group {name:?}.");
            }
            GroupCommands::RemoveFromGroup { name, member_of } => {
                client
                    .http_request::<Value, _>(
                        Method::PATCH,
                        &format!("/admin/principal/{name}"),
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
                eprintln!("Successfully updated group {name:?}.");
            }
            GroupCommands::Display { name } => {
                client.display_principal(&name).await;
            }
            GroupCommands::List { from, limit } => {
                client.list_principals("group", "Group", from, limit).await;
            }
        }
    }
}
